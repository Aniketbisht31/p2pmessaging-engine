package p2p

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Core networking layer: per-connection read/write goroutines communicating
// with a central ConnManager via channels. Backpressure, timeouts and
// graceful shutdown are supported. Inbound frames are dispatched to a
// worker pool to avoid blocking network loops.

var (
	ErrConnNotFound = errors.New("connection not found")
	// when outbound channel is full and send times out
	ErrOutboundFull = errors.New("outbound channel full")
)

type InboundMessage struct {
	PeerID string
	Frame  Frame
}

type PeerConn struct {
	id       string
	conn     net.Conn
	mgr      *ConnManager
	outbound chan Frame
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	// reliable delivery state
	pending   map[uint64]*pendingEntry
	pendingMu sync.Mutex
	// processed message ids for idempotency
	processed   map[uint64]struct{}
	processedMu sync.Mutex
}

func (p *PeerConn) start(readTimeout, writeTimeout time.Duration, backpressure time.Duration) {
	p.wg.Add(2)
	go p.readLoop(readTimeout, backpressure)
	go p.writeLoop(writeTimeout)
}

func (p *PeerConn) close() {
	if p.cancel != nil {
		p.cancel()
	}
	p.conn.Close()
	p.wg.Wait()
	if p.mgr != nil {
		p.mgr.onPeerDisconnect(p.id)
	}
}

func (p *PeerConn) readLoop(readTimeout, backpressure time.Duration) {
	defer p.wg.Done()
	for {
		select {
		case <-p.ctx.Done():
			return
		default:
		}
		_ = p.conn.SetReadDeadline(time.Now().Add(readTimeout))
		f, err := ReadFrame(p.conn, DefaultMaxPayload)
		if err != nil {
			return
		}
		// handle ACK frames locally
		switch f.Header.Type {
		case TypeACK:
			ack, err := DecodeAck(f.Payload)
			if err == nil {
				p.handleAck(ack.MessageID)
			}
			continue
		case TypeMSG:
			// decode message and check idempotency
			msg, err := DecodeMessage(f.Payload)
			if err != nil {
				// malformed message; close
				return
			}
			seq := uint64(0)
			if len(msg.Body) >= 8 {
				seq = binary.BigEndian.Uint64(msg.Body[0:8])
			}
			// if already processed, send ACK and skip enqueue
			p.processedMu.Lock()
			_, seen := p.processed[msg.ID]
			if !seen {
				p.processed[msg.ID] = struct{}{}
			}
			p.processedMu.Unlock()
			fmt.Printf("[readLoop %s] TypeMSG id=%d seq=%d len=%d seen=%v\n", p.id, msg.ID, seq, len(msg.Body), seen)
			// send ACK to peer to stop retransmits
			ack := Ack{MessageID: msg.ID, Status: 0}
			ackPayload := EncodeAck(ack)
			ackFrame, _ := NewFrame(TypeACK, 0, ackPayload)
			// best-effort enqueue ACK
			select {
			case p.outbound <- ackFrame:
			default:
			}
			if seen {
				continue
			}
			// backpressure: attempt to deliver inbound frame to manager with timeout
			select {
			case p.mgr.inbound <- InboundMessage{PeerID: p.id, Frame: f}:
			case <-time.After(backpressure):
				// manager is too slow; treat as error and close connection
				return
			case <-p.ctx.Done():
				return
			}
			continue
		case TypeDiscovery:
			addrs := DecodeDiscovery(f.Payload)
			if len(addrs) > 0 {
				p.mgr.handleDiscoveredPeers(addrs)
			}
			continue
		default:
			// other frame types: forward to manager
		}
		// backpressure: attempt to deliver inbound frame to manager with timeout
		select {
		case p.mgr.inbound <- InboundMessage{PeerID: p.id, Frame: f}:
		case <-time.After(backpressure):
			// manager is too slow; treat as error and close connection
			return
		case <-p.ctx.Done():
			return
		}
	}
}

type pendingEntry struct {
	frame    Frame
	done     chan struct{}
	attempts int
}

func (p *PeerConn) handleAck(messageID uint64) {
	p.pendingMu.Lock()
	defer p.pendingMu.Unlock()
	if e, ok := p.pending[messageID]; ok {
		fmt.Printf("[handleAck %s] ack messageID=%d attempts=%d\n", p.id, messageID, e.attempts)
		select {
		case <-e.done:
			// already closed
		default:
			close(e.done)
		}
		delete(p.pending, messageID)
	}
}

func (p *PeerConn) writeLoop(writeTimeout time.Duration) {
	defer p.wg.Done()
	for {
		select {
		case <-p.ctx.Done():
			return
		case f, ok := <-p.outbound:
			if !ok {
				return
			}
			_ = p.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := f.WriteTo(p.conn); err != nil {
				return
			}
		}
	}
}

// ConnManager manages active connections, discovery, and a worker pool.
type ConnManager struct {
	listener   net.Listener
	listenAddr string
	mu         sync.Mutex
	conns      map[string]*PeerConn

	inbound chan InboundMessage

	workersWG sync.WaitGroup

	storage        *Storage
	knownPeers     map[string]KnownPeer
	reconnecting   map[string]context.CancelFunc
	readTimeout    time.Duration
	writeTimeout   time.Duration
	backpressure   time.Duration
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
}

func NewConnManager(store *Storage) *ConnManager {
	ctx, cancel := context.WithCancel(context.Background())
	knownPeers := make(map[string]KnownPeer)
	if store != nil {
		if peers, err := store.LoadKnownPeers(); err == nil {
			for _, peer := range peers {
				knownPeers[peer.Address] = peer
			}
		}
	}
	return &ConnManager{
		conns:          make(map[string]*PeerConn),
		inbound:        make(chan InboundMessage, 1024),
		storage:        store,
		knownPeers:     knownPeers,
		reconnecting:   make(map[string]context.CancelFunc),
		shutdownCtx:    ctx,
		shutdownCancel: cancel,
	}
}

// ListenAndServe starts listening on the address and accepts incoming peers.
// Each accepted connection is wrapped and run with read/write goroutines.
func (m *ConnManager) ListenAndServe(addr string, readTimeout, writeTimeout, backpressure time.Duration) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	m.listener = ln
	m.listenAddr = addr
	m.readTimeout = readTimeout
	m.writeTimeout = writeTimeout
	m.backpressure = backpressure
	m.StartDiscoveryBroadcaster(30 * time.Second)
	go func() {
		<-m.shutdownCtx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-m.shutdownCtx.Done():
				return nil
			default:
				return err
			}
		}
		id := conn.RemoteAddr().String()
		m.recordPeer(id)
		pc := m.addConn(id, conn)
		pc.start(readTimeout, writeTimeout, backpressure)
	}
}

func (m *ConnManager) addConn(id string, conn net.Conn) *PeerConn {
	m.mu.Lock()
	defer m.mu.Unlock()
	ctx, cancel := context.WithCancel(m.shutdownCtx)
	pc := &PeerConn{id: id, conn: conn, mgr: m, outbound: make(chan Frame, 128), ctx: ctx, cancel: cancel, pending: make(map[uint64]*pendingEntry), processed: make(map[uint64]struct{})}
	m.conns[id] = pc
	return pc
}

func (m *ConnManager) onPeerDisconnect(id string) {
	m.mu.Lock()
	_, ok := m.conns[id]
	if ok {
		delete(m.conns, id)
	}
	if m.shutdownCtx.Err() != nil {
		m.mu.Unlock()
		return
	}
	_, known := m.knownPeers[id]
	_, reconnecting := m.reconnecting[id]
	m.mu.Unlock()
	if known && !reconnecting {
		m.scheduleReconnect(id)
	}
}

func (m *ConnManager) recordPeer(address string) {
	if address == "" || address == m.listenAddr {
		return
	}
	now := time.Now()
	m.mu.Lock()
	m.knownPeers[address] = KnownPeer{Address: address, LastSeen: now}
	m.mu.Unlock()
	if m.storage != nil {
		_ = m.storage.SaveKnownPeer(address, now)
	}
}

func (m *ConnManager) handleDiscoveredPeers(addresses []string) {
	for _, addr := range addresses {
		if addr == "" || addr == m.listenAddr {
			continue
		}
		m.recordPeer(addr)
		m.scheduleReconnect(addr)
	}
}

func (m *ConnManager) scheduleReconnect(address string) {
	m.mu.Lock()
	if m.shutdownCtx.Err() != nil {
		m.mu.Unlock()
		return
	}
	if _, connected := m.conns[address]; connected {
		m.mu.Unlock()
		return
	}
	if _, reconnecting := m.reconnecting[address]; reconnecting {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(m.shutdownCtx)
	m.reconnecting[address] = cancel
	readTimeout := m.readTimeout
	writeTimeout := m.writeTimeout
	backpressure := m.backpressure
	m.mu.Unlock()

	m.workersWG.Add(1)
	go func() {
		defer m.workersWG.Done()
		defer func() {
			m.mu.Lock()
			delete(m.reconnecting, address)
			m.mu.Unlock()
		}()

		backoff := 500 * time.Millisecond
		for {
			if ctx.Err() != nil {
				return
			}
			_, err := m.Connect(address, readTimeout, writeTimeout, backpressure)
			if err == nil {
				m.recordPeer(address)
				m.BroadcastDiscovery()
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
				if backoff < 30*time.Second {
					backoff *= 2
					if backoff > 30*time.Second {
						backoff = 30 * time.Second
					}
				}
			}
		}
	}()
}

func (m *ConnManager) BroadcastDiscovery() {
	m.mu.Lock()
	if m.listenAddr == "" {
		m.mu.Unlock()
		return
	}
	addrs := []string{m.listenAddr}
	conns := make([]*PeerConn, 0, len(m.conns))
	for _, pc := range m.conns {
		conns = append(conns, pc)
	}
	m.mu.Unlock()

	payload := EncodeDiscovery(addrs)
	frame, err := NewFrame(TypeDiscovery, 0, payload)
	if err != nil {
		return
	}
	for _, pc := range conns {
		_ = m.SendFrame(pc.id, frame, time.Second)
	}
}

func (m *ConnManager) StartDiscoveryBroadcaster(interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	m.workersWG.Add(1)
	go func() {
		defer m.workersWG.Done()
		for {
			select {
			case <-m.shutdownCtx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				m.BroadcastDiscovery()
			}
		}
	}()
}

// SendReliable sends a message and retransmits until an ACK is received or
// the maxAttempts is reached. It blocks until delivery or failure.
func (m *ConnManager) SendReliable(peerID string, msg Message, baseBackoff time.Duration, maxAttempts int, sendTimeout time.Duration) error {
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	if baseBackoff <= 0 {
		baseBackoff = 100 * time.Millisecond
	}
	m.mu.Lock()
	pc, ok := m.conns[peerID]
	m.mu.Unlock()
	if !ok {
		return ErrConnNotFound
	}
	if msg.ID == 0 {
		msg.ID = uint64(time.Now().UnixNano())
	}
	payload := EncodeMessage(msg)
	f, err := NewFrame(TypeMSG, 0, payload)
	if err != nil {
		return err
	}
	entry := &pendingEntry{frame: f, done: make(chan struct{}), attempts: 0}
	pc.pendingMu.Lock()
	pc.pending[msg.ID] = entry
	pc.pendingMu.Unlock()

	backoff := baseBackoff
	for entry.attempts = 0; entry.attempts < maxAttempts; entry.attempts++ {
		// try to send
		select {
		case pc.outbound <- f:
		case <-time.After(sendTimeout):
			// failed to enqueue, count as attempt
		case <-pc.ctx.Done():
			pc.pendingMu.Lock()
			delete(pc.pending, msg.ID)
			pc.pendingMu.Unlock()
			return ErrConnNotFound
		}

		// wait for ack or timeout
		select {
		case <-entry.done:
			// success
			return nil
		case <-time.After(backoff):
			backoff *= 2
			continue
		case <-pc.ctx.Done():
			pc.pendingMu.Lock()
			delete(pc.pending, msg.ID)
			pc.pendingMu.Unlock()
			return ErrConnNotFound
		}
	}
	// exhausted attempts
	pc.pendingMu.Lock()
	delete(pc.pending, msg.ID)
	pc.pendingMu.Unlock()
	return errors.New("reliable send: attempts exhausted")
}

// Connect dials a remote peer and starts its loops.
func (m *ConnManager) Connect(addr string, readTimeout, writeTimeout, backpressure time.Duration) (*PeerConn, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	id := conn.RemoteAddr().String()
	pc := m.addConn(id, conn)
	m.recordPeer(id)
	m.mu.Lock()
	m.readTimeout = readTimeout
	m.writeTimeout = writeTimeout
	m.backpressure = backpressure
	m.mu.Unlock()
	pc.start(readTimeout, writeTimeout, backpressure)
	return pc, nil
}

// SendFrame enqueues a frame for delivery to a peer with backpressure timeout.
func (m *ConnManager) SendFrame(peerID string, f Frame, timeout time.Duration) error {
	m.mu.Lock()
	pc, ok := m.conns[peerID]
	m.mu.Unlock()
	if !ok {
		return ErrConnNotFound
	}
	select {
	case pc.outbound <- f:
		return nil
	case <-time.After(timeout):
		return ErrOutboundFull
	case <-pc.ctx.Done():
		return ErrConnNotFound
	}
}

// StartWorkerPool launches n workers that process inbound messages via the handler.
func (m *ConnManager) StartWorkerPool(n int, handler func(InboundMessage)) {
	for i := 0; i < n; i++ {
		m.workersWG.Add(1)
		go func() {
			defer m.workersWG.Done()
			for {
				select {
				case <-m.shutdownCtx.Done():
					return
				case msg := <-m.inbound:
					handler(msg)
				}
			}
		}()
	}
}

// Close gracefully shuts down the manager and all connections.
func (m *ConnManager) Close() {
	m.shutdownCancel()
	if m.listener != nil {
		m.listener.Close()
	}
	m.mu.Lock()
	pcs := make([]*PeerConn, 0, len(m.conns))
	for _, pc := range m.conns {
		pcs = append(pcs, pc)
	}
	m.conns = make(map[string]*PeerConn)
	m.mu.Unlock()
	for _, pc := range pcs {
		pc.close()
		close(pc.outbound)
	}
	// wait for workers
	m.workersWG.Wait()
}
