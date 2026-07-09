package p2p

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrPeerAlreadyConnected = errors.New("peer already connected")
)

type Client struct {
	mgr     *ConnManager
	storage *Storage
	mu      sync.Mutex
}

func NewClient(mgr *ConnManager, storage *Storage) *Client {
	return &Client{mgr: mgr, storage: storage}
}

func (c *Client) SendMessage(peerID, text string) error {
	if peerID == "" {
		return errors.New("peer ID required")
	}
	msg := Message{ID: uint64(time.Now().UnixNano()), Timestamp: time.Now().Unix(), Body: []byte(text)}
	if err := c.mgr.SendReliable(peerID, msg, 100*time.Millisecond, 5, time.Second); err != nil {
		return err
	}
	if c.storage != nil {
		return c.storage.SaveMessage(peerID, 1, msg)
	}
	return nil
}

func (c *Client) ListPeers() []KnownPeer {
	c.mgr.mu.Lock()
	defer c.mgr.mu.Unlock()
	peers := make([]KnownPeer, 0, len(c.mgr.knownPeers))
	for _, peer := range c.mgr.knownPeers {
		peers = append(peers, peer)
	}
	return peers
}

func (c *Client) ConnectPeer(address string) error {
	c.mgr.mu.Lock()
	if _, ok := c.mgr.conns[address]; ok {
		c.mgr.mu.Unlock()
		return ErrPeerAlreadyConnected
	}
	c.mgr.mu.Unlock()
	_, err := c.mgr.Connect(address, 30*time.Second, 30*time.Second, 5*time.Second)
	return err
}

func (c *Client) AddContact(publicKey, alias string) error {
	if c.storage == nil {
		return errors.New("storage unavailable")
	}
	return c.storage.SaveContact(publicKey, alias)
}

func (c *Client) ListContacts() ([]Contact, error) {
	if c.storage == nil {
		return nil, errors.New("storage unavailable")
	}
	return c.storage.LoadContacts()
}

func (c *Client) ConversationHistory(page, pageSize int) ([]MessageRecord, error) {
	if c.storage == nil {
		return nil, errors.New("storage unavailable")
	}
	return c.storage.GetHistory(page, pageSize)
}

func (c *Client) StartInboundHandler(handler func(InboundMessage)) {
	c.mgr.StartWorkerPool(4, handler)
}

func (c *Client) Shutdown(ctx context.Context) error {
	c.mgr.Close()
	return nil
}
