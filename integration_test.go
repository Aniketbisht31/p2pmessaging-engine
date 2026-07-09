package p2p

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type unreliableConn struct {
	net.Conn
	mu        sync.Mutex
	buffer    bytes.Buffer
	dropEvery int
	count     int
	delay     time.Duration
}

func newUnreliableConn(conn net.Conn, dropEvery int, delay time.Duration) net.Conn {
	return &unreliableConn{Conn: conn, dropEvery: dropEvery, delay: delay}
}

func (u *unreliableConn) Write(p []byte) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	n, err := u.buffer.Write(p)
	if err != nil {
		return n, err
	}
	for {
		if u.buffer.Len() < HeaderSize {
			break
		}
		headBuf := u.buffer.Bytes()[:HeaderSize]
		head, err := DecodeHeader(headBuf, DefaultMaxPayload)
		if err != nil {
			return n, err
		}
		frameLen := HeaderSize + int(head.Length)
		if u.buffer.Len() < frameLen {
			break
		}
		frameBytes := make([]byte, frameLen)
		if _, err := io.ReadFull(&u.buffer, frameBytes); err != nil {
			return n, err
		}
		u.count++
		if u.dropEvery > 0 && u.count%u.dropEvery == 0 {
			continue
		}
		if u.delay > 0 {
			time.Sleep(u.delay)
		}
		if _, err := u.Conn.Write(frameBytes); err != nil {
			return n, err
		}
	}
	return n, nil
}

func (u *unreliableConn) Read(p []byte) (int, error) {
	return u.Conn.Read(p)
}

func setupPeerPair(t *testing.T, dropEveryA int, delayA time.Duration, dropEveryB int, delayB time.Duration) (*ConnManager, *ConnManager, func()) {
	aMgr := NewConnManager(nil)
	bMgr := NewConnManager(nil)

	aConn, bConn := net.Pipe()
	var aPeerConn, bPeerConn net.Conn
	if dropEveryA == 0 && delayA == 0 {
		aPeerConn = aConn
	} else {
		aPeerConn = newUnreliableConn(aConn, dropEveryA, delayA)
	}
	if dropEveryB == 0 && delayB == 0 {
		bPeerConn = bConn
	} else {
		bPeerConn = newUnreliableConn(bConn, dropEveryB, delayB)
	}

	aMgr.addConn("peer-b", aPeerConn).start(5*time.Second, 5*time.Second, time.Second)
	bMgr.addConn("peer-a", bPeerConn).start(5*time.Second, 5*time.Second, time.Second)

	return aMgr, bMgr, func() {
		aMgr.Close()
		bMgr.Close()
	}
}

func TestIntegrationHandshakeAndEncryptedDelivery(t *testing.T) {
	aMgr, bMgr, cleanup := setupPeerPair(t, 0, 0, 0, 0)
	defer cleanup()

	var aKey, bKey []byte
	aKeyCh := make(chan []byte, 1)
	bKeyCh := make(chan []byte, 1)

	_, aPrivID, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	aEphemeralPriv, _, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}

	_, bPrivID, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bEphemeralPriv, _, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}

	hsA, err := NewHandshake(aPrivID, aEphemeralPriv)
	if err != nil {
		t.Fatal(err)
	}
	dataA, err := hsA.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	hsB, err := NewHandshake(bPrivID, bEphemeralPriv)
	if err != nil {
		t.Fatal(err)
	}
	dataB, err := hsB.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	const messageCount = 12
	wantMessages := make([]string, messageCount)
	for i := 0; i < messageCount; i++ {
		wantMessages[i] = fmt.Sprintf("message %c", 'A'+i)
	}

	received := make([]string, 0, messageCount)
	receivedMu := sync.Mutex{}
	done := make(chan struct{})
	var esA, esB *SessionCipher
	var bRespondOnce sync.Once
	bMgr.StartWorkerPool(1, func(msg InboundMessage) {
		switch msg.Frame.Header.Type {
		case TypeHandshake:
			h, err := UnmarshalHandshake(msg.Frame.Payload)
			if err != nil {
				t.Error(err)
				return
			}
			if err := VerifyHandshake(h); err != nil {
				t.Error(err)
				return
			}
			key, err := DeriveSessionKey(bEphemeralPriv, h.EphemeralPublicKey, []byte(SessionKeyInfo))
			if err != nil {
				t.Error(err)
				return
			}
			select {
			case bKeyCh <- key:
			default:
			}
			bRespondOnce.Do(func() {
				frame, err := NewFrame(TypeHandshake, 0, dataB)
				if err != nil {
					t.Error(err)
					return
				}
				if err := bMgr.SendFrame(msg.PeerID, frame, time.Second); err != nil {
					t.Error(err)
				}
			})
		case TypeMSG:
			m, err := DecodeMessage(msg.Frame.Payload)
			if err != nil {
				t.Error(err)
				return
			}
			seq := uint64(0)
			if len(m.Body) >= 8 {
				seq = binary.BigEndian.Uint64(m.Body[0:8])
			}
			t.Logf("decrypt attempt id=%d seq=%d recvSeq=%d len=%d", m.ID, seq, esB.recvSeq, len(m.Body))
			plaintext, err := esB.Decrypt(m.Body)
			if err != nil {
				t.Errorf("decrypt failed id=%d seq=%d recvSeq=%d len=%d: %v", m.ID, seq, esB.recvSeq, len(m.Body), err)
				return
			}
			t.Logf("received raw msg id=%d seq=%d payload=%q", m.ID, seq, plaintext)
			receivedMu.Lock()
			received = append(received, string(plaintext))
			if len(received) == messageCount {
				close(done)
			}
			receivedMu.Unlock()
		}
	})

	var aRespondOnce sync.Once
	aMgr.StartWorkerPool(1, func(msg InboundMessage) {
		if msg.Frame.Header.Type != TypeHandshake {
			return
		}
		h, err := UnmarshalHandshake(msg.Frame.Payload)
		if err != nil {
			t.Error(err)
			return
		}
		if err := VerifyHandshake(h); err != nil {
			t.Error(err)
			return
		}
		key, err := DeriveSessionKey(aEphemeralPriv, h.EphemeralPublicKey, []byte(SessionKeyInfo))
		if err != nil {
			t.Error(err)
			return
		}
		select {
		case aKeyCh <- key:
		default:
		}
		// ensure the peer also receives our initial handshake if it is delayed.
		aRespondOnce.Do(func() {
			frame, err := NewFrame(TypeHandshake, 0, dataA)
			if err != nil {
				t.Error(err)
				return
			}
			if err := aMgr.SendFrame(msg.PeerID, frame, time.Second); err != nil {
				t.Error(err)
			}
		})
	})

	frameA, err := NewFrame(TypeHandshake, 0, dataA)
	if err != nil {
		t.Fatal(err)
	}
	if err := aMgr.SendFrame("peer-b", frameA, time.Second); err != nil {
		t.Fatal(err)
	}

	select {
	case aKey = <-aKeyCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for A handshake completion")
	}
	select {
	case bKey = <-bKeyCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for B handshake completion")
	}

	if !bytes.Equal(aKey, bKey) {
		t.Fatal("derived session keys do not match")
	}

	esA, err = NewSessionCipher(aKey)
	if err != nil {
		t.Fatal(err)
	}
	esB, err = NewSessionCipher(bKey)
	if err != nil {
		t.Fatal(err)
	}

	bMgr.StartWorkerPool(1, func(msg InboundMessage) {
		if msg.Frame.Header.Type != TypeMSG {
			return
		}
		m, err := DecodeMessage(msg.Frame.Payload)
		if err != nil {
			t.Error(err)
			return
		}
		seq := uint64(0)
		if len(m.Body) >= 8 {
			seq = binary.BigEndian.Uint64(m.Body[0:8])
		}
		t.Logf("decrypt attempt id=%d seq=%d recvSeq=%d len=%d", m.ID, seq, esB.recvSeq, len(m.Body))
		plaintext, err := esB.Decrypt(m.Body)
		if err != nil {
			t.Errorf("decrypt failed id=%d seq=%d recvSeq=%d len=%d: %v", m.ID, seq, esB.recvSeq, len(m.Body), err)
			return
		}
		t.Logf("received raw msg id=%d seq=%d payload=%q", m.ID, seq, plaintext)
		receivedMu.Lock()
		received = append(received, string(plaintext))
		if len(received) == messageCount {
			close(done)
		}
		receivedMu.Unlock()
	})

	for i, text := range wantMessages {
		ciphertext, err := esA.Encrypt([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		if len(ciphertext) < 8 {
			t.Fatal("ciphertext too short")
		}
		seq := binary.BigEndian.Uint64(ciphertext[0:8])
		msg := Message{ID: uint64(time.Now().UnixNano()), Timestamp: time.Now().Unix(), Body: ciphertext}
		t.Logf("sending message %d id=%d seq=%d text=%q", i, msg.ID, seq, text)
		if err := aMgr.SendReliable("peer-b", msg, 50*time.Millisecond, 10, time.Second); err != nil {
			t.Fatalf("failed to send message %d: %v", i, err)
		}
		t.Logf("send complete %d", i)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for messages")
	}

	receivedMu.Lock()
	if len(received) != messageCount {
		t.Fatalf("expected %d messages, got %d", messageCount, len(received))
	}
	for i, got := range received {
		if got != wantMessages[i] {
			t.Fatalf("message %d out of order: got %q, want %q", i, got, wantMessages[i])
		}
	}
	receivedMu.Unlock()
}

func TestIntegrationReliableDeliveryWithDroppedFrames(t *testing.T) {
	aMgr, bMgr, cleanup := setupPeerPair(t, 3, 15*time.Millisecond, 4, 5*time.Millisecond)
	defer cleanup()

	messageCount := 20
	wantMessages := make([]string, messageCount)
	for i := 0; i < messageCount; i++ {
		wantMessages[i] = fmt.Sprintf("payload-%d", i%10)
	}

	received := make([]string, 0, messageCount)
	receivedMu := sync.Mutex{}
	done := make(chan struct{})

	bMgr.StartWorkerPool(1, func(msg InboundMessage) {
		if msg.Frame.Header.Type != TypeMSG {
			return
		}
		m, err := DecodeMessage(msg.Frame.Payload)
		if err != nil {
			t.Error(err)
			return
		}
		receivedMu.Lock()
		received = append(received, string(m.Body))
		if len(received) == messageCount {
			close(done)
		}
		receivedMu.Unlock()
	})

	for _, text := range wantMessages {
		if err := aMgr.SendReliable("peer-b", Message{Timestamp: time.Now().Unix(), Body: []byte(text)}, 50*time.Millisecond, 15, time.Second); err != nil {
			t.Fatal(err)
		}
	}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for delivered messages")
	}

	receivedMu.Lock()
	if len(received) != messageCount {
		t.Fatalf("expected %d messages, got %d", messageCount, len(received))
	}
	for i, got := range received {
		if got != wantMessages[i] {
			t.Fatalf("message %d out of order: got %q, want %q", i, got, wantMessages[i])
		}
	}
	receivedMu.Unlock()
}
