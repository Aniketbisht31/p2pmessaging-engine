package p2p

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

type oneByteReader struct{ r io.Reader }

func (r oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.r.Read(p)
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 2 {
		p = p[:2]
	}
	return w.Buffer.Write(p)
}

func TestFrameRoundTripWithPartialIO(t *testing.T) {
	f, err := NewFrame(TypeMSG, 3, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	var wire shortWriter
	if err := f.WriteTo(&wire); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(oneByteReader{bytes.NewReader(wire.Bytes())}, DefaultMaxPayload)
	if err != nil {
		t.Fatal(err)
	}
	if got.Header.Type != TypeMSG || got.Header.Flags != 3 || !bytes.Equal(got.Payload, f.Payload) {
		t.Fatalf("unexpected frame: %+v", got)
	}
}

func TestReadFrameTruncatedHeader(t *testing.T) {
	_, err := ReadFrame(bytes.NewReader(make([]byte, HeaderSize-1)), DefaultMaxPayload)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v", err)
	}
}

func TestReadFrameTruncatedPayload(t *testing.T) {
	f, _ := NewFrame(TypeMSG, 0, []byte("payload"))
	var b bytes.Buffer
	if err := f.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	_, err := ReadFrame(bytes.NewReader(b.Bytes()[:b.Len()-1]), DefaultMaxPayload)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v", err)
	}
}

func TestOversizedFrameRejectedBeforePayloadRead(t *testing.T) {
	h := Header{Magic: Magic, Version: ProtocolVersion, Type: TypeMSG, Length: 1025}
	var raw [HeaderSize]byte
	if err := h.Encode(raw[:]); err != nil {
		t.Fatal(err)
	}
	_, err := ReadFrame(bytes.NewReader(raw[:]), 1024)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("got %v", err)
	}
}

func TestNewFrameRejectsInvalidMessageType(t *testing.T) {
	_, err := NewFrame(MessageType(0xff), 0, nil)
	if !errors.Is(err, ErrBadMessageType) {
		t.Fatalf("got %v", err)
	}
}

func TestDecodeMessageRejectsShortPayload(t *testing.T) {
	_, err := DecodeMessage([]byte("short"))
	if !errors.Is(err, ErrMalformedHeader) {
		t.Fatalf("got %v", err)
	}
}

func TestHandshakeRoundTrip(t *testing.T) {
	_, idPrivA, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, idPrivB, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	privA, _, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	privB, _, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	hsA, err := NewHandshake(idPrivA, privA)
	if err != nil {
		t.Fatal(err)
	}
	hsB, err := NewHandshake(idPrivB, privB)
	if err != nil {
		t.Fatal(err)
	}
	dataA, err := hsA.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	dataB, err := hsB.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	peerA, err := UnmarshalHandshake(dataB)
	if err != nil {
		t.Fatal(err)
	}
	peerB, err := UnmarshalHandshake(dataA)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyHandshake(peerA); err != nil {
		t.Fatal(err)
	}
	if err := VerifyHandshake(peerB); err != nil {
		t.Fatal(err)
	}
	keyA, err := DeriveSessionKey(privA, peerA.EphemeralPublicKey, []byte(SessionKeyInfo))
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := DeriveSessionKey(privB, peerB.EphemeralPublicKey, []byte(SessionKeyInfo))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keyA, keyB) {
		t.Fatalf("session keys differ")
	}
}

func TestVerifyHandshakeRejectsInvalidSignature(t *testing.T) {
	_, idPriv, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	priv, _, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	hs, err := NewHandshake(idPriv, priv)
	if err != nil {
		t.Fatal(err)
	}
	hs.Signature[0] ^= 1
	if err := VerifyHandshake(hs); !errors.Is(err, ErrHandshakeSignature) {
		t.Fatalf("got %v", err)
	}
}

func TestSessionCipherEncryptDecrypt(t *testing.T) {
	_, idPrivA, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, idPrivB, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	privA, _, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	privB, _, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	hsA, err := NewHandshake(idPrivA, privA)
	if err != nil {
		t.Fatal(err)
	}
	hsB, err := NewHandshake(idPrivB, privB)
	if err != nil {
		t.Fatal(err)
	}
	dataA, err := hsA.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	dataB, err := hsB.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	peerA, err := UnmarshalHandshake(dataB)
	if err != nil {
		t.Fatal(err)
	}
	peerB, err := UnmarshalHandshake(dataA)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyHandshake(peerA); err != nil {
		t.Fatal(err)
	}
	if err := VerifyHandshake(peerB); err != nil {
		t.Fatal(err)
	}
	keyA, err := DeriveSessionKey(privA, peerA.EphemeralPublicKey, []byte(SessionKeyInfo))
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := DeriveSessionKey(privB, peerB.EphemeralPublicKey, []byte(SessionKeyInfo))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keyA, keyB) {
		t.Fatalf("session keys differ")
	}
	encA, err := NewSessionCipher(keyA)
	if err != nil {
		t.Fatal(err)
	}
	encB, err := NewSessionCipher(keyB)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("hello, secure world")
	ciphertext, err := encA.Encrypt(message)
	if err != nil {
		t.Fatal(err)
	}
	plaintxt, err := encB.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintxt, message) {
		t.Fatalf("expected %q got %q", message, plaintxt)
	}
}

func TestSessionCipherRejectsReplayedFrames(t *testing.T) {
	key := make([]byte, SessionKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	a, err := NewSessionCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSessionCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := a.Encrypt([]byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Decrypt(data); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Decrypt(data); !errors.Is(err, ErrReplayOrOutOfOrder) {
		t.Fatalf("expected replay error, got %v", err)
	}
}

func TestMalformedHeaders(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte)
		want   error
	}{
		{"magic", func(b []byte) { b[0] ^= 1 }, ErrBadMagic},
		{"version", func(b []byte) { b[4]++ }, ErrBadVersion},
		{"type", func(b []byte) { b[5] = 0xff }, ErrBadMessageType},
		{"reserved", func(b []byte) { b[7] = 1 }, ErrMalformedHeader},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := Header{Magic: Magic, Version: ProtocolVersion, Type: TypePing}
			b := make([]byte, HeaderSize)
			if err := h.Encode(b); err != nil {
				t.Fatal(err)
			}
			tc.mutate(b)
			_, err := DecodeHeader(b, DefaultMaxPayload)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestStateMachine(t *testing.T) {
	s := NewStateMachine()
	if err := s.Accept(TypeMSG); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("MSG before handshake: %v", err)
	}
	for _, typ := range []MessageType{TypeHandshake, TypeAuth, TypeAuth, TypeMSG, TypeACK, TypePing, TypePong, TypeDiscovery} {
		if err := s.Accept(typ); err != nil {
			t.Fatalf("accept %d in state %d: %v", typ, s.State(), err)
		}
	}
	if s.State() != StateReady {
		t.Fatalf("got state %d", s.State())
	}
	s.Close()
	if err := s.Accept(TypePing); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("accepted after close: %v", err)
	}
}
