package p2p

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	Magic               uint32 = 0x50325031 // "P2P1"
	ProtocolVersion     uint8  = 1
	HeaderSize                 = 12
	DefaultMaxPayload          = 4 << 20 // 4 MiB
	HandshakePubKeySize        = 32
	SessionKeySize             = 32
	SessionKeyInfo             = "p2p session key"
)

var (
	ErrBadMagic           = errors.New("protocol: bad magic")
	ErrBadVersion         = errors.New("protocol: unsupported version")
	ErrBadMessageType     = errors.New("protocol: invalid message type")
	ErrMalformedHeader    = errors.New("protocol: malformed header")
	ErrMalformedHandshake = errors.New("protocol: malformed handshake")
	ErrHandshakeSignature = errors.New("protocol: invalid handshake signature")
	ErrFrameTooLarge      = errors.New("protocol: frame too large")
	ErrInvalidState       = errors.New("protocol: message invalid in current state")
	ErrReplayOrOutOfOrder = errors.New("protocol: replayed or out-of-order frame")
	ErrNonceOverflow      = errors.New("protocol: nonce overflow")
)

// MessageType identifies the payload carried by a frame.
type MessageType uint8

const (
	TypeHandshake MessageType = 1 + iota
	TypeAuth
	TypeMSG
	TypeACK
	TypePing
	TypePong
	TypeDiscovery
)

func (t MessageType) Valid() bool { return t >= TypeHandshake && t <= TypeDiscovery }

// Header is the fixed-width wire header. Reserved must be zero in version 1.
// Layout: magic[4], version[1], type[1], flags[1], reserved[1], length[4].
type Header struct {
	Magic    uint32
	Version  uint8
	Type     MessageType
	Flags    uint8
	Reserved uint8
	Length   uint32
}

type Frame struct {
	Header  Header
	Payload []byte
}

// Payload models. Applications may encode these into Frame.Payload using the
// compact helpers below or replace them with a negotiated higher-level codec.
type Handshake struct {
	IdentityPublicKey  ed25519.PublicKey
	EphemeralPublicKey []byte
	Signature          []byte
}
type Auth struct {
	Method uint8
	Proof  []byte
}
type Message struct {
	ID        uint64
	Timestamp int64
	Body      []byte
}
type Ack struct {
	MessageID uint64
	Status    uint8
}
type Ping struct{ Nonce uint64 }
type Pong struct{ Nonce uint64 }
type Discovery struct{ Addresses []string }

func NewFrame(t MessageType, flags uint8, payload []byte) (Frame, error) {
	if !t.Valid() {
		return Frame{}, ErrBadMessageType
	}
	if uint64(len(payload)) > uint64(^uint32(0)) {
		return Frame{}, ErrFrameTooLarge
	}
	p := append([]byte(nil), payload...)
	return Frame{Header: Header{Magic: Magic, Version: ProtocolVersion, Type: t, Flags: flags, Length: uint32(len(p))}, Payload: p}, nil
}

func (h Header) Encode(dst []byte) error {
	if len(dst) < HeaderSize {
		return io.ErrShortBuffer
	}
	if h.Magic != Magic {
		return ErrBadMagic
	}
	if h.Version != ProtocolVersion {
		return ErrBadVersion
	}
	if !h.Type.Valid() {
		return ErrBadMessageType
	}
	if h.Reserved != 0 {
		return ErrMalformedHeader
	}
	binary.BigEndian.PutUint32(dst[0:4], h.Magic)
	dst[4], dst[5], dst[6], dst[7] = h.Version, byte(h.Type), h.Flags, h.Reserved
	binary.BigEndian.PutUint32(dst[8:12], h.Length)
	return nil
}

func DecodeHeader(src []byte, maxPayload uint32) (Header, error) {
	if len(src) < HeaderSize {
		return Header{}, io.ErrUnexpectedEOF
	}
	h := Header{Magic: binary.BigEndian.Uint32(src[0:4]), Version: src[4], Type: MessageType(src[5]), Flags: src[6], Reserved: src[7], Length: binary.BigEndian.Uint32(src[8:12])}
	if h.Magic != Magic {
		return Header{}, ErrBadMagic
	}
	if h.Version != ProtocolVersion {
		return Header{}, ErrBadVersion
	}
	if !h.Type.Valid() {
		return Header{}, ErrBadMessageType
	}
	if h.Reserved != 0 {
		return Header{}, ErrMalformedHeader
	}
	if h.Length > maxPayload {
		return Header{}, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, h.Length, maxPayload)
	}
	return h, nil
}

func (f Frame) WriteTo(w io.Writer) error {
	if uint64(len(f.Payload)) > uint64(^uint32(0)) {
		return ErrFrameTooLarge
	}
	f.Header.Length = uint32(len(f.Payload))
	var header [HeaderSize]byte
	if err := f.Header.Encode(header[:]); err != nil {
		return err
	}
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, f.Payload)
}

func ReadFrame(r io.Reader, maxPayload uint32) (Frame, error) {
	var raw [HeaderSize]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return Frame{}, err
	}
	h, err := DecodeHeader(raw[:], maxPayload)
	if err != nil {
		return Frame{}, err
	}
	payload := make([]byte, int(h.Length))
	if _, err := io.ReadFull(r, payload); err != nil {
		return Frame{}, err
	}
	return Frame{Header: h, Payload: payload}, nil
}

func GenerateIdentity() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return pub, priv, err
}

func GenerateEphemeral() (*ecdh.PrivateKey, []byte, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey().Bytes(), nil
}

func NewHandshake(identityPriv ed25519.PrivateKey, ephemeralPriv *ecdh.PrivateKey) (Handshake, error) {
	if len(identityPriv) != ed25519.PrivateKeySize || ephemeralPriv == nil {
		return Handshake{}, ErrMalformedHandshake
	}
	identityPub, ok := identityPriv.Public().(ed25519.PublicKey)
	if !ok {
		return Handshake{}, ErrMalformedHandshake
	}
	ephemeralPub := ephemeralPriv.PublicKey().Bytes()
	sig := ed25519.Sign(identityPriv, ephemeralPub)
	return Handshake{
		IdentityPublicKey:  append([]byte(nil), identityPub...),
		EphemeralPublicKey: append([]byte(nil), ephemeralPub...),
		Signature:          append([]byte(nil), sig...),
	}, nil
}

func (h Handshake) Marshal() ([]byte, error) {
	if len(h.IdentityPublicKey) != ed25519.PublicKeySize || len(h.EphemeralPublicKey) != HandshakePubKeySize || len(h.Signature) != ed25519.SignatureSize {
		return nil, ErrMalformedHandshake
	}
	buf := make([]byte, ed25519.PublicKeySize+HandshakePubKeySize+ed25519.SignatureSize)
	copy(buf[0:ed25519.PublicKeySize], h.IdentityPublicKey)
	copy(buf[ed25519.PublicKeySize:ed25519.PublicKeySize+HandshakePubKeySize], h.EphemeralPublicKey)
	copy(buf[ed25519.PublicKeySize+HandshakePubKeySize:], h.Signature)
	return buf, nil
}

func UnmarshalHandshake(data []byte) (Handshake, error) {
	expected := ed25519.PublicKeySize + HandshakePubKeySize + ed25519.SignatureSize
	if len(data) != expected {
		return Handshake{}, ErrMalformedHandshake
	}
	h := Handshake{
		IdentityPublicKey:  append([]byte(nil), data[0:ed25519.PublicKeySize]...),
		EphemeralPublicKey: append([]byte(nil), data[ed25519.PublicKeySize:ed25519.PublicKeySize+HandshakePubKeySize]...),
		Signature:          append([]byte(nil), data[ed25519.PublicKeySize+HandshakePubKeySize:]...),
	}
	return h, nil
}

func VerifyHandshake(h Handshake) error {
	if !ed25519.Verify(h.IdentityPublicKey, h.EphemeralPublicKey, h.Signature) {
		return ErrHandshakeSignature
	}
	return nil
}

func DeriveSessionKey(localPriv *ecdh.PrivateKey, peerEphemeralPub []byte, info []byte) ([]byte, error) {
	if localPriv == nil || len(peerEphemeralPub) != HandshakePubKeySize {
		return nil, ErrMalformedHandshake
	}
	curve := ecdh.X25519()
	peerPub, err := curve.NewPublicKey(peerEphemeralPub)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := localPriv.ECDH(peerPub)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, sharedSecret, nil, string(info), SessionKeySize)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func NewSessionCipher(sessionKey []byte) (*SessionCipher, error) {
	if len(sessionKey) != SessionKeySize {
		return nil, ErrMalformedHandshake
	}
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SessionCipher{aead: aead}, nil
}

func makeNonce(seq uint64) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], seq)
	return nonce
}

func seqToAAD(seq uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], seq)
	return b[:]
}

// SessionCipher encrypts and decrypts authenticated payloads with AES-256-GCM.
// Sequence numbers are bound to AAD and replay/out-of-order frames are rejected.
type SessionCipher struct {
	aead    cipher.AEAD
	sendSeq uint64
	recvSeq uint64
}

func (s *SessionCipher) Encrypt(plaintext []byte) ([]byte, error) {
	if s.sendSeq == ^uint64(0) {
		return nil, ErrNonceOverflow
	}
	nonce := makeNonce(s.sendSeq)
	aad := seqToAAD(s.sendSeq)
	ciphertext := s.aead.Seal(nil, nonce, plaintext, aad)
	buf := make([]byte, 8+len(ciphertext))
	binary.BigEndian.PutUint64(buf[0:8], s.sendSeq)
	copy(buf[8:], ciphertext)
	s.sendSeq++
	return buf, nil
}

func (s *SessionCipher) Decrypt(payload []byte) ([]byte, error) {
	if len(payload) < 8 {
		return nil, ErrMalformedHeader
	}
	seq := binary.BigEndian.Uint64(payload[0:8])
	if seq != s.recvSeq {
		return nil, ErrReplayOrOutOfOrder
	}
	nonce := makeNonce(seq)
	aad := seqToAAD(seq)
	plaintext, err := s.aead.Open(nil, nonce, payload[8:], aad)
	if err != nil {
		return nil, err
	}
	s.recvSeq++
	return plaintext, nil
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(p) {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

// Connection lifecycle: New -> Handshaking -> Authenticating -> Ready -> Closed.
type ConnState uint8

const (
	StateNew ConnState = iota
	StateHandshaking
	StateAuthenticating
	StateReady
	StateClosed
)

type StateMachine struct{ state ConnState }

func NewStateMachine() *StateMachine     { return &StateMachine{state: StateNew} }
func (s *StateMachine) State() ConnState { return s.state }

// Accept validates an inbound/outbound message and advances the lifecycle.
// PING/PONG are permitted once handshaking has begun; discovery and user
// messages require an authenticated connection.
func (s *StateMachine) Accept(t MessageType) error {
	if !t.Valid() || s.state == StateClosed {
		return ErrInvalidState
	}
	switch s.state {
	case StateNew:
		if t != TypeHandshake {
			return ErrInvalidState
		}
		s.state = StateHandshaking
	case StateHandshaking:
		switch t {
		case TypeHandshake:
		case TypeAuth:
			s.state = StateAuthenticating
		case TypePing, TypePong:
		default:
			return ErrInvalidState
		}
	case StateAuthenticating:
		switch t {
		case TypeAuth:
			s.state = StateReady
		case TypePing, TypePong:
		default:
			return ErrInvalidState
		}
	case StateReady:
		if t == TypeHandshake || t == TypeAuth {
			return ErrInvalidState
		}
	}
	return nil
}

func (s *StateMachine) Close() { s.state = StateClosed }

// Byte-level payload helpers use network byte order.
func EncodeMessage(m Message) []byte {
	b := make([]byte, 16+len(m.Body))
	binary.BigEndian.PutUint64(b[0:8], m.ID)
	binary.BigEndian.PutUint64(b[8:16], uint64(m.Timestamp))
	copy(b[16:], m.Body)
	return b
}

func DecodeMessage(b []byte) (Message, error) {
	if len(b) < 16 {
		return Message{}, ErrMalformedHeader
	}
	return Message{ID: binary.BigEndian.Uint64(b[0:8]), Timestamp: int64(binary.BigEndian.Uint64(b[8:16])), Body: append([]byte(nil), b[16:]...)}, nil
}

// Ack encode/decode helpers.
func EncodeAck(a Ack) []byte {
	buf := make([]byte, 9)
	binary.BigEndian.PutUint64(buf[0:8], a.MessageID)
	buf[8] = a.Status
	return buf
}

func DecodeAck(b []byte) (Ack, error) {
	if len(b) < 9 {
		return Ack{}, ErrMalformedHeader
	}
	return Ack{MessageID: binary.BigEndian.Uint64(b[0:8]), Status: b[8]}, nil
}

func EncodeDiscovery(addresses []string) []byte {
	return []byte(strings.Join(addresses, "\n"))
}

func DecodeDiscovery(b []byte) []string {
	str := strings.TrimSpace(string(b))
	if str == "" {
		return nil
	}
	parts := strings.Split(str, "\n")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
