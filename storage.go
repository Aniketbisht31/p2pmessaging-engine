package p2p

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"io"
	"time"

	"golang.org/x/crypto/argon2"
	_ "modernc.org/sqlite"
)

type MessageRecord struct {
	Message
	Sender string
	Status uint8
}

type KnownPeer struct {
	Address  string
	LastSeen time.Time
}

type Contact struct {
	PublicKey string
	Alias     string
	AddedAt   time.Time
}

type Storage struct {
	db   *sql.DB
	aead cipher.AEAD
	salt []byte
}

const (
	saltKey = "salt"
)

func InitStorage(path string, passphrase []byte) (*Storage, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// set pragmas for WAL and synchronous normal for safety
	if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		// ignore
	}
	if _, err := db.Exec("PRAGMA synchronous=NORMAL;"); err != nil {
		// ignore
	}
	if err := migrateDB(db); err != nil {
		db.Close()
		return nil, err
	}
	salt, err := readOrCreateSalt(db)
	if err != nil {
		db.Close()
		return nil, err
	}
	key := deriveKey(passphrase, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		db.Close()
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Storage{db: db, aead: aead, salt: salt}, nil
}

func migrateDB(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL,
    sender TEXT,
    timestamp INTEGER,
    status INTEGER,
    body BLOB,
    nonce BLOB
);
CREATE TABLE IF NOT EXISTS known_peers (
    address TEXT PRIMARY KEY,
    last_seen INTEGER
);
CREATE TABLE IF NOT EXISTS contacts (
    public_key TEXT PRIMARY KEY,
    alias TEXT,
    added_at INTEGER
);`)
	return err
}

func readOrCreateSalt(db *sql.DB) ([]byte, error) {
	var salt []byte
	row := db.QueryRow("SELECT v FROM meta WHERE k = ?", saltKey)
	if err := row.Scan(&salt); err == nil {
		return salt, nil
	}
	// create salt
	salt = make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	if _, err := db.Exec("INSERT INTO meta(k,v) VALUES(?,?)", saltKey, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

func deriveKey(passphrase, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, 1, 64*1024, 4, 32)
}

func (s *Storage) SaveMessage(sender string, status uint8, m Message) error {
	// encrypt body
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	aad := make([]byte, 8)
	binary.BigEndian.PutUint64(aad[:], m.ID)
	ciphertext := s.aead.Seal(nil, nonce, m.Body, aad)
	_, err := s.db.Exec("INSERT INTO messages(message_id, sender, timestamp, status, body, nonce) VALUES(?,?,?,?,?,?)",
		m.ID, sender, m.Timestamp, status, ciphertext, nonce)
	return err
}

func (s *Storage) GetHistory(page, pageSize int) ([]MessageRecord, error) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize
	rows, err := s.db.Query("SELECT message_id, sender, timestamp, status, body, nonce FROM messages ORDER BY id DESC LIMIT ? OFFSET ?", pageSize, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MessageRecord
	for rows.Next() {
		var mid uint64
		var sender string
		var ts int64
		var status int
		var body []byte
		var nonce []byte
		if err := rows.Scan(&mid, &sender, &ts, &status, &body, &nonce); err != nil {
			return nil, err
		}
		aad := make([]byte, 8)
		binary.BigEndian.PutUint64(aad[:], mid)
		plaintext, err := s.aead.Open(nil, nonce, body, aad)
		if err != nil {
			// decryption failed; skip or return error
			return nil, err
		}
		out = append(out, MessageRecord{Message: Message{ID: mid, Timestamp: ts, Body: plaintext}, Sender: sender, Status: uint8(status)})
	}
	return out, nil
}

func (s *Storage) Close() error {
	return s.db.Close()
}

func (s *Storage) SaveContact(publicKey, alias string) error {
	if publicKey == "" {
		return nil
	}
	_, err := s.db.Exec("INSERT INTO contacts(public_key, alias, added_at) VALUES(?,?,?) ON CONFLICT(public_key) DO UPDATE SET alias = excluded.alias, added_at = excluded.added_at", publicKey, alias, time.Now().UnixNano())
	return err
}

func (s *Storage) LoadContacts() ([]Contact, error) {
	rows, err := s.db.Query("SELECT public_key, alias, added_at FROM contacts")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var contacts []Contact
	for rows.Next() {
		var key string
		var alias string
		var addedAtNano int64
		if err := rows.Scan(&key, &alias, &addedAtNano); err != nil {
			return nil, err
		}
		contacts = append(contacts, Contact{PublicKey: key, Alias: alias, AddedAt: time.Unix(0, addedAtNano)})
	}
	return contacts, nil
}

func (s *Storage) SaveKnownPeer(address string, lastSeen time.Time) error {
	_, err := s.db.Exec("INSERT INTO known_peers(address, last_seen) VALUES(?,?) ON CONFLICT(address) DO UPDATE SET last_seen = excluded.last_seen", address, lastSeen.UnixNano())
	return err
}

func (s *Storage) LoadKnownPeers() ([]KnownPeer, error) {
	rows, err := s.db.Query("SELECT address, last_seen FROM known_peers")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var peers []KnownPeer
	for rows.Next() {
		var address string
		var lastSeenNano int64
		if err := rows.Scan(&address, &lastSeenNano); err != nil {
			return nil, err
		}
		peers = append(peers, KnownPeer{Address: address, LastSeen: time.Unix(0, lastSeenNano)})
	}
	return peers, nil
}
