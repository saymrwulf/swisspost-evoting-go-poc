package returncodes

import (
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/user/evote/pkg/hash"
	"github.com/user/evote/pkg/kdf"
	"github.com/user/evote/pkg/symmetric"
)

// MappingTable maps hash(lCC) → encrypted short code.
type MappingTable struct {
	entries map[string]MappingEntry
}

// MappingEntry holds an encrypted short code with its nonce.
type MappingEntry struct {
	Ciphertext []byte
	Nonce      []byte
}

// NewMappingTable creates an empty mapping table.
func NewMappingTable() *MappingTable {
	return &MappingTable{entries: make(map[string]MappingEntry)}
}

// Add adds an entry to the mapping table.
// key = Base64(RecursiveHash(lCC_value))
// The short code is encrypted under a key derived from lCC_value.
func (mt *MappingTable) Add(lCCValue *big.Int, shortCode string) {
	// Hash to get lookup key
	hashBytes := hash.RecursiveHash(hash.HashableBigInt{Value: lCCValue})
	key := base64.StdEncoding.EncodeToString(hashBytes)

	// Derive encryption key from lCC
	lccBytes := hash.IntegerToByteArray(lCCValue)
	encKey := kdf.DeriveKey(lccBytes, nil, 32) // AES-256 key

	// Encrypt the short code
	ct, nonce, err := symmetric.Encrypt(encKey, []byte(shortCode), nil)
	if err != nil {
		panic("MappingTable.Add: encryption failed: " + err.Error())
	}

	mt.entries[key] = MappingEntry{Ciphertext: ct, Nonce: nonce}
}

// Lookup retrieves and decrypts a short code from the mapping table.
func (mt *MappingTable) Lookup(lCCValue *big.Int) (string, error) {
	// Hash to get lookup key
	hashBytes := hash.RecursiveHash(hash.HashableBigInt{Value: lCCValue})
	key := base64.StdEncoding.EncodeToString(hashBytes)

	entry, ok := mt.entries[key]
	if !ok {
		return "", fmt.Errorf("no entry found for key")
	}

	// Derive decryption key
	lccBytes := hash.IntegerToByteArray(lCCValue)
	decKey := kdf.DeriveKey(lccBytes, nil, 32)

	// Decrypt
	plaintext, err := symmetric.Decrypt(decKey, entry.Ciphertext, entry.Nonce, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return string(plaintext), nil
}

// Size returns the number of entries.
func (mt *MappingTable) Size() int {
	return len(mt.entries)
}

// MappingRow is a serializable mapping-table entry (for transport between the
// setup component and the voting server).
type MappingRow struct {
	Key        string `json:"key"`
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
}

// Export returns the table's entries in a serializable form.
func (mt *MappingTable) Export() []MappingRow {
	rows := make([]MappingRow, 0, len(mt.entries))
	for k, e := range mt.entries {
		rows = append(rows, MappingRow{Key: k, Ciphertext: e.Ciphertext, Nonce: e.Nonce})
	}
	return rows
}

// ImportMappingTable rebuilds a mapping table from exported rows.
func ImportMappingTable(rows []MappingRow) *MappingTable {
	mt := NewMappingTable()
	for _, r := range rows {
		mt.entries[r.Key] = MappingEntry{Ciphertext: r.Ciphertext, Nonce: r.Nonce}
	}
	return mt
}
