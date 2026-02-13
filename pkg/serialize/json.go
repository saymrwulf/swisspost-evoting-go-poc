package serialize

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
)

// BigIntJSON is a JSON-serializable big.Int (base64 encoded).
type BigIntJSON struct {
	Value *big.Int
}

func (b BigIntJSON) MarshalJSON() ([]byte, error) {
	if b.Value == nil {
		return json.Marshal(nil)
	}
	encoded := base64.StdEncoding.EncodeToString(b.Value.Bytes())
	return json.Marshal(encoded)
}

func (b *BigIntJSON) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	b.Value = new(big.Int).SetBytes(decoded)
	return nil
}

// ElectionResult is a JSON-serializable election result.
type ElectionResult struct {
	ElectionID string         `json:"election_id"`
	NumVoters  int            `json:"num_voters"`
	NumOptions int            `json:"num_options"`
	Results    map[string]int `json:"results"`
	Verified   bool           `json:"verified"`
}
