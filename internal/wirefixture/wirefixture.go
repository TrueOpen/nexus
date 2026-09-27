// Package wirefixture reads the cross-language test vectors published by TrueOpen/wire from the wire
// module this repository builds against, so tests compare against the pinned release rather than a
// hand-copied snapshot. It is used by tests only.
//
// The field encoder here is written independently of internal/nodecontract on purpose: a vector
// test then checks nexus's encoding against a second implementation, not against itself.
package wirefixture

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const wireModule = "github.com/TrueOpen/wire"

var (
	dirOnce sync.Once
	dir     string
	dirErr  error
)

// Dir returns the directory of the wire module pinned in go.mod.
func Dir(t testing.TB) string {
	t.Helper()
	dirOnce.Do(func() {
		out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", wireModule).Output()
		if err != nil {
			dirErr = fmt.Errorf("locate %s: %w", wireModule, err)
			return
		}
		dir = strings.TrimSpace(string(out))
		if dir == "" {
			dirErr = fmt.Errorf("locate %s: module not downloaded (run go mod download)", wireModule)
		}
	})
	if dirErr != nil {
		t.Fatal(dirErr)
	}
	return dir
}

// ReadFile returns a file of the wire module, rel being relative to the module root.
func ReadFile(t testing.TB, rel string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(Dir(t), rel))
	if err != nil {
		t.Fatalf("read wire %s: %v", rel, err)
	}
	return raw
}

// File is one vector file.
type File struct {
	Schema  string          `json:"schema"`
	Notes   json.RawMessage `json:"notes"`
	Vectors []Vector        `json:"vectors"`
	Raw     json.RawMessage `json:"-"`
}

// Vector is one entry of a vector file. Raw keeps the whole entry for file-specific keys.
type Vector struct {
	Name        string          `json:"name"`
	Domain      string          `json:"domain"`
	Framing     string          `json:"framing"`
	Fields      []Field         `json:"fields"`
	PreimageHex string          `json:"preimage_hex"`
	DigestHex   string          `json:"digest_hex"`
	Raw         json.RawMessage `json:"-"`
}

// Field is one typed preimage field.
type Field struct {
	Name    string          `json:"name"`
	Type    string          `json:"type"`
	Value   json.RawMessage `json:"value"`
	Hex     string          `json:"hex"`
	UTF8    string          `json:"utf8"`
	Bech32  string          `json:"bech32"`
	Bool    *bool           `json:"bool"`
	Empty   bool            `json:"empty"`
	Present bool            `json:"present"`
	Fields  []Field         `json:"fields"`
}

// Load reads and decodes testdata/v1/<rel>.
func Load(t testing.TB, rel string) File {
	t.Helper()
	raw := ReadFile(t, filepath.Join("testdata", "v1", rel))
	var file File
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("decode wire %s: %v", rel, err)
	}
	var rawVectors struct {
		Vectors []json.RawMessage `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &rawVectors); err == nil {
		for i := range file.Vectors {
			file.Vectors[i].Raw = rawVectors.Vectors[i]
		}
	}
	file.Raw = raw
	return file
}

// Vector returns the named vector; with several of the same name, the index-th one.
func (f File) Vector(t testing.TB, name string, index int) Vector {
	t.Helper()
	seen := 0
	for _, v := range f.Vectors {
		if v.Name == name {
			if seen == index {
				return v
			}
			seen++
		}
	}
	t.Fatalf("wire vector %q #%d not found", name, index)
	return Vector{}
}

// Field returns the named top-level field.
func (v Vector) Field(t testing.TB, name string) Field {
	t.Helper()
	for _, f := range v.Fields {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("wire vector %q has no field %q", v.Name, name)
	return Field{}
}

// Digest returns digest_hex decoded.
func (v Vector) Digest(t testing.TB) [32]byte {
	t.Helper()
	var out [32]byte
	raw, err := hex.DecodeString(v.DigestHex)
	if err != nil || len(raw) != 32 {
		t.Fatalf("wire vector %q digest_hex is not 32 bytes", v.Name)
	}
	copy(out[:], raw)
	return out
}

// CheckPreimage recomputes the vector's H_FIELDS_V1 preimage and digest from its fields with this
// package's own encoder, so a vector that does not describe itself consistently fails loudly.
func (v Vector) CheckPreimage(t testing.TB) {
	t.Helper()
	encoded := make([][]byte, 0, len(v.Fields))
	for _, f := range v.Fields {
		b, err := f.Encode()
		if err != nil {
			t.Fatalf("wire vector %q field %q: %v", v.Name, f.Name, err)
		}
		encoded = append(encoded, b)
	}
	preimage := HFieldsPreimage(v.Domain, encoded...)
	if v.PreimageHex != "" && hex.EncodeToString(preimage) != v.PreimageHex {
		t.Fatalf("wire vector %q: independent preimage does not match preimage_hex", v.Name)
	}
	if sum := sha256.Sum256(preimage); hex.EncodeToString(sum[:]) != v.DigestHex {
		t.Fatalf("wire vector %q: independent digest does not match digest_hex", v.Name)
	}
}

// Uint64 returns an unsigned integer field.
func (f Field) Uint64(t testing.TB) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(string(f.Value), 10, 64)
	if err != nil {
		t.Fatalf("wire field %q is not an unsigned integer: %s", f.Name, f.Value)
	}
	return n
}

// Int64 returns a signed integer field.
func (f Field) Int64(t testing.TB) int64 {
	t.Helper()
	n, err := strconv.ParseInt(string(f.Value), 10, 64)
	if err != nil {
		t.Fatalf("wire field %q is not an integer: %s", f.Name, f.Value)
	}
	return n
}

// Bytes returns a bytes or address field (address as codec bytes).
func (f Field) Bytes(t testing.TB) []byte {
	t.Helper()
	if f.Empty {
		return []byte{}
	}
	raw, err := hex.DecodeString(f.Hex)
	if err != nil {
		t.Fatalf("wire field %q hex: %v", f.Name, err)
	}
	return raw
}

// BoolValue returns a bool field.
func (f Field) BoolValue(t testing.TB) bool {
	t.Helper()
	b, err := f.boolValue()
	if err != nil {
		t.Fatalf("wire field %q: %v", f.Name, err)
	}
	return b
}

func (f Field) boolValue() (bool, error) {
	if f.Bool != nil {
		return *f.Bool, nil
	}
	switch string(f.Value) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("not a bool: %s", f.Value)
}

// Encode encodes the field value as it enters an H_FIELDS_V1 preimage.
func (f Field) Encode() ([]byte, error) {
	switch f.Type {
	case "uint32", "enum":
		n, err := strconv.ParseUint(string(f.Value), 10, 32)
		if err != nil {
			return nil, err
		}
		return binary.BigEndian.AppendUint32(nil, uint32(n)), nil
	case "uint64":
		n, err := strconv.ParseUint(string(f.Value), 10, 64)
		if err != nil {
			return nil, err
		}
		return binary.BigEndian.AppendUint64(nil, n), nil
	case "int32":
		n, err := strconv.ParseInt(string(f.Value), 10, 32)
		if err != nil {
			return nil, err
		}
		return binary.BigEndian.AppendUint32(nil, uint32(int32(n))), nil
	case "int64":
		n, err := strconv.ParseInt(string(f.Value), 10, 64)
		if err != nil {
			return nil, err
		}
		return binary.BigEndian.AppendUint64(nil, uint64(n)), nil
	case "bool":
		b, err := f.boolValue()
		if err != nil {
			return nil, err
		}
		if b {
			return []byte{1}, nil
		}
		return []byte{0}, nil
	case "bytes", "address":
		if f.Empty {
			return []byte{}, nil
		}
		return hex.DecodeString(f.Hex)
	case "string":
		return []byte(f.UTF8), nil
	case "frame":
		nested := make([][]byte, 0, len(f.Fields))
		for _, sub := range f.Fields {
			b, err := sub.Encode()
			if err != nil {
				return nil, fmt.Errorf("%s: %w", sub.Name, err)
			}
			nested = append(nested, b)
		}
		return Frames(nested...), nil
	case "optional":
		if !f.Present {
			return []byte{0}, nil
		}
		if len(f.Fields) != 1 {
			return nil, fmt.Errorf("present optional must carry one value")
		}
		b, err := f.Fields[0].Encode()
		if err != nil {
			return nil, err
		}
		return append([]byte{1}, Frames(b)...), nil
	default:
		return nil, fmt.Errorf("unsupported field type %q", f.Type)
	}
}

// Frames concatenates u64_be(len(value)) || value for each value.
func Frames(values ...[]byte) []byte {
	var out []byte
	for _, v := range values {
		out = binary.BigEndian.AppendUint64(out, uint64(len(v)))
		out = append(out, v...)
	}
	return out
}

// HFieldsPreimage is frame(domain) || frame(field_1) || ... || frame(field_n).
func HFieldsPreimage(domain string, fields ...[]byte) []byte {
	return Frames(append([][]byte{[]byte(domain)}, fields...)...)
}
