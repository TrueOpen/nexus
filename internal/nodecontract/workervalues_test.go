package nodecontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// wireWorkerValues assembles the worker_values artifact of wire worker_value_leaf_v1.json: the leaf
// count followed by each leaf's worker_value_leaf_bytes as framed inside the leaf preimages. It
// returns the artifact, the leaves, the root vector and the scope the leaves repeat.
func wireWorkerValues(t *testing.T) (artifact []byte, leaves [][]byte, root wirefixture.Vector, scope WorkerValueScope) {
	t.Helper()
	file := wirefixture.Load(t, "task/worker_value_leaf_v1.json")
	for i := 0; i < 3; i++ {
		v := file.Vector(t, fmt.Sprintf("worker_value_leaf_position_%d", i), 0)
		v.CheckPreimage(t)
		preimage, err := hex.DecodeString(v.PreimageHex)
		if err != nil {
			t.Fatal(err)
		}
		var frames [][]byte
		for off := 0; off < len(preimage); {
			n := int(binary.BigEndian.Uint64(preimage[off:]))
			frames = append(frames, preimage[off+8:off+8+n])
			off += 8 + n
		}
		if len(frames) != 3 {
			t.Fatalf("leaf %d preimage has %d frames, want domain, version and leaf bytes", i, len(frames))
		}
		leaves = append(leaves, frames[2])
	}
	artifact = binary.BigEndian.AppendUint32(nil, uint32(len(leaves)))
	for _, leaf := range leaves {
		artifact = append(artifact, leaf...)
	}
	root = file.Vector(t, "worker_value_root", 0)
	leaf0 := file.Vector(t, "worker_value_leaf_position_0", 0).Field(t, "worker_value_leaf_bytes")
	sub := func(name string) wirefixture.Field {
		for _, f := range leaf0.Fields {
			if f.Name == name {
				return f
			}
		}
		t.Fatalf("leaf has no %s", name)
		return wirefixture.Field{}
	}
	scope = WorkerValueScope{
		ChainID:               sub("chain_id").UTF8,
		TaskID:                sub("task_id").Bytes(t),
		AcceptedTaskHash:      sub("accepted_task_hash").Bytes(t),
		WorkerOperatorAddress: sub("worker_operator_address").Bech32,
	}
	return artifact, leaves, root, scope
}

// TestWorkerValuesRootMatchesWireVectors: decoding the assembled artifact reproduces the wire root,
// the artifact size is the B-level encoded size, and its SHA-256 is the content hash the wire B-level
// manifest names.
func TestWorkerValuesRootMatchesWireVectors(t *testing.T) {
	artifact, _, rootVector, scope := wireWorkerValues(t)
	var meta struct {
		RootHex string `json:"root_hex"`
		Size    uint64 `json:"worker_values_encoded_size_bytes"`
	}
	if err := json.Unmarshal(rootVector.Raw, &meta); err != nil {
		t.Fatal(err)
	}
	if uint64(len(artifact)) != meta.Size {
		t.Fatalf("worker_values is %d bytes, wire says %d", len(artifact), meta.Size)
	}
	root, err := WorkerValuesRootReader(bytes.NewReader(artifact), uint64(len(artifact)), scope, 3)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if hex.EncodeToString(root[:]) != meta.RootHex {
		t.Fatalf("root = %x, want %s", root, meta.RootHex)
	}
	manifest := wirefixture.Load(t, "task/canonical_json_v1.json").Vector(t, "evidence_bundle_manifest_worker_value_v1", 0)
	var payload struct {
		UTF8 string `json:"payload_utf8"`
	}
	if err := json.Unmarshal(manifest.Raw, &payload); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(artifact)
	if !bytes.Contains([]byte(payload.UTF8), []byte(hex.EncodeToString(sum[:]))) {
		t.Fatalf("the B-level manifest does not name content hash %x", sum)
	}
}

// TestWorkerValuesRootRejects covers the strict decode: a leaf count that is not the receipt's token
// count, trailing or missing bytes, positions out of order, a leaf of another task or Worker, and a
// flag byte that is neither 00 nor 01.
func TestWorkerValuesRootRejects(t *testing.T) {
	artifact, leaves, _, scope := wireWorkerValues(t)
	assemble := func(ls ...[]byte) []byte {
		out := binary.BigEndian.AppendUint32(nil, uint32(len(ls)))
		for _, l := range ls {
			out = append(out, l...)
		}
		return out
	}
	lastFlag := func(leaf []byte, value byte) []byte {
		out := append([]byte(nil), leaf...)
		out[len(out)-1] = value
		return out
	}
	otherTask := scope
	otherTask.TaskID = repeatByte(0x99, 32)
	otherWorker := scope
	otherWorker.WorkerOperatorAddress = "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc"
	cases := []struct {
		name  string
		data  []byte
		scope WorkerValueScope
		want  uint64
	}{
		{"leaf count differs from generated_token_count", artifact, scope, 4},
		{"trailing byte", append(append([]byte(nil), artifact...), 0), scope, 3},
		{"truncated", artifact[:len(artifact)-1], scope, 3},
		{"positions swapped", assemble(leaves[1], leaves[0], leaves[2]), scope, 3},
		{"leaf of another task", artifact, otherTask, 3},
		{"leaf of another Worker", artifact, otherWorker, 3},
		{"flag byte 02", assemble(leaves[0], leaves[1], lastFlag(leaves[2], 2)), scope, 3},
		{"empty", nil, scope, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := WorkerValuesRootReader(bytes.NewReader(c.data), uint64(len(c.data)), c.scope, c.want); err == nil {
				t.Fatal("must be rejected")
			}
		})
	}
	// Zero leaves is a well-formed artifact whose root is the empty Merkle root.
	root, err := WorkerValuesRootReader(bytes.NewReader(assemble()), 4, scope, 0)
	if err != nil || root != MerkleRootV1(DomainWorkerValueRootV1, nil) {
		t.Fatalf("zero leaves: root %x, err %v", root, err)
	}
}

// TestMerkleRootV1MatchesWireVectors checks every MERKLE_ROOT_V1 root of wire
// testdata/v1/shared/framing_v1.json: empty trees, one leaf, powers of two and odd promotions.
func TestMerkleRootV1MatchesWireVectors(t *testing.T) {
	var file struct {
		Roots []struct {
			Name   string   `json:"name"`
			Domain string   `json:"domain"`
			Leaves []string `json:"leaves_hex"`
			Root   string   `json:"root_hex"`
		} `json:"merkle_root_v1"`
	}
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/shared/framing_v1.json"), &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Roots) < 11 {
		t.Fatalf("expected at least 11 MERKLE_ROOT_V1 vectors, found %d", len(file.Roots))
	}
	for _, v := range file.Roots {
		leaves := make([][32]byte, len(v.Leaves))
		for i, leaf := range v.Leaves {
			raw, err := hex.DecodeString(leaf)
			if err != nil || len(raw) != 32 {
				t.Fatalf("%s: leaf %d", v.Name, i)
			}
			copy(leaves[i][:], raw)
		}
		if root := MerkleRootV1(v.Domain, leaves); hex.EncodeToString(root[:]) != v.Root {
			t.Fatalf("%s: root %x, want %s", v.Name, root, v.Root)
		}
	}
}

// A leaf count the bytes cannot hold is refused before anything is allocated for it: a Worker that
// signs a huge generated_token_count and uploads a few bytes must not make the Builder allocate.
func TestWorkerValuesRootRejectsCountTheBytesCannotHold(t *testing.T) {
	_, _, _, scope := wireWorkerValues(t)
	for name, c := range map[string]struct {
		count uint32
		want  uint64
	}{
		"max uint32 leaves":        {0xffffffff, 0xffffffff},
		"above the token id bound": {MaxTokenIDCountV1 + 1, MaxTokenIDCountV1 + 1},
		"more leaves than bytes":   {1000, 1000},
	} {
		t.Run(name, func(t *testing.T) {
			data := append(binary.BigEndian.AppendUint32(nil, c.count), make([]byte, 64)...)
			if _, err := WorkerValuesRootReader(bytes.NewReader(data), uint64(len(data)), scope, c.want); err == nil {
				t.Fatal("must be rejected")
			}
		})
	}
}
