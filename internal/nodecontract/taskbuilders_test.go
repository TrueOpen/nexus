package nodecontract

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"sort"
	"testing"

	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// TestTaskBuilderRankMatchesWireVectors binds TaskBuilderRank to wire's
// testdata/v1/task/task_builder_rank_v1.json: the preimage (field order and address codec bytes,
// not Bech32 text) and the digest of every vector.
func TestTaskBuilderRankMatchesWireVectors(t *testing.T) {
	file := wirefixture.Load(t, "task/task_builder_rank_v1.json")
	if len(file.Vectors) == 0 {
		t.Fatal("task_builder_rank_v1.json has no vectors")
	}
	for _, vector := range file.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			if vector.Domain != DomainTaskBuilderRankV1 || vector.Framing != "H_FIELDS_V1" {
				t.Fatalf("domain/framing = %s/%s", vector.Domain, vector.Framing)
			}
			vector.CheckPreimage(t)
			var seed [32]byte
			copy(seed[:], vector.Field(t, "task_builder_seed").Bytes(t))
			builder := vector.Field(t, "builder_operator_address")
			raw, err := CanonicalOperatorAddressBytes("builder", builder.Bech32)
			if err != nil || !bytes.Equal(raw, builder.Bytes(t)) {
				t.Fatalf("bech32 %s decodes to %x, want %s (err %v)", builder.Bech32, raw, builder.Hex, err)
			}
			if got := hex.EncodeToString(CanonicalFramePreimage(DomainTaskBuilderRankV1, seed[:], raw)); got != vector.PreimageHex {
				t.Fatalf("preimage = %s, want %s", got, vector.PreimageHex)
			}
			rank, err := TaskBuilderRank(seed, builder.Bech32)
			if err != nil {
				t.Fatal(err)
			}
			if rank != vector.Digest(t) {
				t.Fatalf("rank = %x, want %s", rank, vector.DigestHex)
			}
		})
	}
}

// TestSelectTaskBuildersFollowsWireSortOrder checks the selection order against the file's
// declared sort (rank bytes ascending, then address codec bytes) over the vectors sharing a seed.
func TestSelectTaskBuildersFollowsWireSortOrder(t *testing.T) {
	file := wirefixture.Load(t, "task/task_builder_rank_v1.json")
	var header struct {
		Sort string `json:"sort"`
	}
	if err := json.Unmarshal(file.Raw, &header); err != nil {
		t.Fatal(err)
	}
	if header.Sort != "rank_bytes_asc_then_address_codec_bytes_asc" {
		t.Fatalf("wire changed the selection sort to %q", header.Sort)
	}
	bySeed := map[string][]wirefixture.Vector{}
	for _, vector := range file.Vectors {
		seed := vector.Field(t, "task_builder_seed").Hex
		bySeed[seed] = append(bySeed[seed], vector)
	}
	checked := false
	for seedHex, vectors := range bySeed {
		if len(vectors) < 2 {
			continue
		}
		checked = true
		sort.Slice(vectors, func(i, j int) bool { return vectors[i].DigestHex < vectors[j].DigestHex })
		want := make([]string, len(vectors))
		members := make([]string, len(vectors))
		for i, vector := range vectors {
			want[i] = vector.Field(t, "builder_operator_address").Bech32
			// Feed the members in reverse rank order so input order cannot pass the test.
			members[len(vectors)-1-i] = want[i]
		}
		seedRaw, _ := hex.DecodeString(seedHex)
		var seed [32]byte
		copy(seed[:], seedRaw)
		for count := 1; count <= len(want); count++ {
			got, err := SelectTaskBuilders(seed, members, uint32(count))
			if err != nil {
				t.Fatal(err)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("seed %s count %d: selection = %v, want %v", seedHex, count, got, want[:count])
				}
			}
		}
	}
	if !checked {
		t.Fatal("no two task_builder_rank_v1 vectors share a seed")
	}
}

// TestTaskBuilderSeedAndSelectedHashMatchWireVectors binds the seed and the committed selection
// hash to the task_builders_v1 and selected_task_builders_v1 vectors of task_domains_v1.json.
func TestTaskBuilderSeedAndSelectedHashMatchWireVectors(t *testing.T) {
	file := wirefixture.Load(t, "task/task_domains_v1.json")

	seedVector := file.Vector(t, "task_builders_v1", 0)
	seedVector.CheckPreimage(t)
	seed, err := TaskBuilderSeed(
		seedVector.Field(t, "chain_id").UTF8,
		seedVector.Field(t, "task_id").Bytes(t),
		seedVector.Field(t, "builder_set_hash").Bytes(t),
		seedVector.Field(t, "session_anchor_block_hash").Bytes(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	if seed != seedVector.Digest(t) {
		t.Fatalf("task_builder_seed = %x, want %s", seed, seedVector.DigestHex)
	}

	selectedVector := file.Vector(t, "selected_task_builders_v1", 0)
	selectedVector.CheckPreimage(t)
	list := selectedVector.Field(t, "builders")
	var builders []string
	for _, element := range list.Fields {
		if element.Type == "address" {
			builders = append(builders, element.Bech32)
		}
	}
	digest, err := SelectedTaskBuildersHash(
		selectedVector.Field(t, "chain_id").UTF8,
		selectedVector.Field(t, "task_id").Bytes(t),
		selectedVector.Field(t, "builder_set_id").UTF8,
		selectedVector.Field(t, "builder_set_hash").Bytes(t),
		builders,
	)
	if err != nil {
		t.Fatal(err)
	}
	if digest != selectedVector.Digest(t) {
		t.Fatalf("selected_task_builders_hash = %x, want %s", digest, selectedVector.DigestHex)
	}
}

func TestTaskBuilderSelectionRejectsInvalidInputs(t *testing.T) {
	hash := bytes.Repeat([]byte{1}, 32)
	if _, err := TaskBuilderSeed("", hash, hash, hash); err == nil {
		t.Fatal("empty chain_id accepted")
	}
	for _, short := range [][]byte{nil, hash[:31]} {
		if _, err := TaskBuilderSeed("chain", short, hash, hash); err == nil {
			t.Fatal("short task_id accepted")
		}
		if _, err := TaskBuilderSeed("chain", hash, short, hash); err == nil {
			t.Fatal("short builder_set_hash accepted")
		}
		if _, err := TaskBuilderSeed("chain", hash, hash, short); err == nil {
			t.Fatal("short session_anchor_block_hash accepted")
		}
	}

	var seed [32]byte
	a := "trueopen1g9q5zs2pg9q5zs2pg9q5zs2pg9q5zs2p3cu7ca"
	b := "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc"
	for name, tc := range map[string]struct {
		members []string
		count   uint32
	}{
		"zero count":        {[]string{a, b}, 0},
		"count above set":   {[]string{a, b}, 3},
		"duplicate builder": {[]string{a, a}, 1},
		"padded address":    {[]string{a + " ", b}, 1},
		"not bech32":        {[]string{"builder-1", b}, 1},
	} {
		if _, err := SelectTaskBuilders(seed, tc.members, tc.count); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}

	if _, err := SelectedTaskBuildersHash("chain", hash, "set", hash, nil); err == nil {
		t.Fatal("empty selection accepted")
	}
	if _, err := SelectedTaskBuildersHash("chain", hash, "", hash, []string{a}); err == nil {
		t.Fatal("empty builder_set_id accepted")
	}
}
