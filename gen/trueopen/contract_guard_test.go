package trueopen

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every direct dependency the contract module is allowed to have. Any addition breaks
// the promise that consumers take the contract and nothing else, so it must be waived
// explicitly in review.
//
// cosmos-sdk is waived only for the two real wire types inside the chain mirror:
// cosmos.base.v1beta1.Coin in shared.v1 and cosmos.base.query.v1beta1.PageRequest
// in the hub.v1 queries. They cannot be stripped during mirroring the way the
// gogoproto / amino annotations are, and they cannot be copied locally either: the
// nexus binary already links cosmos-sdk, so a same-named type would register twice.
var allowedModules = map[string]bool{
	"connectrpc.com/connect":       true,
	"google.golang.org/protobuf":   true,
	"github.com/cosmos/cosmos-sdk": true,
}

func TestGoModRequiresOnlyContractDependencies(t *testing.T) {
	body, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	requireLine := regexp.MustCompile(`^([a-z0-9.\-/]+) v\S+`)
	inBlock := false
	for _, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "require ("):
			inBlock = true
		case inBlock && line == ")":
			inBlock = false
		case inBlock || strings.HasPrefix(line, "require "):
			candidate := strings.TrimPrefix(line, "require ")
			match := requireLine.FindStringSubmatch(candidate)
			if match == nil {
				continue
			}
			if strings.Contains(candidate, "// indirect") {
				continue
			}
			if !allowedModules[match[1]] {
				t.Errorf("go.mod requires %q; contract module allows only connect, protobuf and cosmos-sdk (wire types)", match[1])
			}
		}
	}
}

func TestGeneratedCodeImportsOnlyContractDependencies(t *testing.T) {
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range file.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			stdlib := !strings.Contains(strings.SplitN(p, "/", 2)[0], ".")
			local := strings.HasPrefix(p, "github.com/TrueOpen/nexus/gen/trueopen/")
			allowed := stdlib || local ||
				p == "connectrpc.com/connect" ||
				strings.HasPrefix(p, "connectrpc.com/connect/") ||
				strings.HasPrefix(p, "google.golang.org/protobuf/") ||
				p == "github.com/cosmos/cosmos-sdk/types" ||
				p == "github.com/cosmos/cosmos-sdk/types/query"
			if !allowed {
				t.Errorf("%s imports %q; contract module allows only stdlib, connect, protobuf and cosmos-sdk types (Coin / PageRequest)", path, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
