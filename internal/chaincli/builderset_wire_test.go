// Proto descriptor guard for the BuilderSet query surface (Keeper Interface Contract §16.3 / §16.5).
//
// Why descriptor reflection instead of "build a struct and see whether it compiles": field
// numbers and wire types are a **cross-process** contract. If the nexus mirror changed
// `builder_set_hash` from bytes to string, or moved `active_builders` from field number 6 to 7,
// the Go side would still compile, but against a real node it would silently decode empty or
// wrong values. Only the descriptor can pin this layer down.
package chaincli

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
)

// QueryBuilderSetRequest must be the §16.3 oneof selector, with exactly two branches
// (no term since wire v0.4.1: the Phase 0 BuilderSet only has a version, it never rotates terms).
func TestQueryBuilderSetRequestSelectorIsFrozen(t *testing.T) {
	desc := (&hubv1.QueryBuilderSetRequest{}).ProtoReflect().Descriptor()

	oneofs := desc.Oneofs()
	// proto3 optional also creates a synthetic oneof; none of these fields are optional,
	// so there must be exactly one real oneof.
	if oneofs.Len() != 1 {
		t.Fatalf("QueryBuilderSetRequest has %d oneofs, want exactly 1 (selector)", oneofs.Len())
	}
	selector := oneofs.Get(0)
	if got := string(selector.Name()); got != "selector" {
		t.Fatalf("oneof name = %q, want %q", got, "selector")
	}
	if selector.Fields().Len() != 2 {
		t.Fatalf("selector has %d fields, want 2", selector.Fields().Len())
	}
	if desc.Fields().Len() != 2 {
		t.Fatalf("QueryBuilderSetRequest has %d fields, want 2 (all inside the selector oneof)", desc.Fields().Len())
	}
	// The old shape's term_id / term must be gone entirely: keeping them would still let a
	// "query by term" call compile.
	for _, name := range []string{"term_id", "term"} {
		if desc.Fields().ByName(protoreflect.Name(name)) != nil {
			t.Fatalf("%s must not exist: the frozen selector is height / builder_set_id", name)
		}
	}
	assertFields(t, "QueryBuilderSetRequest", desc, []fieldSpec{
		{number: 1, name: "height", kind: protoreflect.Uint64Kind},
		{number: 2, name: "builder_set_id", kind: protoreflect.StringKind},
	})
}

// QueryBuilderSetResponse only has `1=set:BuilderSetViewV1`.
func TestQueryBuilderSetResponseCarriesBuilderSetView(t *testing.T) {
	desc := (&hubv1.QueryBuilderSetResponse{}).ProtoReflect().Descriptor()
	if desc.Fields().Len() != 1 {
		t.Fatalf("QueryBuilderSetResponse has %d fields, want 1", desc.Fields().Len())
	}
	field := desc.Fields().ByNumber(1)
	if field == nil || string(field.Name()) != "set" || field.Kind() != protoreflect.MessageKind {
		t.Fatalf("field 1 = %v, want message `set`", field)
	}
	if got := string(field.Message().FullName()); got != "hub.v1.BuilderSetViewV1" {
		t.Fatalf("set message = %q, want hub.v1.BuilderSetViewV1", got)
	}
}

// The 8 field numbers/types of BuilderSetViewV1 are checked one by one against §16.5
// (wire v0.4.1: builder_set_version + effective_height, no term / epoch range / duty score version).
func TestBuilderSetViewV1FieldsAreFrozen(t *testing.T) {
	desc := (&hubv1.BuilderSetViewV1{}).ProtoReflect().Descriptor()
	assertFields(t, "BuilderSetViewV1", desc, []fieldSpec{
		{number: 1, name: "builder_set_version", kind: protoreflect.Uint64Kind},
		{number: 2, name: "builder_set_id", kind: protoreflect.StringKind},
		// Hash32 must be bytes: a hex string would add a local encoding convention on top.
		{number: 3, name: "builder_set_hash", kind: protoreflect.BytesKind},
		{number: 4, name: "effective_height", kind: protoreflect.Uint64Kind},
		{number: 5, name: "active_builders", kind: protoreflect.StringKind, repeated: true},
		{number: 6, name: "active_builder_count", kind: protoreflect.Uint32Kind},
		{number: 7, name: "body_status", kind: protoreflect.EnumKind},
		{number: 8, name: "pruned_height", kind: protoreflect.Uint64Kind, optional: true},
	})
	if got := string(desc.Fields().ByNumber(7).Enum().FullName()); got != "shared.v1.StoredBodyStatus" {
		t.Fatalf("body_status enum = %q, want shared.v1.StoredBodyStatus", got)
	}
}

// BuilderState must no longer carry active_term (the root-cause field of a past startup failure),
// nor an admission status: since wire v0.4.1 the admission state lives on the governance side in
// BuilderAdmissionState, and BuilderState only carries identity + current service key + descriptor
// version + the three pending counters.
func TestBuilderStateHasNoActiveTermAndCarriesServiceKey(t *testing.T) {
	desc := (&hubv1.BuilderState{}).ProtoReflect().Descriptor()
	for _, name := range []string{"active_term", "status", "enrolled_height", "last_active_height", "jail_until_height"} {
		if desc.Fields().ByName(protoreflect.Name(name)) != nil {
			t.Fatalf("%s must not exist on BuilderState", name)
		}
	}
	assertFields(t, "BuilderState", desc, []fieldSpec{
		{number: 1, name: "schema_version", kind: protoreflect.Uint32Kind},
		{number: 2, name: "builder_address", kind: protoreflect.StringKind},
		{number: 3, name: "current_service_address", kind: protoreflect.StringKind},
		{number: 4, name: "current_service_pubkey", kind: protoreflect.BytesKind},
		{number: 5, name: "current_service_key_status", kind: protoreflect.EnumKind},
		{number: 6, name: "service_authorization_nonce", kind: protoreflect.Uint64Kind},
		{number: 7, name: "current_descriptor_version", kind: protoreflect.Uint64Kind},
		{number: 8, name: "registered_height", kind: protoreflect.Uint64Kind},
		{number: 9, name: "active_task_liability_count", kind: protoreflect.Uint32Kind},
		{number: 10, name: "pending_stage_duty_count", kind: protoreflect.Uint32Kind},
		{number: 11, name: "pending_evidence_submission_count", kind: protoreflect.Uint32Kind},
	})
	if got := string(desc.Fields().ByNumber(5).Enum().FullName()); got != "hub.v1.ServiceKeyStatus" {
		t.Fatalf("current_service_key_status enum = %q, want hub.v1.ServiceKeyStatus", got)
	}
}

type fieldSpec struct {
	number   protoreflect.FieldNumber
	name     string
	kind     protoreflect.Kind
	repeated bool
	optional bool
}

func assertFields(t *testing.T, message string, desc protoreflect.MessageDescriptor, want []fieldSpec) {
	t.Helper()
	if desc.Fields().Len() != len(want) {
		t.Fatalf("%s has %d fields, want %d", message, desc.Fields().Len(), len(want))
	}
	for _, spec := range want {
		field := desc.Fields().ByNumber(spec.number)
		if field == nil {
			t.Fatalf("%s field %d (%s) is missing", message, spec.number, spec.name)
		}
		if string(field.Name()) != spec.name {
			t.Fatalf("%s field %d name = %q, want %q", message, spec.number, field.Name(), spec.name)
		}
		if field.Kind() != spec.kind {
			t.Fatalf("%s field %d (%s) kind = %s, want %s", message, spec.number, spec.name, field.Kind(), spec.kind)
		}
		if field.IsList() != spec.repeated {
			t.Fatalf("%s field %d (%s) repeated = %v, want %v", message, spec.number, spec.name, field.IsList(), spec.repeated)
		}
		if field.HasOptionalKeyword() != spec.optional {
			t.Fatalf("%s field %d (%s) optional = %v, want %v", message, spec.number, spec.name, field.HasOptionalKeyword(), spec.optional)
		}
	}
}
