// Package protofingerprint hashes the structure of the proto descriptors linked into the binary
// (messages, fields, field numbers, enums and methods, never comments or options) so a test can pin
// a wire mirror to the TrueOpen/wire release it was copied from.
package protofingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// Summary counts what went into a fingerprint, for readable test failures.
type Summary struct {
	Messages, Enums, Methods int
}

// Descriptor fingerprints every registered file whose path starts with one of prefixes
// (for example "task/v1/"). The result depends only on the descriptor structure, so a comment-only
// edit keeps it stable while any field, number, type, cardinality, oneof or rpc change moves it.
func Descriptor(prefixes ...string) (string, Summary) {
	var (
		lines   []string
		summary Summary
	)
	protoregistry.GlobalFiles.RangeFiles(func(file protoreflect.FileDescriptor) bool {
		if !hasAnyPrefix(file.Path(), prefixes) {
			return true
		}
		for i := 0; i < file.Messages().Len(); i++ {
			appendMessage(file.Messages().Get(i), &lines, &summary)
		}
		for i := 0; i < file.Enums().Len(); i++ {
			appendEnum(file.Enums().Get(i), &lines, &summary)
		}
		for i := 0; i < file.Services().Len(); i++ {
			service := file.Services().Get(i)
			for j := 0; j < service.Methods().Len(); j++ {
				method := service.Methods().Get(j)
				lines = append(lines, fmt.Sprintf("service|%s|%s|%s|%s|%t|%t",
					service.FullName(), method.Name(), method.Input().FullName(), method.Output().FullName(),
					method.IsStreamingClient(), method.IsStreamingServer()))
				summary.Methods++
			}
		}
		return true
	})
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:]), summary
}

func hasAnyPrefix(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func appendMessage(message protoreflect.MessageDescriptor, lines *[]string, summary *Summary) {
	summary.Messages++
	*lines = append(*lines, "message|"+string(message.FullName()))
	for i := 0; i < message.Fields().Len(); i++ {
		field := message.Fields().Get(i)
		typeName := ""
		switch field.Kind() {
		case protoreflect.MessageKind, protoreflect.GroupKind:
			typeName = string(field.Message().FullName())
		case protoreflect.EnumKind:
			typeName = string(field.Enum().FullName())
		}
		oneof := ""
		if field.ContainingOneof() != nil {
			oneof = string(field.ContainingOneof().Name())
		}
		*lines = append(*lines, fmt.Sprintf("field|%s|%d|%s|%s|%s|%s|%s|%t",
			message.FullName(), field.Number(), field.Name(), field.Cardinality(), field.Kind(), typeName, oneof, field.HasOptionalKeyword()))
	}
	for i := 0; i < message.Messages().Len(); i++ {
		appendMessage(message.Messages().Get(i), lines, summary)
	}
	for i := 0; i < message.Enums().Len(); i++ {
		appendEnum(message.Enums().Get(i), lines, summary)
	}
}

func appendEnum(enum protoreflect.EnumDescriptor, lines *[]string, summary *Summary) {
	summary.Enums++
	*lines = append(*lines, "enum|"+string(enum.FullName()))
	for i := 0; i < enum.Values().Len(); i++ {
		value := enum.Values().Get(i)
		*lines = append(*lines, fmt.Sprintf("enum_value|%s|%d|%s", enum.FullName(), value.Number(), value.Name()))
	}
}
