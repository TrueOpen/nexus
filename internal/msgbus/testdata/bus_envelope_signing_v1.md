# bus_envelope_signing_v1.json — the TRUEOPEN_BUS_ENVELOPE_V1 signing contract

Cross-repository interoperability fixture for `BusEnvelope` application
authentication on the `trueopen.*` task-control subjects. It pins, for every bus
kind, the 20 signed field values, the canonical payload bytes, the canonical
`SIGNED_FIELDS` object, the framed `SIGN_BYTES`, the `SIGN_DIGEST`, and a
signature — plus one counter-example per signed field.

The normative source is `input-ouput-relay/docs/20-Service Design/nexus/Interface & Topic Catalogue.md`
§5.2. References of the form `§5.1` / `§5.2` / `§5.3` and `§5.2 field N` below are
into that file; single-level `§N` and `§4.1` are sections of this note. That file
is cited by section rather than by line because an upstream reflow (monorepo
`2f43a52`, "docs: unify V1 system design") invalidated every line anchor at once.

Everything a peer needs is in the JSON. This note states the byte layout in full,
so an implementation in any language can reproduce every digest **without reading
Go**; §10 is a complete, runnable reproducer that checks every vector and every
mutation in the file. The Go side is enforced by the tests in
`internal/builderclient/envelope_interop_test.go`, so the fixture cannot drift
from `BusEnvelopeSignBytes` / `BusEnvelopeSignDigest`.

## 1. The signed field set is the spec's numbered table

`TRUEOPEN_BUS_ENVELOPE_V1` covers exactly the **20** fields numbered 1..20 in the
`§5.2` table. `signed_fields` in the JSON is that set, sorted into canonical
order:

```
builder_set_hash, builder_set_id, chain_id, expires_at_unix_ms,
issued_at_unix_ms, kind, message_id, nonce, payload_codec, payload_digest,
schema_version, sender_operator_address, sender_participant_type, sender_role,
service_authorization_nonce, session_id, source_snapshot_height, stage,
subject, task_id
```

The field-set identity lives in that numbered table, not in this repository and
not in the domain string. The domain names the *framing and the version*; the
table names the *fields*. A signer that covers some other set is not signing
`TRUEOPEN_BUS_ENVELOPE_V1` at all, whatever domain string it length-prefixes into
the preimage — which is why a 13-field Cortex signer was never V1 and why fixing
it needs no `V2`: `§5.2 "V1 is not yet deployed"` states V1 is not deployed yet and goes live
as one hard cutover at `schema_version=1` / `TRUEOPEN_BUS_ENVELOPE_V1`.

`§5.2` requires **every** field to be present, and requires non-empty
`session_id`, `task_id`, `builder_set_id` and `stage` on task-control messages.
All eight `trueopen.*` kinds are task-control messages, so no kind omits any field.
There is no `omitempty`: a zero integer is `0`, and a value that is genuinely
unavailable is a refusal, never `""`.

**Not signed:** the `payload` body (committed by `payload_digest`, §5) and the
`signature` itself. Those are the only two envelope members excluded.

**No normalisation at signing time.** Every value is taken verbatim as it appears
on the wire. Nothing is trimmed, case-folded or re-ordered while signing; a
sender that wants trimmed values must trim before it builds the envelope.

## 2. Framing — `FRAME_V1`

```
sign_bytes = "TRUEOPEN_FRAME_V1"            (14 ASCII bytes, no NUL, no length prefix)
          || u32be(len(domain))          (4 bytes, big endian)
          || domain                      ("TRUEOPEN_BUS_ENVELOPE_V1", 21 ASCII bytes)
          || u64be(len(signed_object))   (8 bytes, big endian)
          || signed_object               (the canonical JSON of §3, UTF-8, no BOM)

sign_digest = sha256(sign_bytes)
```

The fixed prefix is therefore `14 + 4 + 21 + 8 = 47` bytes; `signed_object` is the
remainder of `sign_bytes_hex`. The layout is `Keeper Detailed Design.md:2119-2120` and is
byte-identical to the chain's own framing — a shared primitive, not a Cortex-local
one. Length prefixes are unconditional, so no length is elided for an empty value.

## 3. `trueopen_cjson_v1` — the canonical JSON encoding

One encoding is used for both the payload (§5) and the signed object (§4). Rules
are `§5.2`, resolved against the keeper implementation
(`TrueOpen/node d8792e6 x/shared/types/canonical_json.go`) wherever `§5.2`
is silent:

- UTF-8, no BOM, no whitespace anywhere (not between tokens, not after `:` or
  `,`), no trailing newline, no trailing data.
- Object keys ascending by **UTF-8 bytes** (not by code point, not by locale).
  Duplicate keys are rejected. Unknown keys are rejected by the typed decode
  that precedes canonicalisation.
- The value set is closed: object, array, string, boolean, integer. `null` is
  **forbidden** (`canonical_json.go:69-70`). Floats and exponents are forbidden.
- Integers: plain decimal, no `+`, no leading zeros, no exponent, no fraction, no
  `-0`, **non-negative**, and **at most 2^64-1** (`canonical_json.go:59-68`: the
  closed value-type set tops out at `uint64`, so a larger literal is well-formed
  decimal that no conforming implementation can hold and is refused).
- `bytes32` values are lowercase `0x` hex and must decode to exactly 32 bytes.
  The `0x` prefix is unconditional, so an empty byte string would be `"0x"`,
  never `""`.
- Keys, string values and `[]string` elements must be valid UTF-8
  (`canonical_json.go:29-55`). Invalid UTF-8 is **rejected**, never replaced with
  U+FFFD: two senders must not be able to agree on a digest for different bytes.

`json_string(s)`:

- UTF-8, wrapped in `"`.
- Escapes, and **only** these: `"` → `\"`, `\` → `\\`, U+0008 → `\b`,
  U+000C → `\f`, U+000A → `\n`, U+000D → `\r`, U+0009 → `\t`, any other code
  point below U+0020 → `\u00xx`, and U+2028 → `\u2028`, U+2029 → `\u2029`. Hex
  digits are lowercase.
- **No HTML escaping.** `<`, `>` and `&` are emitted literally. Go's
  `encoding/json` escapes them to `\u003c`, `\u003e`, `\u0026` unless
  `SetEscapeHTML(false)` is called (`canonical_json.go:19`), and no other
  language does it at all. See the `worker_handraise_html_escaping` vector (§8).
- No `\/` escape: `/` is literal.
- No other `\uXXXX` escaping: every remaining code point at or above U+0020 is
  emitted as raw UTF-8.

U+2028 and U+2029 are the one non-obvious entry. They are valid unescaped in
JSON, but node's canonicalizer delegates string encoding to Go's
`encoding/json` and only turns off HTML escaping (`canonical_json.go:19`), and
Go escapes those two code points *unconditionally* — `SetEscapeHTML(false)` does
not reach them. `§5.2` is silent, so node is the tie-breaker and they are
escaped. No vector in this file contains either character; the rule is stated so
a peer that encounters one agrees.

## 4. The signed object

A single flat JSON object — no nesting, no arrays:

```
signed_object = "{" || field(0) || "," || field(1) || ... || "," || field(19) || "}"
field(i)      = json_string(name(i)) || ":" || encoded_value(i)
```

`name(0..19)` is `signed_fields` from the JSON, in that order. Encoding by field:

| # | field | wire type | encoded as |
| --- | --- | --- | --- |
| 1 | `schema_version` | `uint32` | plain decimal, unquoted (`1`) |
| 2 | `chain_id` | string | `json_string` |
| 3 | `subject` | string | `json_string`; must equal the delivery subject byte for byte |
| 4 | `kind` | enum string | `json_string` |
| 5 | `sender_participant_type` | `BUILDER` \| `CORTEX` | `json_string` |
| 6 | `sender_operator_address` | bech32 string | `json_string` |
| 7 | `service_authorization_nonce` | `uint64` | plain decimal, unquoted |
| 8 | `sender_role` | `BUILDER` \| `WORKER` \| `VERIFIER` | `json_string` |
| 9 | `session_id` | string | `json_string` |
| 10 | `task_id` | string | `json_string` |
| 11 | `builder_set_id` | string | `json_string` |
| 12 | `builder_set_hash` | bytes32 | `json_string("0x" + lowercase_hex(32 bytes))` |
| 13 | `stage` | `OPEN_TASK` \| `OPEN_VERIFY` \| `SETTLE` | `json_string` |
| 14 | `source_snapshot_height` | `uint64` | plain decimal, unquoted |
| 15 | `message_id` | string | `json_string` |
| 16 | `nonce` | bytes32 | `json_string("0x" + lowercase_hex(32 bytes))` |
| 17 | `issued_at_unix_ms` | `int64` unix **milliseconds** | plain decimal, unquoted; negative is **rejected** |
| 18 | `expires_at_unix_ms` | `int64` unix **milliseconds** | same as `issued_at_unix_ms` |
| 19 | `payload_codec` | string | `json_string`; fixed `"trueopen-cjson-v1"` (`§5.2 field 19`) |
| 20 | `payload_digest` | bytes32 | `json_string("0x" + lowercase_hex(sha256(PAYLOAD_BYTES)))` |

`integer_fields` and `bytes32_fields` in the JSON are the machine-readable form of
that column. Integers are the only unquoted values; there are no floats anywhere
in the object, so no float-formatting question arises.

### 4.1 Which field comes from where

`stage` (`§5.2 field 13`, `§5.2 "Kind maps to a fixed stage"`) is a **coarse grouping
derived from `kind` alone**, not a report of the sender's view of task progress:
the spec fixes the whole Kind -> stage mapping, so a sender has nothing to choose.
`stage_by_kind` in the JSON:

```
OPEN_TASK:    ORDER_BROADCAST, WORKER_HANDRAISE, ASSIGN_NOTIFY, OUTPUT_AVAILABLE
OPEN_VERIFY:  VERIFIER_HANDRAISE, VERIFY_SELECT_NOTIFY, SAMPLE_READY_NOTIFY,
              VERIFY_RESULT
SETTLE:       reserved; no current NATS kind maps to it (`§5.2 "Kind maps to a fixed stage"`)
```

All eight kinds above appear verbatim in the `§5.1` subject table, which lists
nine rows; the ninth, `ASSIGN_PREPARE`, is Builder -> Builder coordination Cortex
neither publishes nor receives.

`sender_participant_type` (`§5.2 field 5`) selects the **key-domain namespace**
the receiver queries for the current service key. It is fixed per kind by the
`§5.3` table — `sender_by_kind` in the JSON — and never a free-form string at a
call site. `§5.3 "unknown combinations are rejected"` is explicit that the two axes are not
interchangeable: an unknown `(kind, participant_type, role)` triple is rejected,
and `sender_role` must never be used to resolve a Cortex participant as a Builder
or the reverse.

`source_snapshot_height` (`§5.2 field 14`, "the sender's chain view") is the **sender's own
chain view** at the moment it built the envelope. It is explicitly **not** for
historical key lookup: the receiver still resolves the *verification-time
current* service key, and `§5.2` allows no historical-key fallback.

`builder_set_id` / `builder_set_hash` (`§5.2 fields 11-12`) change **binding source**
across the life of a task:

| when | bound by | node type |
| --- | --- | --- |
| before the first proposal is accepted on chain | the SignedOrder | `TaskOrderV1.builder_set_id = 29`, `builder_set_hash = 30` |
| after the first proposal is accepted | the Task's locked BuilderSet reference | `TaskBuilderSelectionState.builder_set_id = 3`, `builder_set_hash = 4` |

(node `d8792e6`, `proto/task/v1/msg_assignment.proto` and
`proto/task/v1/assignment.proto`; the same split is node's
`WorkerHandraiseScopeV1` oneof `signed_order` / `existing_task`.) The pair exists
to stop the same id being used to explain a different snapshot, so the hash must
travel with the id.

**The binding is not a wire field.** Each vector records it as
`builder_set_binding` (`SIGNED_ORDER` or `ACCEPTED_TASK`) purely to document which
authority the sender read; the digest only ever commits the resulting id and hash.
Two vectors may legitimately carry the same id and hash under different bindings
— that is the normal case, because acceptance locks the set the SignedOrder named.
`OPEN_VERIFY`-stage kinds admit only `ACCEPTED_TASK`: verification cannot precede
acceptance.

## 5. The payload is committed by its canonical form

```
PAYLOAD_BYTES  = trueopen_cjson_v1(payload)          (§5.2 PAYLOAD_BYTES)
payload_digest = sha256(PAYLOAD_BYTES)            (§5.2 field 20)
```

`payload_digest` commits the **canonical** encoding of the payload, not the bytes
as transmitted. `§5.2` closes the loop: after typed decode the receiver
re-canonicalises and **rejects on any difference**. So:

- A **sender** must transmit the canonical bytes. It cannot transmit a
  struct-field-order or pretty-printed body and sign the canonical digest: its own
  frame would be refused.
- A **receiver** must canonicalise what arrived, compare it against what arrived,
  refuse on mismatch, and only then digest. Digesting the transmitted bytes
  directly is the mistake this fixture pins — see
  `worker_handraise_non_canonical_payload` (§8).
- The envelope signature says nothing about signatures *inside* the payload
  (`signature`, `verifier_sig`, `service_signature`, …). Those are separate
  application-level domains with their own preimages and their own vectors.

Each vector carries `envelope.payload_bytes` (what is on the wire),
`canonical_payload_bytes` (`PAYLOAD_BYTES`), `payload_is_canonical`, and
`payload_digest_hex`. Both are JSON **strings** so the exact bytes are
unambiguous: decode the string, do not re-encode it.

## 6. Signature encoding

- secp256k1 ECDSA over `sign_digest` (32 bytes), **not** over `sign_bytes`
  (`§5.2 "no historical key fallback is allowed"`).
- Wire form: **64-byte compact `R || S`**, each 32 bytes big endian, zero padded.
  DER and the 65-byte recoverable form are rejected.
- **Low-S required**: `S <= n/2`. The malleable twin `n - S` is rejected even
  though it verifies as textbook ECDSA.
- The key is the **current service key** the chain binds to
  `(sender_participant_type, sender_operator_address)`, resolved by
  `QueryCurrentServiceKey` at verification time. The envelope carries neither a
  public key nor a service address, and historical-key fallback is not allowed
  (`§5.2 "no historical key fallback is allowed"`).
- `service_authorization_nonce` must equal the nonce on that current binding
  (`§5.2 field 7`), which is why it is a signed field rather than a lookup result.
- The pinned `signature_hex` values use RFC 6979 deterministic nonces, so
  re-signing a `sign_digest_hex` with `signer.private_key_hex` reproduces them
  byte for byte.

`signer.operator_address` is the bech32 (`trueopen` HRP) address of
`signer.compressed_pubkey_hex` and is the `sender_operator_address` of every
outbound vector, so those vectors are internally consistent: address ↔ key ↔
signature.

## 7. Replay keys (adjacent, not part of the digest)

Not part of `sign_bytes`, recorded here because strict mode is unusable without
it. A receiver claims two durable single-use keys per frame, so reusing either
identifier is suppressed:

```
message_key = H("TRUEOPEN_BUS_ENVELOPE_V1_REPLAY_MESSAGE_ID", chain_id, sender_operator_address, authorization_nonce, trim(message_id))
nonce_key   = H("TRUEOPEN_BUS_ENVELOPE_V1_REPLAY_NONCE",      chain_id, sender_operator_address, authorization_nonce, nonce_bytes)
```

`H` is Cortex's `codec.HashWithDomain` (length-prefixed, u64-only framing) — a
*different* framing from `FRAME_V1`, deliberately: these are local store keys, not
a cross-repository preimage.

## 8. The vectors

| name | direction | kind | stage | binding |
| --- | --- | --- | --- | --- |
| `order_broadcast_real_frame_0` | inbound | `ORDER_BROADCAST` | `OPEN_TASK` | `SIGNED_ORDER` |
| `order_broadcast_real_frame_1` | inbound | `ORDER_BROADCAST` | `OPEN_TASK` | `SIGNED_ORDER` |
| `worker_handraise` | outbound | `WORKER_HANDRAISE` | `OPEN_TASK` | `SIGNED_ORDER` |
| `verifier_handraise` | outbound | `VERIFIER_HANDRAISE` | `OPEN_VERIFY` | `ACCEPTED_TASK` |
| `output_available` | outbound | `OUTPUT_AVAILABLE` | `OPEN_TASK` | `ACCEPTED_TASK` |
| `verify_result` | outbound | `VERIFY_RESULT` | `OPEN_VERIFY` | `ACCEPTED_TASK` |
| `worker_handraise_html_escaping` | outbound | `WORKER_HANDRAISE` | `OPEN_TASK` | `SIGNED_ORDER` |
| `worker_handraise_non_canonical_payload` | inbound | `WORKER_HANDRAISE` | `OPEN_TASK` | `SIGNED_ORDER` |

`§5.2 golden-vector requirement` requires at least the OrderBroadcast, WorkerHandraise, VerifierHandraise
and OutputAvailable groups plus per-field mutation counter-examples; the first six
rows cover those four kinds (and `VERIFY_RESULT` besides), and `field_mutations`
covers all 20 fields individually.

### The two inbound `ORDER_BROADCAST` vectors carry captured bytes

Their twelve captured envelope fields and their payload — thirteen of the twenty
signed values, once `payload_digest` is derived from those payload bytes — are the
two frames captured byte for byte off a live devnet Builder — see
`internal/daemon/testdata/real_order_broadcast_frames.md` for provenance. Real
`chain_id`, real UUID `message_id` — a v4 one, because that is what the live Builder emits;
Cortex's own outbound ids are UUIDv7 per §5.2 field 15, and the version is deliberately not
enforced inbound for exactly this reason — real 32-byte `nonce`, real
ACTIVE Builder operator address, real session/task identity, real order body.
`TestBusEnvelopeInteropRealFramesAnchorTheCapturedBytes` in
`internal/daemon/real_order_broadcast_golden_test.go` re-derives them from the
capture and fails if any captured field or the canonicalised payload drifts.

The remaining **seven** fields — `sender_participant_type`,
`service_authorization_nonce`, `builder_set_id`, `builder_set_hash`, `stage`,
`source_snapshot_height`, `payload_codec` — are **synthetic**. The capture
predates `TRUEOPEN_BUS_ENVELOPE_V1`, so no captured frame can supply them, and a
pre-V1 frame is refused rather than upgraded. Each vector's `source` states this
split; do not read those seven as evidence about the deployed Builder.

The captured payloads happen to be canonical already
(`payload_is_canonical: true`), because that Builder's marshaller emits its
`OrderBroadcast` fields in the same order `trueopen_cjson_v1` sorts them into. That
is luck, not a contract, and §5 still applies.

`signature` in the capture is `null` — the devnet runs `trusted_nats_dev`, so
Builders publish unsigned. The `signature_hex` on these two vectors is the
**fixture** key's signature over the real envelope's sign bytes; it demonstrates
the digest and the signature encoding, not the Builder's key.

### The four outbound Cortex vectors

Payload bodies come from Cortex's own wire structs, then canonicalised per §5, so
the field names and `omitempty` behaviour are exactly what Cortex publishes;
`TestBusEnvelopeInteropOutboundPayloadsMatchTheWireStructs` decodes each one back
into its wire struct with unknown fields disallowed, re-marshals, re-canonicalises
and requires the identical bytes, so it fails on a renamed, dropped or extra field. Envelope stamps, `message_id` and `nonce` are fixed
deterministic values.

Inside those bodies the *application-level* signature fields (`signature`,
`verifier_sig`, `service_signature`) are placeholder byte patterns (`0xaa…`,
`0x01…`). They are opaque to envelope signing — the digest commits the canonical
payload, whatever it contains — and this fixture makes no claim about the
application-level signing domains, which have their own vectors in
`taskdata_signing_v1.json`.

### `worker_handraise_html_escaping` — why this vector exists

It is the only vector that distinguishes `trueopen_cjson_v1` from Go's
`encoding/json` default. `<`, `>` and `&` appear in `chain_id`, in
`builder_set_id`, and in two payload strings. Go escapes all three to `\u003c`,
`\u003e`, `\u0026` unless `SetEscapeHTML(false)` is called
(`canonical_json.go:19`); no other language escapes them at all. An
implementation that leaves Go's default on agrees with **every other vector in
this file** and disagrees only here — which is exactly how the divergence
happened in the wild. Ordinary task identifiers are bech32 addresses, lowercase
hex and dotted NATS subjects, so no realistic fixture contains these three
characters by accident. This one contains them on purpose, in both the signed
object and the payload, so the escaping rule is pinned on both sides of the
digest.

### `worker_handraise_non_canonical_payload` — must be REFUSED

`must_refuse: true`. Its `envelope.payload_bytes` is the `worker_handraise`
payload retransmitted with its keys in **descending** order and whitespace after
`:` and `,`. `canonical_payload_bytes` is what it re-canonicalises to, and
`payload_digest_hex` is `sha256` of *that* — the value a correct signer commits
per `§5.2 PAYLOAD_BYTES`.

Per `§5.2` the receiver re-canonicalises after typed decode and rejects on any
difference, so this frame is refused before the signature is considered. Its
`sign_digest_hex` is recorded anyway so a peer can prove its canonicalisation
agrees with ours; the frame is still not admissible.

For the retained **pre-cutover** non-canonical WorkerHandraise, an
implementation that hashes transmitted bytes computes `541ab3c1…`; canonical
bytes produce `d2f0b1ac…`. The current decoder then refuses the payload because
it carries retired WorkerHandraise fields. The vector therefore pins both the
canonicalization rule and the clean-cutover refusal; it is not a current
outbound payload example.

## 9. Per-field mutation counter-examples

`field_mutations` has one entry per signed field — 20 entries, one for each row
of `§5.2`. Each takes the `worker_handraise` vector, changes **exactly one**
field, and records the resulting `signed_object`, `sign_bytes_hex`,
`sign_digest_hex` and `signature_hex`.

All 21 digests (base plus 20 mutations) are pairwise distinct. That is the
property being pinned: every one of the 20 fields is actually committed, proven
field by field rather than in aggregate. An implementation that drops or ignores
any single field reproduces the base digest for that field's mutation and fails
exactly one entry, which names the field it is missing.

One entry is shaped differently, and has to be. `payload_digest` is not copied
into the preimage from the wire — it is **derived** from the payload (§5) — so the
only way to move it is to move the payload. That entry therefore carries
`mutated_payload_bytes`: the base payload with its `quote` field changed to
`"attested-by-mutation"`. Those bytes are canonical, so the frame is admissible,
and `mutated_value` is their SHA-256. Every other entry leaves the payload alone
and has an empty `mutated_payload_bytes`.

## 10. Reproducing every byte without Go

This script reproduces `canonical_payload_bytes`, `payload_digest_hex`,
`signed_object`, `sign_bytes_hex` and `sign_digest_hex` for every vector and
every mutation in the file, from §2–§5 only. Run it in this directory.

```python
import json, hashlib, struct

fx = json.load(open("bus_envelope_signing_v1.json"))
SHORT = {'"':'\\"', '\\':'\\\\', '\b':'\\b', '\f':'\\f', '\n':'\\n', '\r':'\\r', '\t':'\\t'}

def js(s):                                   # json_string of section 3
    out = ['"']
    for ch in s:
        if ch in SHORT:      out.append(SHORT[ch])
        elif ord(ch) < 0x20 or ch in "\u2028\u2029":
            out.append("\\u%04x" % ord(ch))
        else:                out.append(ch)  # '<', '>', '&' stay literal
    return "".join(out) + '"'

def cjson(v):                                # trueopen_cjson_v1 of section 3
    if v is True:  return "true"
    if v is False: return "false"
    if v is None:  raise ValueError("null is not allowed")
    if isinstance(v, str):  return js(v)
    if isinstance(v, int):
        if v < 0: raise ValueError("integer must be non-negative")
        if v > 0xFFFFFFFFFFFFFFFF: raise ValueError("integer exceeds uint64")
        return str(v)
    if isinstance(v, list): return "[" + ",".join(cjson(x) for x in v) + "]"
    if isinstance(v, dict):
        ks = sorted(v, key=lambda k: k.encode())
        return "{" + ",".join(js(k) + ":" + cjson(v[k]) for k in ks) + "}"
    raise ValueError("type %s is not allowed" % type(v).__name__)

def parse(raw):                              # reject float / dup-key input
    def hook(pairs):
        d = {}
        for k, v in pairs:
            if k in d: raise ValueError("duplicate key %r" % k)
            d[k] = v
        return d
    def nofloat(s): raise ValueError("float %s" % s)
    return json.loads(raw, object_pairs_hook=hook, parse_float=nofloat)

INTS  = set(fx["integer_fields"])
NAMES = fx["signed_fields"]

def sign_bytes(env, payload_digest_hex):
    value = dict(env)
    value["nonce"] = "0x" + env["nonce_hex"]
    value["payload_digest"] = "0x" + payload_digest_hex
    obj = "{" + ",".join(
        js(n) + ":" + (str(value[n]) if n in INTS else js(value[n])) for n in NAMES) + "}"
    dom, ob = fx["sign_domain"].encode("ascii"), obj.encode("utf-8")
    frame = (fx["frame_tag"].encode("ascii")
             + struct.pack(">I", len(dom)) + dom
             + struct.pack(">Q", len(ob))  + ob)
    return obj, frame

for v in fx["vectors"]:
    e = v["envelope"]
    canonical = cjson(parse(e["payload_bytes"]))
    assert canonical == v["canonical_payload_bytes"], v["name"]
    assert (canonical == e["payload_bytes"]) == v["payload_is_canonical"], v["name"]
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert digest == v["payload_digest_hex"], v["name"]
    obj, frame = sign_bytes(e, digest)
    assert obj         == v["signed_object"],  v["name"]
    assert frame.hex() == v["sign_bytes_hex"], v["name"]
    assert hashlib.sha256(frame).hexdigest() == v["sign_digest_hex"], v["name"]
    print("ok", v["name"], "REFUSE" if v.get("must_refuse") else "")

byname = {v["name"]: v for v in fx["vectors"]}
for m in fx["field_mutations"]:
    b = byname[m["base_vector"]]
    e, digest = dict(b["envelope"]), b["payload_digest_hex"]
    if m["field"] == "nonce":
        e["nonce_hex"] = m["mutated_value"][2:]
    elif m["field"] == "payload_digest":
        payload = cjson(parse(m["mutated_payload_bytes"]))
        assert payload == m["mutated_payload_bytes"], "mutated payload must be canonical"
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        assert "0x" + digest == m["mutated_value"], m["field"]
    else:
        e[m["field"]] = m["mutated_value"]
    obj, frame = sign_bytes(e, digest)
    assert obj         == m["signed_object"],  m["field"]
    assert frame.hex() == m["sign_bytes_hex"], m["field"]
    assert hashlib.sha256(frame).hexdigest() == m["sign_digest_hex"], m["field"]
    assert m["sign_digest_hex"] != b["sign_digest_hex"], m["field"]
    print("ok mutation", m["field"])
```

The `signature_hex` values need a secp256k1 signer; everything else above is
reproducible with the standard library alone.

## 11. Regenerating

Don't, casually. These digests are a published cross-repository contract: changing
any of them changes what a peer must reproduce, and the two inbound vectors carry
captured evidence. A change to the signed field set is a change to the
`§5.2` table first — this file follows that table, it does not define it.
