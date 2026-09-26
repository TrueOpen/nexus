# NATS Auth Callout Service (nexus natsauth)

Specification: monorepo ADR-0016 Decision 3, "Interface & Topic Catalogue" §5.13–§5.14, "Task Builder Coordination" §7.5. wire dependency: TrueOpen/wire `v0.2.0`.

## What it does

When Cortex connects to NATS it carries no creds; instead it presents a binding declaration (`bus.v1.NatsUserBindingV1`) signed with its on-chain service key.
The NATS server forwards the connection request to this service, which runs the nine-step check of §5.14.3 (query the chain for `current_service_pubkey`, verify both signatures,
check status) and, on success, signs a user JWT valid for <= 1 hour. The user is signed into the **TRUEOPEN application account** -- the same account as nexus, with roles distinguished by the subject permissions in the JWT;
no separate CORTEX account is created, because JetStream streams are isolated per account and the `TRUEOPEN_TASK` stream Cortex needs to consume lives in the TRUEOPEN account.
No keys or credentials are ever handed between operators manually.

**sentinel onboarding (a necessary detour in operator mode)**: in operator mode nats-server requires CONNECT to carry a user JWT up front,
otherwise it never consults the auth callout at all (nats-server v2.10.22 `server/auth.go:731-736`). And nats.go does not allow the same connection
to supply both `nkey` and `jwt`. So Cortex's CONNECT is:

- `jwt` = the **sentinel** user JWT of the AUTH account -- bearer, with no publish/subscribe permissions whatsoever, purely a "door knocker".
  It is **public, non-secret data**, not a credential: whoever holds it still cannot get in, because it carries no permissions and does not carry the real identity.
  Cortex does not have to copy it by hand; the Builder's nexus ingress serves it via `GET /v1/nats/sentinel`.
- `sig` = the signature over the server nonce made with Cortex's **own** NATS user private key;
- `auth_token` = the binding declaration token (the real identity lives here);
- **no `nkey`**.

Consequently step 4 (nkey equals the bound public key) is only checked when CONNECT actually carries an nkey, and step 5 always verifies `sig` with the
`nats_user_pubkey` from the binding declaration -- this step is the proof of "holds that private key". This service does not verify the sentinel JWT in CONNECT
(the server has already verified it); it only leaves a hint in the debug log.

## NATS-side preparation (nsc, operator mode)

```sh
# 1. Three accounts: SYS (required by JetStream), TRUEOPEN (application account: nexus's builder user and the Cortex users both live here,
#    and TRUEOPEN_TASK is created here too), AUTH (the callout service's own NATS connection + the sentinel user)
nsc add account TRUEOPEN
nsc add account AUTH
# 2. TRUEOPEN account signing key: the seed goes to the callout service, the public key is registered on the account. The callout service uses it to sign Cortex user JWTs
nsc generate nkey --account --store            # prints the SA… seed file path and the A… public key
nsc edit account TRUEOPEN --sk <A… public key>
# 3. Same for the AUTH account signing key
nsc generate nkey --account --store
nsc edit account AUTH --sk <A… public key>
# 4. The callout service's own user and creds (it bypasses the callout and enters the AUTH account directly with creds)
nsc add user --account AUTH natsauth
nsc generate creds --account AUTH --name natsauth > nats-auth.creds
# 4b. sentinel user: bearer, no permissions at all; Cortex uses it to knock on the auth callout (public, non-secret data, not a credential)
nsc add user --account AUTH sentinel --bearer --deny-pub '>' --deny-sub '>'
nsc describe user --account AUTH sentinel --raw > nats-sentinel.jwt
# 5. Enable the auth callout on the AUTH account: auth-user is the public key of the user from the previous step, allowed-account is the TRUEOPEN account public key
#    (--allowed-account only appends; if you switched accounts, first clear the old one with --rm-allowed-account)
nsc edit authcallout --account AUTH --auth-user <natsauth user public key> --allowed-account <TRUEOPEN account public key>
# 6. Push the resolver / regenerate the config, restart nats-server
nsc generate config --nats-resolver --sys-account SYS > nats-resolver.conf
```

nexus keeps using the local creds of the TRUEOPEN account's builder user and does not go through the callout. After changing an account JWT or the resolver, make nats-server reload
(`nats-server --signal reload` or restart); otherwise it keeps deciding by the old `allowed_accounts`, and the log shows
`Account "<signing key public key>" not permitted as valid account option for auth callout`.

In the nats-server TLS block use `handshake_first: "2s"` rather than `true`: `true` requires the client to start the TLS handshake before it receives INFO,
whereas nats.go by default reads INFO first and then upgrades; writing `"2s"` makes the server wait two seconds before falling back to the normal flow,
so both kinds of client can connect.

## Distributing the sentinel

The sentinel is public, non-secret data, but it still should not rely on manual copying. On the Builder side, configure nexus with:

```yaml
nats:
  sentinel_file: ./nats-sentinel.jwt   # relative paths are relative to this config file; NEXUS_NATS_SENTINEL_FILE also works
```

The ingress then serves it on the same port (plain HTTP like `/healthz`, not subject to the api-key / IP allowlist /
SDK envelope checks -- it is public by nature):

```sh
curl -s https://<builder>/v1/nats/sentinel
{"schema_version":1,"auth_account_public_key":"A…","sentinel_jwt":"eyJ…"}
```

`auth_account_public_key` lets Cortex confirm that this JWT really comes from the AUTH account it expects.
When `sentinel_file` is not configured the route returns 404 `{"error":"nats sentinel is not configured"}`;
if it is configured but is not a valid bearer user JWT, nexus refuses to start (fail-closed).
`sentinel_file` is read only once at startup; after changing the file content or path, restart nexus for it to take effect.

The same response can also carry the NATS address and the certificate Cortex verifies NATS with, so a new
Cortex needs neither handed to it by hand (ADR-0016 decision one item 1):

```yaml
nats:
  ca_file: ./nats-cert.pem                 # also what nexus itself verifies NATS with
  sentinel_file: ./nats-sentinel.jwt
  advertise_servers: [tls://203.0.113.10:4222]   # the address Cortex should dial, not necessarily nats.servers
```

```sh
curl -s https://<builder>/v1/nats/sentinel
{"schema_version":1,"auth_account_public_key":"A…","sentinel_jwt":"eyJ…","nats_servers":["tls://203.0.113.10:4222"],"nats_ca_pem":"-----BEGIN CERTIFICATE-----\n…"}
```

Only the `CERTIFICATE` blocks of `ca_file` are served; anything else in the file is not. Every certificate
block must parse, or nexus refuses to start: nexus's own NATS connection skips a block it cannot parse, but a
certificate handed to Cortex must be usable. Cortex trusts the certificate
because it fetched it over the ingress TLS pinned by the on-chain `tls_pubkey_hash`. `advertise_servers` without
`sentinel_file` makes nexus refuse to start; in production each address must be `tls://` and `ca_file` is required.

## Configuration and startup

The `natsauth` block of `nexus.example.yaml`; `chain.chain_id` / `chain.grpc_addr` reuse the main nexus configuration.

```sh
nexus natsauth check                          # only loads the keys and config and prints identities; connects to nothing
nexus natsauth start --jetstream-stream TRUEOPEN_TASK
```

In the `check` output, `cortex_signing_key` must be one of the signing key public keys registered in `nsc describe account TRUEOPEN`,
`cortex_account_public_key` must be the TRUEOPEN account public key (i.e. the one in the AUTH account's `allowed_accounts`),
and `auth_signing_key` likewise must correspond to the AUTH account; otherwise NATS rejects the JWTs this service signs.

Chain queries go through `chain.grpc_addr` (non-loopback must be `https://`), and the server certificate is verified against the **system root CAs**. The testnet node certificate is
issued by the testnet's private CA, so the host running the callout service must trust that CA first: install the CA certificate into the system trust store, or start this service with
`SSL_CERT_FILE=<ca.pem>`; otherwise `check` passes but after `start` every authorization is rejected with `CHAIN_UNAVAILABLE`
(the log `cause` shows `x509: certificate signed by unknown authority`). No switch is provided to skip verification.

`xkey_file` (response encryption) is not implemented in the current version: if a non-empty value is configured, `natsauth` refuses to start outright rather than silently sending plaintext responses.

## Rejections and logging

The closed set of error codes is in §5.14.3. The NATS server does not forward the error text to the client (the client only sees `Authorization Violation`),
so troubleshooting relies on this service's log line `authorization request rejected reason=<CODE>: …`.

With sentinel onboarding, `nkey=` in the log is empty (CONNECT carries no nkey); this is normal, not a client misconfiguration;
identify the party by `operator=`. Conversely, if a client is rejected by the server right after connecting and this service's log has **not a single request**,
the CONNECT almost certainly lacked the sentinel JWT: in operator mode the server does not trigger the callout in that case.

During `CHAIN_UNAVAILABLE` all new connections are rejected, while established connections are kept until their JWT expires (fail-closed).
Upper bound on revocation delay = `chain_query_cache_ttl_ms + user_jwt_ttl_ms`.
