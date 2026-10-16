# Nemo Management API

This is a Nemo-specific server feature layered on top of the OSS RustDesk
server. It is kept behind the `nemo-management-api` Cargo feature so vanilla
server behavior can be tested without it.

## Enable

The feature is included in the default build, but the HTTP API is runtime-off
unless explicitly enabled:

```powershell
cargo run --release -- --nemo-api Y --nemo-api-bind 127.0.0.1:21120
```

When binding to a non-loopback address, a token is required — and since SEC-12 the
API also serves **HTTPS** there by default (self-signed unless you supply a
certificate), because the admin bearer token and every managed secret cross that
socket:

```powershell
cargo run --release -- --nemo-api Y --nemo-api-bind 0.0.0.0:21120 --nemo-api-token "change-me"
# -> https://<host>:21120/nemo/admin
```

Plaintext HTTP on a routable bind is refused at boot. To override it deliberately
(a lab, or a bind already behind a TLS terminator) pass both:

```powershell
cargo run --release -- --nemo-api Y --nemo-api-bind 0.0.0.0:21120 --nemo-api-token "change-me" \
    --nemo-api-tls off --nemo-api-allow-insecure Y
```

Authenticated calls can use either header:

```text
Authorization: Bearer change-me
X-Nemo-Token: change-me
```

The built-in admin GUI is served by the same feature/API:

```text
http://127.0.0.1:21120/nemo/admin
```

That URL serves a **login shell** to anyone who can reach the port: a token field and
nothing else — no route names, no policy keys, no build id. The dashboard itself is
`GET /nemo/admin/app` and needs the admin token like every other management route. A
browser navigation cannot send an `Authorization` header, so the shell fetches the
dashboard with one and renders the result in place. Enter the token once; the browser
keeps it and the shell is invisible from then on.

## Disable

Runtime off:

```powershell
cargo run --release --
```

Compile without the feature:

```powershell
cargo build --release --no-default-features
```

Remove the feature commit for deeper debugging:

```powershell
git revert <nemo-management-api-commit>
```

## Endpoints

- `GET /nemo/admin` — login shell, no token; also at `/nemo` and `/nemo/admin/`
- `GET /nemo/admin/app` — the dashboard HTML itself, admin token required
- `GET /nemo/api/health` — admin token required. Despite the name this is not a
  liveness probe: it returns the server's security policy (same body as
  `GET /nemo/api/policy`). There is no unauthenticated probe endpoint; use the
  process supervisor (the container image health-checks hbbs/hbbr with `s6-svstat`).
- `GET /nemo/api/peers?limit=100&offset=0`
- `GET /nemo/api/peers/{id}`
- `POST /nemo/api/peers/{id}/block`
- `POST /nemo/api/peers/{id}/allow`
- `POST /nemo/api/peers/{id}/reset-policy`
- `POST /nemo/api/peers/{id}/delete`
- `POST /nemo/api/peers/delete`
- `GET /nemo/api/peers/{id}/management-policy`
- `PUT /nemo/api/peers/{id}/management-policy` with JSON body `{"allow_user_override":false,"options":{"enable-clipboard":"N"}}`
- `POST /nemo/api/client/policy` with JSON body `{"id":"123456789","uuid":"base64"}`
- `GET /nemo/api/policy`
- `PUT /nemo/api/policy` with JSON body `{"company_only":true}`
- `GET /nemo/api/stats` — totals, per-peer counters, and (TODO 7) `relay_sessions`:
  what the relay actually carried per session, joined to the two peers hbbs brokered it
  for. `totals.relay_bytes` counts each session once; the per-peer `relay_bytes` charges
  both ends, so the per-peer numbers do not add up to the fleet total.
- `GET /nemo/api/events?limit=100`

### Device keys

- `GET /nemo/api/device-keys`
- `POST /nemo/api/device-keys` with JSON body `{"label":"Reception-PC","peer_id":"123456789"}`
  — generates a keypair, pins the public half, and returns the private half **once**.
  `peer_id` may be empty: the key is then a one-shot provisioning token (see
  *Device-key claims* below). The response also carries `setup_internal` and
  `setup_external` (see *Client setup* below): the same bundle with this key inside it,
  once per side of the network. A profile that could not be built carries its own
  `error`; the key is pinned either way, so losing the convenience never loses the key.
  The body may carry `{"setup":{"internal":{…},"external":{…}}}` to override the
  derivation per profile.
- `POST /nemo/api/device-keys/{id}/delete` — also ends the sessions that key's peer holds.
- `POST /nemo/api/device-keys/{id}/peer-id` with `{"peer_id":"123456789"}` — bind by hand,
  or send `""` to clear the binding and re-arm the key as a claimable token.

### Device-key claims

An unbound pinned key is a provisioning token: the first client that **proves** it is
still refused and files a claim for the operator to confirm. Full rationale in
`DEVICE-KEY-CLAIM.md` in the superproject.

- `GET /nemo/api/device-key-claims` → `{"claims":[…],"claim_unbound_device_keys":true}`
- `POST /nemo/api/device-keys/{id}/claim/approve` with `{"peer_id":"…"}` — the only path
  that writes a binding the operator did not type. Drops the key's other pending rows.
- `POST /nemo/api/device-keys/{id}/claim/deny` with `{"peer_id":"…"}` — the row stays,
  marked, so the client's next poll does not re-raise it.
- `POST /nemo/api/device-keys/{id}/claim/forget` with `{"peer_id":"…"}` — lets a denied
  client ask again.

`claim_unbound_device_keys` is also a `PUT /nemo/api/policy` field, and the health/policy
response reports it along with `pending_device_key_claims` (the waiting count).

### Client setup

Everything a fresh client needs to reach this server, as one importable string
(`tbfdesk-setup-v1:<base64 json>`): the ID/rendezvous server, the relay, the api-server
URL (used as both `api-server` and `nemo-management-server`), the server's identity key
(used as both `key` and `nemo-management-public-key`) and, for a self-signed API, its
certificate fingerprint.

**Two profiles, because this server has two addresses.** A client carries ONE address
set, so `internal` (the LAN address) and `external` (the public one) are exported side by
side and the operator hands over the one matching where that machine connects from. Give a
workstation the public address and every session hairpins out through the router and back;
give a roaming laptop the LAN address and it cannot reach the server at all. The lasting
fix is one split-horizon DNS name, which makes both profiles identical — see
`TOPOLOGY-DEPLOYMENT.md` in the superproject.

- `GET /nemo/api/client-setup` →
  `{"internal":Profile,"external":Profile,"issued_from":"…"}`, where `Profile` is
  `{"scope":"internal","server":{…},"setup_string":"…","filename":"…","error":"…"}`
  — the derived defaults and, for each side, a string with **no** device key in it.
  Nothing here fails as a whole: a profile that cannot be derived carries its reason in
  its own `error` and the other one is still usable.
- `POST /nemo/api/client-setup` with any of
  `{"scope":"external","id_server":"…","relay_server":"…","api_server":"…","api_cert_fingerprint":"…","label":"…"}`
  — **one** profile, with the operator's edits (the dashboard's two blocks each send
  their own, so editing one side cannot disturb the other). `scope` omitted means
  `internal`. An omitted field uses the server's default; an explicitly empty
  `api_cert_fingerprint` means "do not pin" and is not refilled.

Where the defaults come from, per profile:

| | `internal` | `external` |
|---|---|---|
| ID server / api-server host | the request's **Host header**, else `--local-ip` | the host out of **`-r`/`--relay-servers`** |
| relay | `--local-ip` (an internal session must not hairpin via the public relay) | empty — hbbs hands out its own `-r` at runtime |
| flag override | `--nemo-client-id-server`, `--nemo-client-relay`, `--nemo-client-api` | the same three with an `-external` suffix |

The API port is taken from the Host header for both (only the host differs); the
rendezvous port is not, so the client's own default stays implicit unless `--port` says
otherwise. The `external` profile **never** falls back to the Host header: an operator
administering over the LAN would otherwise get a LAN address baked into the
"from the internet" bundle, which is the one mistake this split exists to prevent. It
returns an empty profile with an `error` asking for the address instead.

The bundle carries the client's trust anchor and is deliberately unsigned — what a
signature would be verified against is the identity key inside it — so it has to be moved
like a password. The client half is documented in the client repo's
`docs/nemo-provisioning.md`.

## Policy

Peer status is stored in the existing SQLite `peer.status` column:

- `0`: blocked
- `1`: explicitly allowed
- `null`: open when company-only is off, unapproved when company-only is on

`--nemo-company-only Y` makes remote-control targets require status `1`.
Registration is still allowed so new devices can appear in the peer list before
an admin allows them.

## Client Management Policy

Per-client management policy is stored in SQLite `peer.management_policy`.
The first policy shape is:

```json
{"allow_user_override":false,"options":{"enable-clipboard":"N","enable-file-transfer":"Y"}}
```

Only known RustDesk user-facing option keys are accepted. Unknown keys are
dropped before storage. By default `allow_user_override` is false, so the
client treats policy values as fixed/authoritative settings. When it is true,
the same values are applied as defaults and users may override them locally.

The client policy endpoint validates the client's base64 UUID against the
registered peer row and returns:

```json
{
  "server_public_key": "base64",
  "signed_payload": "base64",
  "payload": {
    "id": "123456789",
    "issued_at": "2026-05-23T12:00:00Z",
    "policy": {"allow_user_override": false, "options": {"enable-clipboard": "N"}}
  }
}
```

If hbbs has a signing key, `signed_payload` is the signed JSON bytes of
`payload`. Nemo clients should configure the same public key in the Management
dialog so policy is applied only when the signature verifies.

Blocked peers also receive `nemo-outbound-enabled=N` as an authoritative
management option. Updated Nemo clients use that option to disable outgoing
connections locally.

The server can additionally enforce controller-side policy during rendezvous
when an updated Nemo client identifies itself in the request:

- `nemo-outbound-enabled=N` rejects all outgoing control attempts from that
  controller.
- `nemo-outbound-targets` limits outgoing control attempts to exact target IDs
  separated by comma, semicolon, or whitespace. `*` allows every target.

The source identity travels in `NemoSource {id, uuid, token}` on `PunchHoleRequest` and
`RequestRelay` (TODO 8, forked `hbb_common`). It used to be encoded inside existing
rendezvous fields — `PunchHoleRequest.version` and `RequestRelay.licence_key` — to avoid
forking the protobuf schema, and the server still reads that marker, so an un-updated
client on either side keeps working. A client that sends both and disagrees with itself
is logged and the field wins.

Either way this identity is **asserted, not proved**. What proves a controller is the
device-key handshake (`NemoClientAuth`), which binds the whole connection to one peer id;
the server prefers that proof wherever both exist and fails closed when a connection can
name no controller at all. Older clients that send no source identity can still be
blocked as targets and can receive management policy.

## Data Covered

The API exposes:

- registered peers from SQLite
- runtime online/offline state from the rendezvous peer map
- last registered/public address
- NAT negotiation signals seen by the rendezvous server
- direct punch attempts, local-address attempts, forced relay decisions, relay
  request/response counters, and policy rejections
- block/allow/reset controls for registered peers

Relay **byte** counters live inside `hbbr`, and since TODO 7 this API reports them too:
hbbs remembers which session a relay grant belongs to, polls hbbr over its loopback admin
channel (`uj`, the machine-readable twin of `usage`) and serves the result in
`GET /nemo/api/stats` as `relay_sessions` plus the `relay_bytes` totals. The join key is a
**hash** of the grant, so nothing that could be used to join a session crosses that
channel and hbbr still learns no peer id.

Two consequences worth knowing: hbbr's admin channel only answers on loopback, so a relay
on another host reports nothing unless its port is tunnelled to the hbbs host
(`--nemo-relay-metrics <host:port>`, `--nemo-relay-metrics-interval`, `""` or `N` to turn
it off); and a session row with no bytes is the **good** outcome — the relay was offered,
the two machines went direct, and the grant expired unused.
