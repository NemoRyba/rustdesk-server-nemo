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

When binding to a non-loopback address, a token is required:

```powershell
cargo run --release -- --nemo-api Y --nemo-api-bind 0.0.0.0:21120 --nemo-api-token "change-me"
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

If `--nemo-api-token` is set, enter the same token in the GUI token field.

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

- `GET /nemo/admin`
- `GET /nemo/api/health`
- `GET /nemo/api/peers?limit=100&offset=0`
- `GET /nemo/api/peers/{id}`
- `POST /nemo/api/peers/{id}/block`
- `POST /nemo/api/peers/{id}/allow`
- `POST /nemo/api/peers/{id}/reset-policy`
- `GET /nemo/api/peers/{id}/management-policy`
- `PUT /nemo/api/peers/{id}/management-policy` with JSON body `{"options":{"enable-clipboard":"N"}}`
- `POST /nemo/api/client/policy` with JSON body `{"id":"123456789","uuid":"base64"}`
- `GET /nemo/api/policy`
- `PUT /nemo/api/policy` with JSON body `{"company_only":true}`
- `GET /nemo/api/stats`
- `GET /nemo/api/events?limit=100`

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
{"options":{"enable-clipboard":"N","enable-file-transfer":"Y"}}
```

Only known RustDesk controlled-side option keys are accepted. Unknown keys and
unknown values are dropped before storage.

The client policy endpoint validates the client's base64 UUID against the
registered peer row and returns:

```json
{
  "server_public_key": "base64",
  "signed_payload": "base64",
  "payload": {
    "id": "123456789",
    "issued_at": "2026-05-23T12:00:00Z",
    "policy": {"options": {"enable-clipboard": "N"}}
  }
}
```

If hbbs has a signing key, `signed_payload` is the signed JSON bytes of
`payload`. Nemo clients should configure the same public key in the Management
dialog so policy is applied only when the signature verifies.

## Data Covered

The API exposes:

- registered peers from SQLite
- runtime online/offline state from the rendezvous peer map
- last registered/public address
- NAT negotiation signals seen by the rendezvous server
- direct punch attempts, local-address attempts, forced relay decisions, relay
  request/response counters, and policy rejections
- block/allow/reset controls for registered peers

Actual relay byte counters still live inside `hbbr`; this API records relay
negotiation from `hbbs`, which is the part needed to debug why a connection was
sent toward relay instead of direct punching.
