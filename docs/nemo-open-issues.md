# Open issues — server

Found on the lab server, 2026-10-16, with a Windows client on build `11c4cac`. The full
register, including the client-side items, is `OPEN-TODOS.md` in the superproject
(`rustdesk-nemo-flavour`); the numbers match.

## 🔴 23. A connected, relaying client shows "provisioned, not polled"  *(CRITICAL)*

Peer `480170882` was online, allowed and had just connected over the relay, and the Peers
panel's *Key auth* column read **provisioned, not polled**.

The label is **literally correct**: `auth_mode` is written only by `client_policy`
(`record_peer_auth_mode`, `src/nemo_management.rs:460`) — i.e. by the **management
poll**. The rendezvous device-key handshake does not touch it. A client whose
`api-server` / `nemo-management-server` is not configured never polls, so it is
provisioned (a key is bound to it in the pinned registry) and never polled. The
underlying fault is the client-side import bug (21), not the server.

It still has to change, because it reads as a server fault:

- say what to do — *"no management poll yet; check this client's api-server"*;
- consider recording the auth mode from the **rendezvous handshake** as well. It proves
  the same device key, more strongly than the poll does, and a machine that connects
  daily should not be described as unverified.

## 🔴 24. The Relayed-bytes panel claims "went direct" for sessions that were relayed  *(CRITICAL)*

The Connections panel showed the session as **relay** via `192.168.1.14`, the client's own
window said relayed — and the Relayed bytes panel listed five sessions, all
**"unused — went direct"**, with `0 B relayed` in the header.

The labelling is the bug: `nemo_admin.html` renders `unused = !r.last_sample_at` as *went
direct* (around `nemo_admin.html:2305`). **"No sample" means the relay told us nothing,
which is not the same as nothing being relayed** — and when the poller cannot reach hbbr
at all (`--nemo-relay-metrics`; hbbr's admin channel answers on loopback only, and in this
deployment hbbs and hbbr are separate containers), *every* session gets that label. A
dashboard that manufactures "went direct" out of missing data is worse than one that shows
nothing.

**Fix:** carry the poller's own state into `GET /nemo/api/stats` (never connected /
last-success time / last error) and render three states instead of two — *relayed N
bytes*; *unused — went direct*, only when the poller is known-good and reported nothing
for that session; and *no data from the relay*, with the reason, otherwise. While the
poller has never succeeded the panel should say so once at the top rather than per row.
Then work out why `uj` is unreachable in the container deployment.

## 🔴 25. "Cut" blocks the peer instead of only ending the session  *(CRITICAL)*

Cutting a relayed connection leaves the target **blocked** in Peers, so the operator has
to go and allow it again afterwards. That is not what "cut" means.

`cut_connection` (`src/nemo_management.rs`) does two things: `set_peer_policy(…, Some(0))`
— a permanent admission change — and `set_peer_terminate`, which is the half that
actually ends the live session (the controlled machine tears it down on its next poll; a
direct session has no server-side data path to interrupt, so the teardown has to happen
there).

**Fix:** cut = `set_peer_terminate` plus dropping the connection row. Blocking stays the
separate, explicit **Block** action the Peers panel already has; an operator who wants
both presses both. The confirm dialog must stop promising a block, and the audit event
should say "sessions revoked", not "blocked".

## Related, tracked on the client side

- **21** a setup string applies the ID server only — the likely cause of 23, and the
  reason the dashboard cannot see a poll.
- **22** the address book stays empty after an import.
- **26** the import dialog's "Load from file…" button is misaligned.
