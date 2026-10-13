# tls-net - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each phase has hard exit criteria.
> Design and decisions: [`PLAN.md`](./PLAN.md).
>
> **Anti-deferral rule:** no listed hard task moves to a later phase unless this file records the move and the reason.

## v0.1.0 - Scaffold (DONE, 2026-10-13)
- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP, PLAN.

## v0.2.0 - Design lock
Exit: seam implementation, server and client configuration, reload, and policy APIs written in `docs/API.md` and approved; crypto provider and root store chosen (O-1, O-2).

## v0.3.0 - Server and client
Exit: tls-net serves HTTPS through net-io in direct mode and smtp-net connects to relays with verification.
- [ ] Seam over rustls; certificates; SNI; ALPN; policy; ClientHello summary.

## v0.4.0 - Operations
Exit: certificates reload under load with zero failed handshakes; expiry warnings reach health.
- [ ] Hot reload; expiry reporting; OCSP stapling; client certificates.

## v1.0.0 - Stable
- [ ] Frozen after direct mode has served the site in production.
