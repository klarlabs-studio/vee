# ADR 0038: TLS for the webhook server

- **Status:** Accepted
- **Date:** 2026-11-27

## Context

`vee hosting webhook-serve` bound to loopback only, because it could not
terminate TLS. Teams that receive webhooks from a hosted Git service had to
run a reverse proxy or tunnel on the same machine, and a container could
not expose the listener at all. `--allow-network` was reserved for this.

## Decision

**Vee serves HTTPS itself.** `--tls-cert PATH` and `--tls-key PATH`, which
must be given together, name a PEM certificate chain and its private key:

- rustls with its safe defaults: TLS 1.2 and 1.3, HTTP/1.1 only;
- the aws-lc-rs provider, already in the build through the HTTP client.

**Binding beyond loopback needs both `--allow-network` and TLS.** That
includes wildcard addresses such as `0.0.0.0`, which a container needs.
Plaintext beyond loopback stays refused; on loopback, TLS is optional.

- Webhooks are authenticated by their signature or Basic credentials, not
  by the Host header, so a wildcard bind is safe for the webhook server.
  The UI server (`vee ui`) is unchanged: loopback only, with its Host and
  Origin guard and token.
- The webhook server's `/api/health` answers `{"status":"ok"}` on any host
  name, as a load balancer or proxy reaches it by a DNS name. It no longer
  names the repository path, which is not for the network.

**Checks at start.** Vee refuses to start when:

- the private key is readable by group or others on Unix, as SSH refuses
  such keys;
- the key does not match the certificate;
- either file does not parse.

**Handshakes do not block one another.** Each connection's handshake runs
in its own task:

- a handshake that does not finish in 10 seconds is dropped;
- at most 64 handshakes are in progress at once;
- a client that connects and stalls cannot hold up the others.

## Consequences

- A team can run `webhook-serve` in a container or on a VM behind a load
  balancer without a sidecar proxy.
- **No certificate renewal while running:** restart Vee to load a renewed
  certificate. Hot reload and ACME are later work.
- **No client certificates:** mutual TLS is not supported; webhook
  signatures remain the authentication.
- **The UI stays loopback only.**
