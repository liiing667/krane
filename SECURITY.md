# Security Policy

## Reporting a Vulnerability

Please contact security@appvia.io

## The dashboard is token-gated

`krane dashboard` serves everything Krane has learned about a cluster's RBAC,
and it binds to `0.0.0.0` by default so that it is reachable through a Service
when running in a cluster. Access is denied by default: the server refuses to
start unless the `KRANE_DASHBOARD_TOKEN` environment variable is set to a
non-empty value, and every request must present that token as an
`Authorization: Bearer ...` header or a `krane_token` cookie. Requests without
it get a `401` before any path is resolved, so the index, report JSON, assets
and error pages all behave identically to an anonymous caller.

The token is read from the environment rather than a command-line flag so it
never shows up in the process list, comparison uses
`OpenSSL.fixed_length_secure_compare` so a wrong token cannot be discovered by
response timing, and the token is never logged or echoed back in a response.

Options for restricting access:

- reach it with `kubectl port-forward` rather than exposing the Service;
- apply a NetworkPolicy. The chart labels the pod `network/krane: "true"` and
  ships a policy using that label;
- put an authenticating proxy in front of it;
- pass `-b 127.0.0.1` when running locally, so it is not reachable from the
  network.

## RBAC data is treated as untrusted input

Object names come from the cluster and can contain anything a Kubernetes name
allows. The dashboard renders them as text, never as markup: `v-html` is
prohibited by a lint rule, tooltips are built as text nodes, and the server
sends a Content-Security-Policy of `default-src 'self'`.
