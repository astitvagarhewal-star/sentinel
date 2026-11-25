# SENTINEL

SENTINEL is a terminal-first, evidence-focused framework for **authorized passive** web
application security audits. Version 0.1 performs bounded metadata collection and
deterministic checks; it does not exploit, authenticate to, or actively attack targets.

## Safety model

Every audit needs a scope file. The HTTP client independently validates every URL,
including redirects, against that scope. Private, loopback, link-local, multicast, and
reserved IP addresses are rejected by default. This prevents the tool from becoming an
SSRF pivot. Only `http` and `https` are supported, and requests have fixed budgets,
timeouts, body-size limits, and per-host rate limits.

An entered URL is not treated as proof of permission. Only assess systems you are
authorized to test.

## Install

```bash
python3 run_sentinel.py --help
```

The source checkout runs without installing packages. When Python packaging tools are
available, `pip install -e .` also provides the `sentinel` command.

## Scope file

```yaml
targets:
  - https://app.example.test
allowed_hosts:
  - app.example.test
allowed_schemes: [https]
allowed_ports: [443]
allowed_paths: ["/"]
mode: passive
limits:
  requests_per_second: 2
  max_requests: 50
  timeout_seconds: 10
  max_response_bytes: 1048576
```

## Commands

```bash
python3 run_sentinel.py scope validate --scope scope.yaml
python3 run_sentinel.py audit https://app.example.test --scope scope.yaml --output reports
python3 run_sentinel.py run show <run-id> --database sentinel.db
python3 run_sentinel.py report export <run-id> --format markdown --output report.md --database sentinel.db
```

Reports contain redacted metadata rather than response bodies. `sentinel.db` is a local
SQLite database; use a protected working directory if the target names are sensitive.

## Current checks

- HTTP response and redirect metadata
- Common security-header gaps
- TLS certificate and negotiated protocol metadata for HTTPS
- Technology hints from safe response headers
- Same-origin links from HTML, without recursively requesting them

## Limitations

This is not a penetration-testing tool. It has no active vulnerability testing, browser
automation, authentication flows, JavaScript crawling, source analysis, or AI provider
integration yet. Findings are hypotheses until independently verified. The current MVP
uses only the Python standard library because its build environment is offline; typed
adapters for httpx, Pydantic, Typer, and external AI providers are planned upgrades.
