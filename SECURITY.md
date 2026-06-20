# Security Policy

## Scope

System Dashboard is a **local-only** monitoring tool. By default it binds to
`127.0.0.1` only and is not reachable from the network.

## Authentication

**Authentication is disabled by default** (development mode). The dashboard is
intended to run on a developer's workstation where localhost access already
implies physical or session-level trust.

To enable authentication, add the following to `config.yaml`:

```yaml
auth:
  enabled: true
  username: admin
  password: "change_me_before_use"
```

When `auth.enabled` is `true` the dashboard will require HTTP Basic
Authentication on all routes.

## Reporting Vulnerabilities

Please report security issues by opening a GitHub Issue with the prefix
`[SECURITY]` in the title. Include:

- A clear description of the vulnerability
- Steps to reproduce
- Potential impact

Do **not** include credentials, tokens, or sensitive data in the report.

We aim to acknowledge reports within 3 business days and provide a fix or
mitigation within 14 days for confirmed issues.

## Network Exposure

If you change `dashboard.host` from `127.0.0.1` to `0.0.0.0` or any external
interface, you are responsible for adding appropriate firewall rules and enabling
authentication. Running with `host: 0.0.0.0` and `auth.enabled: false` on an
untrusted network is **not supported** and not recommended.
