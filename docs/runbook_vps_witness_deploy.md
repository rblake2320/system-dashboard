# Runbook: VPS Witness + Replica Receiver Deployment

## Infrastructure overview

| Layer | Where | What |
|-------|-------|------|
| Witness server | VPS `/opt/witness/` | HMAC-signed checkpoint log, append-only NDJSON |
| BPC replica receiver | VPS `/opt/bpc-replica/` | Idempotent pair store, gunicorn :3101 |
| TSK replica receiver | VPS `/opt/tsk-replica/` | Idempotent tumbler store, gunicorn :3102 |
| Nginx | VPS | Terminates TLS, routes `/witness/`, `/bpc/replica/`, `/tsk/replica/` |
| Cloudflare | DNS + proxy | `witness.ultrarag.app → 2.25.136.64`, Full (strict) SSL |

## VPS details (Hostinger)

| Field | Value |
|-------|-------|
| Provider | Hostinger hPanel |
| VM ID | 1775625 |
| IP | 2.25.136.64 |
| Firewall group | 316129 (allow 22, 80, 443) |
| OS | Ubuntu 22.04 |
| SSH | `ssh -i ~/.ssh/id_ed25519 root@2.25.136.64` |

## Services on VPS

```bash
systemctl status witness          # port 3300 — witness server
systemctl status bpc-replica      # port 3101 — BPC pair receiver
systemctl status tsk-replica      # port 3102 — TSK tumbler receiver
systemctl status nginx            # terminates TLS, routes above
```

## Nginx config

File: `/etc/nginx/sites-available/witness`

Key location blocks:
```nginx
location /witness/      { proxy_pass http://127.0.0.1:3300; }
location /bpc/replica/  { proxy_pass http://127.0.0.1:3101; }
location /tsk/replica/  { proxy_pass http://127.0.0.1:3102; }
location /              { return 403; }
```

**Note trailing slash on all location blocks** — nginx prefix matching requires the slash. Without it, `/bpc/replica/pair` (with a subpath) would not match `/bpc/replica` (no trailing slash).

## Cloudflare setup

1. DNS: `witness.ultrarag.app  A  2.25.136.64  (proxied — orange cloud ON)`
2. SSL/TLS mode: **Full (strict)** — requires a valid Origin CA cert on the VPS
3. Origin certificate: Cloudflare → SSL/TLS → Origin Server → Create Certificate
   - Hostnames: `*.ultrarag.app`, `ultrarag.app`
   - Validity: 15 years
   - Type: RSA (2048)

## ⚠️ CRITICAL: Installing Cloudflare Origin CA certs

**NEVER paste cert/key from the Cloudflare dashboard UI.** The copy-paste action silently corrupts the RSA signature bytes in the PEM base64 — the cert loads into nginx (no parse error) but Cloudflare returns 526 because the signature doesn't verify.

This happened TWICE with two different freshly-generated certs.

**Correct procedure:**

1. In Cloudflare dashboard, click **Download** (not copy) to save the cert and key files locally.
2. SCP from the local downloaded files:
   ```bash
   scp -i ~/.ssh/id_ed25519 ~/Downloads/witness.crt root@2.25.136.64:/etc/nginx/ssl/witness.crt
   scp -i ~/.ssh/id_ed25519 ~/Downloads/witness.key root@2.25.136.64:/etc/nginx/ssl/witness.key
   ```
3. Verify the cert/key match AND the signature is valid:
   ```bash
   ssh root@2.25.136.64 '
     # cert/key public key match
     openssl x509 -in /etc/nginx/ssl/witness.crt -noout -pubkey | md5sum
     openssl pkey -in /etc/nginx/ssl/witness.key -pubout | md5sum
     # must show identical hashes

     # signature verifies against CF root
     curl -sO https://developers.cloudflare.com/ssl/static/origin_ca_rsa_root.pem
     openssl verify -CAfile origin_ca_rsa_root.pem /etc/nginx/ssl/witness.crt
     # must print: /etc/nginx/ssl/witness.crt: OK
   '
   ```
4. Build the chain cert (leaf + CF root, needed for Cloudflare Full strict):
   ```bash
   ssh root@2.25.136.64 '
     cat /etc/nginx/ssl/witness.crt /tmp/cf_origin_ca_root.pem > /etc/nginx/ssl/witness_chain.crt
   '
   ```
5. Update nginx to use the chain file and reload:
   ```bash
   ssh root@2.25.136.64 'nginx -t && systemctl reload nginx'
   ```
6. Verify locally first, then via Cloudflare:
   ```bash
   ssh root@2.25.136.64 'curl -sk https://localhost/witness/health'
   # expect {"ok":true,...}

   curl -s https://witness.ultrarag.app/witness/health
   # must NOT return "error code: 526"
   ```

## How to diagnose 526 errors

Cloudflare 526 = TLS cert on origin is invalid or not trusted by Cloudflare.

```bash
# 1. Confirm Cloudflare is even connecting (should see 172.70.x.x or 104.x.x.x)
ssh root@2.25.136.64 'timeout 10 tcpdump -nn -i eth0 port 443 -c 10'

# 2. Check what cert nginx is serving
ssh root@2.25.136.64 'openssl s_client -connect 127.0.0.1:443 -servername witness.ultrarag.app -showcerts </dev/null 2>&1 | grep -E "depth|error|verify"'

# 3. Verify signature
ssh root@2.25.136.64 'openssl verify -CAfile /tmp/cf_origin_ca_root.pem /etc/nginx/ssl/witness.crt'
# "certificate signature failure" = cert was pasted not downloaded — regenerate and re-download
# "OK" = cert is fine, look elsewhere
```

## Credentials and secrets

All stored in `system-dashboard/.witness.env` (gitignored):
```
WITNESS_URL=https://srv1775625.hstgr.cloud
WITNESS_KEY=<64-char hex HMAC key>
REPLICA_BPC_URL=https://srv1775625.hstgr.cloud/bpc/replica
REPLICA_TSK_URL=https://srv1775625.hstgr.cloud/tsk/replica
REPLICA_TOKEN=<64-char hex shared token>
```

## API endpoints

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `GET /witness/health` | none | Liveness check |
| `POST /witness/checkpoint` | HMAC sig in body | Push signed audit checkpoint |
| `GET /witness/verify/{principal_id}` | none | Read last checkpoint |
| `GET /bpc/replica/health` | none | BPC receiver liveness |
| `POST /bpc/replica/pair` | `x-replica-token` | Upsert/delete pair |
| `GET /tsk/replica/health` | none | TSK receiver liveness |
| `POST /tsk/replica/tumbler` | `x-replica-token` | Upsert/delete tumbler map |

## Running Phase 5 integration tests

```bash
cd system-dashboard
python -m pytest tests/test_phase5_vps_integration.py -v
# 16/16 should pass — hits live VPS over real TLS
```

## Prod hardening checklist (not done yet)

- [ ] Lock VPS firewall: port 22 allow your SSH IP only; port 443 allow Cloudflare IPs only
- [ ] Rotate REPLICA_TOKEN: generate new on VPS, update service envs, update `.witness.env`
- [ ] Merge BPC PR#3 and TSK PR#2 (Ron's decision only)
