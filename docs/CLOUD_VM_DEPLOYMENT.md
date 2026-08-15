# Cloud VM Deployment — AWS EC2, Azure VM, Google Compute Engine

Run AgentWatch Range on a **cloud virtual machine** instead of your laptop. This guide lists **which ports to open**, **which to keep private**, and **provider-specific firewall examples**.

**Related:** [PREREQUISITES.md](PREREQUISITES.md) (full install checklist) · [WORKSHOP.md](WORKSHOP.md) Level 0 · [splunk_app/INSTALL.md](../splunk_app/INSTALL.md) · [.env.example](../.env.example)

---

## Choose a deployment pattern

| Pattern | What runs on the VM | Splunk | Best for |
|---------|---------------------|--------|----------|
| **A — All-in-one lab VM** | Banking app, Attack Panel, Ollama, OTel, **local Splunk container** | `http://<VM-IP>:8000` | Classroom on one shared server |
| **B — Lab VM + external Splunk** | Banking app, Attack Panel, Ollama, OTel only | Splunk Cloud or separate Splunk VM | Production-like; **fewer public ports on lab VM** |
| **C — Splunk on its own VM** | Splunk Enterprise only | Dedicated Splunk host | Large teams; lab VM uses Pattern B |

```bash
# Pattern A — everything on one VM (same as local Docker)
docker compose --profile local up --build -d

# Pattern B — lab VM ships telemetry to Splunk Cloud / external Splunk
docker compose -f docker-compose.yml -f docker-compose.external.yml up --build -d
```

Set `SPLUNK_HEC_ENDPOINT`, `SPLUNK_HEC_TOKEN`, and index settings in `.env` before Pattern B — see [.env.example](../.env.example) Section B.

---

## Port reference (docker-compose defaults)

| Port | Protocol | Service | Pattern A | Pattern B | Open to internet? |
|------|----------|---------|-----------|-----------|-------------------|
| **5000** | TCP | Banking app (defend UI + API) | ✅ | ✅ | **Restrict** — learner / demo access only |
| **5001** | TCP | Attack Panel (workshop UI) | ✅ | ✅ | **Restrict** — facilitator / learner access only |
| **8000** | TCP | Splunk Web UI | ✅ | ❌ (not on lab VM) | **Never `0.0.0.0/0`** — admin IP or VPN only |
| **8088** | TCP | Splunk HEC (ingest) | ✅ (local Splunk) | ❌ on lab VM* | **Private** — same VPC/subnet or Splunk Cloud endpoint only |
| **11434** | TCP | Ollama LLM API | Published | Published | **Do not expose publicly** — keep VPC-internal |
| **4317** | TCP | OTel Collector gRPC | Published | Published | **Do not expose** — internal/debug only |
| **4318** | TCP | OTel Collector HTTP | Published | Published | **Do not expose** — internal only |
| **8889** | TCP | OTel Prometheus metrics | Published | Published | **Do not expose** — internal only |
| **22** | TCP | SSH (OS admin) | ✅ | ✅ | **Your IP / bastion only** — never world-open |
| **9002** | TCP | CSA MAESTRO UI (optional, host Node app) | Optional | Optional | **Restrict** — Level 5A workshop only |

\*Pattern B: OTel Collector sends HEC **outbound** to Splunk Cloud (`443`) or your Splunk VM (`8088` on private network). You do **not** need inbound `8088` on the lab VM.

**Default URLs after deploy (replace `<VM-PUBLIC-IP>`):**

| Service | URL |
|---------|-----|
| Banking app | `http://<VM-PUBLIC-IP>:5000` |
| Attack Panel | `http://<VM-PUBLIC-IP>:5001` |
| Splunk (Pattern A only) | `https://<VM-PUBLIC-IP>:8000` or `http://...` (enable TLS in production) |

---

## Recommended inbound rules (all clouds)

**Principle:** Open the **minimum** ports for learners. Never expose Splunk, HEC, or Ollama to the entire internet.

### Minimum for workshop delivery (Pattern A or B)

| Port | Source | Purpose |
|------|--------|---------|
| 5000 | Learner IP range or corporate VPN CIDR | Banking app |
| 5001 | Learner IP range or corporate VPN CIDR | Attack Panel / workshop |
| 22 | Your admin IP or bastion subnet | SSH maintenance |

### Add only if Splunk runs on the same VM (Pattern A)

| Port | Source | Purpose |
|------|--------|---------|
| 8000 | Learner + admin IP range or VPN | Splunk Web + compliance dashboards |

### Optional

| Port | Source | Purpose |
|------|--------|---------|
| 9002 | Same as 5001 | CSA MAESTRO Threat Analyzer (Node.js on host, not Docker) |

### Do **not** open inbound on a public lab VM

| Port | Why |
|------|-----|
| 8088 | HEC ingest — abuse risk; use localhost + Docker network, or external Splunk |
| 11434 | Unauthenticated LLM API — model abuse and data exfil risk |
| 4317 / 4318 / 8889 | Telemetry/debug — no learner need |

**Outbound (egress):** Allow HTTPS (`443`) for image pulls, Ollama model download, and **Splunk Cloud HEC** (Pattern B). Restrict egress in production per your policy.

---

## AWS EC2

### 1. Launch instance

| Setting | Recommendation |
|---------|----------------|
| AMI | Ubuntu 22.04 LTS or Amazon Linux 2023 |
| Instance type | `t3.xlarge` minimum (Ollama + Splunk); `t3.2xlarge` for comfortable workshops |
| Storage | ≥ 50 GB gp3 (Splunk + Ollama models) |
| VPC | Private subnet + bastion, **or** public subnet with strict security group |

### Install Docker on the VM

Follow **[PREREQUISITES.md](PREREQUISITES.md)** — especially:

1. Install Docker Engine + Compose v2 (`curl -fsSL https://get.docker.com | sudo sh`)
2. Add the login user to the `docker` group: `sudo usermod -aG docker ubuntu` then re-login
3. Verify: `docker ps` (no `sudo`)
4. Clone repo and copy env:

```bash
git clone https://github.com/machowdhury/OrchestraACME.git
cd OrchestraACME
cp .env.example .env
docker compose --profile local up --build -d
```

If you see `permission denied` on `/var/run/docker.sock`, you skipped step 2 — see [PREREQUISITES § docker.sock](PREREQUISITES.md#fix-permission-denied-on-dockersock).

### 2. Security group — inbound rules

Replace `203.0.113.0/24` with **your office VPN CIDR** or `/32` admin IPs. Do **not** use `0.0.0.0/0` for these ports.

| Type | Port | Source | Description |
|------|------|--------|-------------|
| SSH | 22 | `203.0.113.10/32` | Admin SSH |
| Custom TCP | 5000 | `203.0.113.0/24` | Banking app |
| Custom TCP | 5001 | `203.0.113.0/24` | Attack Panel |
| Custom TCP | 8000 | `203.0.113.0/24` | Splunk Web *(Pattern A only)* |
| Custom TCP | 9002 | `203.0.113.0/24` | MAESTRO *(optional)* |

**AWS CLI example** (attach to `sg-xxxxxxxx`):

```bash
# Admin SSH
aws ec2 authorize-security-group-ingress --group-id sg-xxxxxxxx \
  --protocol tcp --port 22 --cidr 203.0.113.10/32

# Workshop UIs
aws ec2 authorize-security-group-ingress --group-id sg-xxxxxxxx \
  --protocol tcp --port 5000 --cidr 203.0.113.0/24
aws ec2 authorize-security-group-ingress --group-id sg-xxxxxxxx \
  --protocol tcp --port 5001 --cidr 203.0.113.0/24

# Splunk Web — Pattern A only
aws ec2 authorize-security-group-ingress --group-id sg-xxxxxxxx \
  --protocol tcp --port 8000 --cidr 203.0.113.0/24
```

### 3. Verify from your laptop

```bash
curl -s http://<EC2-PUBLIC-IP>:5000/health
curl -s http://<EC2-PUBLIC-IP>:5001/health
```

---

## Microsoft Azure

### 1. Create VM

- **Image:** Ubuntu 22.04 LTS  
- **Size:** `Standard_D4s_v3` or larger (4+ vCPU, 16+ GB RAM for Pattern A)  
- Attach **NSG** to the VM NIC or subnet  

### 2. Network Security Group — inbound rules

| Priority | Name | Port | Source | Action |
|----------|------|------|--------|--------|
| 100 | Allow-SSH-Admin | 22 | `203.0.113.10/32` | Allow |
| 110 | Allow-Banking | 5000 | `VirtualNetwork` or VPN CIDR | Allow |
| 120 | Allow-AttackPanel | 5001 | `VirtualNetwork` or VPN CIDR | Allow |
| 130 | Allow-Splunk-Web | 8000 | `VirtualNetwork` or VPN CIDR | Allow *(Pattern A)* |
| 4096 | Deny-All-Inbound | * | * | Deny (default) |

**Azure CLI example:**

```bash
az network nsg rule create --resource-group acme-rg --nsg-name acme-lab-nsg \
  --name Allow-AttackPanel --priority 120 --direction Inbound \
  --access Allow --protocol Tcp --destination-port-ranges 5001 \
  --source-address-prefixes 203.0.113.0/24
```

### 3. Optional: Application Gateway or Front Door

For customer workshops, terminate TLS at Azure Application Gateway and forward to `:5001` on a **private** backend pool instead of exposing raw HTTP on the public internet.

---

## Google Cloud (Compute Engine)

### 1. Create VM

- **Machine type:** `e2-standard-4` minimum  
- **Boot disk:** Ubuntu 22.04, ≥ 50 GB  
- **Network tags:** `acme-lab` (for firewall targeting)  

### 2. VPC firewall rules

Create **ingress** rules with `targetTags: acme-lab`. Use `sourceRanges` = your VPN CIDR, not `0.0.0.0/0`.

```bash
# SSH
gcloud compute firewall-rules create acme-allow-ssh \
  --direction=INGRESS --priority=1000 --network=default --action=ALLOW \
  --rules=tcp:22 --source-ranges=203.0.113.10/32 --target-tags=acme-lab

# Workshop
gcloud compute firewall-rules create acme-allow-workshop \
  --direction=INGRESS --priority=1001 --network=default --action=ALLOW \
  --rules=tcp:5000,tcp:5001 --source-ranges=203.0.113.0/24 --target-tags=acme-lab

# Splunk Web — Pattern A only
gcloud compute firewall-rules create acme-allow-splunk-web \
  --direction=INGRESS --priority=1002 --network=default --action=ALLOW \
  --rules=tcp:8000 --source-ranges=203.0.113.0/24 --target-tags=acme-lab
```

### 3. IAP SSH (recommended)

Use [Identity-Aware Proxy](https://cloud.google.com/iap) for SSH instead of opening port 22 to the public internet.

---

## OS firewall (Ubuntu `ufw`) — defense in depth

After cloud NSG/security group rules, optionally mirror on the VM:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from 203.0.113.0/24 to any port 5000 proto tcp
sudo ufw allow from 203.0.113.0/24 to any port 5001 proto tcp
sudo ufw allow from 203.0.113.0/24 to any port 8000 proto tcp   # Pattern A only
sudo ufw allow from 203.0.113.10 to any port 22 proto tcp
sudo ufw enable
```

Do **not** `ufw allow 11434`, `8088`, or `4318` from `any`.

---

## Pattern B — Lab VM + Splunk Cloud (recommended for public cloud)

**Fewer attack surfaces on the lab VM:** no inbound Splunk ports.

1. On the lab VM, use external compose:

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.external.yml up --build -d
   ```

2. In `.env`:

   ```bash
   SPLUNK_HEC_ENDPOINT=https://http-inputs-<stack>.splunkcloud.com:443/services/collector/event
   SPLUNK_HEC_TOKEN=<your-hec-token>
   SPLUNK_HEC_TLS_SKIP_VERIFY=false
   SPLUNK_HEC_INDEX=acme_agentic_telemetry
   ```

3. Install the compliance app on **Splunk Cloud** — [splunk_app/INSTALL.md](../splunk_app/INSTALL.md).

4. **Inbound on lab VM:** only `5000`, `5001`, and `22` (restricted sources).

5. Learners open **Splunk Cloud URL** for hunts; Attack Panel on `http://<VM-IP>:5001` for scenarios.

---

## Pattern C — Splunk on a separate VM

| VM | Inbound ports (restricted) |
|----|----------------------------|
| **Lab VM** | 5000, 5001, 22 |
| **Splunk VM** | 8000 (Web), 8088 (HEC from lab VM private IP only), 22 |

Point lab VM `.env` `SPLUNK_HEC_ENDPOINT` to the **private IP** of the Splunk VM:

```bash
SPLUNK_HEC_ENDPOINT=https://10.0.1.50:8088/services/collector/event
```

Splunk VM security group: allow `8088` **only** from the lab VM’s private IP / security group — not from the internet.

---

## Optional: CSA MAESTRO on the same VM

MAESTRO runs **on the host** (Node.js), not in Docker:

```bash
git clone https://github.com/CloudSecurityAlliance/MAESTRO.git
cd MAESTRO && npm install
# .env: OLLAMA_SERVER_ADDRESS=http://127.0.0.1:11434
npm run dev   # listens on 9002
```

- Bind MAESTRO to localhost and use **SSH tunnel** if possible: `ssh -L 9002:127.0.0.1:9002 user@<VM-IP>`
- If you must expose `9002`, use the **same source IP restriction** as port `5001`
- Do **not** expose `11434` publicly; MAESTRO should talk to Ollama on `127.0.0.1`

---

## Hardening checklist (before learners connect)

- [ ] Change `SPLUNK_PASSWORD` from default in `.env`
- [ ] Rotate `SPLUNK_HEC_TOKEN` — never commit real tokens
- [ ] Restrict inbound `5000`/`5001`/`8000` to VPN or known CIDRs
- [ ] Keep `8088`, `11434`, `4317`, `4318` off public security groups
- [ ] Prefer **Pattern B** (Splunk Cloud) for internet-facing lab VMs
- [ ] Enable HTTPS (reverse proxy) if exposing UI outside a lab VPN
- [ ] Patch the OS and restart containers after `git pull`
- [ ] Stop the VM when the workshop ends (`docker compose down`)

---

## Instance sizing (rough guide)

| Pattern | vCPU | RAM | Notes |
|---------|------|-----|-------|
| B (no local Splunk) | 4 | 16 GB | Ollama `llama3.2:1b` + apps |
| A (all-in-one) | 4–8 | 16–32 GB | Splunk container is memory-heavy |
| + MAESTRO on host | +0 | +2 GB | Node + Genkit alongside Docker |

First Ollama model pull (~1.3 GB) requires outbound internet on first boot.

---

## Workshop Level 0 on a cloud VM

| Step | Cloud-specific action |
|------|------------------------|
| 0.1 | VM running, Docker installed, repo cloned, firewall rules applied |
| 0.2 | `curl http://<VM-IP>:5001/health` — Attack Panel reachable from learner network |
| 0.3 | Pattern A: `http://<VM-IP>:8000` — Pattern B: Splunk Cloud URL |
| 0.3b | Pattern A: `./scripts/splunk_local_bootstrap.sh` (HEC + index) |
| 0.4 | HEC verified (bootstrap HTTP 200 or `index=acme_agentic_telemetry \| stats count`) |
| 0.5 | Benign loan on `http://<VM-IP>:5000` |

Continue with [WORKSHOP.md](WORKSHOP.md) Level 1.

---

## Troubleshooting

| Symptom | Check |
|---------|--------|
| Connection timeout on `:5001` | Cloud security group / NSG / GCP firewall + `ufw` |
| Splunk empty (Pattern A) | HEC/index not configured | `./scripts/splunk_local_bootstrap.sh`; check `docker compose logs otel_collector` |
| `connection reset by peer` on 8088 | HEC disabled | `./scripts/splunk_local_bootstrap.sh` |
| Splunk empty (Pattern B) | Outbound `443` to Splunk Cloud; HEC token and index on Cloud |
| LLM offline | `docker compose logs ollama` — model pull; **do not** open `11434` to debug publicly |
| Works on VM localhost, not remotely | Docker publishes `0.0.0.0:5001` by default — cloud firewall is the usual blocker |

---

## Document map

| Doc | Topic |
|-----|--------|
| [WORKSHOP.md](WORKSHOP.md) | Workshop curriculum |
| [splunk_app/INSTALL.md](../splunk_app/INSTALL.md) | Splunk Cloud / Enterprise app install |
| [.env.example](../.env.example) | HEC and Splunk mode variables |
| [README.md](../README.md) | Golden path |
| [CONCEPTS.md](CONCEPTS.md) | Architecture |
| [REFERENCE.md](REFERENCE.md) | Install and env vars |
| [scripts/splunk_local_bootstrap.sh](../scripts/splunk_local_bootstrap.sh) | One-time local HEC + index setup |
