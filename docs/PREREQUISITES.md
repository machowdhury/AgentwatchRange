# OrchestraACME — Prerequisites

Complete this checklist **before** `docker compose up` or the workshop. Use it on **laptop**, **Ubuntu cloud VM**, or **Splunk Cloud + lab VM** deployments.

**Related:** [README.md](../README.md) · [WORKSHOP.md](WORKSHOP.md) Level 0 · [CLOUD_VM_DEPLOYMENT.md](CLOUD_VM_DEPLOYMENT.md) · [splunk_app/INSTALL.md](../splunk_app/INSTALL.md)

---

## Quick checklist

| # | Requirement | How to verify |
|---|-------------|---------------|
| 1 | **Hardware** meets minimums | See [Hardware](#hardware) |
| 2 | **Docker Engine 24+** and **Compose v2** installed | `docker --version` and `docker compose version` |
| 3 | Your user can run Docker **without** `permission denied` on `docker.sock` | `docker ps` (no `sudo`) |
| 4 | **Git** installed | `git --version` |
| 5 | Repo cloned, `.env` created | `cp .env.example .env` |
| 6 | **Inbound ports** open (cloud VM only) | `5000`, `5001`, optionally `8000` — see [CLOUD_VM_DEPLOYMENT.md](CLOUD_VM_DEPLOYMENT.md) |
| 7 | Stack started | `docker compose --profile local up --build -d` |
| 8 | **Ollama model** pulled | `docker compose logs ollama` shows `llama3.2:1b` |
| 9 | Splunk one-time | Apps + index + **HEC** — run `./scripts/splunk_install_apps.sh` then `./scripts/splunk_local_bootstrap.sh` |
| 10 | **Baseline in Splunk** (before attacks) | Manual loan on :5000 *or* wait 2–3 min; `index=acme_agentic_telemetry earliest=-15m \| stats count` → > 0 |
| 11 | **Attack Panel** shows TARGET + LLM **ONLINE** | http://localhost:5001 |

---

## Hardware

| Resource | Minimum | Recommended (local Splunk) |
|----------|---------|----------------------------|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | **16 GB** (Splunk container ~4 GB; Ollama ~2–4 GB) |
| Disk | 20 GB free | **50 GB** free (Splunk + Ollama model + images) |
| GPU | Optional | NVIDIA GPU speeds Ollama (not required) |
| Network | Broadband for first boot | ~1.3 GB model download on first start |

**Cloud VM sizing (Pattern A — all-in-one):** `t3.xlarge` / `Standard_D4s_v3` minimum; `t3.2xlarge` or larger for comfortable workshops — see [CLOUD_VM_DEPLOYMENT.md](CLOUD_VM_DEPLOYMENT.md).

---

## Software

| Tool | Version | Purpose |
|------|---------|---------|
| **Docker Engine** | 24.0+ | Runs banking app, Ollama, OTel, Splunk |
| **Docker Compose** | v2.20+ (`docker compose`, not `docker-compose`) | Stack orchestration |
| **Git** | Any recent | Clone the repository |
| **Web browser** | Chrome, Edge, or Firefox | Banking app, Attack Panel, Splunk UI |
| **curl** | Any recent | Health checks (`curl http://localhost:5000/health`) |
| **Python 3** | 3.9+ (host only) | `scripts/package_splunk_app.sh`, optional Cisco pip deps |

**You do not need:** OpenAI/Anthropic API keys, a separate Splunk license for local Docker Splunk, or Jupyter for the core workshop.

---

## Supported hosts

| Host | Notes |
|------|-------|
| **macOS** | Docker Desktop — allocate **≥ 8 GB RAM** to Docker in Desktop settings |
| **Windows** | Docker Desktop with **WSL2** backend; run commands in WSL or PowerShell |
| **Linux (Ubuntu 22.04/24.04)** | Native Docker — common for AWS/Azure/GCP lab VMs |
| **Splunk Cloud** | Lab VM runs Pattern B; Splunk runs in cloud — no local `:8000` |

---

## Install Docker (Ubuntu / cloud VM)

If `docker` is not installed:

```bash
# Official Docker convenience script (Ubuntu / Debian)
curl -fsSL https://get.docker.com | sudo sh

sudo systemctl enable docker
sudo systemctl start docker
```

Verify Compose v2 (bundled with modern Docker):

```bash
docker --version
docker compose version
```

### Fix: `permission denied` on `docker.sock`

If you see:

```text
unable to get image 'ollama/ollama:latest': permission denied while trying to connect to the Docker API at unix:///var/run/docker.sock
```

Docker is installed but your user is **not** in the `docker` group.

**Permanent fix:**

```bash
sudo usermod -aG docker $USER
newgrp docker
# OR log out of SSH and log back in
```

**Verify (must work without sudo):**

```bash
docker ps
```

**Temporary workaround (not recommended for daily use):**

```bash
sudo docker compose --profile local up --build -d
```

### Harmless warning

```text
the attribute `version` is obsolete, it will be ignored
```

Compose v2 ignores the top-level `version:` key in `docker-compose.yml`. Safe to ignore.

---

## Install Docker (macOS / Windows)

1. Install [Docker Desktop](https://www.docker.com/products/docker-desktop/).
2. Start Docker Desktop and wait until it reports **Running**.
3. **Settings → Resources:** assign at least **8 GB memory** (16 GB host RAM recommended).
4. Verify:

   ```bash
   docker compose version
   ```

---

## Clone and configure

```bash
git clone https://github.com/machowdhury/OrchestraACME.git
cd OrchestraACME
cp .env.example .env
```

Edit `.env` only if you use **Splunk Cloud** (Pattern B) or change passwords — defaults work for local lab.

---

## Start the stack

### Pattern A — Local Splunk (default classroom)

```bash
docker compose --profile local up --build -d
```

### Pattern B — Splunk Cloud / external Splunk

```bash
# Set SPLUNK_HEC_* in .env first — see .env.example Section B
docker compose -f docker-compose.yml -f docker-compose.external.yml up --build -d
```

### First-boot timeline

| Phase | Time | What happens |
|-------|------|----------------|
| Image build / pull | 2–10 min | First `up --build` downloads images |
| Ollama model | 2–10 min | Pulls `llama3.2:1b` (~1.3 GB) — watch `docker compose logs -f ollama` |
| Splunk init | 3–8 min | License acceptance, indexer startup (Pattern A) |
| Baseline traffic | ~45s after Ollama healthy | Background benign requests (`testbed_mode=BASELINE_TRAFFIC`) |
| Splunk dashboards | After **you** install app | Not automatic on `docker compose up` |

```bash
docker compose ps
docker compose logs -f ollama   # Ctrl+C to exit
```

---

## Network ports

| Port | Service | Local | Cloud VM inbound |
|------|---------|-------|------------------|
| **5000** | Banking app | localhost | Restrict to learner VPN/CIDR |
| **5001** | Attack Panel | localhost | Restrict to learner VPN/CIDR |
| **8000** | Splunk Web (Pattern A) | localhost | **Never `0.0.0.0/0`** |
| **8088** | Splunk HEC | Docker internal | **Do not expose publicly** |
| **11434** | Ollama | Internal | **Do not expose publicly** |
| **4317–4318** | OTel Collector | Internal | **Do not expose publicly** |
| **22** | SSH | — | Admin IP / bastion only |

Full firewall examples: [CLOUD_VM_DEPLOYMENT.md](CLOUD_VM_DEPLOYMENT.md).

---

## Splunk prerequisites (one-time)

`docker compose up` does **not** install Splunk apps or create the index.

**Quick path (local Docker Splunk) — follow in order:**

```bash
chmod +x scripts/package_splunk_app.sh scripts/splunk_install_apps.sh scripts/splunk_local_bootstrap.sh
./scripts/package_splunk_app.sh
./scripts/splunk_install_apps.sh
./scripts/splunk_local_bootstrap.sh
docker compose restart otel_collector   # if OTel started before HEC was ready
```

| Step | Action | PASS |
|------|--------|------|
| 1 | Package compliance app | `dist/acme_genai_compliance-*.tar.gz` exists |
| 2 | Install apps (compliance + MLTK) | `./scripts/splunk_install_apps.sh` completes; Splunk shows **GenAI Compliance Monitor** and **Splunk ML Toolkit** |
| 3 | HEC + index | `./scripts/splunk_local_bootstrap.sh` prints `HEC returned HTTP 200` |
| 4 | Verify ingest | `` index=acme_agentic_telemetry earliest=-15m \| stats count `` → count > 0 |

**MLTK:** Bundled at `splunk_app/splunk-ai-toolkit_600.tgz` and installed by `splunk_install_apps.sh`. Required for **CTSM token anomaly** and **MLTK Anomaly Hunting** dashboard.

Detail: [splunk_app/INSTALL.md](../splunk_app/INSTALL.md) · Full workshop steps: [WORKSHOP.md Level 0](WORKSHOP.md#level-0--environment-everyone).

---

## Optional overlays

| Overlay | Extra prerequisites | Doc |
|---------|---------------------|-----|
| **Cisco + MLTK** | `docker compose -f docker-compose.yml -f docker-compose.cisco.yml`; MLTK + [cisco-time-series-model](https://github.com/splunk/cisco-time-series-model) | [CISCO_INTEGRATION.md](CISCO_INTEGRATION.md) |
| **CSA MAESTRO** | Node.js host app on `:9002` (not in Compose) | [MAESTRO_WORKSHOP.md](MAESTRO_WORKSHOP.md) |

---

## Verification

Run after startup:

```bash
# 1. Container health
docker compose ps

# 2. Banking + baseline traffic sim
curl -s http://localhost:5000/health | python3 -m json.tool
curl -s http://localhost:5000/api/v1/traffic/status

# 3. Attack panel
curl -s http://localhost:5001/health

# 4. Ollama model loaded
curl -s http://localhost:5000/api/v1/ollama/health
```

**Browser checks:**

| URL | PASS |
|-----|------|
| http://localhost:5001 | Header: **TARGET ONLINE**, **LLM ONLINE** |
| http://localhost:5000 | Loan UI loads |
| http://localhost:8000 | Splunk login (Pattern A; `admin` / password from `.env`) |

**Splunk (after app + index setup):**

```spl
`acme_genai_index` earliest=-15m
| stats count by testbed_mode
```

Expect `BASELINE_TRAFFIC` after a few minutes even if you have not attacked yet.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `permission denied` on `docker.sock` | User not in `docker` group | [Docker group fix](#fix-permission-denied-on-dockersock) |
| `docker: command not found` | Docker not installed | [Install Docker](#install-docker-ubuntu--cloud-vm) |
| `LLM OFFLINE` on Attack Panel | Ollama still pulling model / init timeout | `docker compose logs -f ollama`; wait up to 15 min on first boot; see [Ollama unhealthy](#ollama-unhealthy--did-not-start-within-120s) |
| `acme_otel_collector` shows **unhealthy** | Old compose healthcheck used `wget` (not in distroless image) | `git pull` and `docker compose up -d` — collector works; status label fixed in latest compose |
| `acme_ollama is unhealthy` | Init healthcheck failed (often missing `curl` or low RAM) | Pull latest repo; `docker compose up --build -d`; ensure **≥ 8 GB** host RAM (16 GB for Pattern A) |
| `TARGET OFFLINE` | Banking container down | `docker compose ps`; `docker compose logs banking_app` |
| Splunk dashboards empty | App/index/HEC not configured | Run `./scripts/splunk_local_bootstrap.sh` then [splunk_app/INSTALL.md](../splunk_app/INSTALL.md) |
| No events in Splunk Search | HEC token mismatch | `.env` `SPLUNK_HEC_TOKEN` must match Splunk token; run bootstrap script |
| Cannot log in to Splunk Web | `.env` deleted or wrong password | `cp .env.example .env` then `./scripts/splunk_reset_admin_password.sh` |
| `.env` file missing | Never committed (gitignored) | `./scripts/restore_env.sh` |
| **Start lab from scratch** | Broken Splunk / lost config | `./scripts/lab_fresh_start.sh` (destroys volumes) |
| `connection reset by peer` on port 8088 | HEC disabled or index missing | `./scripts/splunk_local_bootstrap.sh` |
| App install `bundle_tmp` / Permission denied | Prior `splunk` CLI as root | `git pull` then `./scripts/splunk_install_apps.sh` (copies to `etc/apps`, repairs ownership) |
| `permission denied` on `otel-raw-genai.jsonl` | Shared volume permissions | Bootstrap script `chmod 1777` on `/var/log/defenseclaw`; restart otel |
| `permission denied` on scripts | Scripts not executable | `chmod +x scripts/*.sh` |
| Out of disk | Model + Splunk growth | `df -h`; expand volume or `docker system prune` |
| Slow LLM on VM | CPU-only inference | Expected; first response 10–30+ seconds |

---

## Ollama unhealthy / `did not start within 120s`

Logs show `Listening on [::]:11434` but the container exits with **Ollama did not start within 120s** and `docker compose` reports `acme_ollama is unhealthy`.

**Common causes:**

| Cause | Fix |
|-------|-----|
| **Old init script** used `curl` to `localhost` — fails on some Ollama images / IPv6 | `git pull` and rebuild: `docker compose up --build -d` |
| **VM too small** — Splunk + Ollama need RAM | Use **≥ 16 GB** for Pattern A (`t3.xlarge` / `Standard_D4s_v3`); **8 GB minimum** if Splunk is external |
| **First model pull** still running | Wait 10–15 min; watch `docker compose logs -f ollama` for `Model 'llama3.2:1b' pull complete` |

**Recovery on the VM:**

```bash
cd ~/OrchestraACME
git pull
docker compose --profile local down
docker compose --profile local up --build -d
docker compose logs -f ollama
```

**PASS:** Log line `Ollama API ready after Ns`, then `Pulling model` or `already present`, then banking_app starts.

**Manual check inside the container:**

```bash
docker exec -it acme_ollama ollama list
```

---

## Next steps

1. **[WORKSHOP.md](WORKSHOP.md#exercise-map-follow-in-order) Exercise map** — numbered checklist (fastest on-ramp)  
2. **[WORKSHOP.md](WORKSHOP.md) Level 0** — confirm baseline traffic and Splunk ingest  
3. **[WORKSHOP.md](WORKSHOP.md) Level 1** — 15-Minute First Win on Attack Panel (**Workshop** tab, last menu item)  
3. **[USER_GUIDE.md](USER_GUIDE.md)** — dashboards, fields, hunt SPL  
