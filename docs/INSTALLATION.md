# Installation Guide

This guide covers every supported installation method for AdByG0d in full detail.

**Author:** White0xdi3  
**Project:** AdByG0d — Active Directory Security Assessment Platform

---

## Supported installation methods

| Method | Suitable for |
|---|---|
| Docker Compose (recommended) | Most deployments — development and production |
| Manual local setup | Development, debugging, or environments where Docker is unavailable |
| Production deployment | Internet-accessible or multi-user assessment environments |

---

## System requirements

### Hardware

| Resource | Minimum | Recommended |
|---|---|---|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Disk | 20 GB | 50+ GB |

Graph algorithms and AI operator inference are CPU and RAM intensive. Large BloodHound datasets (100,000+ nodes) require 16+ GB RAM for comfortable operation.

### Software

| Requirement | Minimum version | Notes |
|---|---|---|
| Python | 3.12 | 3.13 supported |
| Node.js | 20 LTS | 22 LTS supported |
| npm | 10 | |
| Redis | 7.0 | |
| PostgreSQL | 15 | Production only; SQLite used in development |
| Docker Engine | 24 | For Docker Compose deployment |
| Docker Compose | 2.20 | Plugin form (`docker compose`, not `docker-compose`) |

### Operating system

Linux is the primary supported platform. Ubuntu 22.04 LTS and Debian 12 are tested in CI. macOS (Apple Silicon and Intel) works for development. Windows is not supported.

---

## Option 1: Docker Compose (recommended)

### Clone the repository

```bash
git clone https://github.com/White0xdi3/AdByG0d.git
cd AdByG0d
```

### Configure the environment

```bash
cp .env.docker.example .env
```

Open `.env` in a text editor and set the following required variables:

```bash
# Generate a strong secret key
python3 -c "import secrets; print(secrets.token_urlsafe(48))"

# Paste the output as:
SECRET_KEY=<paste output here>

# Set a strong database password
POSTGRES_PASSWORD=<strong unique password>

# For production, set your domain
ALLOWED_ORIGINS=http://localhost:3000
NEXT_PUBLIC_API_URL=http://localhost:8000
```

### Start the services

```bash
docker compose up --build
```

This starts four services:
- `redis` — job queue and pub-sub
- `api` — FastAPI backend on port 8000
- `worker` — Celery job executor
- `web` — Next.js frontend on port 3000

On first start, the API image is built from `apps/api/Dockerfile`. This takes 3–5 minutes. Subsequent starts use the cached image and start in under 30 seconds.

### Create the first admin account

```bash
docker compose exec api python scripts/bootstrap_admin.py
```

Follow the prompts to enter a username, email address, and password. This account has the superadmin role and can create additional users through the settings page.

### Verify the installation

| Service | URL |
|---|---|
| Web interface | http://localhost:3000 |
| API | http://localhost:8000 |
| API docs (dev only) | http://localhost:8000/docs |

Log in with the admin account you created. You should see the dashboard with no assessments yet.

### Stop the services

```bash
docker compose down
```

Data is persisted in Docker volumes (`adbygod_postgres_data`, `adbygod_redis_data`). Volumes are not deleted on `down` — use `docker compose down -v` to wipe data completely.

---

## Option 2: Manual local setup

Use this when Docker is unavailable or when you need to run individual services separately for debugging.

### Clone the repository

```bash
git clone https://github.com/White0xdi3/AdByG0d.git
cd AdByG0d
```

### Start Redis

Redis must be running before the API and worker start. Install via your package manager:

```bash
# Ubuntu/Debian
sudo apt install redis-server
sudo systemctl start redis

# macOS with Homebrew
brew install redis
brew services start redis

# Verify
redis-cli ping   # should return PONG
```

### Backend setup

```bash
cd apps/api

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Configure environment
cp .env.example .env
```

Edit `apps/api/.env` and set at minimum:

```bash
SECRET_KEY=<your-generated-key>
DEBUG=true
ENVIRONMENT=development
```

Generate a key with:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

Run database migrations:

```bash
PYTHONPATH=src alembic upgrade head
```

This creates `adbygod_dev.db` in the current directory using SQLite.

Start the API server:

```bash
PYTHONPATH=src uvicorn adbygod_api.main:app --reload --host 0.0.0.0 --port 8000
```

The `--reload` flag restarts the server automatically when Python source files change. Remove it for a stable development server.

### Celery worker

Async job execution requires the Celery worker. Open a second terminal:

```bash
cd apps/api
source .venv/bin/activate

PYTHONPATH=src celery -A adbygod_api.core.celery_app:celery_app worker \
  --loglevel=info \
  --queues=offensive_jobs \
  --concurrency=4
```

The `--concurrency=4` value controls how many jobs run in parallel. Adjust based on available CPU cores and memory.

### Frontend setup

Open a third terminal:

```bash
cd apps/web

npm install

cp .env.example .env.local
# .env.local defaults point to http://localhost:8000 — no changes needed for local dev

npm run dev
```

The frontend starts on http://localhost:3000.

### Create the first admin account

With the API running:

```bash
cd apps/api
source .venv/bin/activate
PYTHONPATH=src python scripts/bootstrap_admin.py
```

---

## Option 3: Production deployment

Production deployments have stricter requirements. The application enforces these at startup and will not start if they are not met.

### Infrastructure requirements

- A dedicated server or VM — do not run on shared infrastructure alongside non-assessment workloads
- PostgreSQL 15+ accessible from the API container — do not use SQLite
- Redis 7+ — do not expose Redis ports publicly
- A TLS-terminating reverse proxy in front of both the API and frontend (nginx, Caddy, or Traefik)
- A domain name with valid TLS certificates for both the API and frontend origins

### Configuration

```bash
cp .env.docker.example .env
```

Set these production-required variables:

```bash
SECRET_KEY=<minimum 64 character random value>
POSTGRES_PASSWORD=<strong unique password>
ENVIRONMENT=production
DEBUG=false
AUTH_COOKIE_SECURE=true
ALLOWED_ORIGINS=https://adbygod.yourdomain.com
NEXT_PUBLIC_API_URL=https://api.adbygod.yourdomain.com
NEXT_PUBLIC_WS_URL=wss://api.adbygod.yourdomain.com
```

### Start the production stack

```bash
docker compose -f docker-compose.prod.yml up --build -d
```

### Reverse proxy configuration

The API and frontend must be served behind HTTPS. Example nginx configuration:

```nginx
# API
server {
    listen 443 ssl;
    server_name api.adbygod.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/api.adbygod.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.adbygod.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket support for live streaming
    location /api/graph/ws/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

# Frontend
server {
    listen 443 ssl;
    server_name adbygod.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/adbygod.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/adbygod.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
    }
}
```

### Post-deployment verification

```bash
# Check all containers are running
docker compose -f docker-compose.prod.yml ps

# Check API health
curl https://api.adbygod.yourdomain.com/api/public/health

# Check migration state
docker compose -f docker-compose.prod.yml exec api python -m alembic current
```

---

## Database migrations

Migrations run automatically when the API container starts. To run them manually:

```bash
# Apply all pending migrations
PYTHONPATH=src alembic upgrade head

# Check current version
PYTHONPATH=src alembic current

# View migration history
PYTHONPATH=src alembic history

# Roll back one migration
PYTHONPATH=src alembic downgrade -1
```

In Docker:

```bash
docker compose exec api python -m alembic upgrade head
```

---

## Updating AdByG0d

```bash
git pull origin main

# Rebuild images with the new code
docker compose up --build -d

# Migrations run automatically on container start
# Verify
docker compose exec api python -m alembic current
```

---

## Collectors

### Linux remote collector

```bash
cd collectors/linux_remote

# Install dependencies
pip install -r requirements.txt

# Run with --help to see available modules
python -m adbygod_collector --help

# Full collection example
python -m adbygod_collector \
  --domain EXAMPLE.LOCAL \
  --dc dc01.example.local \
  --username assessor \
  --password 'AssessmentPassword!' \
  --output /tmp/collection.zip
```

The output ZIP imports directly into AdByG0d via the web interface.

### Windows local collector

Run from a domain-joined Windows host with an account that can query AD:

```powershell
# Full AD collection
.\Collect-AdByG0d.ps1

# ADCS CA flags collection (run as local admin on a CA server)
.\Collect-AdByG0d-ADCS-CAFlags.ps1
```

Output is a ZIP archive in the same directory as the script.

---

## Troubleshooting

### API container exits immediately

Check the container logs:

```bash
docker compose logs api
```

Common causes:
- `SECRET_KEY` is too short or matches a weak default
- `DATABASE_URL` is SQLite in production mode
- `AUTH_COOKIE_SECURE=false` in production mode
- PostgreSQL is not yet ready — the API container starts before the database is ready on first boot; wait 10 seconds and retry

### Cannot connect to Redis

```bash
redis-cli -u $REDIS_URL ping
```

If Redis is running in Docker, ensure both containers are on the same Docker network.

### Frontend shows "Network Error" for all API calls

Check that `NEXT_PUBLIC_API_URL` matches the actual API origin, including scheme and port. The browser makes requests from the client — this must be a URL the browser can reach, not an internal Docker hostname.

### Migration errors on startup

Run migrations manually to see the full error:

```bash
docker compose exec api python -m alembic upgrade head
```

If migrations are stuck in a partial state, check the `alembic_version` table and manually correct the version before re-running.

---

*Maintained by [White0xdi3](https://github.com/White0xdi3) — AdByG0d project*
