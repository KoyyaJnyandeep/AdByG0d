#!/usr/bin/env bash
# AdByG0d — Complete A-to-Z installer for a fresh Kali Linux machine.
# Installs every dependency the platform knows about: system packages,
# Python venv, pip/pipx pentest tools, Go tools, Ruby gems, Node.js + frontend,
# Redis, env files, and DB schema.
#
# Usage:  bash install.sh
# Run from the project root directory.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$SCRIPT_DIR"
API_DIR="$ROOT_DIR/apps/api"
WEB_DIR="$ROOT_DIR/apps/web"
VENV_DIR="$API_DIR/.venv"
RUNTIME_DIR="$ROOT_DIR/.dev-runtime"
LOG_DIR="$ROOT_DIR/.logs"
TOOLS_DIR="$HOME/.local/share/adbygod-tools"
NVM_DIR="${NVM_DIR:-$HOME/.nvm}"

# ── colours ────────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  GREEN=$'\033[0;32m'; CYAN=$'\033[0;36m'; YELLOW=$'\033[1;33m'
  RED=$'\033[0;31m';   BOLD=$'\033[1m';    RESET=$'\033[0m';   DIM=$'\033[2m'
else
  GREEN=''; CYAN=''; YELLOW=''; RED=''; BOLD=''; RESET=''; DIM=''
fi

PASS=0; WARN=0

step()  { printf '\n%s╔══ %s%s%s\n' "$CYAN"   "$BOLD" "$*" "$RESET"; }
ok()    { PASS=$((PASS+1)); printf '  %s✓%s  %s\n'     "$GREEN"  "$RESET" "$*"; }
warn()  { WARN=$((WARN+1)); printf '  %s!%s  %s\n'     "$YELLOW" "$RESET" "$*"; }
note()  { printf '  %s·%s  %s%s%s\n' "$DIM"   "$RESET" "$DIM" "$*" "$RESET"; }
die()   { printf '\n%serror:%s %s\n' "$RED"    "$RESET" "$*" >&2; exit 1; }

# ── sanity ─────────────────────────────────────────────────────────────────────
[[ -f "$API_DIR/requirements.txt" ]] || die "Run this script from the AdByG0d project root."
if [[ $EUID -ne 0 ]]; then
  if ! sudo -n true 2>/dev/null; then
    warn "Sudo password is required for apt/system operations."
  fi
  note "Requesting sudo access once before quiet install steps"
  sudo -v || die "sudo authentication failed"
fi

# Ensure ~/.local/bin and ~/go/bin are in PATH for the duration of this script
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$HOME/.local/bin:$GOPATH/bin:$PATH"
mkdir -p "$HOME/.local/bin"

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — SYSTEM PACKAGES (apt)
# ═══════════════════════════════════════════════════════════════════════════════
step "System packages (apt-get)"
note "Apt output is hidden to keep the terminal readable"

sudo apt-get update -qq >/dev/null 2>&1 || die "apt-get update failed"

APT_PKGS=(
  # ── Core build tools ─────────────────────────────────────────────────────
  build-essential gcc g++ make cmake pkg-config
  ca-certificates gnupg curl wget git unzip zip tar

  # ── Python ───────────────────────────────────────────────────────────────
  python3 python3-pip python3-venv python3-dev python3-setuptools
  python2 python2-dev

  # ── Go ───────────────────────────────────────────────────────────────────
  golang

  # ── Ruby ─────────────────────────────────────────────────────────────────
  ruby-full ruby-dev

  # ── Node.js (bootstrap — nvm may override later) ─────────────────────────
  nodejs npm

  # ── pipx ─────────────────────────────────────────────────────────────────
  pipx

  # ── Crypto / TLS / LDAP / Kerberos build deps ────────────────────────────
  libssl-dev libffi-dev libsasl2-dev libldap2-dev libkrb5-dev
  libpq-dev libpcap-dev libsqlite3-dev
  libxml2-dev libxslt1-dev python3-lxml  # needed by donpapi

  # ── Kerberos client ───────────────────────────────────────────────────────
  krb5-user

  # ── Database ─────────────────────────────────────────────────────────────
  redis-server sqlite3

  # ── Network recon / scanning ──────────────────────────────────────────────
  nmap masscan arp-scan nbtscan netdiscover fping hping3
  tcpdump tshark wireshark-common p0f
  dnsutils        # dig, nslookup, host
  whois
  snmp snmpd      # snmpwalk
  telnet

  # ── Web scanning ──────────────────────────────────────────────────────────
  dirb nikto gobuster ffuf feroxbuster wfuzz
  whatweb wpscan dnstwist recon-ng eyewitness

  # ── AD / Kerberos tools ───────────────────────────────────────────────────
  kerbrute
  enum4linux-ng

  # ── SMB / LDAP ────────────────────────────────────────────────────────────
  smbclient samba-common-bin cifs-utils
  ldap-utils      # ldapsearch, ldapmodify

  # ── Neo4j (BloodHound GUI backend) ────────────────────────────────────────
  neo4j

  # ── NTLM / relay ──────────────────────────────────────────────────────────
  bettercap

  # ── Password attacks ──────────────────────────────────────────────────────
  hydra medusa crowbar patator hashcat john wordlists
  cewl crunch

  # ── C2 / exploit framework ────────────────────────────────────────────────
  metasploit-framework exploitdb sqlmap
  set              # Social Engineering Toolkit
  gophish swaks
  powershell-empire
  sliver

  # ── Post-exploitation ─────────────────────────────────────────────────────
  peass            # linpeas / winpeas

  # ── Tunneling & pivoting ──────────────────────────────────────────────────
  proxychains4 socat iodine sshuttle
  netcat-openbsd ncat
  openssh-client openssh-server
  ftp

  # ── Remote desktop ────────────────────────────────────────────────────────
  freerdp2-x11    # xfreerdp

  # ── Credential & forensics tools ─────────────────────────────────────────
  binwalk binutils   # strings
  autopsy
  gdb

  # ── Evasion / payload ─────────────────────────────────────────────────────
  nim upx-ucl wine wine64 mono-complete

  # ── Volatility3 ──────────────────────────────────────────────────────────
  volatility3

  # ── Misc utilities ────────────────────────────────────────────────────────
  jq tmux screen lsof psmisc net-tools iproute2
  iputils-ping openssl perl at xxd hexedit
)

apt_install() {
  local pkg="$1"
  printf '  %s→%s  apt install %s\n' "$CYAN" "$RESET" "$pkg"
  if ! sudo apt-get install -y --no-install-recommends "$pkg" >/dev/null 2>&1; then
    note "apt: $pkg not found or failed (skipped)"
  fi
}

for pkg in "${APT_PKGS[@]}"; do
  apt_install "$pkg"
done
ok "APT packages installed"

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — NODE.JS (via nvm — ensures ≥ 20)
# ═══════════════════════════════════════════════════════════════════════════════
step "Node.js ≥ 20 (nvm)"

[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

install_nvm() {
  if [ ! -s "$NVM_DIR/nvm.sh" ]; then
    curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
  fi
  # shellcheck disable=SC1091
  [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
  [ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"
}

if command -v node &>/dev/null; then
  NODE_MAJOR="$(node -e 'process.stdout.write(process.version.replace(/^v(\d+).*$/,"$1"))')"
  if (( NODE_MAJOR >= 20 )); then
    ok "Node.js $(node --version) already satisfies ≥20"
  else
    warn "Node.js $(node --version) too old — upgrading via nvm"
    install_nvm
    nvm install --lts && nvm use --lts && nvm alias default node
    ok "Node.js $(node --version) ready"
  fi
else
  install_nvm
  nvm install --lts && nvm use --lts && nvm alias default node
  ok "Node.js $(node --version) ready"
fi
command -v npm &>/dev/null || die "npm not available after Node.js install"
ok "npm $(npm --version) ready"

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — GO TOOLS
# ═══════════════════════════════════════════════════════════════════════════════
step "Go tools"

go_install() {
  local pkg="$1" bin="$2"
  if command -v "$bin" &>/dev/null; then
    note "$bin already in PATH — skipping"
    return 0
  fi
  printf '  %s→%s  go install %s\n' "$CYAN" "$RESET" "$pkg"
  go install "$pkg" 2>&1 | tail -2 || warn "go install $pkg failed (non-fatal)"
}

go_install "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"        naabu
go_install "github.com/owasp-amass/amass/v4/...@master"                    amass
go_install "github.com/tomnomnom/assetfinder@latest"                        assetfinder
go_install "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"              dnsx
go_install "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" subfinder
go_install "github.com/projectdiscovery/httpx/cmd/httpx@latest"            httpx
go_install "github.com/projectdiscovery/katana/cmd/katana@latest"          katana
go_install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"       nuclei
go_install "github.com/lc/gau/v2/cmd/gau@latest"                           gau
go_install "github.com/jaeles-project/gospider@latest"                     gospider
go_install "github.com/hakluke/hakrawler@latest"                           hakrawler
go_install "github.com/ropnop/windapsearch@latest"                         windapsearch
go_install "github.com/lkarlslund/Adalanche@latest"                        adalanche
go_install "github.com/jpillora/chisel@latest"                             chisel
go_install "github.com/nicocha30/ligolo-ng/cmd/proxy@latest"               proxy   # binary is 'proxy'
go_install "github.com/sensepost/ruler@latest"                             ruler

# ligolo-ng proxy binary is named 'proxy' — symlink it to ligolo-ng
if [ -f "$GOPATH/bin/proxy" ] && [ ! -f "$GOPATH/bin/ligolo-ng" ]; then
  ln -sf "$GOPATH/bin/proxy" "$GOPATH/bin/ligolo-ng"
  note "Symlinked proxy → ligolo-ng"
fi

# evilginx2 — module has replace directives; clone + build from source
if ! command -v evilginx &>/dev/null && [ ! -f "$HOME/.local/bin/evilginx" ]; then
  printf '  %s→%s  Building evilginx2 from source\n' "$CYAN" "$RESET"
  TMP_EG="$(mktemp -d)"
  git clone --quiet --depth 1 https://github.com/kgretzky/evilginx2 "$TMP_EG/evilginx" 2>/dev/null && \
    (cd "$TMP_EG/evilginx" && go build -o "$HOME/.local/bin/evilginx" . 2>&1 | tail -2) && \
    ok "evilginx built and installed to ~/.local/bin/evilginx" || \
    warn "evilginx build failed (non-fatal)"
  rm -rf "$TMP_EG"
fi

# Spray — it's a bash script, not a Go binary; install directly via curl
if ! command -v spray &>/dev/null && [ ! -f "$HOME/.local/bin/spray" ]; then
  printf '  %s→%s  Installing Spray (bash script)\n' "$CYAN" "$RESET"
  curl -fsSL "https://raw.githubusercontent.com/Greenwolf/Spray/master/spray.sh" \
    -o "$HOME/.local/bin/spray" 2>/dev/null && \
    chmod +x "$HOME/.local/bin/spray" && ok "spray installed to ~/.local/bin/spray" || \
    warn "spray install failed (non-fatal)"
fi

# aquatone — upstream has a broken module; skip silently (Kali has no apt package)
note "aquatone: upstream module broken — skipping (use eyewitness as alternative)"

ok "Go tools installed"

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — RUBY GEMS
# ═══════════════════════════════════════════════════════════════════════════════
step "Ruby gems"

gem_install() {
  local gem_name="$1"
  if gem list -i "^${gem_name}$" &>/dev/null 2>&1; then
    note "$gem_name already installed — skipping"
    return 0
  fi
  printf '  %s→%s  gem install %s\n' "$CYAN" "$RESET" "$gem_name"
  gem install "$gem_name" --no-document 2>&1 | tail -2 || warn "gem install $gem_name failed (non-fatal)"
}

gem_install "evil-winrm"

# dnscat2 and username-anarchy are not on rubygems.org — clone from GitHub
git_clone_bin() {
  local name="$1" url="$2" script="$3"
  local dest="$TOOLS_DIR/$name"
  if [ -d "$dest" ]; then
    note "$name already cloned"
  else
    printf '  %s→%s  git clone %s\n' "$CYAN" "$RESET" "$url"
    git clone --quiet --depth 1 "$url" "$dest" 2>/dev/null || { warn "git clone $name failed (non-fatal)"; return 0; }
  fi
  if [ -n "$script" ] && [ ! -L "$HOME/.local/bin/$name" ]; then
    ln -sf "$dest/$script" "$HOME/.local/bin/$name"
    chmod +x "$dest/$script" 2>/dev/null || true
  fi
}

mkdir -p "$TOOLS_DIR"
git_clone_bin "username-anarchy" "https://github.com/urbanadventurer/username-anarchy" "username-anarchy"
git_clone_bin "dnscat2"          "https://github.com/iagox86/dnscat2"                  "client/dnscat2"

ok "Ruby gems and git-cloned Ruby tools installed"

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — PYTHON PENTEST TOOLS (pipx + pip3)
# Kali PEP668 blocks global pip3 installs; use pipx for standalone tools.
# ═══════════════════════════════════════════════════════════════════════════════
step "Python pentest tools (pipx / pip3)"

# Ensure pipx path is active
export PATH="$HOME/.local/bin:$PATH"
pipx ensurepath --force 2>/dev/null || true

pipx_install() {
  local pkg="$1" bin="${2:-}"
  if [ -n "$bin" ] && command -v "$bin" &>/dev/null; then
    note "$bin already in PATH — skipping"
    return 0
  fi
  printf '  %s→%s  pipx install %s\n' "$CYAN" "$RESET" "$pkg"
  pipx install "$pkg" 2>/dev/null || \
    warn "pipx install $pkg failed (non-fatal)"
}

# Already-in-PATH tools get skipped by the binary check in pipx_install.
# Tools already installed system-wide via apt on Kali are fine either way.

# ── DNS & recon ───────────────────────────────────────────────────────────────
pipx_install "dnsrecon"           "dnsrecon"
pipx_install "fierce"             "fierce"
pipx_install "dirsearch"          "dirsearch"
pipx_install "theHarvester"       "theHarvester"
pipx_install "wafw00f"            "wafw00f"
pipx_install "adidnsdump"         "adidnsdump"

# ── AD enumeration ────────────────────────────────────────────────────────────
pipx_install "bloodhound"                               "bloodhound-python"
pipx_install "ldeep"                                    "ldeep"
pipx_install "man-spider"                               "manspider"
pipx_install "ldapdomaindump"                           "ldapdomaindump"
pipx_install "smbmap"                                   "smbmap"
pipx_install "netexec"                                  "nxc"

# ── NTLM relay / coercion ─────────────────────────────────────────────────────
pipx_install "coercer"                                  "coercer"
pipx_install "mitm6"                                    "mitm6"
pipx_install "responder"                                "responder"
# krbrelayx is not a proper pip package — clone to tools dir instead
if [ ! -d "$TOOLS_DIR/krbrelayx" ]; then
  printf '  %s→%s  git clone krbrelayx\n' "$CYAN" "$RESET"
  git clone --quiet --depth 1 https://github.com/dirkjanm/krbrelayx.git "$TOOLS_DIR/krbrelayx" 2>/dev/null || \
    warn "krbrelayx git clone failed (non-fatal)"
else
  note "krbrelayx already cloned"
fi
pipx_install "impacket"                                 "impacket-secretsdump"

# ── Password spraying ─────────────────────────────────────────────────────────
pipx_install "smartbrute"                               "smartbrute"
pipx_install "sprayhound"                               "sprayhound"
pipx_install "o365spray"                                "o365spray"

# ── PrivEsc / ADCS ────────────────────────────────────────────────────────────
pipx_install "certipy-ad"                               "certipy"
pipx_install "bloodyad"                                 "bloodyAD"
pipx_install "certsync"                                 "certsync"
pipx_install "pywhisker"                                "pywhisker"
pipx_install "git+https://github.com/ShutdownRepo/targetedKerberoast.git" "targetedkerberoast.py"
pipx_install "crackmapexec"                             "crackmapexec"

# ── C2 / lateral movement ─────────────────────────────────────────────────────
pipx_install "pwncat-cs"                                "pwncat-cs"

# ── Credential extraction & loot ─────────────────────────────────────────────
pipx_install "pypykatz"                                 "pypykatz"
pipx_install "lsassy"                                   "lsassy"
pipx_install "git+https://github.com/login-securite/DonPAPI.git" "donpapi"
pipx_install "hashid"                                   "hashid"
pipx_install "cupp"                                     "cupp"

# ── Evasion / analysis ────────────────────────────────────────────────────────
pipx_install "checksec"                                 "checksec"
pipx_install "ROPGadget"                                "ROPgadget"

ok "Python pentest tools installed"

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — GIT-CLONED TOOLS
# ═══════════════════════════════════════════════════════════════════════════════
step "Git-cloned attack tools"

clone_tool() {
  local name="$1" url="$2"
  if [ -d "$TOOLS_DIR/$name" ]; then
    note "$name already cloned — updating"
    git -C "$TOOLS_DIR/$name" pull --quiet 2>/dev/null || true
  else
    printf '  %s→%s  git clone %s\n' "$CYAN" "$RESET" "$url"
    git clone --quiet --depth 1 "$url" "$TOOLS_DIR/$name" 2>/dev/null || \
      warn "git clone $name failed (non-fatal)"
  fi
}

clone_tool "DFSCoerce"       "https://github.com/Wh04m1001/DFSCoerce"
clone_tool "PetitPotam"      "https://github.com/topotam/PetitPotam"
clone_tool "noPac"           "https://github.com/Ridter/noPac"
clone_tool "sam-the-admin"   "https://github.com/WazeHell/sam-the-admin"

ok "Git-cloned tools ready in $TOOLS_DIR"

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — MANUAL BINARY DOWNLOADS
# ═══════════════════════════════════════════════════════════════════════════════
step "Manual binary downloads (pspy, frp)"

ARCH="$(uname -m)"

# ── pspy ──────────────────────────────────────────────────────────────────────
if ! command -v pspy &>/dev/null; then
  printf '  %s→%s  Downloading pspy64\n' "$CYAN" "$RESET"
  curl -fsSL "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64" \
    -o "$HOME/.local/bin/pspy" 2>/dev/null && \
    chmod +x "$HOME/.local/bin/pspy" && ok "pspy → ~/.local/bin/pspy" || \
    warn "pspy download failed — get it from github.com/DominicBreuker/pspy"
else
  note "pspy already installed"
fi

# ── frp (fast reverse proxy) ─────────────────────────────────────────────────
if ! command -v frpc &>/dev/null; then
  printf '  %s→%s  Downloading frp\n' "$CYAN" "$RESET"
  FRP_VER="0.61.1"
  case "$ARCH" in x86_64) FA="amd64" ;; aarch64) FA="arm64" ;; *) FA="amd64" ;; esac
  FRP_URL="https://github.com/fatedier/frp/releases/download/v${FRP_VER}/frp_${FRP_VER}_linux_${FA}.tar.gz"
  TMP_FRP="$(mktemp -d)"
  curl -fsSL "$FRP_URL" -o "$TMP_FRP/frp.tar.gz" 2>/dev/null && \
    tar -xzf "$TMP_FRP/frp.tar.gz" -C "$TMP_FRP" && \
    cp "$TMP_FRP"/frp_*/frpc "$TMP_FRP"/frp_*/frps "$HOME/.local/bin/" && \
    chmod +x "$HOME/.local/bin/frpc" "$HOME/.local/bin/frps" && \
    rm -rf "$TMP_FRP" && ok "frpc/frps → ~/.local/bin/" || \
    warn "frp download failed — get it from github.com/fatedier/frp"
else
  note "frp already installed"
fi

# Note: sliver is installed via apt (kali package), pspy and frp via direct download
note "sliver: installed via apt (kali package)"

ok "Manual binary downloads done"

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — API PYTHON VENV + REQUIREMENTS
# ═══════════════════════════════════════════════════════════════════════════════
step "API Python venv + requirements.txt"

if [ ! -x "$VENV_DIR/bin/python" ]; then
  python3 -m venv "$VENV_DIR"
  ok "Created venv at $VENV_DIR"
else
  ok "Existing venv found"
fi

"$VENV_DIR/bin/pip" install --quiet --upgrade pip setuptools wheel
"$VENV_DIR/bin/pip" install --quiet -r "$API_DIR/requirements.txt"
ok "API Python dependencies installed"

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — NODE / FRONTEND DEPENDENCIES
# ═══════════════════════════════════════════════════════════════════════════════
step "Node.js frontend dependencies"

(cd "$ROOT_DIR"; [ -f "package-lock.json" ] && npm ci --silent || npm install --silent)
ok "Root node_modules ready ($(ls "$ROOT_DIR/node_modules" | wc -l | tr -d ' ') packages)"

(cd "$WEB_DIR"; [ -f "package-lock.json" ] && npm ci --silent || npm install --silent)
ok "Frontend node_modules ready"

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 10 — ENVIRONMENT FILES
# ═══════════════════════════════════════════════════════════════════════════════
step "Environment files"

gen_secret() { "$VENV_DIR/bin/python" -c 'import secrets; print(secrets.token_urlsafe(48))'; }

if [ ! -f "$API_DIR/.env" ]; then
  cp "$API_DIR/.env.example" "$API_DIR/.env"
  sed -i "s|^SECRET_KEY=.*|SECRET_KEY=$(gen_secret)|" "$API_DIR/.env"
  ok "Created apps/api/.env with generated SECRET_KEY"
else
  ok "apps/api/.env already exists (skipped)"
fi

if [ ! -f "$WEB_DIR/.env.local" ]; then
  cp "$WEB_DIR/.env.example" "$WEB_DIR/.env.local"
  ok "Created apps/web/.env.local"
else
  ok "apps/web/.env.local already exists (skipped)"
fi

if [ ! -f "$ROOT_DIR/.env" ] && [ -f "$ROOT_DIR/.env.docker.example" ]; then
  cp "$ROOT_DIR/.env.docker.example" "$ROOT_DIR/.env"
  sed -i "s|^SECRET_KEY=.*|SECRET_KEY=$(gen_secret)|" "$ROOT_DIR/.env"
  ok "Created .env (Docker Compose) with generated SECRET_KEY"
elif [ -f "$ROOT_DIR/.env" ]; then
  ok ".env (Docker Compose) already exists (skipped)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 11 — RUNTIME DIRECTORIES
# ═══════════════════════════════════════════════════════════════════════════════
step "Runtime directories"

mkdir -p "$LOG_DIR" "$ROOT_DIR/apps/web/.next" "$RUNTIME_DIR"
chmod 700 "$RUNTIME_DIR"
ok "Runtime directories ready"

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 12 — REDIS
# ═══════════════════════════════════════════════════════════════════════════════
step "Redis"

if ! pgrep -x redis-server &>/dev/null; then
  if command -v systemctl &>/dev/null && systemctl list-unit-files redis-server.service &>/dev/null 2>&1; then
    sudo systemctl enable redis-server 2>/dev/null || true
    sudo systemctl start redis-server
    ok "Redis started via systemctl"
  else
    redis-server --daemonize yes --logfile "$LOG_DIR/redis.log" --port 6379 --save "" --appendonly no
    ok "Redis started as daemon"
  fi
else
  ok "Redis already running"
fi

redis-cli ping 2>/dev/null | grep -q PONG && ok "Redis responding on localhost:6379" || \
  warn "Redis not responding — check $LOG_DIR/redis.log"

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 13 — DATABASE SCHEMA
# ═══════════════════════════════════════════════════════════════════════════════
step "Database schema (alembic upgrade head)"

(
  cd "$API_DIR"
  export PYTHONPATH="$API_DIR/src"
  export DATABASE_URL="sqlite+aiosqlite:///$API_DIR/adbygod.db"
  export SECRET_KEY="$(gen_secret)"
  "$VENV_DIR/bin/alembic" upgrade head 2>&1 | tail -5
)
ok "Database schema up to date"

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 14 — PERSIST PATH IN SHELL RCS
# ═══════════════════════════════════════════════════════════════════════════════
step "Persisting PATH in shell configs"

add_to_rc() {
  local line="$1"
  for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [ -f "$rc" ] || continue
    grep -qF "$line" "$rc" 2>/dev/null || echo "$line" >> "$rc"
  done
}

add_to_rc "export GOPATH=\"\$HOME/go\""
add_to_rc "export PATH=\"\$HOME/.local/bin:\$HOME/go/bin:\$PATH\""
add_to_rc "[ -s \"$NVM_DIR/nvm.sh\" ] && \\. \"$NVM_DIR/nvm.sh\""

ok "Shell rc files updated"

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 15 — VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════
step "Verification"

# chk: ok if command succeeds, warn if not
chk() {
  local label="$1"; shift
  if "$@" &>/dev/null 2>&1; then
    ok "$label"
  else
    warn "MISSING: $label"
  fi
}

printf '\n  %s── Core platform ──────────────────────────────────────%s\n' "$DIM" "$RESET"
chk "python3 venv"            "$VENV_DIR/bin/python" --version
chk "uvicorn"                 "$VENV_DIR/bin/uvicorn" --version
chk "alembic"                 "$VENV_DIR/bin/alembic" --version
chk "fastapi importable"      "$VENV_DIR/bin/python" -c "import fastapi"
chk "sqlalchemy importable"   "$VENV_DIR/bin/python" -c "import sqlalchemy"
chk "celery importable"       "$VENV_DIR/bin/python" -c "import celery"
chk "redis-cli"               redis-cli ping
chk "next binary"             test -x "$ROOT_DIR/node_modules/.bin/next"
chk "apps/api/.env"           test -f "$API_DIR/.env"
chk "apps/web/.env.local"     test -f "$WEB_DIR/.env.local"

printf '\n  %s── Network recon ──────────────────────────────────────%s\n' "$DIM" "$RESET"
chk "nmap"                    nmap --version
chk "masscan"                 test -f /usr/bin/masscan
chk "gobuster"                test -f /usr/bin/gobuster
chk "ffuf"                    ffuf -V
chk "feroxbuster"             feroxbuster --version
chk "nuclei"                  nuclei -version
chk "subfinder"               subfinder -version
chk "naabu"                   naabu -version
chk "httpx"                   httpx -version
chk "dnsx"                    dnsx -version
chk "amass"                   amass -version
chk "chisel"                  chisel --help

printf '\n  %s── AD / LDAP / Kerberos ───────────────────────────────%s\n' "$DIM" "$RESET"
chk "ldap3 importable"        "$VENV_DIR/bin/python" -c "import ldap3"
chk "impacket importable"     "$VENV_DIR/bin/python" -c "import impacket"
chk "impacket-secretsdump"    impacket-secretsdump --help
chk "certipy"                 certipy --help
chk "bloodhound-python"       bloodhound-python --help
chk "ldapdomaindump"          ldapdomaindump --help
chk "enum4linux-ng"           enum4linux-ng --help
chk "smbmap"                  smbmap --help
chk "smbclient"               smbclient --version
chk "kerbrute"                test -f /usr/local/bin/kerbrute
chk "bloodyAD"                bloodyAD --help
chk "nxc (netexec)"           bash -c 'nxc 2>&1 | grep -q version || nxc --help 2>&1 | head -1 | grep -q nxc'
chk "crackmapexec"            bash -c 'crackmapexec 2>&1 | grep -qiE "crackmapexec|usage"'

printf '\n  %s── NTLM / relay / coercion ───────────────────────────%s\n' "$DIM" "$RESET"
chk "coercer"                 coercer --help
chk "mitm6"                   mitm6 --help
chk "responder"               responder --help
chk "krbrelayx (git-clone)"   test -d "$TOOLS_DIR/krbrelayx"

printf '\n  %s── Password / credential attacks ─────────────────────%s\n' "$DIM" "$RESET"
chk "hashcat"                 hashcat --version
chk "john"                    john
chk "hydra"                   bash -c 'hydra 2>&1 | grep -q Hydra'
chk "medusa"                  medusa -V
chk "hashid"                  hashid --help
chk "pypykatz"                bash -c 'pypykatz 2>&1 | grep -qiE "pypykatz|usage"'
chk "lsassy"                  lsassy --help
chk "donpapi"                 donpapi --help

printf '\n  %s── Tunneling / lateral movement ──────────────────────%s\n' "$DIM" "$RESET"
chk "chisel"                  chisel --help
chk "ligolo-ng (proxy)"       test -f "$GOPATH/bin/ligolo-ng"
chk "proxychains4"            test -f /usr/bin/proxychains4
chk "socat"                   socat -V
chk "pspy"                    test -f "$HOME/.local/bin/pspy"
chk "frpc"                    test -f "$HOME/.local/bin/frpc"
chk "evil-winrm"              evil-winrm --version

printf '\n  %s── C2 / exploit frameworks ───────────────────────────%s\n' "$DIM" "$RESET"
chk "metasploit"              msfconsole --version
chk "sqlmap"                  sqlmap --version
chk "sliver-server"           sliver-server --help
chk "empire (apt)"            test -d /usr/share/powershell-empire
chk "pwncat-cs"               bash -c 'pwncat-cs 2>&1 | grep -qiE "pwncat|usage|error" || test -f "$(command -v pwncat-cs)"'

printf '\n  %s── Evasion / payload crafting ────────────────────────%s\n' "$DIM" "$RESET"
chk "volatility3 (vol)"       vol --help
chk "checksec"                checksec --help
chk "ROPgadget"               ROPgadget --help
chk "nim"                     nim --version
chk "upx"                     upx --version
chk "wine"                    wine --version

printf '\n  %s── Misc utilities ─────────────────────────────────────%s\n' "$DIM" "$RESET"
chk "git"                     git --version
chk "go"                      go version
chk "jq"                      jq --version
chk "tmux"                    tmux -V
chk "curl"                    curl --version
chk "spray"                   test -f "$HOME/.local/bin/spray"
chk "username-anarchy"        test -L "$HOME/.local/bin/username-anarchy"
chk "DFSCoerce (cloned)"      test -d "$TOOLS_DIR/DFSCoerce"
chk "PetitPotam (cloned)"     test -d "$TOOLS_DIR/PetitPotam"

# ═══════════════════════════════════════════════════════════════════════════════
# DONE
# ═══════════════════════════════════════════════════════════════════════════════
printf '\n%s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$CYAN" "$BOLD" "$RESET"
printf '%s  AdByG0d install complete!%s\n' "$BOLD" "$RESET"
printf '\n'
printf '  Checks:  %s%d passed%s   %s%d warnings%s\n' \
  "$GREEN" "$PASS" "$RESET" "$YELLOW" "$WARN" "$RESET"
printf '\n'
printf '  Start dev server:  %s./start.sh%s\n'         "$BOLD" "$RESET"
printf '  Or with Docker:    %sdocker compose up%s\n'   "$BOLD" "$RESET"
printf '\n'
printf '  API  →  http://localhost:8000\n'
printf '  Web  →  http://localhost:3000\n'
printf '\n'
printf '  Edit before starting:\n'
printf '    %sapps/api/.env%s      ← add ANTHROPIC_API_KEY, tune settings\n' "$BOLD" "$RESET"
printf '    %sapps/web/.env.local%s\n'                                         "$BOLD" "$RESET"
printf '\n'
printf '  Git-cloned tools:  %s%s%s\n' "$DIM" "$TOOLS_DIR" "$RESET"
printf '  Manual binaries:   %s~/.local/bin/%s\n' "$DIM" "$RESET"
printf '  Go binaries:       %s~/go/bin/%s\n' "$DIM" "$RESET"
printf '\n'
printf '  %sReload your shell or run:%s source ~/.bashrc\n' "$YELLOW" "$RESET"
printf '%s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n\n' "$CYAN" "$BOLD" "$RESET"
