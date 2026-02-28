FROM kalilinux/kali-rolling:latest

LABEL description="AIRecon Sandbox — Kali Linux with recon tools"
LABEL maintainer="pikpikcu"

# ── System packages + core tools ──
RUN apt-get update && \
    apt-get install -y kali-archive-keyring sudo && \
    apt-get update && \
    apt-get upgrade -y

# Create pentester user
RUN useradd -m -s /bin/bash pentester && \
    usermod -aG sudo pentester && \
    echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    touch /home/pentester/.hushlogin

# Workspace directories
RUN mkdir -p /workspace/output /workspace/tools /workspace/vulnerabilities && \
    chown -R pentester:pentester /workspace

# ── Install all tools in one layer to minimize image size ──
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    # Build essentials
    sudo wget curl git vim nano unzip tar \
    build-essential ca-certificates gnupg \
    gcc libc6-dev pkg-config libpcap-dev libssl-dev \
    # Languages & Ecosystems
    python3 python3-pip python3-dev python3-venv python3-setuptools \
    golang-go nodejs npm pipx \
    # OS Libraries for headless tools (Puppeteer/Playwright/Caido)
    libnss3 libnspr4 libdbus-1-3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libatspi2.0-0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libxkbcommon0 \
    libpango-1.0-0 libcairo2 libasound2t64 fonts-unifont fonts-noto-color-emoji \
    fonts-freefont-ttf fonts-dejavu-core ttf-bitstream-vera libnss3-tools \
    # Networking
    net-tools dnsutils whois iproute2 iputils-ping netcat-traditional \
    # Active Directory / SMB / Pivoting / Exploitation
    responder smbclient impacket-scripts commix enum4linux \
    # Recon tools (from Kali repos)
    nmap ncat masscan subfinder naabu nuclei sqlmap ffuf feroxbuster \
    dnsrecon dnsenum whois nikto wpscan whatweb \
    joomscan hydra medusa hashcat john exploitdb \
    wafw00f zaproxy sublist3r massdns seclists \
    # Utilities
    jq parallel ripgrep grep less procps \
    libcap2-bin tmux \
    # Headless Browser Automation
    chromium \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Allow nmap raw sockets
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)

# Add Caido Auto-Setup Script
COPY caido-setup /usr/local/bin/caido-setup
RUN chmod +x /usr/local/bin/caido-setup

# ── Self-Signed Root CA Generation for intercepting proxies ──
RUN mkdir -p /home/pentester/certs && \
    openssl ecparam -name prime256v1 -genkey -noout -out /home/pentester/certs/ca.key && \
    openssl req -x509 -new -key /home/pentester/certs/ca.key \
    -out /home/pentester/certs/ca.crt \
    -days 3650 \
    -subj "/C=US/ST=CA/O=Security Testing/CN=Testing Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign" && \
    openssl pkcs12 -export \
    -out /home/pentester/certs/ca.p12 \
    -inkey /home/pentester/certs/ca.key \
    -in /home/pentester/certs/ca.crt \
    -passout pass:"" \
    -name "Testing Root CA" && \
    chmod 644 /home/pentester/certs/ca.crt && \
    chmod 600 /home/pentester/certs/ca.key && \
    chmod 600 /home/pentester/certs/ca.p12 && \
    chown -R pentester:pentester /home/pentester/certs

RUN cp /home/pentester/certs/ca.crt /usr/local/share/ca-certificates/ca.crt && \
    update-ca-certificates

# ── Go tools (latest from source) ──
USER pentester
WORKDIR /tmp

RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/notify/cmd/notify@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest && \
    go install -v github.com/projectdiscovery/cvemap/cmd/vulnx@latest && \
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest && \
    go install -v github.com/assetnote/kiterunner@latest && \
    go install -v github.com/nicocha30/ligolo-ng/cmd/proxy@latest && \
    go install -v github.com/jpillora/chisel@latest && \
    go install -v github.com/jaeles-project/gospider@latest && \
    go install -v github.com/tomnomnom/gau@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/tomnomnom/httprobe@latest && \
    go install -v github.com/tomnomnom/meg@latest && \
    go install -v github.com/tomnomnom/gf@latest && \
    go install -v github.com/lc/gau@latest 2>/dev/null || true && \
    go install -v github.com/hahwul/dalfox/v2@latest && \
    go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest && \
    go install -v github.com/edoardottt/csprecon/cmd/csprecon@latest && \
    go install -v github.com/hakluke/hakip2host@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null || true && \
    go install -v github.com/byt3hx/jsleak@latest && \
    go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest && \
    go install -v github.com/mlcsec/headi@latest && \
    go install -v github.com/Charlie-belmer/nosqli@latest && \
    go install -v github.com/xhzeem/toxicache@latest && \
    go install -v github.com/zricethezav/gitleaks/v8@latest && \
    go install -v github.com/ImAyrix/cut-cdn@latest && \
    go install -v github.com/ffuf/ffuf@latest

# ── Copy Go binaries to /usr/local/bin so they are always in default PATH ──
# Ollama subprocess calls (which/command -v) don't always inherit custom PATH
USER root
RUN cp -n /home/pentester/go/bin/* /usr/local/bin/ 2>/dev/null || true

# ── Rust tools (pre-compiled binaries, optional — build continues if download fails) ──
RUN (curl -fsL "https://github.com/Sh1Yo/x8/releases/latest/download/x8-linux.tar.gz" -o x8.tar.gz && \
    tar -xzf x8.tar.gz && chmod +x x8 && mv x8 /usr/local/bin/ && rm -f x8.tar.gz) || \
    (curl -fsL "https://github.com/Sh1Yo/x8/releases/latest/download/x86_64-unknown-linux-musl.tar.gz" -o x8.tar.gz && \
    tar -xzf x8.tar.gz && chmod +x x8 && mv x8 /usr/local/bin/ && rm -f x8.tar.gz) || \
    echo "[WARN] x8 installation skipped (release asset not found)"
RUN (curl -fsL "https://gitlab.com/api/v4/projects/33695681/packages/generic/nrich/latest/nrich_latest_x86_64-unknown-linux-musl.tar.gz" -o nrich.tar.gz && \
    tar -xzf nrich.tar.gz && chmod +x nrich && mv nrich /usr/local/bin/ && rm -f nrich.tar.gz) || \
    echo "[WARN] nrich installation skipped (release asset not found)"

# ── Amass v3.23.3 (pinned — v4+ changed CLI, -o flag broken) ──
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then AMASS_ARCH="amd64"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then AMASS_ARCH="arm64"; \
    else AMASS_ARCH=""; fi && \
    if [ -n "$AMASS_ARCH" ]; then \
    wget -qO /tmp/amass.zip "https://github.com/owasp-amass/amass/releases/download/v3.23.3/amass_Linux_${AMASS_ARCH}.zip" && \
    cd /tmp && unzip -q amass.zip && \
    find /tmp/amass_Linux_${AMASS_ARCH} -name "amass" -type f | head -1 | xargs -I{} mv {} /usr/local/bin/amass && \
    chmod +x /usr/local/bin/amass && \
    rm -rf /tmp/amass.zip /tmp/amass_Linux_${AMASS_ARCH}; \
    else echo "[WARN] amass v3.23.3: unsupported arch $ARCH, skipped"; fi

# Update nuclei templates
USER pentester
RUN nuclei -update-templates 2>/dev/null || true

# ── Python tools ──
RUN pipx install arjun && \
    pipx install dirsearch && \
    pipx inject dirsearch setuptools && \
    pipx install wafw00f && \
    pipx install wapiti3 2>/dev/null || true && \
    pipx install semgrep && \
    pipx install bandit && \
    pipx install shodan && \
    pipx install git+https://github.com/xnl-h4ck3r/waymore.git && \
    pipx install inql && \
    pipx install git-dumper && \
    pipx install s3scanner && \
    pipx install festin && \
    pipx install git+https://github.com/r0oth3x49/ghauri.git && \
    pipx install pacu && \
    pipx install scoutsuite && \
    pipx install git+https://github.com/Pennyw0rth/NetExec.git && \
    pipx install git+https://github.com/initstring/cloud_enum.git

# ── Node.js Tools & Linters ──
ENV NPM_CONFIG_PREFIX=/home/pentester/.npm-global
RUN mkdir -p /home/pentester/.npm-global && \
    npm install -g retire@latest && \
    npm install -g eslint@latest && \
    npm install -g js-beautify@latest && \
    npm install -g jshint && \
    npm install -g wappalyzer && \
    npm install -g jwt-cracker

# ── Symlink pipx and npm binaries to /usr/local/bin ──
# pipx stores symlinks (not regular files) in .local/bin — must use -type l
# npm may store either files or symlinks — cover both
USER root
RUN find /home/pentester/.local/bin -maxdepth 1 \( -type f -o -type l \) -exec ln -sf {} /usr/local/bin/ \; 2>/dev/null || true && \
    find /home/pentester/.npm-global/bin -maxdepth 1 \( -type f -o -type l \) -exec ln -sf {} /usr/local/bin/ \; 2>/dev/null || true
USER pentester

# ── Additional tools from git ──
WORKDIR /home/pentester/tools
RUN git clone https://github.com/aravind0x7/JS-Snooper.git 2>/dev/null || true && \
    chmod +x JS-Snooper/js_snooper.sh 2>/dev/null || true && \
    git clone https://github.com/xchopath/jsniper.sh.git 2>/dev/null || true && \
    chmod +x jsniper.sh/jsniper.sh 2>/dev/null || true && \
    git clone --depth=1 https://github.com/ticarpi/jwt_tool.git 2>/dev/null || true && \
    chmod +x jwt_tool/jwt_tool.py 2>/dev/null || true && \
    git clone --depth=1 https://github.com/s0md3v/Corsy.git 2>/dev/null || true && \
    git clone --depth=1 https://github.com/drwetter/testssl.sh.git 2>/dev/null || true && \
    git clone --depth=1 https://github.com/maurosoria/dirsearch.git 2>/dev/null || true && \
    git clone --depth=1 https://github.com/1ndianl33t/Gf-Patterns 2>/dev/null || true && \
    mkdir -p /home/pentester/.gf && cp Gf-Patterns/*.json /home/pentester/.gf/ 2>/dev/null || true && \
    git clone https://github.com/GerbenJavado/LinkFinder.git 2>/dev/null || true && \
    cd LinkFinder && /opt/poetry/venv/bin/pip install -r requirements.txt 2>/dev/null || true && cd .. && \
    git clone https://github.com/zseano/JS-Scan.git 2>/dev/null || true && \
    git clone https://github.com/arbazkiraak/LinksDumper.git 2>/dev/null || true && \
    git clone https://github.com/kacakb/jsfinder.git 2>/dev/null || true && \
    git clone https://github.com/fuzzdb-project/fuzzdb.git /home/pentester/wordlists/fuzzdb 2>/dev/null || true && \
    git clone https://github.com/swisskyrepo/GraphQLmap.git 2>/dev/null || true && \
    git clone https://github.com/digininja/GitHunter.git 2>/dev/null || true && \
    git clone https://github.com/fransr/postMessage-tracker.git 2>/dev/null || true && \
    git clone https://github.com/kiranreddyrebel/PostMessage_Fuzz_Tool.git 2>/dev/null || true && \
    git clone https://github.com/PortSwigger/param-miner.git 2>/dev/null || true

# ── Symlink git tools to /usr/local/bin ──
# Rules:
#   1. Only symlink files that have a shebang (#!/) — skip utility modules like nmap.py
#   2. Never overwrite an existing file in /usr/local/bin (real system/go/pipx binaries take priority)
USER root
RUN find /home/pentester/tools -type f \( -name "*.sh" -o -name "*.py" \) -exec chmod +x {} \; 2>/dev/null || true && \
    find /home/pentester/tools -type f \( -name "*.sh" -o -name "*.py" \) -exec sh -c \
    'head -1 "$1" | grep -q "^#!" && name=$(basename "${1%.*}") && [ ! -e "/usr/local/bin/$name" ] && ln -sf "$1" "/usr/local/bin/$name"' \
    _ {} \; 2>/dev/null || true
USER pentester

# ── Trivy, Trufflehog & git-secrets ──
USER root
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null || true && \
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null || true && \
    git clone https://github.com/awslabs/git-secrets.git /tmp/git-secrets && \
    cd /tmp/git-secrets && make install && rm -rf /tmp/git-secrets

# ── Privilege Escalation Scripts ──
RUN wget -qO /usr/local/bin/linpeas.sh https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh && \
    chmod +x /usr/local/bin/linpeas.sh && \
    wget -qO /usr/local/bin/pspy64 https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 && \
    chmod +x /usr/local/bin/pspy64

# ── Caido CLI ──
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
    CAIDO_ARCH="x86_64"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
    CAIDO_ARCH="aarch64"; \
    fi && \
    if [ -n "$CAIDO_ARCH" ]; then \
    wget -qO caido-cli.tar.gz https://caido.download/releases/v0.48.0/caido-cli-v0.48.0-linux-${CAIDO_ARCH}.tar.gz && \
    tar -xzf caido-cli.tar.gz && \
    chmod +x caido-cli && \
    rm caido-cli.tar.gz && \
    mv caido-cli /usr/local/bin/; \
    fi

# ── Cleanup ──
RUN apt-get autoremove -y 2>/dev/null; \
    apt-get autoclean 2>/dev/null; \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# ── User shell profile — sets full PATH for login shells (bash --login -c) ──
# Uses printf to avoid heredoc which confuses some Dockerfile linters.
USER pentester
RUN printf '%s\n' \
    '# AIRecon sandbox environment' \
    'export GOPATH=/home/pentester/go' \
    'export GOROOT=/usr/local/go' \
    'export GEM_HOME=/home/pentester/.gem' \
    'export NPM_CONFIG_PREFIX=/home/pentester/.npm-global' \
    'export PIPX_HOME=/home/pentester/.local/pipx' \
    'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.cargo/bin:/home/pentester/.npm-global/bin:/home/pentester/.gem/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"' \
    'export LANG=C.UTF-8' \
    'export TERM=xterm-256color' \
    > /home/pentester/.bashrc && \
    echo 'source ~/.bashrc' > /home/pentester/.bash_profile

# ── Environment ──
ENV PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.cargo/bin:/home/pentester/.npm-global/bin:/home/pentester/.gem/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENV GOPATH=/home/pentester/go
ENV GOROOT=/usr/local/go
ENV GEM_HOME=/home/pentester/.gem
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

USER pentester
WORKDIR /workspace

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
USER root
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER pentester
ENTRYPOINT ["docker-entrypoint.sh"]
