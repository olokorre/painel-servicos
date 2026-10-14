#!/usr/bin/env sh
# Instalador idempotente do painel-servicos (execucao nativa via systemd).
# Uso: scripts/install.sh [--port N] [--bind ADDR] [--no-start] [--uninstall]
# Compativel com dash e bash. Requer root.
set -eu

# Onde este script esta dentro do repo (scripts/install.sh -> repo = pai de scripts/)
SELF=$(dirname "$0")
REPO="$SELF/.."
REPO=$(realpath "$REPO")

# Valida que o repositorio foi resolvido corretamente.
if [ ! -f "$REPO/app/server.py" ] || \
   [ ! -f "$REPO/deploy/painel-servicos.service" ] || \
   [ ! -f "$REPO/.env.example" ]; then
    echo "erro: rode o instalador de dentro do repositorio (scripts/install.sh)" >&2
    exit 1
fi

APP_SRC="$REPO/app"
UNIT_SRC="$REPO/deploy/painel-servicos.service"
ENV_EXAMPLE="$REPO/.env.example"

INSTALL_DIR=/opt/painel-servicos
ENV_DIR=/etc/painel-servicos
ENV_FILE="$ENV_DIR/env"
UNIT=/etc/systemd/system/painel-servicos.service

PORT=""
BIND=""
NO_START=0
UNINSTALL=0

# ---- parse de argumentos ----
while [ "$#" -gt 0 ]; do
    case "$1" in
        --no-start)
            NO_START=1
            shift
            ;;
        --uninstall)
            UNINSTALL=1
            shift
            ;;
        --port)
            if [ "$#" -lt 2 ]; then
                echo "erro: --port precisa de um numero de porta" >&2
                exit 1
            fi
            if case "$2" in *[!0-9]*) true ;; *) false ;; esac; then
                echo "erro: --port precisa ser um numero inteiro" >&2
                exit 1
            fi
            PORT="$2"
            shift 2
            ;;
        --bind)
            if [ "$#" -lt 2 ]; then
                echo "erro: --bind precisa de um endereco" >&2
                exit 1
            fi
            BIND="$2"
            shift 2
            ;;
        *)
            echo "argumento desconhecido: $1" >&2
            exit 1
            ;;
    esac
done

if [ "$(id -u)" != "0" ]; then
    echo "erro: instale como root (sudo scripts/install.sh)" >&2
    exit 1
fi

# ---- desinstalar ----
if [ "$UNINSTALL" = "1" ]; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop painel-servicos 2>/dev/null || true
        systemctl disable painel-servicos 2>/dev/null || true
    fi
    rm -f "$UNIT"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
    fi
    rm -rf "$INSTALL_DIR"
    echo "Desinstalado. /opt/painel-servicos e a unit foram removidos."
    echo "A configuracao em $ENV_DIR foi preservada."
    exit 0
fi

# ---- exige systemd ----
if ! command -v systemctl >/dev/null 2>&1; then
    echo "aviso: systemd nao detectado neste host." >&2
    echo "Use o caminho containerizado em vez disso:" >&2
    echo "  cd $REPO && docker compose up -d" >&2
    exit 0
fi

# ---- usuario de sistema painel ----
if ! id painel >/dev/null 2>&1; then
    if command -v useradd >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin painel
    else
        adduser -S painel
    fi
    echo "usuario de sistema 'painel' criado."
fi

# ---- copia do app (somente leitura) ----
mkdir -p "$INSTALL_DIR"
rm -rf "$INSTALL_DIR/app"
cp -r "$APP_SRC" "$INSTALL_DIR/app"
chown -R root:root "$INSTALL_DIR/app"
chmod -R a+rX "$INSTALL_DIR/app"
rm -rf "$INSTALL_DIR/app/__pycache__"

# ---- diretorio de cache ----
mkdir -p /var/cache/painel-servicos
chown painel:painel /var/cache/painel-servicos
chmod 0755 /var/cache/painel-servicos

# ---- /etc/painel-servicos/env ----
mkdir -p "$ENV_DIR"
chmod 700 "$ENV_DIR"
if [ ! -f "$ENV_FILE" ]; then
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    if [ -n "$PORT" ]; then
        sed -i "s/^PANEL_PORT=.*/PANEL_PORT=$PORT/" "$ENV_FILE"
    fi
    if [ -n "$BIND" ]; then
        sed -i "s/^PANEL_BIND=.*/PANEL_BIND=$BIND/" "$ENV_FILE"
    fi
    chown root:root "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    sed -i 's|^PANEL_CACHE_FILE=|PANEL_CACHE_FILE=/var/cache/painel-servicos/cache.json|' "$ENV_FILE"
    echo "/etc/painel-servicos/env criado a partir do .env.example."
    # aviso de exposicao sem senha na primeira instalacao
    EFFECTIVE_BIND="${BIND:-0.0.0.0}"
    if [ "${EFFECTIVE_BIND}" = "0.0.0.0" ] && \
       grep -q '^PANEL_PASSWORD=$' "$ENV_FILE" 2>/dev/null; then
        echo "aviso: painel exposto em todas as interfaces e SEM senha (PANEL_PASSWORD vazio em $ENV_FILE); qualquer" >&2
        echo "um que alcance a porta vera portas, processos e linhas de comando do host." >&2
    fi
else
    echo "/etc/painel-servicos/env ja existe: nao sobrescrito."
    if [ -n "$PORT" ] || [ -n "$BIND" ]; then
        echo "aviso: --port/--bind ignorados (configuracao existente preservada)." >&2
    fi
fi

# ---- unit systemd ----
cp "$UNIT_SRC" "$UNIT"
chown root:root "$UNIT"
chmod 644 "$UNIT"
systemctl daemon-reload

# ---- detecta interpretador python3 ----
PYTHON=$(command -v python3 || true)
if [ -z "$PYTHON" ]; then
    echo "erro: python3 nao encontrado no PATH. Instale python3 ou use docker compose." >&2
    exit 1
fi
if [ "$PYTHON" != "/usr/bin/python3" ]; then
    sed -i "s|ExecStart=/usr/bin/python3|ExecStart=$PYTHON|" "$UNIT"
    echo "caminho do python3 ajustado para $PYTHON na unit."
fi

if [ "$NO_START" = "1" ]; then
    echo "Unit instalada. Inicialize manualmente com:"
    echo "  systemctl enable --now painel-servicos"
else
    systemctl enable --now painel-servicos
    echo "painel-servicos habilitado e iniciado."
fi

# ---- determina porta efetiva ----
EFFECTIVE_PORT="$PORT"
if [ -z "$EFFECTIVE_PORT" ]; then
    EFFECTIVE_PORT=$(sed -n 's/^PANEL_PORT=//p' "$ENV_FILE" 2>/dev/null | tail -n 1)
fi
[ -z "$EFFECTIVE_PORT" ] && EFFECTIVE_PORT=8090

# ---- dica de firewall (firewalld) ----
if command -v firewall-cmd >/dev/null 2>&1; then
    if firewall-cmd --state 2>/dev/null | grep -q running; then
        echo ""
        echo "Libere a porta no firewall se necessario:"
        echo "  firewall-cmd --permanent --add-port=$EFFECTIVE_PORT/tcp"
        echo "  firewall-cmd --reload"
    fi
fi

# ---- URL de acesso ----
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP=$(hostname)

echo ""
echo "Instalacao concluida."
echo "  Acesse: http://$IP:$EFFECTIVE_PORT/"
echo ""
echo "Para definir a senha (autenticacao Basic), edite"
echo "  $ENV_FILE"
echo "definindo PANEL_PASSWORD, depois rode:"
echo "  systemctl restart painel-servicos"
