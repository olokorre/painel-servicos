# painel-servicos

Painel web mínimo que descobre e lista todas as portas TCP em estado `LISTEN`
no host (porta, endereço, processo, PID, container), sem nenhuma configuração
de portas ou IPs. Cada requisição ao endpoint `/api/ports` recalcula o
inventário dinamicamente; o front-end atualiza a cada 5 segundos.

Serviço novo (processo ou container) aparece sozinho, sem reiniciar nem editar
nada. Pode rodar nativo no host (via systemd) ou em container Docker com
`network_mode: host` e `pid: host`.

## Requisitos

- Linux com `/proc` montado (leitura de `/proc/net/tcp`, `/proc/net/tcp6`,
  `/proc/<pid>/fd`, `/proc/<pid>/comm`, `/proc/<pid>/cmdline`).
- **Não funciona** em Docker Desktop, macOS ou Windows (não há `/proc` real do
  host nem sockets `AF_UNIX` do Docker).
- Python 3.9+ (biblioteca padrão — sem pip, sem dependências).
- Docker (opcional): necessário apenas para listar containers e atribuir portas
  publicadas. Sem Docker, o painel mostra todas as portas com `container: null`.
- `CAP_SYS_PTRACE` **e** `CAP_DAC_READ_SEARCH`: para listar porta, processo e
  PID de serviços que rodam com **outro usuário (ex.: root)**. O motivo: o
  diretório `/proc/<pid>/fd` pertence ao dono do processo com modo `dr-x------`,
  e `CAP_SYS_PTRACE` não concede a permissão de leitura/busca desse diretório
  (necessário burlar a DAC). A unit systemd já traz as duas; no caminho
  container, `cap_add: SYS_PTRACE` cobre o container. Sem elas, o painel lista
  a porta mas mostra `process: null` / `pids: []`.

## Instalação

### 1. Nativo com systemd (recomendado)

```sh
sudo scripts/install.sh              # instala com defaults
sudo scripts/install.sh --port 8080  # porta customizada na primeira instalacao
sudo scripts/install.sh --no-start   # instala sem habilitar/iniciar
sudo scripts/install.sh --uninstall  # remove (preserva /etc/painel-servicos)
```

O instalador:
1. Cria o usuário de sistema `painel`.
2. Copia `app/` para `/opt/painel-servicos/app`.
3. Cria `/etc/painel-servicos/env` a partir do `.env.example` (se não existir).
4. Instala a unit systemd, roda `daemon-reload` e `enable --now`.

Edite `/etc/painel-servicos/env` para ajustar porta, bind, senha, etc., e rode
`sudo systemctl restart painel-servicos`.

### 2. Docker Compose (containerizado)

```sh
cp .env.example .env   # edite se quiser
docker compose up -d
```

O container precisa de `network_mode: host`, `pid: host` e `cap_add: SYS_PTRACE`
para enxergar `/proc` e sockets do host. O código-fonte em `app/` é montado
read-only — editar no host e reiniciar o container é suficiente.

## Variáveis de ambiente

| Variável | Default | Descrição |
|---|---|---|
| `PANEL_PORT` | `8090` | Porta HTTP do painel |
| `PANEL_BIND` | `0.0.0.0` | Endereço de bind do servidor |
| `DOCKER_SOCKET` | `/var/run/docker.sock` | Socket Unix do Docker |
| `PANEL_USER` | `admin` | Usuário do HTTP Basic Auth |
| `PANEL_PASSWORD` | *(vazio)* | Senha do HTTP Basic Auth. Vazio = sem autenticação |
| `PANEL_HTTPS_PORTS` | `443,8443,9443` | Portas que recebem scheme `https` (separadas por vírgula) |

Todas as variáveis têm leitura tolerante: valor ausente, vazio ou inválido cai
no default (nunca `ValueError` na subida).

## Endpoints

| Rota | Método | Autenticação | Descrição |
|---|---|---|---|
| `/healthz` | GET | **Não** | `{"status":"ok","host":<hostname>}` — usado por healthcheck do systemd |
| `/` | GET | Sim\* | `index.html` (front-end) — `text/html; charset=utf-8` |
| `/api/ports` | GET | Sim\* | JSON com `generated_at`, `host`, `items[]`, `containers[]` |

\* Exceto quando `PANEL_PASSWORD` está vazio (sem autenticação).

Todas as respostas levam `Cache-Control: no-store`.

### Payload de `/api/ports`

- `items[]`: `port`, `proto` (`"tcp"`), `family` (`"ipv4"`/`"ipv6"`),
  `address`, `exposed` (bool), `scheme` (`"http"`/`"https"`), `process`,
  `pids[]`, `cmdline`, `container` (nome ou `null`).
- `containers[]`: `name`, `image`, `state`, `status`, `id`, `ports[{private,
  public, type}]`.

Itens ordenados por porta. `exposed` é `false` apenas para `127.0.0.1`/`::1`.

## Segurança

**Expor o painel sem senha (`PANEL_PASSWORD` vazio) publica um inventário
completo de portas, processos, linhas de comando e containers do host.** Isso
inclui PIDs, argumentos de linha de comando (que podem conter senhas em
variáveis de ambiente na cmdline) e nomes de containers.

Recomendações:
- **Proxy reverso**: mantenha `PANEL_BIND=127.0.0.1`, coloque um proxy reverso
  (nginx, Caddy) na frente com TLS e autenticação própria.
- **Senha forte**: defina `PANEL_PASSWORD` com uma senha complexa e restrinja
  o acesso por firewall (iptables, nftables, ufw).
- A autenticação usa HTTP Basic sobre conexão plain-text se exposta direto sem
  TLS — o hash via `hmac.compare_digest` protege contra timing attack, mas a
  senha viaja em Base64. Use sempre TLS quando exposto na rede.

## Limitações

- **Só TCP**: o painel lê apenas `/proc/net/tcp` e `/proc/net/tcp6` (estado
  `LISTEN`). Portas UDP não são descobertas.
- **`hidepid=2`**: Se `/proc` está montado com `hidepid=2`, processos de
  outros usuários ficam invisíveis (PIDs, `comm`, `cmdline`). O painel precisa
  de `CAP_SYS_PTRACE` ou que o usuário `painel` tenha visão dos processos.
- **Containers em rede host**: containers com `network_mode: host` não têm
  porta publicada no Docker. A atribuição ao container é feita por fallback
  via cgroup (`/proc/<pid>/cgroup`), o que resolve containers cujo PID seja
  visível.

## Operação

```sh
systemctl status painel-servicos       # status do servico
systemctl restart painel-servicos      # reinicia (recarrega config + codigo)
journalctl -u painel-servicos -f       # logs em tempo real
```

### Logs

O servidor não loga requisições individuais por padrão (`log_message` é
silenciado). Use `journalctl` para ver mensagens de boot, aviso de
autenticação desligada e erros não recuperáveis.

### Drop-in para ver todos os processos

Se você não quer conceder `CAP_DAC_READ_SEARCH` (ou se em algum ambiente ela
não bastar), uma alternativa é rodar o serviço como root. Crie o diretório e o
arquivo:

```ini
# /etc/systemd/system/painel-servicos.service.d/root.conf
[Service]
User=root
Group=root
```

Depois `systemctl daemon-reload && systemctl restart painel-servicos`.
Isso dá ao painel privilégio total de leitura de `/proc`.