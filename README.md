# painel-servicos

Painel web que descobre todas as portas TCP em estado `LISTEN` no host e as
organiza como um **hub indexador de serviços**. Na visão padrão (modo hub)
mostra apenas os serviços que **respondem em HTTP**, com título da página
e favicon (descobertos por sondagem em background via `127.0.0.1`). Um
alternador revela o **modo técnico** com a tabela completa de portas, processos,
PIDs, endereços e containers.

Tudo é descoberto dinamicamente: nenhuma lista de portas, IP ou container é
configurada no código. A sondagem HTTP é feita em background (thread daemon)
e o resultado fica em cache (memória e, opcionalmente, disco). O front-end
atualiza a cada 5 segundos. Serviço novo aparece sozinho, sem reiniciar nem
editar nada. Pode rodar nativo no host (via systemd) ou em container Docker
com `network_mode: host` e `pid: host`.

## Requisitos

- Linux com `/proc` montado (leitura de `/proc/net/tcp`, `/proc/net/tcp6`,
  `/proc/<pid>/fd`, `/proc/<pid>/comm`, `/proc/<pid>/cmdline`).
- **Não funciona** em Docker Desktop, macOS ou Windows (não há `/proc` real do
  host nem sockets `AF_UNIX` do Docker).
- Python 3.9+ (biblioteca padrão — sem pip, sem dependências).
- Docker (opcional): necessário apenas para listar containers e atribuir
  containers às portas (publicadas e rede host). Sem Docker, o painel mostra
  todas as portas com `container: null`.
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
| `PANEL_PROBE_INTERVAL` | `60` | Segundos entre ciclos de sondagem HTTP em background |
| `PANEL_PROBE_TTL` | `300` | Idade máxima (s) de um resultado para ser considerado fresco |
| `PANEL_PROBE_TIMEOUT` | `2.0` | Timeout (float) por requisição de sondagem individual |
| `PANEL_CACHE_FILE` | *(vazio)* | Arquivo de cache em disco (vazio = só memória; não sobrevive a reinício) |

Todas as variáveis têm leitura tolerante: valor ausente, vazio ou inválido cai
no default (nunca `ValueError` na subida).

## Endpoints

| Rota | Método | Autenticação | Descrição |
|---|---|---|---|
| `/healthz` | GET | **Não** | `{"status":"ok","host":<hostname>}` — usado por healthcheck do systemd |
| `/` | GET | Sim\* | `index.html` (front-end) — `text/html; charset=utf-8` |
| `/api/ports` | GET | Sim\* | JSON com `generated_at`, `host`, `items[]`, `containers[]` |
| `/api/icon?port=N` | GET | Sim\* | Favicon em cache do serviço da porta N (`image/*`) ou `404` |

\* Exceto quando `PANEL_PASSWORD` está vazio (sem autenticação).

Todas as respostas levam `Cache-Control: no-store`.

### Payload de `/api/ports`

- `items[]`: `port`, `proto` (`"tcp"`), `family` (`"ipv4"`/`"ipv6"`),
  `address`, `exposed` (bool), `scheme` (`"http"`/`"https"`), `process`,
  `pids[]`, `cmdline`, `container` (nome ou `null`), **`http`** — objeto
  com resultado da sondagem HTTP: `{ok: bool|null, status: int|null,
  title: str|null, server: str|null, has_icon: bool, checked_at: str|null}`.
  `ok=null` = ainda não sondado; `ok=false` = não responde HTTP;
  `ok=true` = respondeu, com `title` extraído da tag `<title>`.
- `containers[]`: `name`, `image`, `state`, `status`, `id`, `ports[{private,
  public, type}]`.

Itens ordenados por porta. `exposed` é `false` apenas para `127.0.0.1`/`::1`.
O icone de cada serviço é servido pelo próprio painel em `/api/icon?port=N`,
apenas para portas em cache que passaram na validação de bytes mágicos.

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

## Hub indexador de serviços

O painel sonda cada porta em background via `127.0.0.1` (sempre loopback:
a sondagem nunca sai do host). A cada ciclo as portas ausentes ou vencidas
(`PANEL_PROBE_TTL`) são sondadas com uma requisição HTTP `GET /`. Se o
serviço responde com HTML contendo `<title>`, o título é extraído e exibido
no cartão. O favicon é descoberto pelo `<link rel="icon">` da página,
baixado (max 256 KB) e servido pelo próprio painel em `/api/icon?port=N` —
apenas para portas em cache que passaram na validação de bytes mágicos
(ICO/PNG/GIF/SVG/WEBP). Se `PANEL_CACHE_FILE` for definido, o cache (com
títulos, ícones e status) sobrevive a reinícios do serviço.

## Limitações

- **Só TCP**: o painel lê apenas `/proc/net/tcp` e `/proc/net/tcp6` (estado
  `LISTEN`). Portas UDP não são descobertas.
- **`hidepid=2`**: Se `/proc` está montado com `hidepid=2`, processos de
  outros usuários ficam invisíveis (PIDs, `comm`, `cmdline`). O painel precisa
  de `CAP_SYS_PTRACE` ou que o usuário `painel` tenha visão dos processos.
- **Containers em rede host**: containers com `network_mode: host` não têm
  porta publicada no Docker. A atribuição é feita por consulta à API do Docker:
  para cada container em execução o painel lê `State.Pid` em
  `/containers/<id>/json` (PID no host, visível porque o painel roda com
  `pid: host`) e expande a subárvore de processos desse PID (`/proc/<pid>/task/
  <tid>/children`). O mapa de PIDs é recalculado no máximo uma vez a cada
  `PANEL_PROBE_INTERVAL` (não a cada requisição). O cgroup
  (`/proc/<pid>/cgroup`) continua como último fallback — útil na instalação
  nativa fora de container, onde o namespace de cgroup é o do host.

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