# vm-panel

Painel web minúsculo, servido pela própria VM, que lista os sockets TCP em
estado `LISTEN` no host (porta, endereço, processo, PID), associa cada porta
publicada ao container Docker dono e oferece um link "Abrir" para cada serviço.

Tudo é descoberto dinamicamente a cada requisição: nenhuma lista de portas, IP
ou container é configurada no código. O endpoint `/api/ports` é recalculado na
hora e o front atualiza a cada 5 s. Serviço novo (processo ou container) aparece
sozinho, sem reiniciar nem editar nada.

## Como funciona

- O container roda com `network_mode: host` e `pid: host`, então `/proc` é o
  `/proc` do host. A varredura lê `/proc/net/tcp` e `/proc/net/tcp6` (só estados
  `LISTEN`) e resolve inode→PID via `/proc/<pid>/fd`.
- São reportados **todos** os sockets em `LISTEN`, inclusive os que fazem bind
  num IP específico (ex.: o IP do tailnet). `exposed` é `true` para wildcard
  (`0.0.0.0` / `::`) e para qualquer endereço que não seja loopback, e `false`
  apenas para `127.0.0.1` / `::1`. O campo `address` traz o endereço real de
  bind; nenhum IP do host é escrito no código — a URL do link é montada no
  navegador com `location.hostname`, então o mesmo painel funciona pelo IP do
  tailnet ou pelo IP da LAN.
- Sockets de uma mesma porta em IPv4 e IPv6 aparecem como duas linhas (são dois
  sockets distintos do kernel).
- O Docker é consultado diretamente no socket unix com `http.client` sobre um
  socket `AF_UNIX`, em `/v1.41/containers/json?all=1`. A porta publicada de cada
  container é ligada à porta escutada no host (`docker-proxy`); portas só
  internas aparecem apenas no cartão do container, marcadas como "(interna)".
- Só biblioteca padrão do Python 3.12 (`http.server`, `json`, `socket`,
  `http.client`, `glob`, `os`, `signal`, `urllib.parse`). Sem pip, sem
  dependências, sem build.
- `cap_add: [SYS_PTRACE]` é necessário para ler `/proc/<pid>/fd` de outros
  processos com `ptrace_scope=1` (padrão desta VM).

## Endpoints

- `GET /` → `app/index.html` (`text/html; charset=utf-8`).
- `GET /api/ports` → JSON com `generated_at`, `host`, `items` (ordenado por
  porta) e `containers`. `Cache-Control: no-store`.
- Qualquer outra rota → `404` JSON; erros internos → `500` JSON.

## Subir / operar

```sh
cd /home/nemo/deploy/vm-panel
docker compose up -d          # `restart: unless-stopped` sobrevive a reboot
docker compose logs -f        # logs do servidor
docker compose restart        # recarrega app/server.py e app/index.html
```

`app/` é montado read-only em `/app`: editar os arquivos no host e rodar
`docker compose restart` é suficiente — não há imagem para reconstruir.

Acesse `http://<ip-do-host>:8090/` (tailnet: `http://100.92.181.21:8090/`).
