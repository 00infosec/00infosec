<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/00infosec/00infosec/main/assets/logo-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/00infosec/00infosec/main/assets/logo-light.png">
  <img src="https://raw.githubusercontent.com/00infosec/00infosec/main/assets/logo-light.png" alt="00infosec" width="200">
</picture>

# 00INFOSEC RECON

### OSINT · Attack Surface Management · Security Research

Reconhecimento unificado com resultados confiáveis, explicáveis e reproduzíveis.

[![CI](https://github.com/00infosec/00infosec/actions/workflows/00infosec-recon-ci.yml/badge.svg)](https://github.com/00infosec/00infosec/actions/workflows/00infosec-recon-ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-111111?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-111111?style=flat-square)](LICENSE)

[Visão geral](#visão-geral) · [Instalação](#instalação) · [Uso](#uso) · [Módulos](#módulos) · [Outputs](#outputs) · [Arquitetura](#arquitetura) · [Segurança](#escopo-e-segurança-anti-ssrf)

</div>

## Visão geral

O **00INFOSEC RECON** reúne descoberta de ativos, análise de superfície de ataque e enriquecimento de vulnerabilidades em um único pipeline assíncrono. A arquitetura compartilha contexto, cliente HTTP, controle de escopo e modelo de achados entre todos os módulos.

<table>
  <tr>
    <td width="25%" align="center"><strong>PRECISÃO</strong><br><sub>Confiança e evidência explícitas em cada resultado.</sub></td>
    <td width="25%" align="center"><strong>SEGURANÇA</strong><br><sub>Escopo anti-SSRF e mascaramento de dados sensíveis.</sub></td>
    <td width="25%" align="center"><strong>AUTOMAÇÃO</strong><br><sub>CLI, SARIF, baseline e integração MCP.</sub></td>
    <td width="25%" align="center"><strong>PORTABILIDADE</strong><br><sub>Python 3.10+ em Windows, Linux e macOS.</sub></td>
  </tr>
</table>

> O projeto prioriza qualidade de evidência e uso autorizado, não volume de fontes.

---

## Modelo de resultados

Cada achado carrega um **status** e uma **confiança** explícitos:

| status | significado | exemplo |
|---|---|---|
| `observation` | fato observado, não é vulnerabilidade | porta aberta, breach HIBP |
| `candidate` | possível problema, requer confirmação humana | CVE sem versão confirmada, typosquat heurístico |
| `finding` | suficientemente comprovado | `/.env` com validador + anti-soft-404, takeover com fingerprint |

Regras aplicadas no código:

- CVE só vira `finding` com correlação **produto+host+versão** (conf. high).
  Sem versão verificável → `candidate`/medium (match CPE) ou /low (só keyword).
- CISA KEV e EPSS **enriquecem** CVEs já correlacionadas — nunca criam finding sozinhos.
- Todo finding traz: ativo, evidência estruturada, fonte, confiança,
  momento da coleta (`collected_at`) e recomendação curta (`remediation`).

---

## Escopo e segurança (anti-SSRF)

Toda requisição voltada ao alvo passa por um objeto de escopo:

```
Scope(domain=..., include_subdomains=True, allow_private_ips=False, excluded_hosts=...)
```

- URLs externas coletadas de APIs (wayback, urlscan…) são **bloqueadas** ao serem fetchadas;
- IPs privados, loopback, link-local (169.254.169.254) e reservados bloqueados por padrão;
- redirects validados hop-a-hop contra o escopo;
- cada URL bloqueada é registrada com motivo (relatório + `scan.json`);
- `--allow-private` libera ranges privados explicitamente; loopback continua bloqueado.

## Mascaramento de segredos

Por padrão **todos os outputs saem mascarados** (JSON, HTML, JSONL, SARIF, MCP):

```text
AKIA************MPLE        senha: pa**********
```

Valores completos somente com `--include-sensitive` local. **O MCP sempre mascara**,
independente de flags.

---

## Instalação

### Início rápido

```bash
git clone https://github.com/00infosec/00infosec.git
cd 00infosec/tools/00infosec-recon/00infosec-recon
python -m pip install -e ".[full]"
python -m infosec_recon example.com -p passive
```

O perfil `passive` não realiza conexões diretas ao alvo e é o ponto de partida recomendado para conhecer a ferramenta.

### Opções de instalação

```bash
git clone https://github.com/00infosec/00infosec.git
cd 00infosec/tools/00infosec-recon/00infosec-recon

pip install -e .              # core (aiohttp + rich)
pip install -e ".[full]"      # + dnspython (DNS ativo) + bs4 (DDG)
pip install -e ".[mcp]"       # + servidor MCP
pip install -e ".[full,mcp]"  # tudo
```

> **Windows (Python Store):** o executável `infosec` pode não entrar no PATH.
> Use sempre `python -m infosec_recon`.

## Uso

```bash
python -m infosec_recon <dominio> [opcoes]

# exemplos
python -m infosec_recon example.com.br                    # profile default (6 módulos)
python -m infosec_recon example.com.br --deep             # + brute/permute/takeover/internetdb full
python -m infosec_recon banco.b.br -p quick               # recon + leakhunt
python -m infosec_recon example.com.br --only recon,cvescan
python -m infosec_recon example.com.br --skip phishlab
python -m infosec_recon alvo1.com.br alvo2.b.br           # multi-target sequencial
python -m infosec_recon --proxy socks5://user:pass@127.0.0.1:9050 example.com.br
python -m infosec_recon --list-modules
```

### Perfis

| perfil | comportamento |
|---|---|
| `quick` | fontes passivas + leakhunt |
| `default` | tudo: fingerprint, exposures, cloud, phishing |
| `deep` | default + brute-force DNS, permutações, takeover, InternetDB completo |
| `passive` | **nenhuma conexão direta ao alvo** (recon passivo + leakhunt + phishlab) |

### Controles operacionais

| flag | descrição |
|---|---|
| `--max-requests 5000` | teto global de requisições HTTP |
| `--max-duration 20m` | tempo máximo do scan (finaliza com o coletado; checkpoint permite continuar) |
| `--concurrency 30` | conexões simultâneas |
| `--rate-limit 5` | requisições/segundo globais (+ limites por provedor automáticos: NVD, GitHub, DDG…) |
| `--baseline scan.json` | compara com scan anterior → NOVO / RESOLVIDO / ALTERADO |
| `--config recon.json` | carrega defaults operacionais de JSON; flags da linha de comando prevalecem |
| `--fail-on high` | retorna exit code 3 quando houver finding high/critical |

### Flags

| flag | descrição |
|---|---|
| `-p, --profile` | `quick` · `default` · `deep` · `passive` |
| `--only` | executa só os módulos listados (dependências são puxadas automaticamente) |
| `--skip` | pula módulos |
| `--deep` | recon: DNS brute (~90 prefixos) + permutações + takeover checks + InternetDB completo |
| `--proxy` | HTTP/SOCKS propagado a todos os módulos |
| `-o, --out` | diretório raiz de saída (default `infosec_out`) |
| `--max-permutations` | teto de permutações do cloudhunt (default 250) |
| `--max-candidates` | teto de typosquats do phishlab (default 400) |
| `--max-probe-hosts` | teto de hosts probeados pelo recon (default 400; apex/www têm prioridade) |
| `--resume` | reaproveita `checkpoint.json` do diretório de saída e roda só o que falta |
| `--baseline scan.json` | diff com scan anterior (monitoramento de superfície) |
| `--allow-private` | permite IPs privados no escopo (default: bloqueado) |
| `--include-sensitive` | desmascara segredos nos outputs locais (MCP nunca) |
| `--config` | arquivo JSON com defaults das flags operacionais |
| `--fail-on` | `none` · `low` · `medium` · `high` · `critical` |
| `--nvd-key`, `--gh-token` | credenciais por flag (senão via env) |

Exemplo de configuração:

```json
{"profile":"quick","concurrency":20,"rate-limit":5,"fail-on":"high"}
```

### Monitoramento de superfície (baseline)

```bash
python -m infosec_recon example.com.br -o out
# ...dias depois...
python -m infosec_recon example.com.br -o out --baseline out/example.com.br/scan.json
```

```text
NOVO       admin.example.com.br
NOVO       CLOUD_BUCKET_OPEN · acme-backups
RESOLVIDO  /.env exposto
ALTERADO   web.example.com · nginx: 1.20 → 1.24
NOVO       OPEN_PORT · api.example.com.br · 8443
ALTERADO   api.example.com.br · https://…: 200|nginx → 503|nginx
```

O diff vai para o console, para a seção do `report.html` e para
`scan.json → baseline_diff`.

---

## Módulos

| módulo | função | fornece (`ctx.data`) |
|---|---|---|
| **recon** | 18 fontes passivas, wildcard detection, resolve DNS, HTTP probe, stack fingerprint, exposed files, takeover, Shodan InternetDB, RDAP | `subdomains` `hosts_alive` `urls` `stack` `dns_records` `internetdb` `rdap` |
| **cvescan** | NVD (by CPE) + CIRCL + OSV + GHSA + CISA KEV + EPSS + ExploitDB; correlação CVE→host com version gate | `cves` `cve_by_host` |
| **jsleak** | 19 padrões de secrets em JS + entropia, endpoints internos, source maps, exposure scan (18 paths sensíveis c/ anti-soft-404) | `secrets` `endpoints` `source_maps` `js_exposed` |
| **leakhunt** | ProxyNova comb, HIBP breaches, GitHub dorks (validação raw), psbdmp, DDG pastes | `creds` `emails` `breaches` |
| **cloudhunt** | permutações S3/Azure/GCP/DO/Wasabi/Linode; listing XML = bucket aberto; atribuição ao core do domínio | `buckets` |
| **phishlab** | typosquatting (homograph/insertion/omission/transposition/TLD-swap/phish-words), DNS sweep, CT logs (crt.sh), urlscan | `typosquats` |

Detalhes completos: [`docs/MODULES.md`](docs/MODULES.md)

### Fontes passivas do recon

| sem key | com key (env) |
|---|---|
| crt.sh · **crt.name** · OTX · HackerTarget · RapidDNS · AnubisDB · urlscan · ThreatMiner · Wayback CDX · CommonCrawl · Subdomain.center · dnsrepo · Riddler | VirusTotal `VT_API_KEY` · SecurityTrails `ST_API_KEY` · Chaos `CHAOS_API_KEY` · Shodan `SHODAN_API_KEY` · BinaryEdge `BE_API_KEY` · LeakIX `LEAKIX_API_KEY` |

Fontes sem key disponível são puladas silenciosamente. NVD sem key usa rate
limit 5 req/30s (com `NVD_API_KEY`: 50 req/30s).

---

## Servidor MCP

Use o framework direto de Claude Desktop, opencode ou qualquer client MCP:

```bash
pip install "infosec-recon[mcp]"
python -m infosec_recon.mcp_server          # stdio transport
```

**Tools expostas:** `run_scan` (background, retorna `scan_id`) ·
`scan_status` · `get_findings` (filtros severity/module) · `get_scan_data`
(subs, stack, CVEs, buckets, creds, typosquats) · `list_scans` (histórico
persistido em `<out>/.scans/`, sobrevive a restart do servidor) ·
`list_modules` · `cancel_scan`.

<details>
<summary>Claude Desktop (<code>claude_desktop_config.json</code>)</summary>

```json
{
  "mcpServers": {
    "infosec-recon": {
      "command": "python",
      "args": ["-m", "infosec_recon.mcp_server"]
    }
  }
}
```

</details>

<details>
<summary>opencode (<code>opencode.json</code>)</summary>

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "infosec-recon": {
      "type": "local",
      "command": ["python", "-u", "-m", "infosec_recon.mcp_server"],
      "enabled": true
    }
  }
}
```

</details>

---

## Outputs

```
infosec_out/<dominio>/
├── report.html       # dashboard: filtros sev/status/confiança, busca, agrupar por ativo
├── report.md         # relatório portátil em Markdown
├── scan.json         # results + assets + saúde das fontes + métricas + baseline_diff
├── findings.sarif    # SARIF 2.1 p/ GitHub Code Scanning / CI
├── findings.jsonl    # 1 finding por linha (stream-friendly)
├── assets.jsonl      # 1 ativo correlacionado por linha (IPs, portas, stack, CVEs, achados)
├── subdomains.txt    # todos os subdomínios descobertos
├── alive.txt         # hosts resolvidos vivos
├── urls.txt          # URLs coletadas (wayback/otx/urlscan) — alimenta o jsleak
└── http.txt          # "status url | título" dos probes
```

Correlação: `scan.json → assets` liga host, IPs, URLs, portas, tecnologias,
endpoints, CVEs e achados. Observabilidade: `scan.json → source_health` e
`results.<mod>.stats.sources` mostram por fonte
`ok (n hosts)` / `key ausente (...)` / `error ...` — e o relatório distingue
"NVD RATE LIMITED" de "NVD OK, zero resultados". Métricas globais de HTTP
(requests/errors/timeouts/rate-limited/blocked) ficam em `scan.json → http`.

Exemplo de integração CI (GitHub Actions):

```yaml
- run: python -m infosec_recon $TARGET -p quick -o ci_out
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ci_out/${{ env.TARGET }}/findings.sarif
```

## API keys (env)

```
VT_API_KEY=          ST_API_KEY=          CHAOS_API_KEY=
SHODAN_API_KEY=      BE_API_KEY=          LEAKIX_API_KEY=
NVD_API_KEY=         GH_TOKEN=            INFOSEC_INSECURE_TLS=0
```

## Arquitetura

```
cli.py ──▶ runner.execute_scan()
              ├─ HttpClient   (1 sessão aiohttp compartilhada)
              ├─ DnsPool      (resolver pool + wildcard detection)
              └─ engine.scheduler.run_pipeline()   ← DAG in-process
                     recon ──┬─▶ cvescan   (requires stack)
                             └─▶ jsleak    (requires hosts_alive)
                     leakhunt ─ cloudhunt ─ phishlab   (independentes)
              ▼
       ScanContext.data  →  findings[]  →  HTML/JSON/SARIF
```

Módulos independentes rodam concorrentes; `requires` é resolvido com asyncio
events (o consumidor espera o produtor publicar a chave no contexto).
Mais detalhes: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

### Design integrado

| Componente | Implementação |
|---|---|
| Execução | Pipeline 100% assíncrono e in-process |
| HTTP | Um `HttpClient` com proxy e rate limit centralizados |
| Contexto | Estado tipado e compartilhado entre módulos |
| Achados | Modelo `Finding` unificado com severidade e confiança |
| Relatórios | HTML, Markdown, JSON, SARIF e artefatos de texto |
| DNS | Wildcard detection implementada e coberta por testes |

## Testes e CI

```bash
python tests/test_core.py        # unit (também roda com pytest)
python tests/mcp_smoke_ci.py     # handshake MCP + tools/list
```

CI no GitHub Actions (`.github/workflows/00infosec-recon-ci.yml`): lint,
testes unitários, CLI smoke e MCP smoke em Ubuntu e Windows com Python 3.10 a 3.13.

## Contribuindo

Veja [`CONTRIBUTING.md`](CONTRIBUTING.md). Issues e PRs bem-vindos.

## Licença e aviso legal

[Distribuído sob licença MIT](LICENSE).

**USE APENAS EM ALVOS QUE VOCÊ TEM AUTORIZAÇÃO PARA TESTAR.** Reconhecimento
ativo constitui interação real com infraestrutura. Você é responsável por
obter autorização e cumprir a legislação, os contratos e as políticas aplicáveis.
