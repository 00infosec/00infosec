# Changelog

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/)
e [SemVer](https://semver.org/lang/pt-BR/).

## [0.2.0] - 2026-08-23

Foco: **precisão, segurança e explicabilidade** (feedback de revisão arquitetural).

### Adicionado
- **Modelo de achados v2**: `status` (`observation`/`candidate`/`finding`),
  `confidence` (`low`/`medium`/`high`), evidência estruturada,
  `remediation` por tipo e `collected_at`.
- **Escopo anti-SSRF** (`core/scope.py`): bloqueio de IPs privados/loopback/
  link-local, URLs externas coletadas de APIs e redirects fora do escopo;
  log com motivo de cada bloqueio; `--allow-private` para exceção explícita.
- **Mascaramento de segredos** por padrão em todos os outputs;
  `--include-sensitive` para valores completos localmente. MCP sempre mascara.
- **HttpClient v2**: Retry-After respeitado, backoff exponencial c/ jitter,
  rate limit global + por provedor (NVD/GitHub/DDG/ProxyNova/crt.sh…),
  métricas por host, redirects validados no escopo, suporte SOCKS real via
  `aiohttp-socks`, teto `--max-requests`, `--rate-limit`, `--max-duration`,
  `--concurrency`.
- **Observabilidade**: status por fonte (`ok` / `key ausente` / `error`) no
  stats e no relatório — "nenhum resultado" ≠ "API falhou".
- **Baseline/diff**: `--baseline scan.json` → NOVO / RESOLVIDO / ALTERADO
  (subdomínios, buckets, exposições, versões de stack, severidade de CVEs).
- **Perfil `passive`** + `--passive`: zero conexão direta ao alvo.
- Exportação **findings.jsonl**.
- **Inventário correlacionado por ativo** em `scan.json → assets` e
  `assets.jsonl`: host/IP/URLs/portas/stack/endpoints/CVEs/achados.
- Relatório Markdown (`report.md`), configuração JSON (`--config`) e exit code
  de CI por severidade (`--fail-on`).
- Baseline ampliado para novas portas e mudanças de status/servidor HTTP.
- Resumo operacional `scan.json → source_health`.
- Relatório HTML v2: filtros por severidade/status/confiança/módulo, busca,
  agrupamento por ativo, tabela de fontes consultadas/falhas, seção de
  requisições bloqueadas pelo escopo, seção baseline.
- +19 testes de precisão/segurança (KEV sem correlação não vira finding,
  escopo bloqueia externo/privado/redirect, mascaramento, determinismo etc).
  CI estendida p/ Python 3.10–3.13.

### Alterado
- CVEs sem correlação são descartadas; KEV/EPSS apenas enriquecem CVEs ligadas a ativos.
- InternetDB CVEs são `candidate`/low até correlação de produto/versão.
- Dedupe cross-module agora mantém o registro de **maior confiança**.

### Corrigido
- Windows: removida a política `WindowsSelectorEventLoopPolicy`, que causava
  `ValueError: too many file descriptors in select()` em alvos com milhares
  de hosts. A resolução DNS agora usa um conjunto limitado de workers e
  encerra as tarefas corretamente em cancelamentos.
- Progresso live agora é recalculado continuamente; resolução DNS mostra
  concluídos/total, percentual e ETA. Consultas A/AAAA/CNAME rodam em paralelo.

## [0.1.0] - 2026-08-23

Primeira release pública em uma base independente, com framework único
in-process.

### Adicionado
- Core: `HttpClient` compartilhado (proxy/retry/rate-limit), `DnsPool`
  (dnspython + fallback OS), modelo unificado `Finding`/`ScanContext`.
- Engine: scheduler DAG in-process com asyncio events (zero subprocess).
- Módulo **recon**: 18 fontes passivas (inclui crt.name), wildcard detection
  funcional, DNS brute (~90 prefixos) + permutações, HTTP probe, stack
  fingerprint de 25 tecnologias, exposed files, takeover checks (12 serviços),
  Shodan InternetDB e RDAP.
- Módulo **cvescan**: NVD by CPE + CIRCL + OSV + GHSA + KEV + EPSS +
  ExploitDB, dedup multi-fonte e correlação CVE→host.
- Módulo **jsleak**: 19 padrões de secrets, entropia Shannon, endpoints,
  source maps, exposure scan com anti soft-404.
- Módulo **leakhunt**: ProxyNova, HIBP breaches, GitHub dorks com validação
  raw, psbdmp, DDG pastes.
- Módulo **cloudhunt**: permutações S3/Azure/GCP/DO/Wasabi/Linode com
  detecção de listing aberto e atribuição ao domínio.
- Módulo **phishlab**: typosquatting (6 algoritmos), DNS sweep, CT logs,
  urlscan, score de risco.
- Relatórios: HTML unificado, `scan.json`, SARIF 2.1.
- CLI única com profiles (`quick`/`default`/`deep`), `--only`/`--skip`,
  multi-target.
- Servidor MCP (stdio) com 6 tools: `run_scan`, `scan_status`,
  `get_findings`, `get_scan_data`, `list_modules`, `cancel_scan`.
- Compatível com SDK `mcp` 1.x (FastMCP) e 2.x (MCPServer).

### Corrigido
- jsleak agora analisa as URLs `.js` coletadas pelo recon (wayback/otx/urlscan),
  não só homepages probeadas.
- Findings duplicados entre módulos são colapsados no contexto
  (ex.: `/.env` visto por recon e jsleak = 1 achado).
- cvescan: version gate com faixas `versionStart/End*` do NVD + segunda onda
  de busca keyword para produtos sem retorno CPE.

### Adicionado (P1)
- **Checkpoint/resume**: cada módulo concluído é gravado em
  `<out>/<dominio>/checkpoint.json`; `--resume` (CLI) ou `resume=true` (MCP)
  roda só o que falta. Checkpoint removido quando o scan completa.
- **Persistência de scans no MCP**: registros em `<out>/.scans/<scan_id>.json`
  sobrevivem a restart; nova tool `list_scans`; LRU de memória (20 scans).
- **`--max-probe-hosts`** configurável no recon com aviso explícito quando o
  cap corta hosts (apex/www priorizados).
- Suíte de testes (`tests/test_core.py`, 12 testes) + smoke MCP p/ CI +
  workflow GitHub Actions (Ubuntu/Windows × Python 3.11/3.13).
