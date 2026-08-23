# Arquitetura

## Princípios

1. **In-process, zero subprocess** — todos os módulos rodam no mesmo event
   loop asyncio. Sem serialização intermediária.
2. **Um client HTTP** — `core.http.HttpClient` encapsula a única
   `aiohttp.ClientSession`: UA rotativo, retries com backoff em 429/502/503/504,
   proxy global, TLS opt-out (`INFOSEC_INSECURE_TLS`), contagem de bytes.
3. **Contexto compartilhado tipado por convenção** — `ScanContext.data` é um
   dict onde módulos publicam chaves declaradas em `provides` e consomem as de
   `requires`.
4. **Findings unificados** — todo achado vira `Finding(module, type, severity,
   target, evidence, source)`, independente do módulo de origem. O relatório e
   o SARIF consomem só isso.

## Fluxo

```
main()                          # cli.py: parse + Windows loop policy
 └─ scan_domain(domain)
     └─ runner.execute_scan(domain, args)
         ├─ ScanContext(domain, out_dir, args)
         ├─ Config(args)                    # keys de env + proxy
         ├─ HttpClient(cfg)                 # async context manager
         ├─ DnsPool()                       # dnspython p/ 1.1.1.1/8.8.8.8/9.9.9.9
         └─ engine.scheduler.run_pipeline()
              para cada módulo (concorrente):
                espera eventos das chaves em `requires`
                → inst.run(ctx, http, dns, cfg, console)
                → ModuleResult{status, elapsed, stats, findings[]}
         ├─ report.assets.build_asset_inventory() # correlação por ativo
         ├─ report.write_scan_json()        # out/…/scan.json + assets
         ├─ report.build_html()             # out/…/report.html
         ├─ report.markdown.write_markdown()# out/…/report.md
         └─ report.write_sarif()            # out/…/findings.sarif
```

## DAG de módulos

| módulo | requires | provides |
|---|---|---|
| recon | — | subdomains, hosts_alive, urls, http_records, stack |
| cvescan | stack | cves |
| jsleak | subdomains, hosts_alive | secrets, endpoints |
| leakhunt | — | creds, emails, breaches |
| cloudhunt | — | buckets |
| phishlab | — | typosquats |

O scheduler materializa um `asyncio.Event` por chave provida. Um módulo com
`requires=("stack",)` aguarda `event["stack"].wait()` antes de rodar; se o
produtor falhar, o evento é setado mesmo assim (o consumidor decide o que
fazer com dado ausente — ex.: cvescan segue só com KEV/EPSS).

## Adicionando um módulo

```python
# infosec_recon/modules/meumod.py
from .base import Module

class MeuModModule(Module):
    name = "meumod"
    description = "faz algo útil"
    provides = ("meus_dados",)
    requires = ()          # ou ("subdomains",)

    async def run(self):
        r = await self.http.get_json("https://api.example.com/query")
        self.result.stats["itens"] = len(r or [])
        for item in r or []:
            self.add("tipo_achado", "medium", item["host"],
                     evidence=item["detalhe"])
        self.ctx.data["meus_dados"] = r
```

Registre em `modules/__init__.py`. O CLI (`--only/--skip`) e o MCP
(`list_modules`) passam a enxergá-lo automaticamente.

## Decisões de design relevantes

- **Windows**: `WindowsSelectorEventLoopPolicy` no CLI/MCP; stdout/stderr
  reconfigurados p/ UTF-8. No MCP toda saída rich vai pra stderr (stdout é
  exclusivo do protocolo).
- **DNS**: dnspython opcional. Sem ele, resolve via OS (`getaddrinfo`) e
  desativa wildcard detection/brute.
- **Rate limits respeitados**: NVD 6.5s/página sem key; GitHub dorks 2.5s entre
  queries; DDG 2s; EPSS chunks de 100 c/ 0.4s.
- **Anti falso-positivo no jsleak exposure scan**: fingerprint de 404 por host
  (len+hash do corpo) + validador de conteúdo por path.
- **Cloudhunt**: existência = status ∈ exists_codes (403 = existe mas não
  lista); aberto = HTTP 200 + marcadores XML de listing (`<ListBucketResult`,
  `<EnumerationResults`). `attributed` = core do domínio contido no nome.

## Compatibilidade SDK MCP

`mcp_server.py` tenta importar `mcp.server.fastmcp.FastMCP` (SDK 1.x) e cai
para `mcp.server.mcpserver.MCPServer` (2.x). Ambos expõem `.tool()` e
`.run("stdio")` — o resto do código é idêntico.
