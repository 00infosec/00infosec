# Módulos

Referência técnica de cada módulo: fontes, heurísticas e limites.

---

## recon

**provides:** `subdomains` `hosts_alive` `urls` `http_records` `stack`
`dns_records` `internetdb` `rdap`

### Fontes passivas (concorrentes)

| fonte | endpoint | obs |
|---|---|---|
| crtsh | `crt.sh/?q=%.<dom>&output=json` | timeout 90s |
| crtname | `crt.name/v1/search?apex=<dom>` | 1000 req/IP/dia |
| otx | `otx.alienvault.com/.../passive_dns` + `url_list` | urls alimentam jsleak |
| hackertarget | `api.hackertarget.com/hostsearch/` | ~50 req/dia/IP |
| rapiddns | `rapiddns.io/subdomain/<dom>?full=1` | scrape HTML |
| anubis | `jldc.me/anubis/subdomains/<dom>` | JSON array |
| urlscan | `urlscan.io/api/v1/search/?q=domain:<dom>` | hosts + urls |
| threatminer | `api.threatminer.org/v2/domain.php?rt=5` | |
| wayback | `web.archive.org/cdx/search/cdx?url=*.<dom>/*` | até 20k urls |
| subdomaincenter | `api.subdomain.center/?domain=<dom>` | |
| dnsrepo | `dnsrepo.noc.org/?search=<dom>` | scrape |
| riddler | `riddler.io/search?q=pld:<dom>` | |
| virustotal | `.../domains/<dom>/subdomains` | header `x-apikey`, pagina cursor (8 págs) |
| securitytrails | `.../domain/<dom>/subdomains` | header `APIKEY` |
| chaos | `dns.projectdiscovery.io/dns/<dom>/subdomains` | header `Authorization` |
| shodan | `api.shodan.io/dns/domain/<dom>` | key na query |
| binaryedge | `api.binaryedge.io/v2/query/domains/subdomain/<dom>` | header `X-Key` |
| leakix | `leakix.net/api/subdomains/<dom>` | header `api-key` |

Hosts são normalizados (`normalize_host`: lowercase, sem `*.`, valida regex
RFC, aceita só `<algo>.<dom>` ou o apex) e deduplicados por fonte.

### Expansão ativa (com `--deep`)

- **DNS brute**: ~90 prefixos de alto valor (www/mail/vpn/sso/api/k8s/grafana +
  termos BR-financeiros pix/boleto/cartao…) → `{w}.<dom>`
- **Permutações**: subs descobertos × afixos (dev/hml/uat/prod/bkp/v2…) em 4
  formas, cap 3000 candidatos
- Vivos creditados às fontes `dns-brute` / `dns-permute`

### Resolução

dnspython → resolvers públicos 1.1.1.1/8.8.8.8/9.9.9.9 (A+AAAA+CNAME). Sem
dnspython: `getaddrinfo` do OS. **Wildcard detection**: resolve 3 labels
aleatórios de 14 chars; host cujos IPs ⊆ IPs do wildcard (ou CNAMEs idem) é
marcado `wildcard_fp` e tratado como morto.

### HTTP probe + stack

https→http por host vivo, timeout 10s, body ≤200KB, título extraído. Fingerprint
por 25 assinaturas (server/header/cookie/html): nginx, apache, tomcat, iis,
cloudflare, php, asp.net, express, next.js, react, vue.js, angular, jquery,
wordpress, drupal, joomla, shopify, vercel, netlify, gunicorn, django, laravel,
spring… + `package.json` expondo versão da app + até 40 deps npm.

**Exposed files** (por host probeado): `/package.json` `/composer.json`
`/CHANGELOG.txt` `/readme.html` `/.git/config` `/.env` `/swagger.json`
`/api/swagger.json` `/openapi.json` — HTTP 200 sem redirect = achado
(critical p/ `.env`/`.git`).

### Takeover (`--deep`)

12 serviços com assinatura CNAME+fingerprint de corpo: GitHub Pages, AWS S3,
Heroku, Azure, Fastly, Shopify, Bitbucket, Surge.sh, Pantheon, Zendesk, Tumblr.

### InternetDB (Shodan, sem key)

Para IPs A dos hosts vivos (até 64): `internetdb.shodan.io/<IP>` → portas,
hostnames, CVEs. Portas não-web geram finding `open_port`; CVEs geram
`internetdb_cve` (high) — correlação barata antes do cvescan.

### RDAP

`rdap.org/domain/<dom>` → registrar, datas de registro/expiração, nameservers,
status, entidades.

---

## cvescan

**requires:** `stack` · **provides:** `cves` `cve_by_host`

Stack (host→techs) vira produtos via `STACK_CPE_MAP` (60+ mapeamentos
vendor/product). Para cada produto:

| fonte | detalhe |
|---|---|
| NVD 2.0 | `virtualMatchString`/`cpeName` + `isVulnerable`; paginação 2000; delay 6.5s (0.6s com key); parse CVSS V3.1>V3.0>V2, CWEs, CPEs, refs |
| CIRCL | `cve.circl.lu/api/search/<vendor>/<product>` |
| OSV | `POST api.osv.dev/v1/query` package+ecosystem (mapa npm/PyPI/Maven/Packagist/RubyGems) |
| GHSA | `api.github.com/advisories?ecosystem=` (requer GH_TOKEN), 3 páginas |
| KEV | feed CISA inteiro → flag `kev` + meta (ransomware use) |
| EPSS | chunks de 100 CVEs → score+percentil |
| ExploitDB | CSV files_exploits.csv → ids por CVE |

Dedup por CVE id com merge de campos e lista de fontes. Correlação host-level:
match por substring CPE (`:vendor:`+`:product:`) nos criteria do CVE, fallback
keyword na descrição; **version gate**: quando o hit tem versão, faixas
`versionStart/End*` do NVD rejeitam CVEs fora da faixa (com escape p/ CPE
exato). `matched_hosts` propaga para `cve_by_host`. Produtos sem nenhum
retorno de CPE no NVD ganham uma segunda onda `keywordSearch` (até 3 produtos).

Achados duplicados entre módulos (mesmo type+target+evidence) são
colapsados uma única vez no contexto — ex.: `/.env` visto pelo probe do recon
e pelo exposure scan do jsleak vira um finding só.

Severidade: CVSS ≥9 critical / ≥7 high / ≥4 medium. `exploitable` =
ExploitDB ∪ KEV. Findings emitidos top-80 ordenados por (KEV, CVSS desc).

## jsleak

**requires:** `subdomains` `hosts_alive` · **provides:** `secrets` `endpoints`

1. **Descoberta JS**: (a) URLs `.js` já coletadas pelo recon no contexto
   (`urls.txt` — wayback/otx/urlscan) entram direto na análise; (b) regex sobre
   o HTML das homepages vivas (≤50 páginas).
2. **Análise** (≤400 arquivos, body ≤1.5MB):
   - 19 padrões nomeados (AWS AKIA, GCP AIza, GitHub ghp_, Stripe sk_live,
     Slack xox, JWT, PEM/RSA/SSH keys, JDBC, OpenAI/Anthropic…) c/ contexto ±40
     chars e filtro de placeholders;
   - entropia de Shannon ≥4.5 em blobs base64-ish ≥32 chars (estilo truffleHog);
   - endpoints internos: `/api/v*/`, `/v\d/`, `/admin/`, `/internal/`,
     `/graphql`, `/auth/`, absolutos api/admin/internal;
   - source maps: `//# sourceMappingURL` → fetch `.map` → conta `sources`.
3. **Exposure scan** (≤150 hosts, 18 paths): `/.git/HEAD` `/.env`
   `/actuator/env` `/backup.sql` `/credentials.json` etc — exige status 200 +
   validador de conteúdo + anti soft-404 (fingerprint len+hash do 404 real) +
   anti catch-all SPA.

## leakhunt

**provides:** `creds` `emails` `breaches`

| fonte | método |
|---|---|
| ProxyNova | `GET api.proxynova.com/comb?query=<dom>&limit=50` → pares email:senha filtrados pelo domínio |
| HIBP | catálogo público `haveibeenpwned.com/api/v3/breaches` filtrado por Domain (sem key) |
| psbdmp | `psbdmp.ws/api/search/<dom>` → ids de pastes |
| DDG | 5 dorks site:pastebin/rentry/etc via html.duckduckgo.com (bs4; sleep 2s) |
| GitHub | 10 dorks `search/code` (GH_TOKEN; sleep 2.5s) + fetch raw do arquivo + validação (padrões de secret fortes / combolist com domínio) → confidence confirmed/suspicious |

Credencial duplicada é descartada por (email, senha).

## cloudhunt

**provides:** `buckets`

6 providers × permutações do core do domínio (core, dom com/sem pontos, 40+
sufixos × 4 separadores ambos os lados, prefixos, cap `--max-permutations`).

Existência = status ∈ exists_codes do provider (S3/DO/Wasabi/Linode: 200+403;
Azure: +400; GCP: +401/403). **Aberto** = HTTP 200 + marcador XML de listing
(`<ListBucketResult` / `<EnumerationResults`) → finding
`cloud_bucket_open` (critical se atribuído ao domínio, senão high).
`attributed` = core contido no nome do bucket.

## phishlab

**provides:** `typosquats`

Geração (≤`--max-candidates`): homograph substitution, insertion, omission,
transposition, TLD-swap (28 TLDs alternativos), palavras de phishing
(login/secure/auth/verify/banking…). Dedup contra o próprio domínio.

Triangulação de sinais por variante:

| sinal | pontos |
|---|---|
| DNS vivo (A/AAAA) | +30 |
| MX presente | +20 |
| cert CT recente (crt.sh, 90d, match core) | +25 |
| aparece no urlscan | +15 |
| contém palavra de phishing | +10 |

≥60 critical · ≥40 high (contabiliza `phish high-score`) · ≥30 medium.
Sem dnspython o sweep é pulado (CT+urlscan seguem).
