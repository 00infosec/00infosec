# Contribuindo

## Setup de dev

```bash
git clone https://github.com/00infosec/00infosec.git
cd 00infosec/tools/00infosec-recon/00infosec-recon
pip install -e ".[full,mcp,dev]"
```

## Antes de abrir PR

1. Teste com um alvo inofensivo:

```bash
python -m infosec_recon example.com -p quick -o /tmp/out
python -m infosec_recon example.com --only recon,cvescan --deep -o /tmp/out
python -m infosec_recon example.com --only phishlab --max-candidates 100 -o /tmp/out
echo '{"jsonrpc":"2.0"}' | python -c "import infosec_recon.mcp_server"  # import ok
```

2. Sem segredos no diff (tokens de API aparecem em logs — sanitize antes).
3. Um PR = uma mudança coerente. Descreva o porquê, não só o o que.

## Convenções

- Módulos implementam `Module` (`modules/base.py`): declare `provides` /
  `requires`; publique achados via `self.add(...)`; dados no
  `self.ctx.data[chave]`.
- Nenhum achado deve existir fora do modelo `Finding` — é o que alimenta
  relatório e SARIF.
- Fontes novas no recon: decorador `@_src("nome")`, retorne `set[str]` de
  hosts normalizados; erros são capturados por fonte e não derrubam o módulo.
- Rate limit de terceiros é lei: sleep entre requests paginados.

## Reportando bugs

Inclua: comando executado (sem proxy/keys), trecho do `scan.json`
(`results.<modulo>.stats` + `error`), SO e versão do Python.
