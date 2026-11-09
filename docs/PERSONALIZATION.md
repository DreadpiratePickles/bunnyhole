# 🧭 Personalization: personas, remembered context & sanctions screening

Bunnyhole adapts to *how you investigate*. Three pieces work together, all keyless and local:

1. **Investigator personas** — a lens that tunes the run.
2. **A remembered profile** — your persona, watchlist, jurisdictions and defaults, persisted across cases.
3. **OpenSanctions sanctions/PEP screening** — a new data source wired into every corporate/person lead.

Everything lives in `~/.bunnyhole/profile.json` (the same secured config dir as your keys and case DB; `$BUNNYHOLE_HOME` relocates it). Nothing is uploaded anywhere.

---

## 1. Personas

A persona bundles sensible run defaults (gear / depth / breadth), the domains it cares about, whether it leans on sanctions/PEP screening, and a one-line **analyst framing** that rides along in every result so the output reads in the right register. Personas set *defaults* — you can always override them per run.

```bash
uv run bunnyhole personas          # list them (● marks your active one)
```

| Key | Lens | Defaults | Sanctions emphasis |
|---|---|---|---|
| `generalist` | Balanced, no bias | fast / d2 / b4 | — |
| `journalist` | Public-interest accountability, sourcing & provenance | fast / d2 / b5 | — |
| `compliance` | KYC/AML DD: UBO, sanctions/PEP, adverse media | deep / d3 / b4 | ✔ |
| `threat_intel` | Infra pivoting, breach exposure, attribution | fast / d2 / b6 | — |
| `crypto_tracer` | On-chain fund-flow tracing, bridges, off-ramps | deep / d3 / b5 | ✔ |
| `pi` | Private-investigator method on the lawful, passive layer (auto-selected by `--pi`, see [PI_STREAM.md](PI_STREAM.md)) | deep / d3 / b4 | ✔ |

`--persona` is case-insensitive (`--persona Compliance` works); an unknown key is rejected (exit 2) with the six valid keys.

When a persona emphasizes sanctions, OpenSanctions screening also runs on domain-derived company stems, not just explicit company/person leads.

---

## 2. Your remembered profile

```bash
# View your profile
uv run bunnyhole profile

# Set a persona + build a watchlist of recurring targets
uv run bunnyhole profile --persona compliance --watch acme.io --watch 0xDEADBEEF --name "Nat"

# Standing scope: jurisdictions of interest + exclusions folded into every case
uv run bunnyhole profile --jurisdiction KY --jurisdiction VG --exclude unrelated.com

# Override a persona's run defaults (these win over the persona; depth 1-4, breadth 2-8)
uv run bunnyhole profile --gear deep --depth 4

# Tidy up
uv run bunnyhole profile --unwatch acme.io          # remove one
uv run bunnyhole profile --clear-watch              # empty the list
```

**Watchlist** — when a case surfaces an entity whose id or label contains a watchlist term, it's reported under `watchlist_hits` in the result. Your recurring targets announce themselves.

**Run defaults** — `trace`/`intake` fill gear/depth/breadth from your persona (or your overrides) for any flag you don't pass. Flags you *do* pass always win. Run a one-off under a different lens without changing your saved profile:

```bash
uv run bunnyhole trace acme.io --persona crypto_tracer
```

Every finished case now carries your `persona` and `analyst_framing`, so the dossier is framed for your line of work.

---

## 3. OpenSanctions sanctions / PEP screening

A new FollowTheMoney-native data source screens names/entities against the **consolidated OFAC / EU / UN / OFSI sanctions lists, PEP lists, and watchlists**. It runs automatically on every company/person lead (and on domain-derived company stems for sanctions-emphasizing personas).

**Keyless-first**, in order of preference:

- **Self-hosted [yente](https://www.opensanctions.org/docs/self-hosted/)** — fully keyless. Point Bunnyhole at it:
  ```bash
  export OPENSANCTIONS_API_URL="http://localhost:9000"
  # or store it in the vault: uv run bunnyhole keys --set OPENSANCTIONS_API_URL=http://localhost:9000
  ```
  (yente defaults to port 8000, which is also `bunnyhole serve`'s default: run one of them on another port.)
- **Hosted free tier** — set a key (stored in your vault via `bunnyhole keys`):
  ```bash
  uv run bunnyhole keys --set OPENSANCTIONS_API_KEY=xxxx
  ```
- **Neither** — the source degrades to a logged skip; the rest of the investigation runs normally.

Screen a name on its own, without a full investigation:

```bash
# via the MCP server tool `sanctions_screen` (e.g. from Claude Desktop)
```

**Honesty:** a sanctions/PEP hit is an *authoritative listing* (Admiralty **B2**) but a **soft name match** to your target — every hit is flagged `SOFT_NAME_MATCH_VERIFY` with a low-confidence edge. It's a lead to verify, never an onboarding decision.

---

## MCP tools

The per-instance [MCP server](MCP_SERVER.md) exposes personalization too: `get_profile`, `set_persona`, `watchlist_add`, `watchlist_remove`, and `sanctions_screen`. `trace` / `intake` / `link` honor your saved profile when run parameters are omitted.
