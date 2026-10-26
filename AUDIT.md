# Bunnyhole — Security & Code-Quality Audit

**Date:** 2026-10-24
**Scope:** Full codebase (~10,500 LOC across engine, agents, API, CLI, arsenal, scripts) plus packaging and project hygiene.
**Method:** Static review of every module, three parallel domain audits (agent modules; API/CLI/scripts; packaging/tests), empirical verification of key findings (SSRF guard, vault hardening, receipt collection, FastAPI hardening via `TestClient`), and the existing test suite (8/8 passing throughout).

Status legend: **[FIXED]** applied in this pass · **[OPEN]** documented backlog (needs product/analyst judgment or larger refactor).

---

## 1. Executive summary

Bunnyhole is a genuinely sophisticated, well-structured investigative engine. The deterministic cores are correct (the FAA N-number ↔ ICAO-hex codec round-trips cleanly over all 915,399 values; the Beneish M-Score formula matches the 8-variable model; the HIBP k-anonymity range check is sound). The architecture — a provenance-backed graph with NATO Admiralty grading, a Red-Cell skeptic, an ACH matrix, and a 3-stage LLM council — is coherent and unusually thoughtful.

The problems clustered in three areas:

1. **A real security exploit chain in the Web War-Room** — untrusted OSINT data rendered via `innerHTML` (DOM XSS) reaching an unauthenticated local API that accepted arbitrary environment-variable names (`PATH`/`LD_PRELOAD` → code execution). This chain is now broken.
2. **Epistemic over-claiming** — many API results were stamped `A1`/`B1` at 0.9–1.0 confidence regardless of whether the match was exact, fuzzy, or a *failed* lookup, undermining the grading framework the tool is built around.
3. **Operational fragility** — no shared HTTP layer (no retries/rate-limits/pooling), wholesale `except: pass`, and no version control, lockfile, CI, or license.

This pass fixed every clear-cut security and correctness bug and established project hygiene. The remaining backlog (Section 4) is mostly confidence-calibration work that changes analytic behavior and should be done with the author's judgment.

---

## 2. Fixes applied in this pass

### Project hygiene & packaging
- **[FIXED]** Initialized git, added `.gitignore` (ignores `.venv`, caches, `*.db`, `.env*`, `api_keys.env`).
- **[FIXED]** Added `LICENSE` (MIT) and `ACCEPTABLE_USE.md` (responsible-use policy for a dual-use tool).
- **[FIXED]** `pyproject.toml`: added `dev` extra (pytest, pytest-cov, respx, ruff, mypy), tool config (ruff, mypy, pytest), full metadata (license, authors, keywords, classifiers, urls), and an explicit hatch wheel target.
- **[FIXED]** Generated `uv.lock` (109 packages pinned).
- **[FIXED]** Added `.github/workflows/ci.yml` (ruff + mypy + pytest on 3.11/3.12), `.env.example` (corrected to the real registry key names), and a `py.typed` marker.

### Security — the critical chain
- **[FIXED]** **Env-injection → RCE.** `ArsenalManager.set_api_key` and `load_api_keys_into_env` now enforce an **allow-list** (`ALLOWED_KEY_NAMES`, derived from the registry) plus a name regex. `PATH`, `LD_PRELOAD`, `PYTHONPATH`, etc. are rejected on write and ignored on load, even from a tampered vault file. (`arsenal/manager.py`)
- **[FIXED]** **Plaintext world-readable secrets.** The vault dir is `0700` and the file is written `0600` atomically via a temp-file + `os.replace`. (`arsenal/manager.py`)
- **[FIXED]** **Vault leaked unrelated env secrets to disk.** Removed the `os.environ.get(rk, "")` fallback that persisted any exported secret; only keys already in the file plus the one being set are written.
- **[FIXED]** **Comment-truncation parser bug.** Values containing `#` are no longer truncated (split only on `" #"`).
- **[FIXED]** **DOM XSS in the War-Room UI.** Added `esc()`/`escAttr()`/`safeUrl()`/`jsStr()` helpers and applied them to every interpolated OSINT field (node/edge labels, receipt facts, ACH rows, learnings, timeline, keystones, paths, predicted links, council opinions, research files). `source_url` is scheme-validated to `http(s)`; inline-handler arguments are sanitized. (`api/server.py`)
- **[FIXED]** **Unauthenticated / DNS-rebindable API.** Added `TrustedHostMiddleware` (loopback only, blocks rebinding), a security-headers + CSP middleware, and an **optional per-launch bearer token** (`BUNNYHOLE_API_TOKEN`) enforced on all mutating routes and auto-injected into the first-party UI. (`api/server.py`)
- **[FIXED]** **DoS / unbounded memory.** `ACTIVE_CASES` is now a bounded LRU; investigations run under a concurrency semaphore; request bodies are size/selector-capped; `install_tool` runs via `asyncio.to_thread` instead of blocking the event loop. (`api/server.py`)
- **[FIXED]** **SSRF.** New `engine/netutil.py` (`host_is_public`, `assert_public_url`, `is_safe_selector`) blocks private/loopback/link-local/metadata targets. Wired into the site-fetch path; Scrapling now runs off the event loop and httpx auto-redirects are disabled so a 3xx can't bounce to an internal host. (`agents/osint.py`)
- **[FIXED]** **Subprocess argv injection + process leaks.** whois/subfinder/sherlock/holehe selectors are validated (`is_safe_selector`, blocks leading `-` and shell metacharacters); a shared `_communicate()` helper kills and reaps children on timeout. (`agents/osint.py`)
- **[FIXED]** **Cleartext key over HTTP.** Numverify switched from `http://` to `https://`. (`agents/osint.py`)
- **[FIXED]** **Legacy scripts quarantined.** `scripts/osint_orchestrator.py` (shell-injection, broken vault parser, key leakage — and unused) now refuses to run without `BUNNYHOLE_ALLOW_LEGACY=1` and documents the maintained replacement. Installer `--check` is genuinely non-destructive; `os.geteuid()` is Windows-guarded.

### Correctness
- **[FIXED]** **Citation ledger dropped all edge evidence.** `InvestigativeSynthesizer._collect_indexed_receipts` collected receipts from nodes only; it now includes edge receipts (matching the council). This was the single highest-value correctness bug — most relationship proof was silently missing from the brief. (`engine/synthesizer.py`)
- **[FIXED]** **HIBP failed-lookup reported as a high-confidence finding.** A timeout/non-200 left `pwned_count = 0`, which was read as "highly distinctive secret" (`A1`, 0.99) and clustered accounts. Now tracks `lookup_ok`; a failed lookup is `F6`/UNKNOWN, common passwords no longer create a clustering edge, and plaintext characters are no longer logged. (`agents/osint.py`)
- **[FIXED]** **URLScan key leaked to AlienVault.** The httpx client's default headers (with the URLScan `API-Key`) merged into the OTX request; secrets are now passed per-request only. (`agents/osint.py`)
- **[FIXED]** **Wikipedia whitewash sign reversed.** Revisions are newest-first, so `prev_size - size` measured bytes *added* and misattributed the editor. Now iterates oldest-first. (`agents/journalist.py`)
- **[FIXED]** **Unstable node IDs.** `abs(hash(...))` (salted per process) replaced with `hashlib` so articles/dockets dedupe across runs and cross-case memory works. (`agents/journalist.py`)
- **[FIXED]** **Crash on Bitcoin coinbase txs.** `v.get("prevout", {})` returned `None` for coinbase inputs and aborted the whole analysis; guarded with `(v.get("prevout") or {})`. (`agents/onchain.py`)
- **[FIXED]** **GoPlus flag dedup never fired** (checked `f`, appended `GOPLUS_{f}`). (`agents/onchain.py`)
- **[FIXED]** **TUI menu item 1 crashed** (`TypeError: 'OptionInfo' object is not iterable`) because the TUI omitted most `trace_command` options; all parameters are now passed explicitly. (`cli/main.py`)
- **[FIXED]** **Rich markup injection** from hostile OSINT strings could crash the CLI; agent-log fields are escaped with `rich.markup.escape`. (`cli/main.py`)
- **[FIXED]** CLI key prompt uses `password=True`; `serve --host` warns on non-loopback binds and when no token is set. (`cli/main.py`)

---

## 3. Verification

| Check | Result |
| :--- | :--- |
| Test suite | 8/8 passing before and after all changes |
| SSRF guard | blocks `127.0.0.1`, `169.254.169.254`, `10.x`, `localhost`, `::1`; allows public IPs |
| Vault | file `0600`, dir `0700`; `#`-containing values survive roundtrip; `PATH`/`LD_PRELOAD` rejected and ignored on load |
| Server | CSP + `X-Frame-Options` present; `/api/keys` rejects `PATH` (400); oversized body 422; spoofed `Host` 400; token 401/200 |
| Synthesizer | now collects edge receipts (was 0, now matches council) |

---

## 4. Open backlog (prioritized — not yet changed)

These are real findings deferred because they change analytic behavior (confidence semantics), need live-API testing, or are larger refactors. Ordered by value.

### High
1. **Shared HTTP layer.** 29 ad-hoc `httpx.AsyncClient` constructions with no pooling, retries, backoff, or rate-limiting. SEC EDGAR requires a real contact in the User-Agent (currently fake `research@bunnyhole.local`) and a 10 req/s cap that isn't enforced. Build one `HttpClient` (pooled, retrying, compliant UA, redirect-safe) and route all agents through it.
2. **Confidence recalibration (systemic).** Fuzzy/substring matches are stamped `A1`/`B1` at 0.9–1.0 across: GLEIF/ProPublica name matches → `LINKED_IDENTITY` (`accountant.py`); SEC EFTS full-text hits → `FILED` 0.98 and Beneish run on an arbitrary CIK (`accountant.py`); OpenAlex/co-occurrence substring matches (`journalist.py`, `link_sleuth.py`); ADS-B "operator" claims at 0.95 (`accountant.py`); DexScreener base/quote confusion and `SWAPPED_IN` using pool liquidity as amount (`onchain.py`); THORChain memo decode without router check (`onchain.py`); Bitcoin CIOH treating CoinJoin as same-owner (`onchain.py`); ENS text records (self-asserted) at `A1`/0.99 (`onchain.py`); first-funder ignoring `isError`/internal txs (`onchain.py`). Each should score the match and downgrade non-exact ones.
3. **IP lead misattribution.** `investigate_ip_shodan_and_ripestat` treats `origin_node_id` as the IP's own node, so a lead-driven IP lookup merges Shodan ports/CVEs into the *origin* node (e.g. a Wikipedia article) and never creates the IP node. (`agents/osint.py`)
4. **`extract_entity_stem` TLD/boundary bugs.** `.co`/`.eth` matched inside `wallet.coinbase.com`/`foo.ethereum.org` (returns `''`); agent label prefixes leak into stems. Produces junk lateral leads. (`agents/link_sleuth.py`)
5. **Document forensics** (`journalist.py`): unvalidated path, no extension/size caps (zip-bomb), runs synchronously in the async loop, emits an `A1` receipt even on error, and leaves the node orphaned (`origin_id` computed but unused).
6. **`all_simple_paths` exponential blowup** on dense graphs, run synchronously (`link_sleuth.py`); use `itertools.islice` + a node/time budget.

### Medium
7. Error handling: ~38 `except: pass` / bare `except:` across agents swallow data and failures silently — convert to specific exceptions + a warning-level log.
8. GitHub push-event commits attribute co-committers' emails to the target (`osint.py`); keep only emails matching the profile.
9. Favicon fetched without a `Content-Type: image/*` check, so SPA HTML gets hashed as a shared "favicon" fingerprint (`osint.py`).
10. Phone parsing (`+1` assumptions, wrong country-code slicing); adopt the `phonenumbers` library.
11. SEC `form.startswith("D")` matches DEF 14A etc.; smoke overwritten instead of `max()` (`accountant.py`).
12. CDN-IP guardrail never fires because it checks the emoji label, not the IP (`graph.is_shared_cdn_ip` + `osint.py` node labels).
13. Analytics recomputation: `run_skeptic_network_analytics()` (betweenness centrality) runs 3×/finalize and `analyze_interconnected_web()` 2×; compute once and pass through (`orchestrator.py`, `graph.py`). `to_dict()` also has analytic side effects — separate analyze from serialize.
14. Credential combo: email never becomes a node; unsalted 16-hex SHA-256 prefix in exports is dictionary-attackable (`osint.py`).

### Low
15. Dead code: `run_exiftool` unused (`scripts`), several unused imports across agents, misleading module docstrings (accountant advertises FEC/sanctions/USAspending not implemented).
16. Duplication: Google-News/CourtListener fetch logic duplicated in `journalist.py` and `link_sleuth.py`; the two `scripts/` files duplicate package code (recommend deletion — they are not imported anywhere).
17. Modernize default LLM model identifiers in `synthesizer.py`/`council.py`.
18. Test coverage: only pure helpers are tested (~250 lines for ~10k LOC). Add `respx`-mocked tests for agents, orchestrator, storage, and the FastAPI routes via `TestClient`, and a `conftest.py` that isolates `HOME` and blocks network so tests never hit live APIs or load the user's real keys.

---

## 5. Not defects (verified correct)
- `n_number_to_icao_hex` / `icao_hex_to_n_number` — 0 mismatches over all 915,399 N-numbers.
- Beneish M-Score coefficients and formula — match the published 8-variable model.
- CORS config — correctly scoped to localhost (not a wildcard with credentials).
- `ArsenalManager.install_tool` — already uses `shell=False` with a catalog allow-list.
- SQLite layer (`storage.py`) — fully parameterized, no injection.
