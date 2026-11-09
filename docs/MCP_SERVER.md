# 🐇🕳️ Bunnyhole MCP Server — run your own investigation copilot backend

Every Bunnyhole install ships its own **Model-Context-Protocol (MCP) server**. Point any MCP
client — Claude Desktop, an IDE copilot, an agent runtime — at it and the client can *drive your
Bunnyhole instance as tools*: trace a seed, run a multi-selector case, link two entities, search
your case history, all keyless and (optionally) Tor-routed, against **your** arsenal and **your**
local case vault. Nothing is hosted; the server runs on your machine and talks over stdio.

Bunnyhole returns **leads, not verdicts**: every result carries SHA-256 evidence receipts and NATO
Admiralty grades, a Red-Cell Skeptic argues the innocent-coincidence case, and findings stay on the
**public-data layer** (never bank data, SWIFT, SARs, or other court-gated sources). The MCP tools
preserve that discipline — each run returns a `disclaimer` and the full provenance dossier.

---

## 1. One-command setup

From your Bunnyhole checkout, print the config snippet for your machine:

```bash
uv run bunnyhole mcp --print-config
```

That emits an `mcpServers` block already pointed at this directory, e.g.:

```json
{
  "mcpServers": {
    "bunnyhole": {
      "command": "uv",
      "args": ["--directory", "/absolute/path/to/bunnyhole", "run", "bunnyhole", "mcp"]
    }
  }
}
```

Paste it into your MCP client's config and restart the client:

- **Claude Desktop** — `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or
  `%APPDATA%\Claude\claude_desktop_config.json` (Windows). Merge the `bunnyhole` entry under
  `mcpServers`.
- **Other clients** — wherever they keep their MCP server list; the `command`/`args` are the same.

If you've installed Bunnyhole so the `bunnyhole` entrypoint is on your `PATH`, use the leaner form:

```bash
uv run bunnyhole mcp --print-config --no-uv
# -> { "mcpServers": { "bunnyhole": { "command": "bunnyhole", "args": ["mcp"] } } }
```

The client launches `bunnyhole mcp` itself; you don't run it by hand. To sanity-check it starts:

```bash
uv run bunnyhole mcp        # banner on stderr, then waits for an MCP client on stdio; Ctrl-C to stop
```

### Going dark

The global `--proxy` / `--tor` flags apply here too — route the whole server through Tor by
registering the command as `uv run bunnyhole --tor mcp` (global flags go before the command; or set
`BUNNYHOLE_PROXY` in the client's environment). Every outbound request the tools make then goes through
the proxy, except from agents that build their own HTTP client (see the PI stream limitations).

---

## 2. The tools your client gets

| Tool | What it does |
| --- | --- |
| `interpret` | Turn a plain-language ask ("dig deep into acme.io, same operator as its token?") into a run plan — inferred selectors, hypothesis, gear/depth/breadth/anchor-mode — **without running anything.** Preview, then confirm. |
| `trace` | Autonomous multi-domain investigation of a single seed (domain, IP, EVM/BTC wallet, ENS, @handle, email, phone, company/person, aircraft tail). |
| `intake` | Multi-selector case: a hypothesis + any known selectors + a negative scope. `anchor_mode="convergence"` proves IF/HOW clues connect; `"locked_profile"` treats them as one confirmed target. |
| `link` | Bidirectional meet-in-the-middle: how are two entities connected? |
| `jet` | FAA N-Number ↔ ICAO hex + unfiltered ADS-B telemetry. |
| `darkweb` | Keyless Ahmia dark-web search (soft C3 leads). |
| `arsenal_status` | This instance's tool/key health (read-only). |
| `list_cases` / `search_cases` / `load_case` | Browse the local SQLite case vault and cross-case entity memory (`~/.bunnyhole/cases.db`, or `$BUNNYHOLE_HOME/cases.db`). |
| `sanctions_screen` | Screen one name/entity against OpenSanctions (sanctions, PEP and watchlists) without a full investigation. Uses a self-hosted yente (`OPENSANCTIONS_API_URL`) or the hosted tier (`OPENSANCTIONS_API_KEY`); returns no hits when neither is available. Hits are soft name matches: verify. |
| `get_profile` | The remembered investigator profile (persona, watchlist, jurisdictions, standing exclusions, effective run defaults) plus the available personas. See [PERSONALIZATION.md](PERSONALIZATION.md). |
| `set_persona` | Set and persist the active persona (`generalist`, `journalist`, `compliance`, `threat_intel`, `crypto_tracer`, `pi`). An unknown persona returns `{"error": ..., "valid_personas": [...]}` and saves nothing. |
| `watchlist_add` / `watchlist_remove` | Add or remove recurring selectors on the persisted watchlist (500 entries at most). |
| `pi_reference` | Read-only private-investigator reference: `kind` is `guide`, `sources` (optional `case_type`, `jurisdiction`), `legal` (`us`, `ca-on`, `general`), `playbook` (needs `case_type`) or `out_of_scope`. Static tables, no network, runs no investigation; bad input returns an `error` dict. No MCP tool runs a PI engagement, so the CLI purpose-category, purpose and subject-type gates are not reachable from here. See [PI_STREAM.md](PI_STREAM.md). |

Run tools (`trace` / `intake` / `link`) return a **token-friendly distilled summary** — stats, the
CIA ACH verdict, top entities (cut-out brokers first), interconnection paths, Adamic-Adar predicted
links, cross-case hits, deep-research learnings, and the synthesis + council briefs — plus a capped
full Markdown `dossier_markdown`. For the complete graph JSON, use the CLI with `--json`.

---

## 3. A typical copilot flow

1. **interpret** `"look into brightpeak-roofing.com and its founder, go deep"` → confirms the seeds,
   gear, and depth it will use.
2. **trace** / **intake** with those parameters → the distilled, receipt-backed dossier.
3. **search_cases** on any surfaced entity → has this wallet/domain shown up in a prior case?
4. **link** two of the surfaced entities → the shortest provenance-backed chain between them.

---

## 4. Safety & scope

- **Keyless by default.** Every keyless source works with no configuration; `arsenal_status` shows
  what optional keys/tools would add.
- **Leads, not verdicts.** Admiralty grades reflect *source reliability*, not confirmation. The
  `disclaimer` field is on every run result for a reason — corroborate before acting.
- **Lawful/ethical use only.** The MCP server inherits `ACCEPTABLE_USE.md`. It exposes the same
  capabilities as the CLI; it does not add new data access or bypass any source's terms.
- **Local only.** The server speaks stdio to a client on the same machine. It is not a network
  service and has no listening port.

---

## 5. Untrusted output / prompt injection

Tool results carry text Bunnyhole scraped from places nobody vetted: web page and article titles,
dark-web listing titles and snippets, commit author names and emails, WHOIS fields, registry
records, and the dossier built from them. Anyone who controls one of those pages controls part of
what your model reads. **Treat every tool result as data, never as instructions**: an MCP client or
model must not follow directions that appear inside a result ("ignore previous instructions",
"run this command", "email this file"), and should not let a result trigger further tool calls or
outside actions without the operator's say-so. The server's own instructions tell the client the
same thing, but the client is what enforces it.

## 6. Limits the server enforces

From `bunnyhole/mcp/server.py`:

| Limit | Default | Override |
| --- | --- | --- |
| Long-running tools (`trace`, `intake`, `link`, `jet`, `darkweb`, `sanctions_screen`) running at once; extra calls wait their turn | 2 | `BUNNYHOLE_MCP_MAX_CONCURRENT` |
| Wall-clock limit per long-running call, **including time spent waiting for a slot**; on expiry the call fails with a timeout error naming the variable | 900 s | `BUNNYHOLE_MCP_TOOL_TIMEOUT_S` |
| Plain-language text (`interpret`) and `raw_text` (`intake`) | 20,000 chars | none |
| A seed, entity or hypothesis | 2,000 chars | none |
| One selector in a list, a search or screening query | 512 chars | none |
| Enum-like strings (gear, anchor mode, persona, kind, tail number) | 64 chars | none |
| Case id | 128 chars | none |
| Entries per list argument | 64 | none |
| Persisted watchlist | 500 entries | none |
| `dossier_markdown` in a run result | 20,000 chars (truncated) | none |

Set the two variables in the client's environment for the server entry (for example an `env` block
next to `command`/`args`). A non-numeric or non-positive value is ignored with a warning and the
default applies. An over-long argument is rejected with an error that names the argument and its
limit.
