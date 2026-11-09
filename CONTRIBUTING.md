# Contributing to Bunnyhole

Thanks for helping. Read [`ACCEPTABLE_USE.md`](ACCEPTABLE_USE.md) first. Report security problems privately,
as described in [`SECURITY.md`](SECURITY.md), not in an issue.

## Setup

You need [uv](https://docs.astral.sh/uv/) and Python 3.11 or newer (CI tests 3.11 to 3.14).

```bash
git clone https://github.com/DreadpiratePickles/bunnyhole.git
cd bunnyhole
uv sync --extra dev            # add --extra arsenal for the optional local OSINT libraries
uv run bunnyhole --help        # or: uv run python -m bunnyhole --help
```

Optional: `pre-commit install` runs `ruff check` on the files you commit
(see [`.pre-commit-config.yaml`](.pre-commit-config.yaml)).

## Checks to run before a pull request

```bash
uv run pytest -q -o addopts=""   # the whole suite, about 30 s, no network needed
uv run ruff check .              # must be clean
uv run mypy bunnyhole            # must report no issues (blocking in CI)
uv lock --check                  # if you changed dependencies, run `uv lock` and commit uv.lock
```

CI runs the same commands on every push and pull request. It also builds the wheel, installs it into a
clean venv and runs `bunnyhole --help`, and runs a gitleaks secret scan.

## Test rules

The suite is hermetic. [`tests/conftest.py`](tests/conftest.py) enforces it:

- **No live network in tests.** A socket to a non-loopback address, a public DNS lookup, or a subprocess that
  is a network tool (holehe, sherlock, curl, `pip install` and the like) fails the test, even when the code
  under test swallows the error. Mock HTTP with [respx](https://lundberg.github.io/respx/) or monkeypatch the
  adapter. Do not loosen the guard to make a test pass.
- **A deliberate live test** gets `@pytest.mark.network`. It is skipped unless `BUNNYHOLE_TEST_NETWORK=1`
  is set, and it never runs in CI.
- **No real state.** `BUNNYHOLE_HOME` and `HOME` point at a temp dir for the whole run, so tests never read or
  write your vault, cases or installed tools.
- **No real secrets or personal data**, not even in fixtures. Use obviously fake sentinels and fictional
  selectors (`example.com`, `203.0.113.0/24`).
- Write the failing test first. Never weaken or delete an existing assertion to make a change pass. If a
  requirement changed, say so in the pull request.

## Adding a source or agent

A source is one `async` method on an agent in `bunnyhole/agents/`. The shape, in eight lines:

```python
async def investigate_example_registry(self, query: str, origin_node_id: str, hop_depth: int) -> None:
    async with new_async_client(timeout=10.0, headers=self.std_headers) as client:  # never httpx.AsyncClient()
        resp = await client.get(EXAMPLE_URL, params={"q": query})
    rcpt = EvidenceReceipt(tool="example_registry", domain=DomainCategory.FIAT, source_url=str(resp.url),
                           admiralty_code="B2", extracted_fact=f"Registry record for {query}")
    node = GraphNode(id=f"org:{query.lower()}", label=query, entity_type=EntityType.ORGANIZATION,
                     domain=DomainCategory.FIAT, receipts=[rcpt])
    self.graph.upsert_node(node)  # then upsert_edge(...) from origin_node_id to node.id
```

Then:

1. Wire it into `BunnyholeOrchestrator._execute_lead` in `bunnyhole/engine/orchestrator.py` for the lead
   types it serves.
2. Grade honestly. A failed or fuzzy lookup must never get a high Admiralty code or confidence, and a source
   that returns nothing is recorded as a negative, not as a match.
3. Validate the response shape before using it, and catch and log errors without crashing the run.
4. Add respx-mocked tests: a hit, a miss, a malformed response and an HTTP error.
5. If the source needs a key, add it to the registry in `bunnyhole/arsenal/manager.py` and to `.env.example`.
   Bunnyhole stays keyless by default, so the source must degrade cleanly without the key.
6. If the PI stream should use it, wrap the call in `_execute_lead` with the `pi("<source>", ...)` recorder
   like its neighbours, and map the source name in `SOURCE_CLASS_MAP` (`bunnyhole/engine/pi_runtime.py`), so
   every run logs it, including skips and negatives.

## The PI-stream gates are safety nets

The private-investigator stream (`--pi`, see [`docs/PI_STREAM.md`](docs/PI_STREAM.md)) has purpose gates,
phrase screens, credential redaction, and a block on breach and infostealer sources. They are deliberately
conservative and are covered by their own tests. A pull request that relaxes, removes or works around any of
them needs a discussion in an issue first, with the use case and the risk. Do not bundle such a change into
an unrelated pull request.

## Pull requests

- Keep each pull request to one change, with tests and the matching docs update.
- Do not commit generated files, caches, `.env` files, case data or anything personal.
- Describe what you ran to verify the change and what the output was.
