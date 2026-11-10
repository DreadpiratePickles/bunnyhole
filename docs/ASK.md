# `bunnyhole ask`: ask in plain English

```bash
uv run bunnyhole ask "see if Acme Ltd is connected to Globex Inc"
uv run bunnyhole ask "see if Dalia Tech Ltd has anything shady going on" --out answer.md
```

`ask` reads one sentence, works out which existing investigation answers it, runs that, and prints a short sourced
answer. The sentence is parsed by fixed patterns in `bunnyhole/engine/ask.py`: no model and no network are used to
understand the question. The only network and model use is what the underlying investigation already does.

## What it understands

| Intent | Example phrasings | What runs |
| --- | --- | --- |
| Connection between two entities | "see if X is connected to Y", "is X linked to Y", "any ties between X and Y", "does X have anything to do with Y", "how is X connected to Y", "find the link between X and Y" | The Link Sleuth bidirectional investigation (`bunnyhole link`) |
| Risk checklist for one company | "see if X has anything shady going on", "is X legit", "any red flags on X", "check X for fraud", "can I trust X" | The organisation trace (`bunnyhole trace`) through the `compliance` persona (sanctions emphasis) |

X and Y can be a person, a company or a domain (`daliatech.ca`). Put a name in quotes when it contains "and" or
filler words (`"Smith and Sons Ltd"`). A risk question may also name a person ("see if Acme Ltd run by Jane Smith has
anything shady going on"): it then runs the link investigation between the two and shows both the checklist and the
chains. Anything else prints the supported shapes and exits 2; use `trace`, `link` or `intake` for it.

## The answer

- **Connection.** Either `Connection found` with each chain (every hop's relation, confidence and receipt ids, labelled
  confirmed, probable or lead by the same independent-source rule the PI report uses; the weakest hop labels the
  chain), or `No connection found in the sources searched; absence is not proof.` followed by the sources searched
  and the sources that were unavailable.
- **Company risk.** A fixed seven-check list built from the finished graph by code: sanctions and PEP screening
  (including which lists were not screened), registry status and officers or ownership, litigation, adverse media,
  domain age, leaked-data mentions, and ownership opacity or shell indicators. Each check is `signals found`,
  `nothing found in sources searched` or `not checked or unavailable`, with the receipt ids behind any signal. Look-alike
  domain detection does not exist in this version and is reported as not checked.
- `--out FILE` writes the same answer as Markdown. `--json FILE` writes the full graph JSON, as `trace` does.

## The honesty rule

`ask` never says two entities are "not connected", never calls a company clean or safe, and never upgrades a label. A
check is only `nothing found` when the run shows the source ran; otherwise it is `not checked or unavailable`. Every
risk answer ends with: "No hit is not clearance. This lists signals found in public sources; it is not a finding of
wrongdoing." Name matches against sanctions lists are soft (verify identifiers). News flags come from headline
keywords. CourtListener covers US federal dockets only. The run log the checklist reads keeps the last 100 events, so a
list whose scan fell out of the log is shown as not confirmed rather than screened.

## Person gates (PI mode)

Naming a person (or a personal identifier such as an email or handle) makes the run a private-investigator engagement.
The gates are the existing ones from `trace --pi` (`pi_commands.resolve_pi_flags`), not a copy: without a vetted
`--purpose`, `--purpose-category` and `--matter-ref` the command prints the same refusal and exits 2 before anything is
investigated. `--pi-report`, `--no-ai-analysis` and `--pi-jurisdiction` work as on `trace`.

```bash
uv run bunnyhole ask "is Jane Smith linked to Acme Ltd" --pi \
  --purpose "vet a counterparty before signing a supply contract" \
  --purpose-category counterparty_due_diligence --matter-ref "MSA-2026-114" --pi-report report.md
```

A company-only question needs no PI mode (add `--pi` to run it as an entity engagement). A two-word company name with no
legal form ("Blue River") reads as a person and is gated; add its legal form (Ltd, Inc, LLC) or its domain. The PI
subject of a connection question is the first person named.

## What it will not do

It will not answer free-form questions, read local files named in a sentence, bypass or soften a PI gate, call a
language model to interpret the question, or state a verdict about a person or company. Results are leads to verify.
See [`ACCEPTABLE_USE.md`](../ACCEPTABLE_USE.md) and [`PI_STREAM.md`](PI_STREAM.md).
