<!-- generated-by: gsd-doc-writer -->
# PI casework loop — design spec (2026-11-12)

This spec supersedes one sentence of [`2026-11-09-pi-stream-design.md`](2026-11-09-pi-stream-design.md), in section 1 (Outcome):

> Single pass (rulebook principle 17 loop check: no executable oracle needing 4+ rounds).

The next sentence of that spec is not superseded. Human gates are unchanged: this stream does not send, publish, purchase, or file anything.

## Why that sentence changes

The 2026-11-09 spec kept the case-type playbook as a report the human reads after one sweep. The run took the playbook objective, searched once, and scored playbook progress afterwards. The order of work, the stop-ifs, and the escalation triggers guided the human. They did not drive the run.

Casework runs the playbook in order for entity `due_diligence`, `asset_search`, and `fraud_screen`. It opens a hypothesis board from that playbook, runs each step's mapped sources, re-scores the board after each step, and stops with a stated reason.

The default remains the sweep. This spec does not flip it. The rest of the 2026-11-09 spec stands, including the legal filter, the gates, and the report. The playbook order itself is unchanged; it is the table in [`docs/PI_STREAM.md`](../../PI_STREAM.md) section 6 and the text from `bunnyhole pi playbook <type>`.

## Flags

Both flags require `--pi`.

- `--pi-loop` takes `casework` or `sweep`. `casework` is the loop in this spec. `sweep` is the 2026-11-09 single pass. The default remains `sweep` until a later measured flip.
- `--pi-budget` is an integer from 10 to 400 inclusive. It caps source calls.

Passing either flag without `--pi` is not a casework run.

## Who stays on the sweep

Person case types stay on the sweep: `locate`, `background`, and `missing_person`. Any person subject stays on the sweep, including a person named on `due_diligence`, `asset_search`, or `fraud_screen`.

When casework was asked for and the run stays on the sweep for that reason, the skip is logged in these words:

`person case types use the sweep in this release`

Casework runs only when `--pi` and `--pi-loop casework` are set, the case type is `due_diligence`, `asset_search`, or `fraud_screen`, and the subject is an entity.

## What does not change

- No gate change. Purpose, category, matter reference, and the refusal exits are the same.
- No credential change. `--cred` stays out.
- No breach change.
- No holehe change.
- No new sources. The allowed list is the sources the playbook step already maps.

Non-PI `trace`, `intake`, and `link` are unchanged. The TUI, the API, and MCP are unchanged.

## Control split

Code owns the calls that can widen a search, extend a run, or treat someone as clear:

- Hypothesis scores, from a fixed signal table. The model does not assign scores. The board is re-scored from that table after each playbook step.
- The sanctions stop and the 50% rule stop.
- The budget (`--pi-budget`, bounded 10 to 400).
- The allowed source list.

A configured LLM — the existing provider chain in `bunnyhole/engine/llm_providers.py` — may only:

- Choose which of the already-offered tasks to run, so the budget is spent on a subset of those checks.
- Recommend a stop reason of `done`, `dead_end`, or `no_progress`.

The model cannot add a source, waive a sanctions stop, raise the budget, or mark anyone clear.

With no provider key, every offered task runs in playbook order. Nothing is dropped for lack of a model, and there is no model stop recommendation.

## Stop reasons

The run records one of: `done`, `escalated`, `dead_end`, `budget_spent`, `no_progress`.

A sanctions hit or a 50% rule block stops the run. Later playbook steps stay not run. That stop is recorded as `escalated`. The model cannot waive it.

A crypto cash-out is not a case stop. It stops further crypto tracing. The rest of the case continues.

`budget_spent` is the source-call cap. Code enforces it. The model cannot raise it.

`done`, `dead_end`, and `no_progress` are the reasons the model may recommend. A recommendation does not override a sanctions stop, the 50% rule, the budget, or the source list, and it is never a clearance.

## Result

`result["pi"]` gains three fields. They are additive. No existing field is removed or redefined, so old consumers stay valid.

- `loop_mode` — `casework` or `sweep`. The default is `sweep`.
- `case_board` — the hypothesis board, including the scores from the last re-score.
- `done_status` — `met`, `not_met`, or `not_evaluated`. This is the automated done-when check. It is not the stop reason. The stop reason is `case_board.stop_reason`. A sweep, including a person case kept on the sweep, stays `not_evaluated`.

On a sweep, including a person case that was kept on the sweep, the three fields are still present at defaults that do not change the meaning of the previous `result["pi"]` payload. Readers that ignore unknown keys keep working.
