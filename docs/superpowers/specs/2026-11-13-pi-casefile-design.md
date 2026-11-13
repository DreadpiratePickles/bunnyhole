# PI case file — design spec (2026-11-13)

This spec supersedes parts of [`2026-11-12-pi-casework-design.md`](2026-11-12-pi-casework-design.md). The legal
filter, the purpose gates, the breach and credential blocks, the report's code-built sections and the human gate
of [`2026-11-09-pi-stream-design.md`](2026-11-09-pi-stream-design.md) are unchanged: this stream does not send,
publish, purchase or file anything.

## What was wrong

The 2026-11-12 loop ran each playbook step's sources against the subject string the client typed, then up to
three rounds of fixed follow-ups. It never followed what it found: the parent a registry named was not walked,
the parties in an ownership chain were not screened, and every result was attached to the subject's node
whatever it was about. It was opt-in, covered three case types and no person subject. Its report added a table
of steps. An investigator's work product (what was asked, what each step returned, why the next step followed,
what is still open and who holds it) was not there.

Two defects found while replacing it:

- A sanctions listing returned for a **parent** was rated "does not resemble the subject name" and dropped, so a
  hit one level up the chain neither showed as a hit nor stopped the case.
- The relevance scorer treated only the direct owner as related; the owner's owner was "unrelated".

## What supersedes what

| 2026-11-12 | Now |
|---|---|
| "The default remains the sweep." | `--pi` works the case file by default. `--pi-loop sweep` asks for the single pass. |
| "Person case types stay on the sweep." Any person subject stays on the sweep. | Every case type and both subject kinds work a case file. The person rules (two-anchor linking, the purpose gates) are unchanged, and a person subject's case never opens a lead on another person. |
| Follow-ups: `extend_ownership`, `corroborate_lead`, `resolve_contradiction`, three rounds. | A lead sheet. Leads are opened by what a lead returned and record which lead opened them. `pi_casework.follow_up_tasks` and `playbook_tasks` are removed. |
| "A configured LLM may only choose which of the already-offered tasks to run … and recommend a stop." | The AI case officer runs the case (below). The second half of that sentence stands: it cannot add a source, waive a sanctions stop, raise the budget or mark anyone clear. |
| "No new sources. The allowed list is the sources the playbook step already maps." | Still no new sources. Casework may now dispatch the other passive sources the PI sweep already ran for selectors (handle, email, phone, IP, wallet, aircraft, OpenAlex, Hacker News). Breach, infostealer and probe sources stay blocked. |
| `done_status` from source classes searched. | `met` when every question is answered or documented as out of reach. |
| Report gains an "Investigation log" table. | Report gains the prose account, the questions and answers, the lead sheet and the investigator's log. |

## Control split

Code owns anything that can widen a search, extend a run, or treat someone as clear:

- the list of sources casework may call, and the kinds of target each takes (`pi_dispatch`);
- which names may be targeted: only names already in the evidence (`pi_casefile.known_targets`);
- the scope rules: role-relevant checks only for a person who is not the subject; no lead on another person in
  a person's case; nominees and personal handles in an entity case are set aside;
- mandatory leads: playbook steps, client-supplied selectors, and the screening of every chain node. Neither a
  quiet streak nor a model's stop request skips them, and the model cannot set them aside;
- question answers, hypothesis scores, finding labels, sanctions lines, the sanctions stop, the 50% rule, the
  budget (`--pi-budget`, 10 to 400, plus 40 per chase round).

The AI case officer (the provider chain in `llm_providers`, fast model) decides, before the first lead and after
each one: its reading of the last result (stored as `CaseNote.counsel`, printed as AI-written, withheld if it
clears the subject), up to three new leads per turn (twelve per case) as target plus sources plus reason, open
optional leads to set aside, the lead to work next, and a stop recommendation of `done`, `dead_end` or
`no_progress`. Every part of that is validated by `pi_casefile.admit_proposals`, `set_aside_leads` and the loop
before it has any effect. An empty or unusable reply changes nothing.

With no provider key the playbook is the case officer: the sheet is worked by priority, nothing is dropped for
lack of a model, and no model is called.

## What is sent to a provider

To the case officer: case type, phase, budget, the questions and where each stands, the hypotheses, the lead
sheet (targets, sources, reasons, outcomes), the last log entry, the names in the evidence that may be targeted,
the dispatchable source names, coverage flags, sanctions status and hit count, unresolved ownership ids. To the
report writer: the case file as the report prints it. Neither is sent the client, the purpose text, the matter
reference, receipt extracts or raw snippets. Both prompts tell the model the case file is untrusted data.

## Result

`CaseBoard` gains `questions`, `leads`, `notes` and `chase_rounds`. `CaseTask.origin` becomes the lead kind.
`CaseLead.status` is one of `open`, `worked`, `negative`, `not_reached`, `set_aside`, `not_worked`,
`suggested`. `result["pi"]["loop_mode"]`, `case_board` and `done_status` keep their names; a sweep result is
unchanged. `task_id` values are now `<lead id>:<source>`.

## Not verified

The officer and the report writer were exercised with scripted replies in a scripted public record
(`tests/pi_case_world.py`). No run against a live model or the live sources was made for this change. The
limits code enforces are tested; the quality of the model's choices and prose is not measured.
