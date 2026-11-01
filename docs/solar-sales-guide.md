# ☀️ Bunnyhole for Solar Sales — A Field Guide

*For selling solar-panel self-cleaning technology to solar companies — IPPs, utilities, EPCs and O&M contractors — anywhere, with a focus on India.*

This guide is for the person doing the selling, not the person who wrote the code. You do not need to know Python. You need a terminal, two commands to remember, and ten minutes.

---

## 1. What this actually does for you

Bunnyhole's solar mode answers three questions you ask before every deal:

1. **Who should I chase first?** — it ranks solar companies by how "ready to buy" they look right now, from public news.
2. **How do I get in the door?** — for any one company, it finds every lawful way to reach the people who own the cleaning budget, and tells you which to use first.
3. **What do I say?** — for a named person you're about to meet, it pulls what they've said in public and hands you openers, questions and talking points.

It only ever uses information that is public and professional: company websites, news, conference programmes, filings, tenders, patents, papers. It does **not** dig into anyone's private life, and that is on purpose — more on that in section 9. Think of it as the research a sharp analyst would do before every call, done in a minute.

> **The one idea to hold onto:** you are not selling cleaning. You are selling **recovered electricity and removed risk**. Every number the tool gives you is there to make that case to a specific person.

---

## 2. One-time setup

You need [uv](https://docs.astral.sh/uv/) (a Python runner) and Python 3.11+. Then, once:

```bash
git clone https://github.com/DreadpiratePickles/bunnyhole.git
```

```bash
cd bunnyhole
```

```bash
uv sync
```

That's it. It works with no API keys and no paid accounts. Every command below is run from inside the `bunnyhole` folder and starts with `uv run bunnyhole`.

If you ever get stuck:

```bash
uv run bunnyhole solar --help
```

---

## 3. The weekly rhythm

Do these four things, in this order, and the tool earns its keep:

| When | Command | What you get |
| --- | --- | --- |
| Monday, pick your week | `solar sweep` | A ranked list of which companies to chase now |
| Before you reach out | `solar scout <company>` | Every way into that company + a 90-day plan |
| Before any meeting | `solar profile "<name>" --company "<co>"` | What that person has said, and what to ask them |
| Whenever you're unsure | `solar playbook <topic>` | The reference: events, tactics, India, the law |

The rest of this guide is just those four commands in detail.

---

## 4. Step 1 — Find who to chase: `solar sweep`

This scans a built-in list of real solar companies, reads the public news about each, and scores how "hot" each looks: a plant just commissioned, an O&M contract reopening, a water restriction, a competitor's cleaning robot going in — these are the moments a buyer is reachable.

Start with India, where soiling is worst and budgets are live:

```bash
uv run bunnyhole solar sweep --region india --limit 15
```

Only want companies that **already** bought automated cleaning (they're educated — you differentiate instead of explaining)?

```bash
uv run bunnyhole solar sweep --tag robotic_cleaning_adopter
```

Narrow it further any way you like:

```bash
uv run bunnyhole solar sweep --region mena --type ipp --front-door
```

**How to read it:** each row has a **Heat** score and a band — `HOT`, `WARM`, `COLD` — plus the **top triggers** (why it's hot) and the latest headline. Start your week at the top of the list. `--front-door` also checks each company's website for a supplier-registration page (slower, but tells you where to register).

The useful tags to filter on: `robotic_cleaning_adopter`, `dusty_fleet`, `innovation_program`, `listed`, `in_house_om`, `public_tender`, `epc_om_channel`.

To see the whole target list and why each is ranked:

```bash
uv run bunnyhole solar targets --region india
```

---

## 5. Step 2 — Get into one company: `solar scout`

This is the core command. Point it at a company you want to sell to and it builds a full **Approach Plan**.

```bash
uv run bunnyhole solar scout "Adani Green" --out adani-plan.md
```

Works on a website too, and you can tell it the region and company type if it's not one it already knows:

```bash
uv run bunnyhole solar scout https://some-ipp.com --region india --type ipp --gear deep --out plan.md
```

Open the `.md` file it writes — that's your plan. It has ten parts; here's what each is for:

1. **Heat** — is now a good time, and why (the dated signals).
2. **Decision-making unit** — the roles you need to reach, in order: who champions, who decides, who signs, who can block. Each row tells you what that person cares about, what they're afraid of, and the pitch angle that lands.
3. **Ranked routes** — *every lawful way in*, best first. "CONFIRMED" means the tool checked the company's live website and found that door (a leadership page, a vendor-registration portal); "CATALOG" means it's a known route for this kind of company. Each has a cost, a rough time-to-meeting, and a first step.
4. **Sequenced plan** — the routes arranged into a 90-day campaign: prepare, open doors, get in the room, pilot to contract.
5. **Buying signals** — the dated news that makes this company worth your time now.
6. **Where they gather** — the exact conferences and programmes their O&M people attend.
7. **Regional notes** — how to sell in their part of the world.
8. **Compliance** — the outreach rules where they are (so you don't get flagged as spam).
9. **Key assumptions** — what the plan is quietly betting on, flagged red/yellow/green, so you know what to double-check.
10. **Receipts** — the source link behind every confirmed route and signal. Click them; verify before you act.

**What to do with it:** work the plan top to bottom. Register on the vendor portal in week one (it takes weeks to clear). Get your proof pack ready — an abrasion test and a module-maker compatibility letter — because the number-one fear of every buyer is that cleaning scratches their panels. Then open the warm-intro and direct routes the plan ranks highest.

Use `--gear deep` when a company is worth the extra couple of minutes; it also probes the website harder for hidden supplier and careers portals.

---

## 6. Step 3 — Prep for the meeting: `solar prep` and `solar profile`

Once you have a name and a meeting, prepare. **A company is always required** — these only work on someone in their professional role.

Quick conversation brief (what they've said on stage and in print):

```bash
uv run bunnyhole solar prep "Jane Doe" --company "Some IPP" --role "Head of O&M" --out jane-brief.md
```

Fuller professional profile (adds the company's own published bio of them and any patents they're named on):

```bash
uv run bunnyhole solar profile "Jane Doe" --company "Some IPP" --domain some-ipp.com --role "Head of O&M" --out jane-profile.md
```

**How to read it:** you get **openers** that quote their own words back to them ("I read your panel talk on soiling — that's exactly what we fix"), **questions** matched to what they've publicly worried about, and **talking points** tied to their role. Every line links to where you'd have read it, so you can say "I saw your interview in Mercom," which is true and disarming.

**If you also use this for hiring**, add `--purpose hiring`:

```bash
uv run bunnyhole solar profile "Jane Doe" --company "Some IPP" --domain some-ipp.com --purpose hiring --out candidate.md
```

That prints a short set of rules at the top. Read them — they protect *you*. Screening candidates is regulated almost everywhere: get the person's consent, judge only job-relevant things, never let race, age, sex, religion, disability or the like enter the decision, and let them respond before you act on anything. The tool deliberately won't fetch anyone's private life, social media or breach data, so you can't accidentally build a profile that gets you sued.

---

## 6b. Hiring with Bunnyhole — the `--purpose` flag, step by step

You said you also use this to research candidates. Here is exactly how, and where the guardrails are.

The command is the same `solar profile`, with `--purpose hiring`:

```bash
uv run bunnyhole solar profile "Priya Rao" --company "Her Current Employer" --domain employer.com --role "O&M Engineer" --purpose hiring --out candidate.md
```

**What `--purpose` changes.** It takes one of three values and only changes the *framing and the rules printed*, never what data is collected — the collection is always professional-public only:

| `--purpose` | Use it when | What it adds |
| --- | --- | --- |
| `meeting` (default) | You're selling to this person | A short reminder to cite sources and stop if asked |
| `partnership` | They're a potential partner/investor/OEM | Same light-touch reminder |
| `hiring` | The profile will inform an employment decision | A full **hiring-use guardrail block**, printed first in the terminal and at the top of the saved file |

**What the hiring guardrail block tells you — and why to follow it:**

1. **This is professional research, not a background check.** The moment research formally screens candidates, the law gets involved. In the US that's the FCRA (and if you use a third-party service, it requires the candidate's written consent and a formal "adverse action" process before you reject them); India, the EU and the Gulf have their own versions. Treat the profile as *context to discuss*, not a verdict.
2. **Judge only job-relevant things.** Their patents, their talks, their O&M track record — fine. Anything that hints at a protected characteristic — age, race, religion, sex, pregnancy, disability, national origin, marital status — must never enter the decision. The tool refuses to fetch photos or social media precisely so those don't land in front of you.
3. **Tell the candidate and let them respond.** Before you act on anything you read, raise it with them. People change jobs, names get confused, old articles mislead.
4. **Don't go around the tool.** It won't pull breach data, personal social accounts, home or family details — and you shouldn't feed those in from elsewhere either. That's the line between lawful hiring research and an illegal profile.
5. **Keep little, delete when done.** Hold only what the role needs, store it per your data-protection duties, bin it after the decision.

**How to use the output in practice.** Read the professional-background section to verify what the candidate told you (tenure, prior employers, the plants they ran). Read the patents and papers to gauge real technical contribution. Read their public statements to see how they think about the work. Bring the interesting bits to the interview as questions, not conclusions. That's it — it's a preparation aid, the same as it is for sales.

> If what you need is a formal, decision-grade background check (criminal, credit, verified employment), this tool is the wrong instrument by design. Use a licensed, consent-based screening service for that; it exists to carry the legal weight this tool deliberately won't.

---

## 7. The reference desk: `solar playbook`

When you want the background rather than a plan, these print instantly and need no internet:

```bash
uv run bunnyhole solar playbook india
```

```bash
uv run bunnyhole solar playbook events
```

The sections are:

- **`india`** — the whole India playbook: who buys, the institutions (MNRE, SECI, NTPC, GeM), customs and BIS rules, how business is actually done, the calendar, entry structures.
- **`events`** — every conference where O&M and asset-management people gather, with dates and how concentrated the right audience is. **Verify the dates** before you book.
- **`programs`** — accelerators and corporate innovation challenges (the fastest door to a funded pilot).
- **`partners`** — investors, independent engineers, OEMs and O&M firms who can introduce you.
- **`triggers`** — the buying signals the tool looks for, and the pitch for each.
- **`guerrilla`** — the unconventional, low-budget tactics (section 8).
- **`compliance`** — the outreach law by country.

You can also see the routes and roles for a company type without scanning a specific company:

```bash
uv run bunnyhole solar routes --region india --type ipp --verbose
```

```bash
uv run bunnyhole solar roles --type epc
```

---

## 7b. The routes — the different ways to approach a lead, and how to work each one

When `solar scout` gives you an Approach Plan, section 3 is a list of **routes**. A route is one lawful way to reach the buyer. Every route belongs to a **category**, and the categories are the real menu of approaches. Here's each one, who it reaches, and how you actually work it.

**See the full how-to for any category, for any company type, without scanning a company:**

```bash
uv run bunnyhole solar routes --region india --type ipp --category warm_intro --verbose
```

Drop `--category` to see them all; `--verbose` prints the step-by-step and the legal note for each.

| Category | What it is | How you work it |
| --- | --- | --- |
| **identify** | Public sources that reveal *who* holds the role | Read the leadership page, annual report, press releases, conference speaker lists and (manually) LinkedIn. Map titles to the decision-making unit before you reach out. Free, do it first. |
| **warm_intro** | A third party introduces you | The strongest route. Ask an investor who owns the company, the independent engineer who signs off their plants, an OEM whose trackers they use, or an O&M contractor who carries their cleaning scope. One intro from a fund can mandate a pilot across its whole portfolio. |
| **direct** | You contact them yourself | Register on the vendor/supplier portal first (slow, start early). Then a short, compliant email or a warm LinkedIn note to the role, with a plant-specific one-pager. Phone the switchboard and ask for the O&M department. Follow the compliance rules in section 9. |
| **event** | Meet them where they gather | Attend the asset-management summits as a delegate, pre-book meetings, host a small dinner. Cheaper and higher-yield than a booth in year one. |
| **program** | Accelerators and innovation challenges | Apply. A corporate challenge (Iberdrola, Enel, Free Electrons, ACWA, or an Indian major's pilot scheme) puts you in front of the right team *with an internal sponsor and a funded pilot* — the shortest path from zero to a plant trial. |
| **association** | Trade bodies with O&M committees | Join (or have your local partner join), present soiling data at a member session, get written into the O&M best-practice guidelines. Builds standing, not speed. |
| **credibility** | Third-party proof | Commission an independent-engineer technology review, co-author a field study with a research institute, get your abrasion and compatibility test reports. This is what unlocks every other route — buyers ask for it first. |
| **media** | Trade press, podcasts, awards | Pitch *data*, not product ("measured soiling losses at X parks"). Every published piece becomes the attachment in your next outreach. Enter the startup awards; judges are often buyers. |
| **tender** | Public procurement | For public/utility buyers (SECI, NTPC, GeM in India; SAM.gov, EU TED). Register, watch for cleaning/O&M scopes, and often the real path is to be the subcontractor of the winning EPC. |
| **guerrilla** | Non-traditional, proof-first | Section 8. |

**Reading a route row in the plan.** Each route shows a **status**, a **score**, a **cost**, a **time-to-meeting**, who it **reaches**, and a **first step**:

- **Status `CONFIRMED`** — the tool checked the company's live website and found this door (e.g. it found their actual vendor-registration page). Act on these first; the URL is in the plan.
- **Status `CATALOG`** — a known-good route for this type of company that the tool didn't verify live. Still real, just confirm the specifics yourself.
- **Score** — the tool's ranking for *this* company, factoring in heat, cost, speed and fit. Higher = do sooner.
- **Reaches** — which roles from the decision-making unit this route gets you to.

**Accessing the detail.** The plan's section 3 table is the summary; the collapsible "why each route scored" block under it gives the reasoning, and section 4 arranges the top routes into a 90-day sequence. For the fully written-out steps of a route, run the `solar routes --verbose` command above, or open the matching playbook section (`events`, `programs`, `partners`). Confirmed-route URLs and every signal's source link are in section 10 of the plan.

**The through-line.** The sequence that actually closes deals, which the plan encodes, is: build **credibility** proof → win one **program** or warm pilot → convert via **warm_intro** to an anchor customer → scale through **event** and channel **warm_intro** → add **tender** once you have a local entity. Direct outreach supports that; it rarely leads it.

---

## 8. The non-traditional plays

`solar playbook guerrilla` lists these in full, with a cost and risk flag on each. The ones that actually work in this business are **proof-first and data-led**, not stunts:

- **Free soiling audit.** Using a plant's public location and size plus regional dust data, estimate what soiling is costing them per MW, and send it as a one-page audit addressed to the role. Cheap, legal, opens doors.
- **One-row demo.** With written permission, treat one row of panels and compare it against an untreated row for a month. The data sells itself upward.
- **Publish a "dustiest parks" index.** Rank the public plants by soiling climate. Every owner on the list reads it, and you offer the per-plant detail privately.
- **No-gain-no-fee pilot.** Charge only on measured yield recovery. It removes the finance objection and forces a data-driven trial.
- **Host a dinner** for eight plant managers near a big park (Bhadla, Khavda, Pavagada), or next to a conference. You're the convener, which beats a booth.

**What to never do**, because it's illegal or will burn your reputation: fly a drone over a plant without permission, walk onto a site uninvited, "clean a few panels as a free sample" without sign-off, or blast cold WhatsApp and SMS. The guide flags all of these.

---

## 9. Why the tool won't do certain things (and why that's good for you)

You may wonder why it refuses an email or phone number as a starting point, and won't pull someone's social media or personal details. Two reasons, both in your interest:

1. **It keeps you legal and safe.** Across the US, EU, India and the Gulf, assembling a private profile of a person — even from public scraps — is the thing data-protection and anti-stalking laws exist to stop, and using it in a hiring decision is strictly regulated. The tool stays on professional ground so you never cross that line by accident.
2. **You don't need it to sell.** Deals are won by knowing someone's *job* — their performance targets, their water problem, their next O&M renewal — and meeting them on it. That's exactly what these commands give you. Private-life digging adds legal risk and zero sales value.

So the boundary isn't the tool being timid. It's the tool keeping your pitch on the ground where deals are actually made.

---

## 10. Your first two weeks

**Week 1 — build the base.**
1. `solar sweep --region india --limit 15` → pick your top 5 companies.
2. `solar scout` each of them, save the plans.
3. From the plans, start vendor-registration everywhere it's a confirmed route (it's slow, so start now).
4. Get your proof pack together: an abrasion test on the buyer's glass type and a module-maker compatibility letter. Nothing moves without these.

**Week 2 — open doors.**
5. `solar playbook events` → find the next conference where your top targets' O&M people will be; plan to attend as a delegate, not a booth.
6. For every named contact you have, `solar profile` them before you reach out.
7. Send the free soiling audit (section 8) to the highest-heat company's O&M head.
8. Apply to one innovation programme from `solar playbook programs` — it's the shortest path to a funded pilot.

Then repeat the Monday rhythm from section 3. Aim for one pilot with one motivated sponsor; convert that into a master supply agreement with one anchor developer; let the rest follow.

---

## 11. Every command and every flag

A short flag has a dash (`-r`); a long flag has two (`--region`). Anything in `<>` is a value you supply. Run any command with `--help` to see this live.

### `solar sweep` — rank many companies by heat
| Flag | Values | What it does |
| --- | --- | --- |
| `--region` / `-r` | india, us, eu, mena, apac, latam, africa | Limit to one region |
| `--type` / `-t` | ipp, utility, epc, om, ci, oem, fund | Limit to one company type |
| `--tag` | robotic_cleaning_adopter, dusty_fleet, innovation_program, listed, in_house_om, public_tender, epc_om_channel | Limit to companies with that trait |
| `--limit` / `-n` | a number (default 12) | How many to scan |
| `--front-door` | (on/off) | Also check each website for vendor/leadership routes — slower, more useful |
| `--json` | a file path | Save the ranked list as data |

### `solar scout` — one company → Approach Plan
| Flag | Values | What it does |
| --- | --- | --- |
| *(first argument)* | a company name or website | Who to research (required) |
| `--region` / `-r` | india, us, eu, … or a country code | Override the region if the tool guessed wrong or doesn't know the company |
| `--type` / `-t` | ipp, utility, epc, om, ci, oem, fund, ie | Override the company type |
| `--gear` / `-g` | fast (default), deep | `deep` adds news narrative, court dockets and a harder website probe |
| `--follow-parents` | 0–3 (default 1) | Also sweep this many parent/owner companies for signals |
| `--out` / `-o` | a file path | Write the Markdown plan (this is the thing you read) |
| `--json` | a file path | Write the full data |
| `--no-persist` | (on/off) | Don't save the case to your local history |

### `solar prep` — meeting brief from someone's public statements
| Flag | Values | What it does |
| --- | --- | --- |
| *(first argument)* | the person's full name | Required; a full professional name, not an email or handle |
| `--company` / `-c` | the company they represent | **Required** — keeps it professional |
| `--domain` / `-d` | their company's website | Also reads the company newsroom for releases quoting them |
| `--role` / `-r` | e.g. "Head of O&M" | Maps them to the decision-making unit so the pitch fits |
| `--out` / `-o` | a file path | Write the Markdown brief |
| `--json` | a file path | Write the data |

### `solar profile` — fuller professional profile (adds bio + patents)
Same as `prep`, plus:
| Flag | Values | What it does |
| --- | --- | --- |
| `--purpose` / `-p` | meeting (default), hiring, partnership | `hiring` prints the hiring-law guardrails (section 6b) |

### `solar routes` — list routes for a company type (no internet)
| Flag | Values | What it does |
| --- | --- | --- |
| `--region` / `-r` | india, us, eu, mena, apac, latam, africa, global | Which region's routes |
| `--type` / `-t` | ipp, utility, epc, om, ci, oem, fund, ie | Which company type |
| `--category` / `-c` | identify, event, association, warm_intro, program, media, credibility, direct, tender, guerrilla | Show only one kind of route |
| `--verbose` / `-v` | (on/off) | Print the full step-by-step and legal note for each |

### `solar targets` — the built-in company list
`--region`, `--type`, `--tag` — same values as `sweep`, used to filter the list.

### `solar roles` — the decision-making unit for a company type
`--type` / `-t` — ipp (default), utility, epc, om, ci, oem, fund, ie.

### `solar playbook` — the reference sections
One argument: `india`, `events`, `programs`, `partners`, `triggers`, `guerrilla`, or `compliance`.

---

## 12. Cheat sheet

```bash
# who to chase
uv run bunnyhole solar sweep --region india --limit 15

# how to get in
uv run bunnyhole solar scout "Company Name" --out plan.md

# what to say
uv run bunnyhole solar profile "Person Name" --company "Company Name" --out profile.md

# the reference
uv run bunnyhole solar playbook india      # or: events, programs, partners, triggers, guerrilla, compliance
```

Everything the tool reports is a **lead, not a verdict** — it links its sources so you can confirm before you act. The deep background on all of this lives in [`research/10_solar_bd_executive_brief.md`](../research/10_solar_bd_executive_brief.md), and the house rules are in [`ACCEPTABLE_USE.md`](../ACCEPTABLE_USE.md). Go close.
