# 🐇🕳️ Bunnyhole Cheat Sheet — Lead & Prospect Research

A quick, practical guide for researching **companies** you want to sell to, partner with,
or buy from. Point Bunnyhole at a prospect you already know (a website, a company name, an
email) and it maps their public footprint into a plain-English report with sourced findings.

> ✅ **Good for:** vetting a commercial prospect, partner, installer, supplier, or competitor
> you have a name/website for — "is this company real, established, and who's behind it?"
> ❌ **Not for:** generating marketing lists of private individuals or homeowners. Bunnyhole
> researches *known* entities from public records; it is not a contact-scraper. See
> [`ACCEPTABLE_USE.md`](./ACCEPTABLE_USE.md).

---

## 1. One-time setup

```bash
git clone https://github.com/DreadpiratePickles/bunnyhole.git && cd bunnyhole
```

```bash
uv sync
```

Needs Python ≥ 3.11 and [uv](https://docs.astral.sh/uv/). Works **with no API keys** against
free public sources. Optional — check what extra deep-scan tools are available:

```bash
uv run bunnyhole doctor
```

> Every command below is run from inside the `bunnyhole` folder.

---

## 2. Everyday commands

Replace `brightpeak-roofing.com` / `"BrightPeak Roofing LLC"` with your real prospect.

### 🔎 Quick scan of a prospect (start here)
Fast, keyless, uses their website as the seed:

```bash
uv run bunnyhole trace brightpeak-roofing.com
```

### 📄 Deeper dive + save a report
`deep` gear pulls more sources; `--out` writes a report file you can open or email:

```bash
uv run bunnyhole trace "BrightPeak Roofing LLC" --gear deep --depth 3 --out brightpeak-lead.md
```

### 🧩 Research with everything you already know, plus a question
Pass multiple known details and a plain-English question to steer the research:

```bash
uv run bunnyhole intake --org "BrightPeak Roofing LLC" --domain brightpeak-roofing.com --email info@brightpeak-roofing.com --hypothesis "Is BrightPeak an established commercial installer worth pursuing as a partner?"
```

### 🔗 See how two companies/people connect
Great for checking whether a prospect is tied to a competitor or a known person:

```bash
uv run bunnyhole link "BrightPeak Roofing LLC" brightpeak-roofing.com
```

### 🖥️ Visual "War-Room" (point-and-click)
A full-screen interactive view — type a seed and click through the results:

```bash
uv run bunnyhole ui
```

### 🗂️ Look back at past research
Every entity you've scanned is remembered locally:

```bash
uv run bunnyhole cases --search "BrightPeak"
```

---

## 3. The knobs (options worth knowing)

| Option | What it does | When to use |
| --- | --- | --- |
| `--gear fast` (default) | Quick scan of public APIs | First look at any lead |
| `--gear deep` | Adds slower, heavier sources | A lead that looks worth the time |
| `--depth 1–4` | How many hops it follows out | Higher = wider net, slower |
| `--breadth 2–8` | How many leads per hop | Higher = more thorough |
| `--out report.md` | Saves a Markdown report | Anything you want to keep/share |
| `--hypothesis "..."` | A question to focus the scan | Qualifying a specific lead |

**Rule of thumb:** start with plain `trace <website>`. Only reach for
`--gear deep --depth 3` when a lead looks promising enough to justify the extra minutes.

---

## 4. How to read the results

- **Every finding has a source link** — click through and confirm it yourself.
- **Confidence grades** (NATO A1–F6 / VERIFIED → HYPOTHESIS) tell you how solid a finding is.
  Treat low-confidence items as *things to check*, not facts.
- **PAI vs CAI** labels show whether a finding came from free public data (PAI) or a paid
  commercial source (CAI).
- **Key Assumptions Check** — each report ends with the assumptions the conclusion rests on,
  flagged 🟢 solid / 🟡 supported / 🔴 fragile. If something's 🔴, verify it before acting.

> 🧭 **Bottom line:** findings are **leads, not verdicts.** Use them to qualify and prioritize,
> then confirm anything important with a real source or a phone call before you act on it.

---

## 5. Getting help

```bash
uv run bunnyhole --help
```

```bash
uv run bunnyhole trace --help
```
