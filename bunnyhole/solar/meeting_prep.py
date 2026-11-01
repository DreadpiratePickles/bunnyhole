"""Meeting prep (bunnyhole-solar): a conversation brief built ONLY from a role-holder's public professional statements.

What it does
    Given a person's name and the company they represent, it gathers what that person has said *in their
    professional capacity* - press and trade-press coverage that names them with their company, conference /
    webinar / podcast appearances, bylined pieces, scholarly works (OpenAlex), and press releases on the
    company's own newsroom that quote them - then maps those statements to the solar buying triggers and
    produces openers, questions and talking points for a business meeting.

What it will not do (enforced in code, not only in docs)
    - A company is mandatory; the seed must be a name, never an email, phone number or @handle.
    - It never calls identity, breach, credential, phone, social-media or people-search sources, never
      stores contact details, photos, addresses, family or personal-life information, and keeps only
      professional publications tied to the business topic.
    - Everything it records carries the public URL it came from; the brief tells the user to cite that
      source in conversation and to stay on professional ground.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote_plus, urljoin, urlsplit

from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import (
    DomainCategory,
    EntityType,
    EvidenceReceipt,
    GearMode,
    GraphEdge,
    GraphNode,
    RelationType,
    SelectorStrength,
    TimelineItem,
)
from bunnyhole.engine.netutil import UnsafeHostError, assert_public_url, new_async_client
from bunnyhole.solar import playbook as pb
from bunnyhole.solar.playbook import BUYING_TRIGGERS, DECISION_ROLES, classify_buying_signals


class ScopeError(ValueError):
    """Raised when a request falls outside the professional-statements scope."""


# Seeds that would turn this into identity resolution are refused outright.
_PERSONAL_SEED_RE = re.compile(r"@|^\+?[\d\s().-]{7,}$|https?://")
_HREF_RE = re.compile(r"""<a[^>]+href=["']([^"'#?]+)["'][^>]*>(.*?)</a>""", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_STAGE_RE = re.compile(r"keynote|panel|panelist|speaker|speaks at|webinar|podcast|fireside|interview|q&a|in conversation|summit|conference|roundtable", re.IGNORECASE)
_BYLINE_RE = re.compile(r"\bby\b|op-ed|opinion|column|viewpoint|guest post", re.IGNORECASE)

# Professional topics beyond the buying triggers, so the brief can say what else they talk about.
PROFESSIONAL_TOPICS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("ENERGY_STORAGE", ("storage", "bess", "battery", "hybrid")),
    ("DIGITAL_AND_AI", ("digital", "ai ", "artificial intelligence", "analytics", "data", "automation", "drone")),
    ("FINANCING", ("financing", "ppa", "tariff", "auction", "bid", "irr", "lcoe", "capex", "opex")),
    ("POLICY", ("policy", "regulat", "mnre", "seci", "ferc", "subsidy", "duty", "alMM".lower(), "tender")),
    ("SUPPLY_CHAIN", ("module", "supply chain", "manufactur", "cell", "wafer", "tracker", "inverter")),
    ("ESG_AND_WATER", ("esg", "sustainab", "water", "net zero", "community")),
    ("OPERATIONS", ("o&m", "operations", "maintenance", "performance", "availability", "soiling", "cleaning", "yield", "plant")),
    ("SAFETY", ("safety", "hse", "incident")),
    ("PEOPLE", ("hiring", "talent", "team", "workforce", "skills")),
)

PURPOSES: Tuple[str, ...] = ("meeting", "hiring", "partnership")

# Shown whenever the profile will inform a hiring decision. These are guardrails, not legal advice.
HIRING_GUARDRAILS: Tuple[str, ...] = (
    "This is professional research, NOT a background check or a consumer report. If you formalise screening or use a third party, FCRA (US) and equivalent laws require the candidate's written consent, disclosure, and an adverse-action process before you act on anything.",
    "Use only job-relevant professional information. Never consider or infer protected characteristics - race, colour, religion, sex, pregnancy, age, disability, national origin, marital or veteran status, or anything a photo or social profile would reveal.",
    "Tell the candidate what you reviewed and let them respond before you rely on it; verify every claim with them directly.",
    "Do not seek or use breach data, personal social media, home, family, health or financial information in a hiring decision - this engine never collects it, and neither should you by other means.",
    "Keep what you collect to what the role needs, store it under your data-protection obligations, and delete it when the decision is made.",
)

PATENTSVIEW_LEGACY = "https://api.patentsview.org/patents/query"
PATENTSVIEW_V1 = "https://search.patentsview.org/api/v1/patent/"

PREP_ANGLES: Tuple[Tuple[str, str], ...] = (
    ("COMPANY", '"{n}" "{c}"'),
    ("TOPIC", '"{n}" solar OR "O&M" OR soiling OR cleaning OR "asset management" OR plant'),
    ("STAGE", '"{n}" keynote OR panel OR speaker OR webinar OR podcast OR interview OR summit'),
)

_QUESTION_BY_TRIGGER: Dict[str, str] = {
    "SOILING_AWARENESS": "You've spoken publicly about soiling - how do you measure it today, and what does a lost percentage point cost you per MW?",
    "WATER_CONSTRAINT": "With water being the constraint you've described, what would a litres-per-MW-year target look like for your fleet?",
    "COMPETITOR_CLEANING_ADOPTED": "You've already deployed automated cleaning - what did the first season teach you about breakage, uptime and the OEM warranty side?",
    "NEW_PLANT_COMMISSIONED": "For the capacity you've just commissioned, is the O&M baseline set yet, or is there room to specify cleaning before the first dry season?",
    "OM_CONTRACT_CYCLE": "When your O&M scope is next reopened, who writes the cleaning clause - the asset team or the contractor?",
    "YIELD_SHORTFALL": "On the generation gap you've discussed, how much of it does your team attribute to soiling versus other losses?",
    "INNOVATION_OPEN": "You've backed innovation programmes - what does a pilot need to show in its first 60 days for you to take it to the board?",
    "EXEC_CHANGE": "In your first quarter in the role, which O&M number do you most want to move?",
    "CAPITAL_EVENT": "With the refinancing / raise, is the independent engineer revisiting the soiling assumption in the model?",
    "PIPELINE_GROWTH": "For the awarded capacity, at what stage does the cleaning method get specified - EPC design or O&M handover?",
    "DUSTY_GEOGRAPHY": "At your desert sites, how often are you cleaning in the dry season and what does that cost in labour and water?",
    "LABOUR_PRESSURE": "You've mentioned workforce pressure - which O&M tasks would you automate first if breakage risk were off the table?",
    "MODULE_DAMAGE_SENSITIVITY": "Given your focus on module damage, what evidence (abrasion tests, OEM letters) would you want before any trial?",
    "ESG_REPORTING": "Which water and emissions numbers would your sustainability report most like to be able to publish?",
    "PORTFOLIO_EXPANSION": "As the portfolio grows, are you standardising O&M methods across sites or letting each plant choose?",
    "DIGITAL_OM": "How does soiling show up in your monitoring stack today, and would you want cleaning logs exposed through the same API?",
}

_AVOID: Tuple[str, ...] = (
    "Stay on professional ground: cite only the published talk, interview, article or release you found, with its source.",
    "Do not reference personal life, family, location, social-media activity or anything you did not find in a professional publication.",
    "Do not imply you have researched them; say you read their talk or interview and found it relevant.",
    "If they object to any reference, drop it immediately; never use contact details they did not give you.",
)


def _sha(prefix: str, raw: str) -> str:
    return f"{prefix}:{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:12]}"


def _name_tokens(name: str) -> List[str]:
    return [t for t in re.split(r"[^a-z]+", (name or "").lower()) if len(t) >= 2]


def assert_professional_scope(name: str, company: str) -> Tuple[str, str]:
    """Validate the request: a plain personal name plus the company they represent; nothing that resolves identities."""
    n = (name or "").strip()
    c = (company or "").strip()
    if not n or not c:
        raise ScopeError("Meeting prep needs both a name and the company the person represents (professional context only).")
    if _PERSONAL_SEED_RE.search(n) or _PERSONAL_SEED_RE.search(c):
        raise ScopeError("Meeting prep accepts a name and a company, never an email, phone number, @handle or URL.")
    if len(_name_tokens(n)) < 2:
        raise ScopeError("Give the person's full professional name (first and last) as it appears in press coverage.")
    return n, c


@dataclass
class Statement:
    kind: str                     # COVERAGE | APPEARANCE | BYLINE | PRESS_RELEASE | SCHOLARLY
    title: str
    url: str
    source: str
    date: str
    topics: List[str] = field(default_factory=list)
    triggers: List[str] = field(default_factory=list)
    named: bool = True


@dataclass
class ConversationBrief:
    name: str
    company: str
    role_hint: str
    generated_at: str
    statements: List[Statement]
    topic_counts: Dict[str, int]
    trigger_counts: Dict[str, int]
    openers: List[str]
    questions: List[str]
    talking_points: List[str]
    avoid: List[str]
    receipts: List[Dict[str, str]]
    scope_note: str = "Professional public statements only - no personal data was sought or stored."

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "company": self.company, "role_hint": self.role_hint, "generated_at": self.generated_at,
            "statements": [s.__dict__ for s in self.statements], "topic_counts": self.topic_counts, "trigger_counts": self.trigger_counts,
            "openers": self.openers, "questions": self.questions, "talking_points": self.talking_points, "avoid": self.avoid,
            "receipts": self.receipts, "scope_note": self.scope_note,
        }

    def export_markdown(self) -> str:
        L = [
            f"# 🗣️ CONVERSATION BRIEF: {self.name} ({self.company})",
            f"**Role (as given):** {self.role_hint or 'not specified'} | **Generated:** `{self.generated_at}`",
            "",
            f"> {self.scope_note} Every line below links to the professional publication it came from.",
            "",
            "## 1. What they talk about publicly",
        ]
        if self.topic_counts:
            L += ["", "| Topic | Mentions |", "| :--- | :---: |"] + [f"| `{t}` | {n} |" for t, n in sorted(self.topic_counts.items(), key=lambda kv: kv[1], reverse=True)]
        else:
            L.append("- No professional statements surfaced. Check the company newsroom and event programmes by hand before the meeting.")
        if self.trigger_counts:
            L += ["", "**Buying triggers present in their statements:** " + ", ".join(f"`{t}` x{n}" for t, n in sorted(self.trigger_counts.items(), key=lambda kv: kv[1], reverse=True))]
        L += ["", "## 2. Their public statements (newest first)"]
        if self.statements:
            L += ["", "| Date | Kind | Statement | Source | Topics |", "| :--- | :--- | :--- | :--- | :--- |"]
            for s in self.statements[:30]:
                L.append(f"| {s.date[:16]} | {s.kind} | [{s.title[:100]}]({s.url}) | {s.source} | {', '.join(s.topics[:3])} |")
        L += ["", "## 3. Openers (each cites the source you found)"] + [f"- {o}" for o in self.openers] if self.openers else ["", "## 3. Openers", "- Open on their company's latest public O&M or capacity milestone instead."]
        L += ["", "## 4. Questions worth asking"] + [f"- {q}" for q in self.questions]
        L += ["", "## 5. Talking points to prepare"] + [f"- {t}" for t in self.talking_points]
        L += ["", "## 6. Stay on professional ground"] + [f"- {a}" for a in self.avoid]
        L += ["", "## 7. Receipts"] + [f"- `{r['grade']}` {r['fact']} - {r['url']}" for r in self.receipts[:30]]
        return "\n".join(L)


class MeetingPrepAgent:
    """Builds a ConversationBrief from public professional statements. See module docstring for the scope."""

    def __init__(self, graph: InvestigationGraph, gear: GearMode = GearMode.FAST) -> None:
        self.graph = graph
        self.gear = gear
        self.headers = {"User-Agent": "Mozilla/5.0 (compatible; BunnyholeSolarScout/0.1; +https://github.com/DreadpiratePickles/bunnyhole)"}

    def _log(self, action: str, target: str, detail: str, level: str = "info", receipts: int = 0) -> None:
        self.graph.log(DomainCategory.COMMERCIAL, action, target, detail, receipt_count=receipts, level=level)

    async def _get(self, client: Any, url: str, max_bytes: int = 600_000) -> Optional[Any]:
        try:
            assert_public_url(url)
            resp = await client.get(url)
            if resp is not None and len(resp.content or b"") > max_bytes:
                resp._content = resp.content[:max_bytes]  # noqa: SLF001
            return resp
        except (UnsafeHostError, Exception):
            return None

    @staticmethod
    def classify_topics(text: str) -> List[str]:
        low = (text or "").lower()
        return [tid for tid, kws in PROFESSIONAL_TOPICS if any(k in low for k in kws)]

    # ------------------------------------------------------------------ sources
    async def public_statements(self, name: str, company: str) -> List[Statement]:
        """Press / trade-press items that name the person; kind inferred from the headline."""
        toks = _name_tokens(name)
        c_tok = (company.lower().split() or [""])[0]
        out: Dict[str, Statement] = {}
        async with new_async_client(timeout=12.0, follow_redirects=True, headers=self.headers) as client:
            for angle, tmpl in PREP_ANGLES:
                q = tmpl.format(n=name, c=company)
                url = f"https://news.google.com/rss/search?q={quote_plus(q)}&hl=en-US&gl=US&ceid=US:en"
                resp = await self._get(client, url)
                if resp is None or resp.status_code != 200 or not resp.text:
                    continue
                try:
                    root = ET.fromstring(resp.text)
                except ET.ParseError:
                    continue
                for item in root.findall(".//item")[:15]:
                    title = (item.findtext("title") or "").strip()
                    link = (item.findtext("link") or "").strip()
                    pub = (item.findtext("pubDate") or "").strip()
                    src_el = item.find("source")
                    source = (src_el.text if src_el is not None and src_el.text else "News").strip()
                    low = title.lower()
                    if not title or not link or link in out:
                        continue
                    named = all(t in low for t in toks)
                    if not named:
                        continue  # the person must be named in the headline - we do not chase ambiguous items
                    company_named = bool(c_tok) and c_tok in low
                    kind = "APPEARANCE" if _STAGE_RE.search(title) else ("BYLINE" if _BYLINE_RE.search(title) else "COVERAGE")
                    out[link] = Statement(kind=kind, title=title, url=link, source=source, date=pub,
                                          topics=self.classify_topics(f"{title} {angle}"), triggers=[t.trigger_id for t in classify_buying_signals(title)],
                                          named=company_named or angle == "COMPANY")
        return list(out.values())

    async def scholarly_work(self, name: str, company: str) -> List[Statement]:
        """OpenAlex works where the person is an author and the work is solar/energy related."""
        url = f"https://api.openalex.org/works?search={quote_plus(name + ' solar photovoltaic')}&per-page=8&sort=publication_year:desc"
        out: List[Statement] = []
        toks = _name_tokens(name)
        async with new_async_client(timeout=12.0, headers=self.headers) as client:
            resp = await self._get(client, url)
            if resp is None or resp.status_code != 200:
                return out
            try:
                works = resp.json().get("results", [])
            except Exception:
                return out
            for w in works:
                authors = [str((a.get("author") or {}).get("display_name", "")).lower() for a in w.get("authorships", [])]
                if not any(all(t in au for t in toks) for au in authors):
                    continue
                title = w.get("title") or "Publication"
                out.append(Statement(kind="SCHOLARLY", title=title, url=w.get("doi") or w.get("id") or "https://openalex.org",
                                     source="OpenAlex", date=str(w.get("publication_year") or ""), topics=self.classify_topics(title),
                                     triggers=[t.trigger_id for t in classify_buying_signals(title)]))
        return out

    async def company_newsroom_mentions(self, name: str, company_domain: Optional[str]) -> List[Statement]:
        """Press releases on the company's own newsroom whose link text or page mentions the person (their official statements)."""
        if not company_domain:
            return []
        clean = company_domain.lower().replace("https://", "").replace("http://", "").split("/")[0]
        toks = _name_tokens(name)
        out: List[Statement] = []
        probe = [f"https://{clean}{p}" for p in pb.ROUTES_BY_ID["press_newsroom"].probe_paths[:6]]
        async with new_async_client(timeout=10.0, follow_redirects=True, headers=self.headers) as client:
            for url in probe:
                resp = await self._get(client, url)
                if resp is None or resp.status_code != 200 or not resp.text:
                    continue
                for m in _HREF_RE.finditer(resp.text):
                    text = re.sub(r"\s+", " ", _TAG_RE.sub(" ", m.group(2))).strip()
                    low = text.lower()
                    if 15 <= len(text) <= 220 and all(t in low for t in toks):
                        link = urljoin(url, m.group(1))
                        if urlsplit(link).netloc.lower().endswith(clean):
                            out.append(Statement(kind="PRESS_RELEASE", title=text, url=link, source=clean, date="",
                                                 topics=self.classify_topics(text), triggers=[t.trigger_id for t in classify_buying_signals(text)]))
                if out:
                    break
        return out[:10]

    # ------------------------------------------------------------------ brief
    async def build_brief(self, name: str, company: str, company_domain: Optional[str] = None, role_hint: str = "", origin_node_id: Optional[str] = None, hop_depth: int = 1) -> ConversationBrief:
        name, company = assert_professional_scope(name, company)
        self._log("MEETING_PREP_START", f"{name} ({company})", "Collecting public professional statements only: press coverage, appearances, bylines, scholarly work, company press releases")
        statements: List[Statement] = []
        statements += await self.public_statements(name, company)
        statements += await self.scholarly_work(name, company)
        statements += await self.company_newsroom_mentions(name, company_domain)
        statements.sort(key=lambda s: s.date, reverse=True)

        person_id = _sha("rolehold", f"{name.lower()}|{company.lower()}")
        rcpt0 = EvidenceReceipt(tool="bunnyhole_meeting_prep", domain=DomainCategory.COMMERCIAL, admiralty_code="B3", selector_strength=SelectorStrength.SOFT,
                                source_url=f"prep://{person_id}", extracted_fact=f"Role-holder '{name}' at {company} ({role_hint or 'role not given'}) - professional statements scope",
                                raw_snippet="scope=professional_public_statements_only")
        node = self.graph.upsert_node(GraphNode(
            id=person_id, label=f"🗣️ {name} ({company})", entity_type=EntityType.PERSON, domain=DomainCategory.COMMERCIAL, ftm_schema="Person",
            selector_strength=SelectorStrength.SOFT, smoke_score=30.0, risk_flags=["PROFESSIONAL_STATEMENTS_ONLY"],
            attributes={"name": name, "company": company, "role_hint": role_hint, "scope": "professional_public_statements_only"}, receipts=[rcpt0], hop_depth=hop_depth,
        ))
        if origin_node_id:
            self.graph.upsert_edge(GraphEdge(source_id=origin_node_id, target_id=node.id, relation=RelationType.TARGET_ROLE, domain=DomainCategory.COMMERCIAL,
                                             admiralty_code="B3", confidence=0.6, summary=role_hint or "role-holder", receipts=[rcpt0]))
        receipts: List[Dict[str, str]] = []
        for s in statements[:40]:
            sid = _sha("statement", s.url)
            grade = "C2" if s.kind in ("COVERAGE", "APPEARANCE", "BYLINE") else ("B1" if s.kind == "PRESS_RELEASE" else "B2")
            rcpt = EvidenceReceipt(tool=f"meeting_prep_{s.kind.lower()}", domain=DomainCategory.COMMERCIAL, admiralty_code=grade, selector_strength=SelectorStrength.SOFT,
                                   source_url=s.url, extracted_fact=f"{s.kind}: {s.source} ({s.date}) - {s.title}", raw_snippet=f"topics={s.topics} | triggers={s.triggers}")
            self.graph.upsert_node(GraphNode(
                id=sid, label=f"📰 {s.kind}: {s.title[:56]}", entity_type=EntityType.NEWS_ARTICLE if s.kind != "SCHOLARLY" else EntityType.DOCUMENT,
                domain=DomainCategory.COMMERCIAL, ftm_schema="Document", selector_strength=SelectorStrength.SOFT, smoke_score=25.0 + 10.0 * len(s.triggers),
                risk_flags=s.triggers[:3], attributes=s.__dict__ | {"kind": s.kind}, receipts=[rcpt], hop_depth=hop_depth + 1,
            ))
            self.graph.upsert_edge(GraphEdge(source_id=node.id, target_id=sid, relation=RelationType.MENTIONED_IN, domain=DomainCategory.COMMERCIAL,
                                             admiralty_code=grade, confidence=0.75, summary=s.kind, event_date=s.date or None, receipts=[rcpt]))
            if s.date:
                self.graph.add_timeline_event(TimelineItem(timestamp=s.date, domain=DomainCategory.COMMERCIAL, title=f"{s.kind}: {s.title[:70]}", description=", ".join(s.topics),
                                                           node_ids=[node.id, sid], source_url=s.url, admiralty_code=grade))
            receipts.append({"grade": grade, "fact": f"{s.kind} - {s.title[:90]}", "url": s.url})

        topic_counts = Counter(t for s in statements for t in s.topics)
        trigger_counts = Counter(t for s in statements for t in s.triggers)
        openers: List[str] = []
        for s in [x for x in statements if x.kind in ("APPEARANCE", "BYLINE", "COVERAGE", "PRESS_RELEASE")][:3]:
            verb = {"APPEARANCE": "spoke", "BYLINE": "wrote", "PRESS_RELEASE": "said in your company's release", "COVERAGE": "were quoted"}.get(s.kind, "said")
            openers.append(f'"I read that you {verb} about {s.topics[0].replace("_", " ").lower() if s.topics else "the business"} - {s.title[:80]} ({s.source}, {s.date[:11] or "undated"}). That is exactly the problem we work on." -> {s.url}')
        questions: List[str] = [_QUESTION_BY_TRIGGER[t] for t, _ in trigger_counts.most_common(5) if t in _QUESTION_BY_TRIGGER]
        if not questions:
            questions = [
                "What does a lost percentage point of performance ratio cost you per MW-year today?",
                "Who signs off a cleaning-method change - the asset team, the O&M contractor, or the independent engineer?",
                "What evidence would you need before allowing a one-row trial on a live plant?",
            ]
        talking_points: List[str] = []
        role = next((r for r in DECISION_ROLES if role_hint and any(p in role_hint.lower() for p in r.title_patterns)), None)
        if role:
            talking_points.append(f"As a {role.dmu_role.lower()} ({role.role_id}), they care about: {'; '.join(role.cares_about[:3])}. Fears: {'; '.join(role.fears[:2])}. Pitch: {role.pitch_angle}")
        for t, n in trigger_counts.most_common(3):
            trig = next((x for x in BUYING_TRIGGERS if x.trigger_id == t), None)
            if trig:
                talking_points.append(f"{t} (x{n}): {trig.why} -> {trig.pitch}")
        if not talking_points:
            talking_points.append("No trigger-specific angle found; lead with the module-OEM compatibility evidence and a one-row, no-cost trial offer.")

        brief = ConversationBrief(name=name, company=company, role_hint=role_hint, generated_at=datetime.now(timezone.utc).isoformat(), statements=statements,
                                  topic_counts=dict(topic_counts), trigger_counts=dict(trigger_counts), openers=openers, questions=questions,
                                  talking_points=talking_points, avoid=list(_AVOID), receipts=receipts)
        self._log("MEETING_PREP_DONE", f"{name} ({company})", f"{len(statements)} professional statements; topics={dict(topic_counts.most_common(4))}", level="discovery", receipts=len(receipts))
        return brief

    async def professional_background(self, name: str, company: str, company_domain: Optional[str]) -> List["Statement"]:
        """Bio sentences the ORGANISATION itself publishes about the person (leadership / about / team pages)."""
        if not company_domain:
            return []
        clean = company_domain.lower().replace("https://", "").replace("http://", "").split("/")[0]
        toks = _name_tokens(name)
        out: List[Statement] = []
        async with new_async_client(timeout=10.0, follow_redirects=True, headers=self.headers) as client:
            for path in pb.ROUTES_BY_ID["leadership_page"].probe_paths[:10]:
                resp = await self._get(client, f"https://{clean}{path}")
                if resp is None or resp.status_code != 200 or not resp.text:
                    continue
                text = re.sub(r"\s+", " ", _TAG_RE.sub(" ", resp.text))
                for sent in re.split(r"(?<=[.!?])\s+", text):
                    low = sent.lower()
                    if 20 <= len(sent) <= 400 and all(t in low for t in toks):
                        out.append(Statement(kind="BACKGROUND", title=sent.strip()[:300], url=f"https://{clean}{path}", source=clean, date="",
                                             topics=self.classify_topics(sent), triggers=[]))
                if out:
                    break
        seen: set = set()
        uniq: List[Statement] = []
        for st in out:
            if st.title not in seen:
                seen.add(st.title)
                uniq.append(st)
        return uniq[:8]

    async def patents_as_inventor(self, name: str, company: str) -> List["Statement"]:
        """Granted patents naming the person as inventor (public professional output). Keyless best-effort; silent on failure."""
        toks = _name_tokens(name)
        if len(toks) < 2:
            return []
        first, last = toks[0], toks[-1]
        key = os.environ.get("PATENTSVIEW_API_KEY", "").strip()
        parsed: List[tuple] = []  # (id, title, date, assignee_org)
        async with new_async_client(timeout=12.0, headers=self.headers) as client:
            try:
                if key:
                    body = {"q": {"_and": [{"inventors.inventor_name_first": first}, {"inventors.inventor_name_last": last}]},
                            "f": ["patent_id", "patent_title", "patent_date", "assignees.assignee_organization"], "o": {"size": 12}}
                    kr = await client.post(PATENTSVIEW_V1, json=body, headers={**self.headers, "X-Api-Key": key})
                    rows = (kr.json().get("patents", []) if kr is not None and kr.status_code == 200 else []) or []
                    for r in rows:
                        org = next((a.get("assignee_organization") for a in (r.get("assignees") or []) if a.get("assignee_organization")), "")
                        parsed.append((r.get("patent_id", ""), r.get("patent_title", ""), r.get("patent_date", ""), org))
                else:
                    q = {"_and": [{"inventor_first_name": first}, {"inventor_last_name": last}]}
                    f = ["patent_number", "patent_title", "patent_date", "assignee_organization"]
                    url = f"{PATENTSVIEW_LEGACY}?q={quote_plus(json.dumps(q))}&f={quote_plus(json.dumps(f))}"
                    lr = await self._get(client, url)
                    rows = (lr.json().get("patents", []) if lr is not None and lr.status_code == 200 else []) or []
                    for r in rows:
                        org = r.get("assignee_organization") or next((a.get("assignee_organization") for a in (r.get("assignees") or []) if a.get("assignee_organization")), "")
                        parsed.append((r.get("patent_number", ""), r.get("patent_title", ""), r.get("patent_date", ""), org))
            except Exception:
                return []
        c_tok = (company.lower().split() or [""])[0]
        built: List[Statement] = []
        for pid, title, date, org in parsed[:12]:
            if not title:
                continue
            purl = f"https://patents.google.com/patent/US{pid}" if pid else "https://patentsview.org"
            built.append(Statement(kind="PATENT", title=f"{title} (assignee: {org or 'n/a'})", url=purl, source="PatentsView", date=str(date),
                                   topics=self.classify_topics(title), triggers=[], named=bool(c_tok) and c_tok in (org or "").lower()))
        relevant = [x for x in built if x.named]
        return (relevant or built)[:8]

    async def build_profile(self, name: str, company: str, company_domain: Optional[str] = None, role_hint: str = "",
                            purpose: str = "meeting", origin_node_id: Optional[str] = None, hop_depth: int = 1) -> "ProfessionalProfile":
        """A professional-background profile: the meeting brief plus org-published bio and patents, with a purpose banner.

        Collects public PROFESSIONAL information only; it never queries breach, credential, phone, handle or
        social-media sources and stores no private-life data. For purpose='hiring' it attaches HIRING_GUARDRAILS.
        """
        name, company = assert_professional_scope(name, company)
        if purpose not in PURPOSES:
            purpose = "meeting"
        brief = await self.build_brief(name, company, company_domain=company_domain, role_hint=role_hint, origin_node_id=origin_node_id, hop_depth=hop_depth)
        background = await self.professional_background(name, company, company_domain)
        patents = await self.patents_as_inventor(name, company)
        person_id = _sha("rolehold", f"{name.lower()}|{company.lower()}")
        extra: List[Dict[str, str]] = []
        for st in background + patents:
            sid = _sha("profitem", f"{st.url}|{st.title[:40]}")
            grade = "B1" if st.kind == "BACKGROUND" else "A2"
            rcpt = EvidenceReceipt(tool=f"meeting_prep_{st.kind.lower()}", domain=DomainCategory.COMMERCIAL, admiralty_code=grade, selector_strength=SelectorStrength.SOFT,
                                   source_url=st.url, extracted_fact=f"{st.kind}: {st.title[:120]}", raw_snippet=f"source={st.source} date={st.date}")
            self.graph.upsert_node(GraphNode(id=sid, label=f"🧾 {st.kind}: {st.title[:52]}", entity_type=EntityType.DOCUMENT, domain=DomainCategory.COMMERCIAL,
                                             ftm_schema="Document", selector_strength=SelectorStrength.SOFT, smoke_score=25.0, risk_flags=[f"PROFILE_{st.kind}"],
                                             attributes={**st.__dict__, "kind": st.kind}, receipts=[rcpt], hop_depth=hop_depth + 1))
            self.graph.upsert_edge(GraphEdge(source_id=person_id, target_id=sid, relation=RelationType.MENTIONED_IN, domain=DomainCategory.COMMERCIAL,
                                             admiralty_code=grade, confidence=0.7, summary=st.kind, event_date=st.date or None, receipts=[rcpt]))
            extra.append({"grade": grade, "fact": f"{st.kind} - {st.title[:90]}", "url": st.url})
        affiliations = sorted({t.split("assignee: ", 1)[-1].rstrip(")") for t in (p.title for p in patents) if "assignee: " in t and "n/a" not in t} | {company})
        compliance = list(HIRING_GUARDRAILS) if purpose == "hiring" else ["Use these professional facts to inform the conversation, cite the source, and stop referencing anything the person asks you not to."]
        prof = ProfessionalProfile(brief=brief, purpose=purpose, background=background, patents=patents, affiliations=affiliations, compliance=compliance, receipts=extra)
        self._log("PROFILE_DONE", f"{name} ({company})", f"purpose={purpose}; {len(background)} background, {len(patents)} patents, {len(brief.statements)} statements", level="discovery", receipts=len(extra))
        return prof


@dataclass
class ProfessionalProfile:
    """A meeting brief plus the organisation's published bio and the person's patents. Professional scope only."""
    brief: ConversationBrief
    purpose: str
    background: List[Statement]
    patents: List[Statement]
    affiliations: List[str]
    compliance: List[str]
    receipts: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "purpose": self.purpose, "affiliations": self.affiliations, "compliance": self.compliance,
            "background": [s.__dict__ for s in self.background], "patents": [s.__dict__ for s in self.patents],
            "brief": self.brief.to_dict(), "receipts": self.receipts,
        }

    def export_markdown(self) -> str:
        b = self.brief
        L = [
            f"# 🧾 PROFESSIONAL PROFILE: {b.name} ({b.company})",
            f"**Purpose:** {self.purpose} | **Role (as given):** {b.role_hint or 'not specified'} | **Generated:** `{b.generated_at}`",
            "",
            f"> {b.scope_note} Professional, public, business-context information only - no breach, credential, account-enumeration, social-media or private-life data. Every line links to its public source.",
        ]
        if self.purpose == "hiring":
            L += ["", "## ⚖️ Hiring-use guardrails (read first)"] + [f"- {c}" for c in self.compliance]
        L += ["", "## Professional background (the organisation's own words)"]
        L += [f"- {s.title} — [{s.source}]({s.url})" for s in self.background] or ["- No published bio found on the company site; confirm role and tenure with the person directly."]
        L += ["", "## Patents as named inventor"]
        L += [f"- [{s.title}]({s.url}) ({s.date})" for s in self.patents] or ["- None found via public patent search (or the lookup was unavailable)."]
        if self.affiliations:
            L += ["", "**Public affiliations (from patents / company):** " + ", ".join(self.affiliations)]
        body = b.export_markdown().split("\n", 1)
        L += ["", "---", "", body[1] if len(body) > 1 else ""]
        return "\n".join(L)
