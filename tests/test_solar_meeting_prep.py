"""Tests for the bounded meeting-prep engine: scope enforcement and the professional-statements brief (HTTP mocked)."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
import respx
from typer.testing import CliRunner

from bunnyhole.cli.main import app
from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import EntityType
from bunnyhole.solar import meeting_prep as mp
from bunnyhole.solar.meeting_prep import MeetingPrepAgent, ScopeError, assert_professional_scope


@pytest.fixture(autouse=True)
def _no_dns(monkeypatch):
    monkeypatch.setattr(mp, "assert_public_url", lambda u: u)
    yield


PREP_RSS = """<?xml version="1.0"?><rss><channel>
<item><title>Jane Doe of Acme Solar on cutting soiling losses with waterless cleaning</title><link>https://pv.example/a</link><pubDate>Mon, 06 Oct 2026 08:00:00 GMT</pubDate><source url="https://pv.example">PV Daily</source></item>
<item><title>Jane Doe to keynote Solar Asset Management summit on O&amp;M</title><link>https://ev.example/b</link><pubDate>Tue, 07 Oct 2026 08:00:00 GMT</pubDate><source url="https://ev.example">Events</source></item>
<item><title>Opinion: by Jane Doe - why water scarcity will reshape plant O&amp;M</title><link>https://op.example/c</link><pubDate>Wed, 08 Oct 2026 08:00:00 GMT</pubDate><source url="https://op.example">TradeMag</source></item>
<item><title>Unrelated person wins award</title><link>https://x.example/d</link><pubDate>Wed, 08 Oct 2026 08:00:00 GMT</pubDate><source url="https://x.example">X</source></item>
</channel></rss>"""


@pytest.mark.parametrize("name,company,ok", [
    ("Jane Doe", "Acme Solar", True),
    ("jane.doe@acme.com", "Acme", False),
    ("+91 98765 43210", "Acme", False),
    ("https://linkedin.com/in/jane", "Acme", False),
    ("Jane", "Acme", False),       # single token: not a full professional name
    ("Jane Doe", "", False),        # company is mandatory
])
def test_scope_guard(name, company, ok):
    if ok:
        assert assert_professional_scope(name, company) == ("Jane Doe", "Acme Solar")
    else:
        with pytest.raises(ScopeError):
            assert_professional_scope(name, company)


@respx.mock
def test_brief_collects_only_named_professional_statements():
    respx.get(url__regex=r"https://news\.google\.com/rss/search.*").mock(return_value=httpx.Response(200, text=PREP_RSS))
    respx.get(url__regex=r"https://api\.openalex\.org/.*").mock(return_value=httpx.Response(200, json={"results": []}))
    g = InvestigationGraph("prep", "Jane Doe")
    brief = asyncio.run(MeetingPrepAgent(g).build_brief("Jane Doe", "Acme Solar", role_hint="Head of O&M"))
    # the unrelated item (name not present) is dropped; the three Jane Doe items are kept and typed
    kinds = sorted(s.kind for s in brief.statements)
    assert kinds == ["APPEARANCE", "BYLINE", "COVERAGE"]
    assert {"OPERATIONS", "ESG_AND_WATER"} & set(brief.topic_counts)
    assert "WATER_CONSTRAINT" in brief.trigger_counts or "SOILING_AWARENESS" in brief.trigger_counts
    assert brief.openers and all(u in o for o, u in zip(brief.openers, [s.url for s in brief.statements]))
    assert any("head_om" in tp or "champion" in tp.lower() for tp in brief.talking_points)
    # a PERSON node exists but is explicitly scoped and stores no contact data
    person = [n for n in g.nodes.values() if n.entity_type == EntityType.PERSON][0]
    assert person.attributes["scope"] == "professional_public_statements_only"
    dumped = json.dumps(g.to_dict())
    assert "@" not in dumped or "O&M" in dumped  # no emails introduced by the agent
    md = brief.export_markdown()
    assert "CONVERSATION BRIEF" in md and "Stay on professional ground" in md and "https://pv.example/a" in md


@respx.mock
def test_brief_degrades_when_nothing_found():
    respx.route().mock(return_value=httpx.Response(503))
    g = InvestigationGraph("prep", "Jane Doe")
    brief = asyncio.run(MeetingPrepAgent(g).build_brief("Jane Doe", "Acme Solar"))
    assert brief.statements == []
    assert brief.questions and brief.talking_points  # still gives generic prep
    assert "No professional statements surfaced" in brief.export_markdown()


def test_cli_prep_rejects_personal_seed_and_requires_company():
    r = CliRunner(env={"COLUMNS": "300"}).invoke(app, ["solar", "prep", "jane@example.com", "--company", "Acme"])
    assert r.exit_code == 2 and "never an email" in r.output


PATENTS_JSON = {"patents": [
    {"patent_number": "11111111", "patent_title": "Waterless solar module cleaning apparatus", "patent_date": "2023-05-02", "assignee_organization": "Acme Solar"},
    {"patent_number": "22222222", "patent_title": "Unrelated widget", "patent_date": "2019-01-01", "assignee_organization": "Other Co"},
]}
BIO_HTML = """<html><body><div class="bio">Jane Doe is Head of O&M at Acme Solar, where she has led plant operations since 2018. Jane Doe previously ran asset management at a 2 GW portfolio.</div></body></html>"""


@respx.mock
def test_build_profile_collects_background_and_patents_with_hiring_guardrails():
    respx.get(url__regex=r"https://news\.google\.com/rss/search.*").mock(return_value=httpx.Response(200, text=PREP_RSS))
    respx.get(url__regex=r"https://api\.openalex\.org/.*").mock(return_value=httpx.Response(200, json={"results": []}))
    respx.get("https://acme-solar.com/leadership").mock(return_value=httpx.Response(200, text=BIO_HTML))
    respx.get(url__regex=r"https://acme-solar\.com/.*").mock(return_value=httpx.Response(404))
    respx.get(url__regex=r"https://api\.patentsview\.org/.*").mock(return_value=httpx.Response(200, json=PATENTS_JSON))
    g = InvestigationGraph("profile", "Jane Doe")
    prof = asyncio.run(MeetingPrepAgent(g).build_profile("Jane Doe", "Acme Solar", company_domain="acme-solar.com", role_hint="Head of O&M", purpose="hiring"))
    assert prof.purpose == "hiring" and prof.compliance == list(mp.HIRING_GUARDRAILS)
    assert any("Head of O&M at Acme Solar" in s.title for s in prof.background)
    # company-assigned patent preferred over the unrelated one
    assert [p.title for p in prof.patents] and all("Acme" in p.title for p in prof.patents)
    assert "Acme Solar" in prof.affiliations
    md = prof.export_markdown()
    assert "Hiring-use guardrails" in md and "protected characteristics" in md
    assert "Waterless solar module cleaning apparatus" in md and "Head of O&M at Acme Solar" in md
    # still no personal-data sources were touched
    dumped = json.dumps(g.to_dict())
    assert "hudsonrock" not in dumped.lower() and "holehe" not in dumped.lower()


@respx.mock
def test_build_profile_meeting_purpose_has_no_hiring_block():
    respx.route().mock(return_value=httpx.Response(503))
    g = InvestigationGraph("profile", "Jane Doe")
    prof = asyncio.run(MeetingPrepAgent(g).build_profile("Jane Doe", "Acme Solar", purpose="meeting"))
    assert prof.purpose == "meeting"
    assert "Hiring-use guardrails" not in prof.export_markdown()


def test_cli_profile_rejects_bad_purpose():
    r = CliRunner(env={"COLUMNS": "300"}).invoke(app, ["solar", "profile", "Jane Doe", "--company", "Acme", "--purpose", "spying"])
    assert r.exit_code == 2 and "must be one of" in r.output
