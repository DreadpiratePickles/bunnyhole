"""Parser tests for ``bunnyhole ask``: plain English in, an ``AskPlan`` out. Deterministic: no model, no network."""

from __future__ import annotations

from typing import List, Tuple

import pytest

from bunnyhole.engine.ask import AskPlan, EntityKind, Intent, classify_entity, parse_question

CONNECTION_CASES: List[Tuple[str, str, str]] = [
    ("see if Abdul Rehman Akingbola is connected to Dalia Tech Ltd", "Abdul Rehman Akingbola", "Dalia Tech Ltd"),
    ("is Abdul Rehman Akingbola linked to daliatech.ca", "Abdul Rehman Akingbola", "daliatech.ca"),
    ("Is Jane Smith connected with Acme Ltd?", "Jane Smith", "Acme Ltd"),
    ("check whether John Doe is linked to Globex Inc", "John Doe", "Globex Inc"),
    ("find out if Jane Smith is tied to Initech LLC.", "Jane Smith", "Initech LLC"),
    ("any ties between Jane Smith and Acme Ltd", "Jane Smith", "Acme Ltd"),
    ("Any connection between Acme Ltd and Globex Inc?", "Acme Ltd", "Globex Inc"),
    ("is there a link between John Doe and daliatech.ca", "John Doe", "daliatech.ca"),
    ("are there any links between Acme Ltd and Globex Inc", "Acme Ltd", "Globex Inc"),
    ("does Jane Smith have anything to do with Acme Ltd", "Jane Smith", "Acme Ltd"),
    ("Does Acme Ltd have anything to do with Globex Inc?!", "Acme Ltd", "Globex Inc"),
    ("does John Doe have any connection to Initech LLC", "John Doe", "Initech LLC"),
    ('see if "Abdul Rehman Akingbola" is connected to "Dalia Tech"', "Abdul Rehman Akingbola", "Dalia Tech"),
    ("is 'Smith and Sons' linked to 'Acme Ltd'", "Smith and Sons", "Acme Ltd"),
    ("IS JANE SMITH CONNECTED TO ACME LTD", "JANE SMITH", "ACME LTD"),
    ("is jane smith connected to acme ltd", "jane smith", "acme ltd"),
    ("how is Jane Smith connected to Globex Inc", "Jane Smith", "Globex Inc"),
    ("are Acme Ltd and Globex Inc connected?", "Acme Ltd", "Globex Inc"),
    ("please check if Acme Ltd is associated with daliatech.ca", "Acme Ltd", "daliatech.ca"),
    ("can you see if Jane Smith is related to Acme Ltd", "Jane Smith", "Acme Ltd"),
    ("find the link between Jane Smith and Acme Ltd", "Jane Smith", "Acme Ltd"),
    ("what is the connection between acme.com and globex.com", "acme.com", "globex.com"),
    ("see if Acme Ltd is somehow linked to Globex Inc ...", "Acme Ltd", "Globex Inc"),
    ("is O'Brien Holdings Ltd linked to Jane Smith", "O'Brien Holdings Ltd", "Jane Smith"),
    ("  see   if   Jane   Smith   is   connected   to   Acme   Ltd  ", "Jane Smith", "Acme Ltd"),
]

RISK_CASES: List[Tuple[str, str]] = [
    ("see if Acme Ltd has anything shady going on", "Acme Ltd"),
    ("see if Dalia Tech Ltd has anything shady going on?", "Dalia Tech Ltd"),
    ("is Acme Ltd legit", "Acme Ltd"),
    ("Is daliatech.ca legit?", "daliatech.ca"),
    ("is Globex Inc a scam", "Globex Inc"),
    ("is Initech LLC dodgy?", "Initech LLC"),
    ("any red flags on Acme Ltd", "Acme Ltd"),
    ("what are the red flags for Globex Inc", "Globex Inc"),
    ("does Acme Ltd have anything shady going on", "Acme Ltd"),
    ("is there anything wrong with Acme Ltd", "Acme Ltd"),
    ("anything wrong with Initech LLC?", "Initech LLC"),
    ("check Acme Ltd for fraud", "Acme Ltd"),
    ("run a fraud check on Globex Inc", "Globex Inc"),
    ("is Acme Ltd risky", "Acme Ltd"),
    ("see if Acme Ltd is legit", "Acme Ltd"),
    ("see if Globex Inc is a scam", "Globex Inc"),
    ("can I trust Acme Ltd", "Acme Ltd"),
    ('see if "Smith and Sons Ltd" has anything shady going on', "Smith and Sons Ltd"),
    ("IS ACME LTD LEGIT?", "ACME LTD"),
    ("find out whether Acme Ltd is suspicious", "Acme Ltd"),
    ("is Acme Ltd safe to do business with", "Acme Ltd"),
    ("check whether the company Globex Inc has anything dodgy going on", "Globex Inc"),
]

UNKNOWN_CASES: List[str] = [
    "",
    "   ",
    "hello",
    "what is the weather in Toronto",
    "tell me a joke",
    "Acme Ltd",
    "is Jane Smith connected to",
    "is connected to Acme Ltd",
    "is Acme Ltd connected to Acme Ltd",
    "any ties between Acme Ltd",
    "is anything shady",
    "is legit",
]


def _texts(plan: AskPlan) -> List[str]:
    return [entity.text for entity in plan.entities]


@pytest.mark.parametrize(("question", "first", "second"), CONNECTION_CASES)
def test_connection_phrasings(question: str, first: str, second: str) -> None:
    plan = parse_question(question)
    assert plan.intent is Intent.CONNECTION, plan
    assert _texts(plan) == [first, second]


@pytest.mark.parametrize(("question", "company"), RISK_CASES)
def test_company_risk_phrasings(question: str, company: str) -> None:
    plan = parse_question(question)
    assert plan.intent is Intent.COMPANY_RISK, plan
    assert _texts(plan) == [company]


@pytest.mark.parametrize("question", UNKNOWN_CASES)
def test_unknown_phrasings(question: str) -> None:
    plan = parse_question(question)
    assert plan.intent is Intent.UNKNOWN
    assert plan.entities == ()


def test_suite_has_at_least_25_phrasings_for_both_intents() -> None:
    assert len(CONNECTION_CASES) + len(RISK_CASES) + len(UNKNOWN_CASES) >= 50
    assert len(CONNECTION_CASES) >= 20 and len(RISK_CASES) >= 15


def test_entity_kinds_in_a_connection() -> None:
    plan = parse_question("see if Abdul Rehman Akingbola is connected to daliatech.ca")
    assert [e.kind for e in plan.entities] == [EntityKind.PERSON, EntityKind.DOMAIN]
    assert plan.person is not None and plan.person.text == "Abdul Rehman Akingbola"
    assert plan.needs_pi is True


def test_company_only_plan_needs_no_pi() -> None:
    plan = parse_question("is Dalia Tech Ltd legit")
    assert [e.kind for e in plan.entities] == [EntityKind.ORGANISATION]
    assert plan.person is None
    assert plan.needs_pi is False


def test_risk_question_can_name_a_person_too() -> None:
    plan = parse_question("see if Acme Ltd run by Jane Smith has anything shady going on")
    assert plan.intent is Intent.COMPANY_RISK
    assert _texts(plan) == ["Acme Ltd", "Jane Smith"]
    assert plan.needs_pi is True


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("Abdul Rehman Akingbola", EntityKind.PERSON),
        ("Jane Smith", EntityKind.PERSON),
        ("Dalia Tech Ltd", EntityKind.ORGANISATION),
        ("Acme Holdings", EntityKind.ORGANISATION),
        ("daliatech.ca", EntityKind.DOMAIN),
        ("https://www.acme.com/about", EntityKind.DOMAIN),
        ("jane.smith@gmail.com", EntityKind.PERSON),
        ("0x52908400098527886E0F7030069857D2E4169EE7", EntityKind.OTHER),
    ],
)
def test_classify_entity(text: str, kind: EntityKind) -> None:
    assert classify_entity(text) is kind


def test_unknown_plan_has_help_text() -> None:
    plan = parse_question("what is the weather")
    assert plan.intent is Intent.UNKNOWN
    assert "is X connected to Y" in plan.help_text()
    assert "bunnyhole trace" in plan.help_text()
