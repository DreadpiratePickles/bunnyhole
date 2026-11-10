"""Word lists and patterns of the AI-analysis validator: allowlists first, blocklists as a second layer.

Pure data. Kept apart from the checks so each list can be read (and challenged) on its own. Every regex here is
linear: no nested quantifiers, possessive quantifiers where a run can be long, and every pattern is only ever run on
text that has already passed the length cap of ``pi_narrative_validate``.
"""

from __future__ import annotations

import re
from typing import FrozenSet

# --------------------------------------------------------------------------------------- allowlists

#: Verbs a next-step sentence may start with (casefolded). Anything else is rejected: structure, not a blocklist.
LAWFUL_VERBS: FrozenSet[str] = frozenset(
    {"obtain", "request", "verify", "review", "search", "check", "screen", "confirm", "compare", "archive", "record",
     "engage", "consult", "interview", "seek", "ask", "retain", "collect", "document", "monitor", "cross-check",
     "crosscheck", "run", "query", "escalate", "stop", "refer", "preserve", "capture", "identify", "trace",
     "corroborate", "re-screen", "rescreen", "extend", "narrow", "list", "map", "note", "contact", "call", "pull"}
)
#: Verbs that reach a person: the sentence must also carry an honest-identification phrase.
CONTACT_VERBS: FrozenSet[str] = frozenset({"interview", "ask", "contact", "call"})
HONEST_IDENTIFICATION_RE = re.compile(
    r"\bidentify\s+yourself\b|\bidentifying\s+yourself\b|\bopenly\b|\bwith\s+disclosure\s+of\s+(?:the\s+)?purpose\b"
    r"|\btruthfully\b|\bhonest(?:ly)?\s+self-identification\b|\bself-identif\w+\b",
    re.IGNORECASE,
)

#: Capitalised words that may start a sentence without being in the evidence (function words and starters).
SENTENCE_STARTERS: FrozenSet[str] = frozenset(
    {"the", "this", "these", "those", "both", "each", "any", "all", "some", "its", "their", "his", "her", "our",
     "whether", "while", "although", "however", "if", "when", "since", "because", "after", "before", "as", "in", "on",
     "at", "by", "for", "from", "with", "without", "of", "to", "and", "or", "but", "not", "no", "none", "neither",
     "nothing", "nobody", "only", "several", "multiple", "many", "most", "other", "another", "one", "two", "three",
     "four", "five", "six", "it", "there", "what", "which", "where", "who", "how", "why", "licensed", "free", "paid",
     "incorporated", "registered", "appointed", "filed", "founded", "dissolved", "formed", "listed", "owned",
     "ownership", "no-hit", "a", "an", "hash", "digest", "receipt", "receipts", "record", "records", "source",
     "sources", "finding", "findings", "extract"}
) | LAWFUL_VERBS

#: Capitalised words allowed anywhere: acronyms and legal frames the rules name, generic institutional words.
ALLOWED_WORDS: FrozenSet[str] = frozenset(
    {"ofac", "sdn", "pipeda", "fcra", "glba", "dppa", "ubo", "kyc", "aml", "pep", "peps", "sha", "url", "ai", "llm",
     "pi", "eu", "un", "uk", "us", "usa", "lei", "id", "ids", "canada", "canadian", "ontario", "wayback", "ltd",
     "inc", "llc", "plc", "corp", "gmbh",
     "business", "registry", "registries", "corporate", "court", "courts", "land", "title", "titles", "companies",
     "company", "house", "office", "commercial", "securities", "exchange", "commission", "federal", "provincial",
     "national", "county", "primary", "official", "public", "consolidated", "sanctions", "list", "lists", "docket",
     "dockets", "register"}
)
MONTHS = ("january", "february", "march", "april", "may", "june", "july", "august", "september", "october",
          "november", "december")
#: Constants with digits that the rules themselves name; always allowed.
ALLOWED_NUMBER_TOKENS: FrozenSet[str] = frozenset({"50", "50%", "256", "sha-256", "sha256"})

#: Jurisdiction code (as in ``--pi-jurisdiction``) to the words a model may use for it.
JURISDICTION_WORDS = {
    "ca": ("canada", "canadian"), "us": ("united", "states", "america", "american"),
    "uk": ("united", "kingdom", "britain", "british", "england"), "au": ("australia", "australian"),
}

# --------------------------------------------------------------------------------------- forbidden methods

_LEGAL_PROCESS = r"court\s+order|subpoena|legal\s+process|production\s+order|warrant|through\s+counsel|via\s+counsel"
LEGAL_PROCESS_RE = re.compile(_LEGAL_PROCESS, re.IGNORECASE)
#: Records that only legal process may reach: rejected unless the same sentence names the legal process.
PROCESS_ONLY_RE = re.compile(
    r"\b(?:bank|account|phone|call|telephone|mobile|text\s+message|sms)\s+(?:records?|statements?|logs?|history)\b",
    re.IGNORECASE,
)
PUBLIC_PLACE_RE = re.compile(r"\bpublic\s+(?:place|space|road|street)s?\b|\bpublicly\b", re.IGNORECASE)
SURVEIL_RE = re.compile(r"\bsurveil\w*|\bstake[- ]?out\b|\bfollow(?:ing|ed)?\s+(?:him|her|them|the\s+subject)\b", re.IGNORECASE)
FORBIDDEN_METHOD_RE = re.compile(
    r"\bpretext\w*|\bfalse\s+(?:pretens?es?|pretences?|name|names|identity|identities)\b"
    r"|\b(?:assumed|fake|fictitious|borrowed)\s+(?:identity|identities|name|names)\b"
    r"|\bhack(?:ing|ed|s|er|ers)?\b|\bbypass\w*|\bimpersonat\w+|\bsocial[- ]engineer\w*|\bphish\w*|\bspoof\w*"
    r"|\bbrute[- ]?forc\w*|\bcredential[- ]stuff\w*"
    r"|\b(?:log(?:ging|s)?|sign(?:ing|s)?)\s+in(?:to)?\s+(?:to\s+)?(?:his|her|their|the|a|an|someone's)\s+(?:\w+\s+){0,2}account"
    r"|\bpassword\s+(?:reset|resets|recovery)\b|\breset\s+links?\b|\b(?:reset|guess|crack)\w*\s+(?:his|her|their|the|a)\s+(?:\w+\s+)?password"
    r"|\b(?:get|getting|break|breaking|gain\w*|access\w*)\s+(?:into|to)?\s*(?:his|her|their|the\s+subject's)\s+"
    r"(?:\w+\s+)?(?:accounts?|mailbox|mailboxes|phone|device|devices|email|inbox|messages|computer|laptop)"
    r"|\b(?:get|getting|break|breaking)\s+into\b|\bbreak(?:ing)?\s+in\b"
    r"|\btrespass\w*|\bwiretap\w*|\beavesdrop\w*|\bintercept\w*|\bstalk\w*|\btap(?:s|ped|ping)?\b"
    r"|\bgps\s+track\w*|\btrackers?\b|\btracking\s+device|\btail(?:s|ed|ing)\b"
    r"|\btrack\w*\s+(?:his|her|their|the\s+subject's)\s+(?:phone|vehicle|car|location|movements)"
    r"|\b(?:monitor|watch|read|listen)\w*\s+(?:to\s+)?(?:his|her|their|the\s+subject's)\s+(?:phone|calls|messages|email|mailbox|texts)"
    r"|\bpos(?:e|es|ed|ing)\s+as\b|\bpretend\w*|\bpassing\s+(?:yourself|himself|herself)\s+off\b"
    r"|\b(?:fake|dummy|sock[- ]?puppet|burner)\s+(?:account|profile|identity|persona|email)"
    r"|\bcovert(?:ly)?\b|\bdumpster\b|\btrash\b|\binsiders?\b|\bleak\w*|\bbreach(?:ed)?\s+(?:database|data|dump|corpus)\b"
    r"|\bdehashed\b|\bwithout\s+(?:their|his|her|the\s+subject's)\s+(?:knowledge|consent|permission)"
    r"|\bdeceiv\w+|\bdeceptive\w*",
    re.IGNORECASE,
)

# --------------------------------------------------------------------------------------- accusations

ACCUSATION_RE = re.compile(
    r"\bfraud\w*|\bcriminal\w*|\bcrimes?\b|\blaunder\w*|\billegal\w*|\bunlawful\w*|\bcorrupt\w*|\bbrib\w*|\bscam\w*"
    r"|\bterror\w*|\bguilty\b|\bdangerous\b|\bshady\b|\bsuspicious\b|\bsuspect(?:s|ed)?\b|\bevad\w*|\bevasion\b|\bsham\b"
    r"|\bfront\s+compan\w+|\bembezzl\w*|\btheft\b|\bsteal\w*|\bstole\b|\billicit\b|\bwrongdoing\b|\bmisconduct\b"
    r"|\bdishonest\w*|\bmalicious\b|\bextort\w*|\bblackmail\w*|\bnefarious\b|\bmafia\b|\bracketeer\w*",
    re.IGNORECASE,
)

# --------------------------------------------------------------------------------------- sanctions and clearance

#: A sentence is about sanctions when it matches this (or cites an S or W id).
SANCTIONS_CONTEXT_RE = re.compile(
    r"\bsanction\w*|\blisted\b|\blistings?\b|\bscreen\w*|\bofac\b|\bsema\b|\bsdn\b|\bwatch\s?list\w*|\bblocklist\w*"
    r"|\bdenied\s+part\w+|\bdesignat\w+",
    re.IGNORECASE,
)
#: Conclusions that are rejected even when negated (they are claims about risk or fitness, not restatements).
CLEARANCE_ALWAYS_RE = re.compile(
    r"\ball[- ]clear\b|\bin\s+the\s+clear\b|\b(?:low|minimal|zero|negligible|no|little|limited)\s+(?:\w+\s+){0,2}risks?\b"
    r"|\brisk[- ]free\b|\bnot\s+(?:been\s+)?sanctioned\b|\binnocen\w*|\bexonerat\w*|\bcompliant\b|\bcompliance\b"
    r"|\bsaf(?:e|ely|ety)\b|\bno\s+(?:\w+\s+)?(?:concerns?|worr(?:y|ies)|issues?|problems?|red\s+flags?|exposure)\b"
    r"|\bworr(?:y|ies)\b|\bgood\s+standing\b|\bgreen\s+light\b|\bfree\s+(?:of|from)\s+(?:any\s+)?(?:sanctions?|listings?)\b"
    r"|\b(?:clear|clean)\s+(?:of|from)\b|\bnot\s+(?:on|in)\s+(?:any|a|the)\s+(?:\w+\s+){0,2}(?:lists?|register)\b",
    re.IGNORECASE,
)
#: Rejected unless negated directly before the word.
CLEARANCE_NEGATABLE_RE = re.compile(r"\b(?:clear|cleared|clearance|clean)\b", re.IGNORECASE)
#: Same, but only in a sanctions sentence.
SANCTIONS_NEGATABLE_RE = re.compile(
    r"\b(?:pass|passed|passes|passing|fine|ok|okay|acceptable|proceed|eligible|approved|approve)\b", re.IGNORECASE
)
#: Absence-of-a-hit phrasing: allowed only in a sentence that also carries a qualifier.
NEGATED_HIT_RE = re.compile(
    r"\bno[- ](?:\w+[- ]){0,2}(?:hits?|match(?:es)?|matching|listings?|entries|results?|records?)\b"
    r"|\bzero\s+(?:hits?|matches)\b|\bnothing\s+(?:was\s+|were\s+)?(?:found|returned|matched)\b|\bnot\s+(?:found|listed|present)\b"
    r"|\bdid\s+not\s+(?:match|return|appear|find)\b|\breturned\s+(?:nothing|no)\b|\babsence\s+of\b"
    r"|\bfound\s+(?:nothing|no)\b|\bnot\s+matched\b|\bnon-match\b",
    re.IGNORECASE,
)
SANCTIONS_QUALIFIER_RE = re.compile(
    r"\bnot\s+(?:been\s+)?(?:screened|reached|run)\b|\bnot\s+clearance\b|\bnot\s+a\s+clearance\b"
    r"|\bdoes\s+not\s+(?:clear|establish)\b|\bcannot\s+(?:be\s+treated\s+as\s+)?clear\b|\bno\s+clearance\b",
    re.IGNORECASE,
)

# --------------------------------------------------------------------------------------- labels

NEGATORS: FrozenSet[str] = frozenset({"not", "no", "never", "cannot", "can't", "isn't", "aren't", "wasn't", "hasn't",
                                      "without", "neither", "nor", "un"})
#: Words that may sit between a negator and the word it negates ("has not been confirmed").
NEGATION_BRIDGES: FrozenSet[str] = frozenset({"been", "be", "yet", "a", "an", "the", "fully", "really", "simply",
                                              "necessarily", "is", "was", "are", "were"})
UPGRADE_RE = re.compile(
    r"\bconfirmed\b|\bconfirms\b|\bconfirming\b|\bverified\b|\bverifies\b|\bcorroborated\b|\bproven\b|\bproves?\b"
    r"|\bestablished\b|\bauthenticated\b|\bdefinite(?:ly)?\b|\bcertain(?:ly)?\b|\bundoubted(?:ly)?\b"
    r"|\b(?:beyond|without|no)\s+(?:any\s+)?(?:doubt|question)\b|\bconclusive(?:ly)?\b|\bdefinitive(?:ly)?\b"
    r"|\bunquestion\w+|\bindisputabl\w+|\b(?:a|the)\s+fact\b|\bfactual(?:ly)?\b"
    r"|\bbelongs?\s+to\s+the\s+subject\b|\b(?:is|are)\s+the\s+subject(?:'s)?\b|\bsame\s+(?:person|entity|individual|company)\b",
    re.IGNORECASE,
)
#: Words that are not negations even though they contain one ("no doubt" is an upgrade, not a negation).
PROBABLE_RE = re.compile(r"\bprobabl[ey]\b|\blikely\b", re.IGNORECASE)
HEDGE_RE = re.compile(
    r"\bappears?\b|\bmay\b|\bmight\b|\bcould\b|\bpossibl[ey]\b|\bsuggests?\b|\bsuggested\b|\blead\b|\bleads\b"
    r"|\bunverified\b|\bunconfirmed\b|\bnot\s+(?:been\s+)?(?:confirmed|verified|established)\b|\bsingle\s+source\b"
    r"|\bone\s+source\b|\bonly\s+one\b|\bcorroborat\w+|\buncorroborated\b|\btentative\b|\bneeds?\s+(?:a\s+)?(?:second|further)\b",
    re.IGNORECASE,
)
SET_ASIDE_WORDING_RE = re.compile(
    r"\bset[- ]aside\b|\bnot\s+linked\b|\bweak\b|\bunconfirmed\b|\bnot\s+(?:a\s+)?finding\b|\bname\s+match\b|\bno\s+link\b",
    re.IGNORECASE,
)
IDENTITY_CLAIM_RE = re.compile(
    r"\bsame\s+(?:person|entity|individual|company)\b|\b(?:is|are)\s+the\s+subject\b|\bbelongs?\s+to\s+the\s+subject\b"
    r"|\b(?:linked|connected|tied|related)\s+to\s+the\s+subject\b|\bassociated\s+with\s+the\s+subject\b",
    re.IGNORECASE,
)
