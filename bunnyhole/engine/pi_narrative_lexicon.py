"""Word lists and patterns of the AI-analysis validator.

The model writes one thing only: citation-first connection bullets. These lists decide what such a bullet may NOT
contain (topics that belong to code-built sections, certainty words, accusation words) and which capitalised words
need no support in the evidence. Pure data. Every regex is linear: no nested quantifiers, bounded repetition, and it
only ever runs on text that already passed the length cap and the character allowlist of ``pi_narrative_validate``.
"""

from __future__ import annotations

import re
from typing import FrozenSet

#: Closed-class English words: articles, pronouns, prepositions, conjunctions, auxiliaries. A capitalised one (the
#: first word of a sentence) needs no support in the evidence because none of them can be a name. They also feed the
#: cheap language gate (``MIN_FUNCTION_WORD_SHARE``).
FUNCTION_WORDS: FrozenSet[str] = frozenset(
    {"a", "an", "the", "this", "that", "these", "those", "both", "each", "every", "any", "all", "some", "its", "their",
     "his", "her", "our", "it", "they", "them", "he", "she", "we", "i", "you", "there", "here", "of", "to", "in", "on",
     "at", "by", "for", "from", "with", "without", "into", "onto", "over", "under", "between", "through", "across",
     "within", "about", "against", "among", "and", "or", "but", "nor", "so", "yet", "if", "when", "while", "although",
     "because", "since", "after", "before", "until", "as", "than", "then", "also", "only", "just", "more", "most",
     "other", "another", "such", "same", "is", "are", "was", "were", "be", "been", "being", "am", "has", "have", "had",
     "do", "does", "did", "will", "would", "may", "might", "could", "can", "should", "must", "shall", "not", "no",
     "which", "who", "whom", "whose", "what", "where", "how", "why", "whether", "either", "neither", "per", "via",
     "upon", "off", "out", "up", "down", "too", "very", "still", "even", "ever", "never", "often", "once", "again"}
)
#: Share of the words that are not in the evidence which must be English function words (language gate).
MIN_FUNCTION_WORD_SHARE = 0.25
MIN_WORDS_FOR_LANGUAGE_GATE = 4

#: Capitalised words allowed without support in the evidence: legal forms and generic institution words.
ALLOWED_WORDS: FrozenSet[str] = frozenset(
    {"ltd", "inc", "llc", "plc", "corp", "gmbh", "co", "business", "registry", "registries", "register", "corporate",
     "court", "courts", "land", "title", "titles", "companies", "company", "house", "office", "commercial",
     "securities", "exchange", "commission", "federal", "provincial", "national", "county", "official", "public",
     "docket", "dockets", "ontario", "canada", "canadian", "canlii", "pacer", "edgar", "sec", "gleif", "opencorporates",
     "wikidata", "courtlistener"}
)
MONTHS = ("january", "february", "march", "april", "may", "june", "july", "august", "september", "october",
          "november", "december")
#: Jurisdiction code (as in ``--pi-jurisdiction``) to the words a model may use for it.
JURISDICTION_WORDS = {
    "ca": ("canada", "canadian"), "us": ("united", "states", "america", "american"),
    "uk": ("united", "kingdom", "britain", "british", "england"), "au": ("australia", "australian"),
}

#: Number words: must be in the evidence like any digit (write digits that the evidence has).
NUMBER_WORDS_RE = re.compile(
    r"\b(?:zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|"
    r"seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|hundreds|thousand|"
    r"thousands|million|millions|billion|billions|percent|per\s+cent|half|quarter|dozen|dozens|double|doubled|triple|"
    r"tripled|twice|thrice|couple)\b",
    re.IGNORECASE,
)
OBFUSCATION_RE = re.compile(r"\bdot\b|\(\s*(?:at|dot)\s*\)", re.IGNORECASE)

# --------------------------------------------------------------------------------------- excluded topics

#: Connections bullets never need these words: sanctions, screening and absence talk belong to the code-built report.
EXCLUDED_TOPIC_RE = re.compile(
    r"\bsanction\w*|\bscreen\w*|\bofac\b|\bsema\b|\bsdn\b|\bwatch\s?list\w*|\bblock\s?list\w*|\bpeps?\b"
    r"|\bpolitically\s+exposed\b|\blists?\b|\blisted\b|\blisting\w*|\bhits?\b|\bmatch(?:es|ed|ing)?\b"
    r"|\bflag(?:s|ged|ging)?\b|\bunflagged\b|\bclear\w*|\bclean\w*|\bsafe\w*|\bsafety\b|\brisk\w*|\bcompliant\b"
    r"|\bcompliance\b|\bconcern\w*|\bworr\w*|\bnegative\b|\bempty\b|\bnothing\b|\bnone\b|\bno\s+(?:\w+\s+){0,2}"
    r"(?:found|matched|returned)\b|\babsent\w*|\babsence\b|\bnot\s+on\b|\bnot\s+listed\b|\bfine\b|\bok\b|\bokay\b"
    r"|\bchecks?\s+out\b|\brul(?:e|ed|es|ing)\s+out\b|\bpass(?:ed|es|ing)?\b|\badverse\b|\bspotless\b|\breassur\w*"
    r"|\bgood\s+to\s+go\b|\ball\s+good\b|\bgood\s+shape\b|\bpriority\b|\bissues?\b|\bproblems?\b|\bred\s+flags?\b"
    r"|\bexposure\b|\beligible\b|\bapproved?\b|\bacceptable\b|\bproceed\w*|\binnocen\w*|\bexonerat\w*",
    re.IGNORECASE,
)

# --------------------------------------------------------------------------------------- certainty words

#: Label words and certainty words: the code renders the label next to every tag, so the model never states one.
CERTAINTY_RE = re.compile(
    r"\bconfirm\w*|\bverif\w*|\bestablish\w*|\bprov(?:e|es|ed|en|ing)\b|\bdefinite\w*|\bcertain\w*|\bundoubted\w*"
    r"|\bauthentic\w*|\bconclusive\w*|\bdefinitive\w*|\bunquestion\w*|\bindisput\w*|\bbeyond\s+(?:any\s+)?doubt\b"
    r"|\b(?:no|without)\s+(?:any\s+)?(?:doubt|question)\b|\bsurely\b|\bsame\s+(?:person|entity|individual|company)\b"
    r"|\bbelong\w*|\b(?:is|are|was|were)\s+the\s+subject\b|\bthe\s+subject's\b|\bvalidated?\b|\bvalid\b|\bsolid\b"
    r"|\bsettled\b|\bgenuine\b|\bindeed\b|\bobviously\b|\bclearly\b|\bfactual\w*|\ba\s+fact\b",
    re.IGNORECASE,
)

# --------------------------------------------------------------------------------------- accusations

ACCUSATION_RE = re.compile(
    r"\bfraud\w*|\bcriminal\w*|\bcrimes?\b|\blaunder\w*|\billegal\w*|\bunlawful\w*|\bcorrupt\w*|\bbrib\w*|\bscam\w*"
    r"|\bterror\w*|\bguilty\b|\bdangerous\b|\bshady\b|\bsuspicious\b|\bsuspect(?:s|ed)?\b|\bevad\w*|\bevasion\b|\bsham\b"
    r"|\bfront\s+compan\w+|\bembezzl\w*|\btheft\b|\bsteal\w*|\bstole\b|\billicit\b|\bwrongdoing\b|\bmisconduct\b"
    r"|\bdishonest\w*|\bmalicious\b|\bextort\w*|\bblackmail\w*|\bnefarious\b|\bmafia\b|\bracketeer\w*|\bcrook\w*"
    r"|\bfelon\w*|\bconvict\w*|\borgani[sz]ed\s+crime\b|\bhide\s+money\b|\bshell\b",
    re.IGNORECASE,
)


# --------------------------------------------------------------------------------------- methods and advice

#: The code builds every next step. A Connections bullet that names a method or gives advice is rejected, including
#: a sentence that only says "do not ...".
ADVICE_OR_METHOD_RE = re.compile(
    r"\bshould\b|\bmust\b|\bought\b|\brecommend\w*|\badvis\w*|\bsuggest\w*|\bneeds?\s+to\b|\bnext\s+steps?\b|\bwe\s+can\b"
    r"|\bpretext\w*|\bfalse\s+(?:pretens?es?|pretences?|name|names|identity|identities)\b"
    r"|\b(?:assumed|fake|fictitious|borrowed)\s+(?:identity|identities|name|names)\b"
    r"|\b(?:fake|dummy|sock[- ]?puppet|burner)\s+(?:account|profile|identity|persona|email)\b"
    r"|\bhack(?:ing|ed|s|er|ers)?\b|\bbypass\w*|\bimpersonat\w+|\bsocial[- ]engineer\w*|\bphish\w*|\bspoof\w*"
    r"|\bbrute[- ]?forc\w*|\bcredential\w*|\bpassword\w*|\blog(?:ging|s)?\s*in\b|\bsign(?:ing|s)?\s+in\b|\blogin\b"
    r"|\b(?:get|getting|break|breaking|gain\w*|access\w*)\s+(?:into|to)\b|\bbreak(?:ing)?\s+in\b"
    r"|\btrespass\w*|\bwiretap\w*|\beavesdrop\w*|\bintercept\w*|\bstalk\w*|\btap(?:s|ped|ping)?\b"
    r"|\bgps\b|\btrackers?\b|\btracking\b|\btail(?:s|ed|ing)\b|\bsurveil\w*|\bstake[- ]?out\b"
    r"|\bfollow(?:ing|ed)?\s+(?:him|her|them)\b"
    r"|\bpos(?:e|es|ed|ing)\s+as\b|\bpretend\w*|\bcovert(?:ly)?\b|\bdumpster\b|\btrash\b|\binsiders?\b|\bleak\w*"
    r"|\bbreach(?:ed)?\b|\bdehashed\b|\bphone\s+(?:records?|numbers?)\b|\bbank\s+(?:records?|statements?)\b"
    r"|\bcall\s+records?\b|\bmedical\b|\bcredit\s+report\b"
    r"|\bwithout\s+(?:their|his|her)\s+(?:knowledge|consent|permission)"
    r"|\bdeceiv\w+|\bdeceptive\w*|\bunlock\w*",
    re.IGNORECASE,
)
#: Imperative verbs that may not start a bullet (a bullet describes a link; it never gives an instruction).
IMPERATIVE_STARTS: FrozenSet[str] = frozenset(
    {"obtain", "request", "verify", "review", "search", "check", "screen", "confirm", "compare", "archive", "record",
     "engage", "consult", "interview", "seek", "ask", "retain", "collect", "document", "monitor", "run", "query",
     "contact", "call", "do", "don't", "never", "use", "go", "visit", "send", "download", "capture", "stop"}
)
SEASONS_RE = re.compile(
    r"\b(?:spring|summer|autumn|fall|winter|yesterday|today|tomorrow|recently|decade|decades|century|annual\w*|"
    r"monthly|weekly)\b",
    re.IGNORECASE,
)
