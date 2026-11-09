"""Phrase and pattern vocabulary for the PI purpose gates (data only; matching lives in ``pi_gates``).

Split out of ``pi.py`` unchanged. Every literal is matched against text normalised by ``pi_gates._normalize_text``.
"""

from __future__ import annotations

from bunnyhole.engine.pi_gate_patterns import (
    ELIGIBILITY_VERB_ROLE_PATTERNS,
    EXTRA_ELIGIBILITY_TERMS,
    PURSUIT_EXTRA_PATTERNS,
)

MIN_PURPOSE_CHARS = 15

# Eligibility decisions are FCRA-regulated consumer-report territory: Bunnyhole refuses them outright.
# Literal phrases (any case, any hyphen/space/punctuation spelling: both sides are normalised, see
# ``_normalize_text``). Bare risky words ("hiring", "underwriting", "rental") are NOT listed: they also occur in
# legitimate fraud and asset work ("fraud in hiring of subcontractor", "underwriting syndicate litigation").
FORBIDDEN_ELIGIBILITY_TERMS: tuple[str, ...] = (
    "employment screening",
    "employment background check",
    "pre-employment",
    "preemployment",
    "employment eligibility",
    "employment decision",
    "hiring decision",
    "hire decision",
    "hiring purposes",
    "job applicant",
    "job candidate",
    "job seeker",
    "new hire",
    "new employee",
    "prospective employee",
    "prospective tenant",
    "potential tenant",
    "tenant screening",
    "tenant eligibility",
    "tenant background check",
    "tenant risk",
    "good tenant",
    "rental application",
    "rental eligibility",
    "rental screening",
    "rental applicant",
    "lease applicant",
    "housing eligibility",
    "housing application",
    "housing decision",
    "credit application",
    "credit eligibility",
    "credit decision",
    "creditworthiness",
    "credit worthiness",
    "creditworthy",
    "extend credit",
    "credit score",
    "credit history",
    "credit report",
    "loan application",
    "loan eligibility",
    "loan decision",
    "loan applicant",
    "lending decision",
    "insurance eligibility",
    "insurance underwriting",
    "insurance application",
    "insurability",
    "loan underwriting",
    "credit underwriting",
    "mortgage underwriting",
    "underwriting decision",
    "babysitter",
    "nanny",
    "caregiver applicant",
    "offer letter",
    "safe hire",
    "good hire",
    "bad hire",
    "financial responsibility",
    "prospective renter",
    "prospective borrower",
    "prospective hire",
    *EXTRA_ELIGIBILITY_TERMS,
)

# Flexible eligibility wordings (regexes over the normalised text). Kept short and specific.
FORBIDDEN_ELIGIBILITY_PATTERNS: tuple[str, ...] = (
    r"\bcandidates?\b",  # job candidates; non-hiring senses are removed first, see _NON_HIRING_CANDIDATE
    r"\b(?:job|loan|credit|mortgage|nanny|housing|employment|tenant|caregiver|babysitter)\s+applicants?\b",
    r"\bapplicants?\s+(?:qualif\w*|is\s+eligible|are\s+eligible|is\s+suitable|is\s+safe)\b",
    r"\bapplicants?\s+for\s+(?:the\s+|an?\s+)?"
    r"(?:job|position|role|apartment|flat|rental|lease|tenancy|loan|credit|mortgage)\b",
    r"\bqualif(?:y|ies|ied)\s+for\s+(?:the\s+|an?\s+)?"
    r"(?:apartment|flat|rental|lease|tenancy|loan|mortgage|credit|job|position|housing)\b",
    r"\b(?:safe|suitable|fit|okay|ok|good|right)\s+to\s+(?:hire|employ|rent|lease|lend)\b",
    r"\bwhether\s+(?:or\s+not\s+)?(?:to\s+)?(?:hire|employ|rent|lease|lend|extend|approve|offer)\b",
    r"\b(?:extend|extending|grant|granting|approve|approving|deny|denying)\s+"
    r"(?:a\s+|the\s+|him\s+|her\s+|them\s+)?(?:credit|loan|mortgage|tenancy)\b",
    r"\b(?:offer|offering)\s+(?:him\s+|her\s+|them\s+)?(?:the\s+|a\s+)?(?:position|job|role|employment)\b",
    r"\b(?:rent|renting|lease|leasing)\s+to\s+(?:this|him|her|them|a|an|the|my|our)\b",
    r"\bcredit\s+risk\s+of\s+(?:this|the|that|an?|my|our)\s+"
    r"(?:person|individual|applicant|consumer|borrower|customer|man|woman|couple|tenant)\b",
    r"\bcredit\s+risk\s+of\s+(?:him|her|them)\b",
    r"\b(?:good|bad|suitable|reliable|risky|trustworthy)\s+(?:tenant|borrower|renter|hire)s?\b",
    r"\bhiring\s+(?:process|manager|someone|somebody|him|her|them)\b",
    r"\bbackground\s+(?:check|screening|screen|vetting)s?\b.{0,40}"
    r"\b(?:applicant|candidate|new\s+hire|new\s+employee|prospective\s+(?:employee|tenant))",
    r"\bunderwrit(?:e|ing)\s+(?:the\s+|a\s+|this\s+)?(?:policy|loan|applicant|application|risk|file)\b",
    # --- second hardening pass: concepts the first lists missed (hire, applicant, tenant, loan, insurance) ---
    r"\bapplicants?\b",  # patent/permit/visa/... senses are removed first, see _NON_HIRING_APPLICANT
    r"\bappl(?:ied|y|ying)\s+(?:for|to)\b(?:\s+\w+){0,4}?\s+"
    r"(?:jobs?|positions?|roles?|posts?|openings?|vacanc(?:y|ies)|apartments?|flats?|units?|rentals?|leases?|"
    r"tenanc(?:y|ies)|loans?|mortgages?|credit|insurance|housing|internships?)\b",
    r"\b(?:safe|good|great|right|solid|suitable|reliable|trustworthy|risky|bad|wrong)\s+"
    r"(?:hires?|employees?|renters?|borrowers?)\b",
    r"\bbring(?:ing)?\s+(?:him|her|them|(?:this|that|the|a|an|our|my)\s+(?:\w+\s+){0,2}"
    r"(?:person|guy|man|woman|lady|applicant|candidate|engineer|developer|accountant|driver|hire|employee|"
    r"contractor|worker|staff|member|assistant))\s+(?:on|onboard|aboard)\b",
    r"\bonboard(?:ing)?\s+(?:him|her|them)\b",
    r"\bonboard(?:ing)?\s+(?:(?:a|an|the|this|our|my|new)\s+)+(?:\w+\s+){0,2}"
    r"(?:person|individual|employee|hire|engineer|developer|worker|staff|contractor|driver|nanny|assistant|"
    r"accountant)\b",
    r"\bput(?:ting)?\s+(?:him|her|them|\w+)\s+on\s+(?:the\s+|our\s+|my\s+)?payroll\b",
    r"\bnew\s+(?:driver|recruit|team\s+member|staff\s+member|receptionist|cleaner|housekeeper|assistant)\b",
    r"\b(?:rent|renting|lease|leasing|sublet|subletting|sublease|subleasing)\s+(?:out\s+)?(?:my|our)\b",
    r"\b(?:wants?|wanting|wanted|hopes?|hoping|looking|planning)\s+to\s+(?:rent|lease|sublet|move\s+in)\b",
    r"\bred\s+flags?\b(?:\W+\w+){0,8}?\W+(?:tenant|renter|applicant|candidate|hire|borrower|employee|nanny)s?\b",
    r"\b(?:tenant|renter|applicant|candidate|hire|borrower|nanny)s?\b(?:\W+\w+){0,8}?\W+red\s+flags?\b",
    r"\bfinancial(?:ly)?\s+responsib\w+",
    r"\b(?:approve|approving|approved|grant|granting|deny|denying|extend|extending)\s+"
    r"(?:a\s+|an\s+|the\s+|him\s+|her\s+|them\s+)?(?:\w+\s+){0,2}"
    r"(?:loan|mortgage|credit|financing|line\s+of\s+credit|credit\s+line|tenancy)\b",
    r"\bgood\s+for\s+(?:a\s+|an\s+|the\s+)?(?:\w+\s+){0,2}(?:loan|mortgage|credit|line\s+of\s+credit)\b",
    r"\bqualif(?:y|ies|ied|ying)\s+for\s+(?:our|the|a|an|this|my)\s+(?:\w+\s+){0,2}"
    r"(?:insurance|polic(?:y|ies)|coverage|loan|mortgage|credit|apartment|flat|rental|lease|tenancy|housing|job|"
    r"position|unit)\b",
    r"\bshould\s+(?:we|i)\s+(?:hire|employ|rent|lease|lend|approve|extend|offer)\b",
    r"\b(?:hire|hiring|employ|employing)\s+(?:him|her|them|this\s+(?:person|man|woman|guy|individual|lady)|"
    r"that\s+(?:person|man|woman|guy)|a\s+(?:new\s+)?(?:person|man|woman|guy|worker|driver|nanny|assistant|"
    r"receptionist))\b",
    r"\bbefore\s+(?:we\s+|i\s+)?(?:hire|hiring|employ|employing|renting|leasing)\b",
    # "before onboarding" is a cue only next to a person role: see ONBOARDING_CUE (a KYC refresh of a company is not)
    # --- third hardening pass: verb + role in either order, prospective roles, loanword stems (pi_gate_patterns) ---
    *ELIGIBILITY_VERB_ROLE_PATTERNS,
)

# "Before onboarding" is an eligibility cue only when the same text also names a person role (employee, hire,
# candidate, tenant, nanny, driver, an individual contractor ...): "know-your-customer refresh on a corporate client
# before onboarding" is regulatory work. Matched in ``pi_gates``; the declared KYC category exempts the cue.
ONBOARDING_CUE = r"\bbefore\s+(?:we\s+|i\s+)?onboard\w*"
ONBOARDING_PERSON_ROLE = (
    r"\b(?:employees?|new\s+hires?|recruits?|candidates?|tenants?|renters?|lodgers?|nann(?:y|ies)|babysitters?|"
    r"drivers?|applicants?|interns?|staffers?|workers?|borrowers?|"
    r"(?:independent|individual|freelance|sole)\s+contractors?|contractors?\s+(?:himself|herself))\b"
)

# "Candidate" senses that are not hiring: removed before matching so due diligence on them stays possible.
_NON_HIRING_CANDIDATE = (
    r"\b(?:acquisition|merger|takeover|investment|political|party|presidential|mayoral|electoral|election|senate|"
    r"congressional|parliamentary|partnership|licensing|clinical|drug)\s+candidates?\b"
)
# "Applicant" senses that are not a hiring, tenancy or credit decision.
_NON_HIRING_APPLICANT = (
    r"\b(?:patent|trademark|trade\s+mark|permit|planning|licen[cs]e|licensing|visa|asylum|grant|funding|motion|"
    r"petition|court|bankruptcy|insolvency|immigration|building|zoning|regulatory|registration|"
    r"ex\s+parte)\s+applicants?\b"
    r"|\bapplicants?\s+(?:company|companies|entity|entities|firm|corporation|organi[sz]ation|business)\b"
    r"|\b(?:trade|commercial|corporate|supplier|vendor)\s+(?:credit|loans?|financing)\b"
)

# Phrases that signal a locate or surveillance of a former partner or someone avoiding the client.
MOTIVE_RED_FLAGS: tuple[str, ...] = (
    "ex-girlfriend",
    "ex-boyfriend",
    "ex-wife",
    "ex-husband",
    "ex-partner",
    "ex girlfriend",
    "ex boyfriend",
    "ex wife",
    "ex husband",
    "ex partner",
    "former wife",
    "former husband",
    "former girlfriend",
    "former boyfriend",
    "former partner",
    "former fiance",
    "estranged",
    "ghosted",
    "blocked me",
    "left me",
    "dumped me",
    "broke up with me",
    "we broke up",
    "since the breakup",
    "after our relationship",
    "our relationship ended",
    "stalk",
    "revenge",
    "protective order",
    "restraining order",
    "she moved",
    "he moved",
    "won't talk to me",
    "wont talk to me",
    "won't speak to me",
    "stopped talking to me",
    "stopped speaking to me",
    "stopped replying to me",
    "stopped responding to me",
    "cut off contact",
    "cut off all contact",
    "cut me off",
    "avoiding me",
    "hiding from me",
    "changed her number",
    "changed his number",
    "changed their number",
    "where she goes",
    "where he goes",
    "get back at",
    "broke my heart",
    "breaking my heart",
    "unmatched me",
    "stopped answering",
    "stopped answering me",
    "won't give me her number",
    "won't give me his number",
    "wont give me her number",
    "wont give me his number",
    "isn't speaking to me",
    "isnt speaking to me",
    "is not speaking to me",
    "i was dating",
    "we were dating",
    "i used to date",
    "deleted her accounts",
    "deleted his accounts",
    "deleted their accounts",
    "where she lives",
    "where he lives",
    "where they live",
)

# Flexible former-partner / evasion wordings (regexes over the normalised text).
_PARTNER_WORDS = r"(?:girlfriend|boyfriend|wife|husband|partner|fianc[eé]e?|spouse|lover|significant\s+other)"
_LOCATE_WORDS = (
    r"\b(?:where|locate|find|finding|whereabouts|moved|relocated|lives|living|address|follow|following|track|"
    r"tracking|goes|going|watch|watching|monitor|spy|check\s+on|checking\s+on|at\s+night)\b"
)
_EX_NOT_PARTNER = (
    r"(?!\s+(?:employees?|employers?|colleagues?|coworkers?|boss|managers?|landlord|tenants?|suppliers?|vendors?|"
    r"contractors?|business|company|firm|clients?|customers?|associates?|staff|workers?))"
)
_WONT_GIVE_RE = (
    r"\b(?:won'?t|refus\w+\s+to|will\s+not|wouldn'?t)\s+give\s+me\s+(?:her|his|their)\s+"
    r"(?:phone\s+|cell\s+)?(?:number|address|contact|details|email)\b"
)
_DELETED_ACCOUNTS_RE = (
    r"\b(?:deleted|deactivated|disabled)\s+(?:her|his|their)\s+(?:\w+\s+){0,2}"
    r"(?:accounts?|profiles?|socials?|social\s+media|facebook|instagram|snapchat|tiktok|twitter)\b"
)
_POSTED_ABOUT_ME_RE = (
    r"\bwho\s+(?:posted|wrote|left|sent|made|said)\b[^.;]{0,80}\b(?:about|against)\s+me\b"
    r"|\b(?:reviews?|posts?|comments?|tweets?|messages?|emails?)\s+(?:about|against)\s+me\b"
)
_NOT_SPEAKING_RE = (
    r"\b(?:isn'?t|isnt|is\s+not|aren'?t|are\s+not)\s+(?:speaking|talking)\s+(?:to|with)\s+me\b"
    r"|\bnot\s+speaking\s+to\s+me\b|\bfamily\s+(?:feud|dispute|fight|rift|falling\s+out|estrangement)\b"
    r"|\bfell\s+out\s+with\b|\bfalling\s+out\b"
)
_WHERE_LIVE_RE = r"\bwhere\s+(?:she|he|they)\s+(?:lives?|stays?|resides?|is\s+staying)\b"
_FAMILY_WORDS = (
    r"(?:sister|brother|sibling|mother|father|mom|dad|aunt|uncle|cousin|in\s+law|niece|nephew|daughter|son|"
    r"family|relative)"
)
_RELOCATED_WORDS = r"(?:relocated|moved\s+away|moved\s+out|left\s+town|moved)"
_FAMILY_RELOCATED_RE = rf"\b{_FAMILY_WORDS}\b[^.;]{{0,80}}\b{_RELOCATED_WORDS}\b"
_FAMILY_RELOCATED_REVERSE_RE = rf"\b{_RELOCATED_WORDS}\b[^.;]{{0,80}}\b{_FAMILY_WORDS}\b"
_FAMILY_LEGAL_SENSE = r"\bfamily\s+(?:court|law|lawyer|solicitor|division|code|trust|office|business|company|firm)\b"

MOTIVE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("my ex", r"\bmy\s+ex\b" + _EX_NOT_PARTNER),
    ("former partner", r"\b(?:former|estranged|ex)\s+" + _PARTNER_WORDS + r"\b"),
    ("where they go at night", r"\bwhere\s+(?:she|he|they|my\s+\w+)\s+(?:goes|go|spends|hangs)\b"),
    ("dated", r"\b(?:woman|girl|man|guy|lady|boy|gentleman)\s+(?:i|we)\s+"
     r"(?:dated|was\s+dating|were\s+dating|matched|hooked)\b"),
    ("dated", r"\b(?:i|we)\s+dated\s+(?:her|him|them|last|in|a\s|an\s|for|\w+\s+(?:years?|months?))"),
    ("won't give me her number", _WONT_GIVE_RE),
    ("deleted her accounts", _DELETED_ACCOUNTS_RE),
    ("posted about me", _POSTED_ABOUT_ME_RE),
    ("not speaking to me", _NOT_SPEAKING_RE),
    ("where they live", _WHERE_LIVE_RE),
    ("family relocation", _FAMILY_RELOCATED_RE),
    ("family relocation", _FAMILY_RELOCATED_REVERSE_RE),
)
# "my wife/girlfriend/..." is only a red flag when paired with locate-ish words (so "my wife's company" passes).
_MY_PARTNER = r"\bmy\s+" + _PARTNER_WORDS + r"\b"


# Wordings that mean the client is pursuing someone who is avoiding them. Refused for EVERY case type and EVERY
# subject type, because the declared subject type can be a lie. Kept narrower than MOTIVE_RED_FLAGS (no "revenge",
# "stalk", "protective order"), which stay person-and-locate-only so entity due diligence is not over-refused.
PURSUIT_EVASION_FLAGS: tuple[str, ...] = (
    "blocked me",
    "blocked my number",
    "won't talk to me",
    "wont talk to me",
    "won't speak to me",
    "wont speak to me",
    "stopped talking to me",
    "stopped speaking to me",
    "stopped replying to me",
    "stopped responding to me",
    "isn't speaking to me",
    "isnt speaking to me",
    "is not speaking to me",
    "avoiding me",
    "hiding from me",
    "cut off contact",
    "cut off all contact",
    "cut me off",
    "ghosted me",
    "changed her number",
    "changed his number",
    "changed their number",
    "where she goes",
    "where he goes",
    "where she lives",
    "where he lives",
    "where they live",
    "where they go",
)
_PURSUIT_PATTERN_STRINGS: tuple[str, ...] = (
    _WONT_GIVE_RE,
    _DELETED_ACCOUNTS_RE,
    _POSTED_ABOUT_ME_RE,
    _WHERE_LIVE_RE,
    r"\bwhere\s+(?:she|he|they)\s+(?:goes|go|spends|hangs)\b",
    r"\b(?:current|new|latest|present)\s+(?:home\s+)?address\s+(?:of|for)\s+my\s+(?:ex|former|estranged)\b",
    r"\bmy\s+(?:ex|former|estranged)\b[\w\s']{0,20}?\s(?:current|new|latest|present)\s+(?:home\s+)?address\b",
    # --- third hardening pass: doxxing, grievance, custody and where-a-person-lives wordings (pi_gate_patterns) ---
    *PURSUIT_EXTRA_PATTERNS,
)
