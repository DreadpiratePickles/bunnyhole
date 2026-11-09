"""Generated phrase patterns for the PI purpose gates (third hardening pass): data only, matching lives in ``pi_gates``.

A phrase blocklist can never reach full recall; the allowlist of permissible purposes (``PurposeCategory``) is the
structural gate. These patterns are the cross-check that keeps a declared category honest: they catch an eligibility
decision (employment, tenancy, credit, insurance) or a pursuit of a person who avoids the client when the purpose
text says so. Every pattern runs over text normalised by ``pi_gates._normalize_text`` (lowercase, punctuation turned
into single spaces, apostrophes kept). Words are matched as whole words; a gap of up to six words is tolerated
between an assessing verb and a person role, in either order.

Safety net, not a guarantee: a wording with no listed verb or role still passes.
"""

from __future__ import annotations

# --------------------------------------------------------------------------- eligibility: verb + role, either order

_NOT_A_COMPANY = (
    r"(?!\s+(?:company|companies|corporation|corp|entity|entities|firm|ltd|inc|llc|llp|plc|business|improvements?|"
    r"fit\s?outs?|allowances?|inducements?|ledgers?))"
)
_WORD_GAP = r"\s+(?:[\w']+\s+){0,6}?"  # up to six words between the verb and the role

# Verbs that, next to ANY person role (tenant, employee, borrower, hire ...), signal an eligibility decision.
_STRONG_VERB = (
    r"(?:vet|vets|vetted|vetting|screen|screens|screened|screening|prescreen\w*|pre\s+screen\w*|"
    r"qualif(?:y|ies|ied|ying)|underwrit(?:e|es|ing|ten)|onboard\w*|due\s+diligence)"
)
# Verbs that signal an eligibility decision only next to a role that is almost always one (tenant, nanny, lodger).
_WEAK_VERB = (
    r"(?:check|checks|checked|checking|verif(?:y|ies|ied|ying|ication)|assess(?:es|ed|ing|ment)?|"
    r"evaluat(?:e|es|ed|ing|ion)|background|trustworth\w*|suitab\w*|vouch\w*|look\s+into|looking\s+into|"
    r"look\s+at|confirm(?:s|ed|ing)?|determin(?:e|es|ed|ing)|establish(?:es|ed|ing)?|review(?:s|ed|ing)?|"
    r"apprais(?:e|es|ed|ing)|gaug(?:e|es|ed|ing)|judge|judges|judged|judging|examin(?:e|es|ed|ing)|"
    r"inspect(?:s|ed|ing)?)"
)
# Roles that are an eligibility subject whenever an assessing verb is near them.
_ROLE_PERSON = (
    rf"(?:tenants?{_NOT_A_COMPANY}|renters?{_NOT_A_COMPANY}|lodgers?|room\s?mates?|flat\s?mates?|house\s?mates?|"
    r"house\s?keepers?|nann(?:y|ies)|"
    r"baby\s?sitters?|care\s?givers?|care\s?takers?|sitters?|carers?|au\s+pairs?|domestic\s+(?:help|workers?)|"
    rf"home\s+help|cleaners?|sub\s?tenants?|occupants?{_NOT_A_COMPANY}|boarders?|house\s?sitters?|"
    r"proposed\s+insureds?|prospective\s+insureds?)"
)
# Roles that are an eligibility subject next to a STRONG verb only (an employee can also be the subject of a fraud).
_ROLE_WORKER_OR_BORROWER = (
    r"(?:employees?|new\s+hires?|recruits?|staffers?|interns?|volunteers?|trainees?|apprentices?|borrowers?|"
    r"policy\s?holders?|insureds?|"
    r"(?<!car )(?<!van )(?<!plant )(?<!tool )(?<!equipment )hires?"
    r"(?!\s+(?:company|companies|firm|purchase|agreement|equipment|business|service|fleet|car|van)))"
)
# Job titles: an eligibility subject only when the person is "incoming", "prospective", "proposed" ...
_ROLE_TITLE = (
    r"(?:cfos?|ceos?|coos?|ctos?|cios?|controllers?|bookkeepers?|receptionists?|accountants?|executives?|"
    r"managers?|directors?|officers?|assistants?|engineers?|developers?|drivers?|teachers?|tutors?|franchisees?)"
)
_STRONG_ROLES = rf"(?:{_ROLE_PERSON}|{_ROLE_WORKER_OR_BORROWER})"
# Ordinary job nouns: an eligibility subject when the person is "new", "prospective" ...
_ROLE_JOB = (
    r"(?:bookkeepers?|accountants?|receptionists?|assistants?|drivers?|tutors?|teachers?|engineers?|developers?|"
    r"foremen|foreman|cashiers?|clerks?|cooks?|chefs?|mechanics?|electricians?|plumbers?|handymen|handyman|"
    r"security\s+guards?|janitors?|labou?rers?|workers?|nurses?|aides?|residents?)"
)
_PERSON_DESCRIPTOR = (
    r"(?:guy|man|woman|lady|girl|boy|person|someone|somebody|individual|couple|kid|candidate|gentleman)"
)
# "A would-be / incoming / proposed <role>": the role has not been engaged yet, so it is an eligibility decision.
_PROSPECTIVE = (
    r"(?:incoming|prospective|potential|proposed|would\s+be|possible|future|intended|soon\s+to\s+be|upcoming)"
)
_POSITION_NOUNS = r"(?:role|position|job|vacancy|apartment|flat|tenancy)"


def _both_orders(first: str, second: str) -> tuple[str, str]:
    return (
        rf"\b{first}\b{_WORD_GAP}{second}\b",
        rf"\b{second}\b{_WORD_GAP}{first}\b",
    )


ELIGIBILITY_VERB_ROLE_PATTERNS: tuple[str, ...] = (
    *_both_orders(_STRONG_VERB, _STRONG_ROLES),
    *_both_orders(_WEAK_VERB, _ROLE_PERSON),
    # "incoming CFO", "prospective housekeeper", "possible lodger", "proposed insured"
    rf"\b{_PROSPECTIVE}\s+(?:[\w']+\s+)?(?:{_ROLE_PERSON}|{_ROLE_WORKER_OR_BORROWER}|{_ROLE_TITLE})\b",
    # "the new bookkeeper", checked with a weak verb in reach (either order)
    *_both_orders(_WEAK_VERB, rf"new\s+{_ROLE_JOB}(?!')"),
    # "the guy we want to hire", "someone I am about to rent to"
    rf"\b{_PERSON_DESCRIPTOR}\b(?:\s+[\w']+){{0,3}}?\s+(?:we|i)\s+(?:are\s+|am\s+)?(?:about\s+to|going\s+to|want\s+to|"
    rf"wish\s+to|plan\s+to|hope\s+to|intend\s+to|might|may|could)\s+(?:hire|employ|engage|rent|lease|let|take\s+on|"
    rf"sign|trust)\b",
    rf"\b{_PERSON_DESCRIPTOR}\b(?:\s+[\w']+){{0,6}}?\s+to\s+(?:lend|loan|hire|employ|rent\s+to|lease\s+to|let\s+in)\b",
    r"\bwhether\s+to\s+(?:give|grant|offer|sign|let)\s+(?:\w+\s+){0,3}(?:lease|loan|job|tenancy|mortgage|credit|"
    r"position|rental)\b",
    r"\blet(?:ting)?\s+(?:him|her|them)\s+(?:rent|lease|move|stay|live|use|babysit|watch|have\s+(?:a|the|my)\s+key)\b",
    r"\b(?:sign|signing|take|taking|accept|accepting|engage|engaging|have|having)\s+(?:him|her|them|this\s+\w+|"
    r"that\s+\w+)\s+(?:up\s+|on\s+)?as\s+(?:a|my|our|the)\s+(?:new\s+)?(?:\w+\s+)?"
    rf"(?:{_ROLE_PERSON}|{_ROLE_JOB}|employees?|hires?)\b",
    r"\b(?:wants?|wanting|wanted|hopes?|hoping|looking|planning)\s+to\s+move\s+into\b",
    r"\b(?:watch|watching|babysit\w*|look(?:ing)?\s+after|mind(?:ing)?|care\s+for|caring\s+for)\s+(?:my|our)\s+"
    r"(?:\w+\s+)?(?:kids?|children|child|baby|babies|son|daughter|mother|father|parents?|grandmother|grandfather)\b",
    r"\b(?:answer|respond|repl)(?:ed|ing|y|ied)?\s+(?:to\s+)?(?:my|our|the)\s+(?:\w+\s+)?(?:ad|advert|advertisement|"
    r"listing|posting)\b",
    r"\b(?:job|position|vacancy|rental|room|flat|apartment)\s+(?:ad|advert|advertisement|posting|listing)\b",
    r"\b(?:good|bad|poor|high|low|safe)\s+credit\s+risk\b",
    r"\bpre\s*hire\b|\bpre\s*approv\w*|\bpre\s*qualif\w*",
    r"\b(?:leasing|lease|rental|tenancy|renting|approval|screening)\s+decisions?\b",
    # "the man we are thinking of renting to", "the person hiring" style: a person descriptor next to the decision verb
    rf"\b{_PERSON_DESCRIPTOR}\b(?:\s+[\w']+){{0,6}}?\s+(?:renting|leasing|lending|letting|hiring|employing)\b",
    # "the driver's history", "the worker's past jobs": a personal record asked about a would-be worker or occupant
    r"\b(?:driver|worker|intern|resident|occupant|guy|man|woman|lady|couple|kid|gentleman|nanny|cleaner)'?s\s+"
    r"(?:past|history|record|background|criminal\s+\w+)\b",
    r"\b(?:funding|lending\s+to|engaging|renting\s+to|leasing\s+to)\s+(?:him|her|them)\b",
    r"\b(?:issu\w+|bind\w*)\s+(?:the\s+|a\s+|any\s+)?(?:cover|coverage|polic(?:y|ies)|mortgage|loan)\b",
    r"\bhouse\s?sit\w*",
    r"\b(?:lend|lending|loan|loaning)\s+(?:money\s+)?to\s+(?:a|an|the|this|that|my)\s+(?:private\s+)?"
    r"(?:individual|person|man|woman|guy|couple|friend|stranger)\b",
    r"\b(?:rent|renting|lease|leasing|let|letting)\s+(?:him|her|them|someone|somebody)\s+(?:my|our|the|a)\b",
    r"\b(?:offer|offered|offering)\s+(?:\w+\s+)?(?:a\s+)?(?:tenancy|lease|loan|mortgage)\b",
    r"\b(?:on|in)\s+instal+ments?\b",
    r"\b(?:resumes?|r[eé]sum[eé]s?)\b|\bjob\s+interviews?\b|\bwe\s+(?:just\s+)?interviewed\b",
    r"\bonboard\w*\s+as\s+(?:a|an|our|the)\b",
    r"\bappl(?:y|ies|ied|ying)\s+(?:to\s+(?:be|become|work|join)|as\s+(?:a|an|our|the))\b",
    r"\bafford\s+(?:the\s+|our\s+|my\s+|this\s+|that\s+|a\s+)?(?:\w+\s+)?"
    r"(?:rental|rent|flat|apartment|unit|lease|mortgage|loan|payments?)\b",
    # "hiring due diligence", "due diligence on the new hire"
    r"\bhiring\s+(?:due\s+diligence|vetting|checks?|screening|background|verification|review)\b",
    r"\b(?:due\s+diligence|vetting|screening|verification)\s+(?:on|of|for)\s+(?:a\s+|an\s+|the\s+|our\s+|my\s+)?"
    r"(?:new\s+)?(?:hires?|recruits?|employees?)\b",
    # "check Mr. Lee for the CFO position", "vet the engineer for the vacancy"
    rf"\b(?:{_STRONG_VERB}|check\w*|verif\w+|assess\w*|evaluat\w+)\b(?:\s+[\w']+){{0,8}}?"
    rf"\s+for\s+(?:a|an|the|our|this|that|my)\s+(?:[\w']+\s+){{0,3}}{_POSITION_NOUNS}\b",
    # "underwrite a life policy", "underwriting review of this file"
    r"\bunderwrit\w*\b(?:\s+[\w']+){0,6}?\s+(?:policy|policies|loan|mortgage|risk|applicant|application|insured|"
    r"coverage|cover|file|case)\b",
    # "approve funding for the borrower"
    r"\bapprov\w*\s+(?:the\s+|a\s+|this\s+|that\s+|our\s+)?(?:\w+\s+){0,2}(?:funding|financing|advance|disbursement)\b",
    r"\b(?:trustworthy|reliable|suitable)\s+enough\s+to\s+(?:hire|employ|rent|lease|lend|trust\s+with|let)\b",
    # Spanish, French and German loanword stems for the common eligibility subjects.
    r"\bsolicitantes?\b",
    r"\binquilin[oa]s?\b",
    r"\bempleados?\b|\bempleadas?\b",
    r"\bcr[eé]dit(?:o|os|icia|icias|icio|icios)\b",
    r"\bcandidat(?:s|e|es|o|os|a|as|ure|ura)?\b",
    r"\blocataires?\b",
    r"\bbewerber\w*\b|\bantragsteller\w*\b",
    r"\bmieter\w*\b",
    r"\bkredit(?!anstalt|institut)\w*\b",
)

# Extra literal phrases (any case or spelling; normalised on both sides) for the eligibility screen.
EXTRA_ELIGIBILITY_TERMS: tuple[str, ...] = (
    "tenant vetting",
    "employee vetting",
    "candidate vetting",
    "tenant check",
    "lodger screening",
    "roommate screening",
    "housekeeper screening",
    "employee screening",
    "employment verification",
    "verification of employment",
    "reference check",
    "reference checks",
    "trustworthiness check",
    "suitability check",
    "suitability assessment",
    "suitability for the vacancy",
    "hiring due diligence",
    "tenant suitability",
    "applicant screening",
    "credit file",
    "credit pull",
    "bank history",
    "rental history",
    "work history",
    "past employers",
    "previous employers",
    "driving record",
    "eviction history",
    "tenancy suitability",
    "pre-placement",
    "preplacement",
    "housing check",
    "tenancy report",
    "tenant report",
    "borrower screening",
    "borrower vetting",
)

# --------------------------------------------------------------------------- pursuit of someone who avoids the client

_PERSON_NOUN = (
    r"(?:she|he|they|wife|husband|partner|girlfriend|boyfriend|friend|ex|brother|sister|mother|mom|father|dad|son|"
    r"daughter|neighbou?r|colleague|coworker|co\s+worker|boss|kid|child|guy|man|woman|girl|boy|lady|person|"
    r"classmate|schoolmate|acquaintance|stranger|teacher|student|in\s+law|cousin|aunt|uncle|nephew|niece|"
    r"step\s?(?:mother|father|daughter|son)|grand(?:mother|father|ma|pa)|"
    r"fianc[eé]e?|lover|roommate|landlord|tenant)"
)
_ME_VERB = (
    r"(?:insult|reject|humiliat|disrespect|mock|bully|unfriend|unfollow|unmatch|ghost|dump|shun|snub|"
    r"snitch(?:ed|es|ing)?\s+on|rat(?:ted|s|ting)?\s+on|report|ignor|dodg|duck|embarrass|cheat(?:ed|s|ing)?\s+on)\w*"
)

_THIRD_PARTY = r"(?:my|our|his|her|their|the|this|that)"
_PARTNER_ROLE = r"(?:boyfriend|girlfriend|wife|husband|partner|fianc[eé]e?|spouse|lover|ex)"
_LOCATE_VERB = (
    r"(?:find|locate|get|obtain|look\s+up|track|trace|address|whereabouts|where\s+(?:he|she)\s+(?:lives?|works?|goes))"
)
_DISLIKE = (
    r"i\s+(?:really\s+|just\s+|simply\s+)?(?:do\s+not\s+like|don'?t\s+like|dont\s+like|can'?t\s+stand|hate)\s+"
    r"(?:him|her)"
)

PURSUIT_EXTRA_PATTERNS: tuple[str, ...] = (
    # doxxing
    r"\bdox{1,2}(?:es|ed|ing|er|ers)?\b",
    # romantic or social pursuit
    r"\bold\s+flames?\b",
    r"\bsurpris\w*\s+(?:her|him|them)\b",
    r"\bdrop(?:ping)?\s+(?:by|in)\s+(?:on\s+(?:her|him|them)\s+)?(?:unannounced|unexpectedly|uninvited)\b",
    r"\b(?:unannounced|uninvited)\s+(?:visit|at\s+(?:her|his|their))\b",
    # someone ignoring the client
    r"\b(?:dodg\w+|ignor\w+|avoid\w+|duck\w+|ghost\w+|screen\w+|not\s+(?:answering|returning|replying\s+to|"
    r"responding\s+to))\s+(?:all\s+)?(?:of\s+)?my\s+(?:phone\s+)?(?:calls?|texts?|messages?|dms?|emails?)\b",
    r"\brefus\w*\s+to\s+(?:answer|respond|reply|talk|speak|see)\s+(?:to\s+)?(?:me|my)\b",
    # grievances against a named-by-pronoun person
    rf"\b{_ME_VERB}\s+me\b",
    r"\b(?:criticis|criticiz|slander|defam|libel|harass|threaten|troll|trash|bad\s*mouth|stalk|expos|photograph|film|"
    r"laughed\s+at|yelled\s+at|shouted\s+at|stared\s+at|spied\s+on)\w*\s+me\b",
    r"\bstalk(?:ing|ed|er|ers|s)?\b(?!\s+horse)",
    r"\b(?:doesn'?t|does\s+not|didn'?t|did\s+not|won'?t|will\s+not)\s+want\s+(?:to\s+(?:see|talk\s+to|speak\s+to|"
    r"hear\s+from)\s+)?me\b",
    r"\brun\s?away\s+(?:wife|husband|girlfriend|boyfriend|partner|spouse|daughter|son|teen)\b",
    r"\bstole\s+my\s+(?:girlfriend|boyfriend|wife|husband|partner)\b",
    r"\b(?:and|with)\s+(?:his|her|their)\s+(?:home\s+)?address\b",
    r"\bfind\s+(?:out\s+)?exactly\s+where\b",
    r"\b(?:follow|trail|shadow|tail)(?:s|ed|ing)?\s+(?:the\s+)?(?:guy|man|woman|girl|lady|boy|stranger|person)\b",
    r"\bwithout\s+(?:her|him|them)\s+(?:knowing|finding\s+out|noticing)\b",
    r"\b(?:track|monitor|follow|watch|spy\s+on)\w*\s+my\s+(?:girlfriend|boyfriend|wife|husband|partner|fianc[eé]e?|ex)\b",
    r"\b(?:woman|man|girl|guy|lady|mistress|other\s+woman)\s+(?:my|our)\s+(?:husband|wife|boyfriend|girlfriend|"
    r"partner|fianc[eé]e?|ex)\b",
    r"\bso\s+(?:i|we)\s+can\s+(?:show\s+up|turn\s+up|drop\s+by|run\s+into|see\s+(?:her|him|them))\b",
    r"\b(?:get|want|need|find|locate|obtain|learn)\s+(?:out\s+)?(?:her|his)\s+(?:phone\s+)?(?:number|address|email)\b",
    rf"\bwhere\s+(?:does|do|did)\s+(?:the\s+|this\s+|that\s+|my\s+|our\s+)?{_PERSON_NOUN}\s+(?:[\w']+\s+){{0,8}}?"
    r"(?:live|work|stay|sleep|hide|park|hang\s+out)\b",
    r"\b(?:she|he|they|who)\s+(?:has\s+|had\s+)?(?:left|abandoned|dumped|rejected|ignored|dismissed|betrayed|"
    r"cut\s+me\s+off|turned\s+me\s+down)(?:\s+me)?\b(?:\s+without\s+a\s+word)?",
    r"\b(?:rejected|refused|declined|turned\s+down)\s+(?:my|our)\s+(?:proposal|advances?|invitation|date)\b",
    r"\b(?:we|i)\s+(?:have\s+)?(?:fell|fallen)\s+out\b|\bwe\s+fell\s+out\b",
    r"\b(?:online|internet)\s+trolls?\b",
    r"\b(?:unmask|deanonymi[sz]e|de\s+anonymi[sz]e|expose|reveal|identify)\w*\s+(?:the\s+)?(?:identity\s+of\s+)?"
    r"(?:the\s+)?(?:anonymous|online|internet|twitter|reddit|facebook|instagram|burner|fake)\s+"
    r"(?:user|poster|troll|account|reviewer|commenter|person|critic|profile)\b",
    r"\b(?:anonymous|fake|burner|throwaway)\s+(?:account|profile)\b[^.;]{0,60}\b(?:me|my)\b",
    r"\bwho\s+(?:reported|snitched\s+on|ratted\s+on|complained\s+about|informed\s+on)\s+me\b",
    # children and custody
    r"\bbab(?:y|ies)'?s?\s+(?:mother|mom|mama|father|dad|daddy|papa)\b",
    r"\bbaby\s+(?:mama|daddy|momma)\b",
    r"\b(?:my|our)\s+(?:kid|child|son|daughter|baby)'?s?\s+(?:mother|mom|mama|father|dad|daddy)\b",
    r"\b(?:vanish|disappear|run|ran|took|taken|left|gone|fled|flee)\w*\s+(?:off\s+)?with\s+(?:the|my|our)\s+"
    r"(?:kids?|child|children|baby|babies|son|daughter|boy|girl)\b",
    # tracking and following a person
    r"\b(?:track|follow|shadow|stake\s*out|spy\s+on)(?:s|ed|ing)?\s+(?:down\s+)?(?:her|him)\b",
    r"\b(?:track|follow|monitor|trail)(?:s|ed|ing)?\s+(?:her|his)\s+"
    r"(?:movements?|whereabouts|location|car|phone|every)\b",
    r"\bkeep(?:ing)?\s+tabs\s+on\b",
    r"\b(?:learn|find\s+out|study|map|log|record|note|know|discover)\s+(?:about\s+)?(?:her|his|their)\s+"
    r"(?:daily\s+)?(?:routine|schedule|habits|movements|comings\s+and\s+goings)\b",
    r"\bmy\s+ex'?s\s+(?:new|current|latest|home|phone|number|address|location|whereabouts|workplace|job|place|"
    r"boyfriend|girlfriend|husband|wife)\b",
    r"\b(?:address|number|location|whereabouts|workplace|job|home|phone)\s+(?:of|for)\s+my\s+(?:ex|old\s+flame|"
    r"estranged)\b",
    r"\bwhich\s+(?:hotel|motel|inn|room|house|apartment|flat|building|city|town|street|gym|bar|restaurant|church|"
    r"school)\s+(?:she|he|they)\s+(?:is|are|was|were|stays?|lives?|works?|goes|attends|visits|sleeps)\b",
    r"\bwhat\s+(?:hotel|city|town|street|address|neighbou?rhood|building|gym|school|church|bar)\s+(?:she|he|they)\b",
    r"\bwhere\s+(?:did|does|do|is|has|had|will|would|can|could)\s+(?:she|he)\s+(?:move|go|live|work|stay|sleep|"
    r"hide|moved|gone|went|been)\b",
    r"\bwho\s+(?:she|he)'?s\s+(?:been\s+)?(?:seeing|dating|sleeping\s+with|meeting|talking\s+to|with)\b",
    r"\bspy(?:ing)?\s+on\s+(?:her|him|them|my)\b",
    r"\bshow(?:ing)?\s+up\s+(?:at|outside|in\s+front\s+of)\s+(?:her|his|their)\b",
    r"\bconfront(?:ing)?\s+(?:him|her|them)\b",
    r"\b(?:teach|show)(?:ing)?\s+(?:him|her|them)\s+a\s+lesson\b",
    r"\bpay(?:ing)?\s+(?:him|her|them)\s+a\s+visit\b",
    r"\btrace\s+(?:her|him)\s+to\b",
    r"\bwhich\s+(?:one|school|college|university|class)\s+(?:she|he)\s+(?:goes|attends|is\s+at|went)\b",
    r"\b(?:won'?t|will\s+not|wouldn'?t|doesn'?t|does\s+not|didn'?t|did\s+not|never)\s+(?:return|answer|pick\s+up|"
    r"reply\s+to|respond\s+to|replied\s+to|responded\s+to|accept)\s+(?:any\s+of\s+)?(?:my|our)\s+(?:\w+\s+)?"
    r"(?:calls?|letters?|texts?|messages?|emails?|dms?|invitations?|phone)\b",
    # where a person lives, works or is staying
    rf"\bwhere\s+(?:[\w']+\s+){{0,6}}?{_PERSON_NOUN}(?:'s)?\s+(?:lives?|living|resides?|stays?|staying|is\s+staying|"
    rf"is\s+living|is\s+hiding|hides?|sleeps?|works?|moved|parks?|meets?|hangs?\s+out|shops?|eats?|goes|go|drives|"
    rf"walks|jogs|runs?|spends?)\b",
    r"\bwhere\s+(?:she|he|they)\s+(?:is|are)\s+(?:staying|living|hiding)\b",
    r"\bfigure\s+out\s+where\s+(?:she|he)\b",
    r"\bwhere\s+(?:my|our)\s+(?:ex|estranged|baby|kid|child|old\s+(?:flame|girlfriend|boyfriend|friend))\b",
    r"\bwhereabouts\s+of\s+(?:my|our)\s+(?:ex|estranged|baby|kid|child|neighbou?r|old\s+\w+)\b",
    r"\b(?:locate|find|identify|discover|learn|get|determine|reveal|uncover|dig\s+up|look\s+up)\s+(?:out\s+)?"
    r"(?:her|his|their)\s+(?:work\s*place|workplace|home|house|apartment|flat|residence|whereabouts|hideout|"
    r"new\s+(?:home|address|job|place|number|apartment|flat|employer|city|town|school|email)|"
    r"current\s+(?:home\s+)?address|"
    r"home\s+address)\b",
    r"\bwhat'?s\s+(?:her|his|their)\s+(?:home\s+|new\s+|current\s+)?address\b",
    # --- fourth hardening pass: routine and movements of a person, a relative's partner's address, dirt on a person ---
    rf"\b(?:monitor|track|follow|watch|trail|log|record|map|study)\w*\s+(?:the\s+|her\s+|his\s+|their\s+)?"
    rf"(?:daily\s+|weekly\s+|nightly\s+)?(?:movements?|routine|schedule|habits|comings\s+and\s+goings)\s+of\s+"
    rf"{_THIRD_PARTY}\s+(?:[\w']+\s+){{0,3}}?{_PERSON_NOUN}\b",
    rf"\b(?:daily|weekly|nightly)\s+(?:movements?|routine|schedule|habits)\s+of\s+"
    rf"{_THIRD_PARTY}\s+(?:[\w']+\s+){{0,3}}?{_PERSON_NOUN}\b",
    # "my daughter's boyfriend's home address", "the address of my brother's girlfriend"
    rf"\b(?:my|our|his|her|their)\s+(?:[\w']+\s+){{0,2}}?[\w']+'s\s+{_PARTNER_ROLE}'?s\s+"
    r"(?:home\s+|new\s+|current\s+|private\s+)?(?:address|whereabouts|location|workplace|phone|number|house|"
    r"apartment|flat)\b",
    rf"\b(?:address|whereabouts|location|workplace)\s+(?:of|for)\s+(?:my|our|his|her|their)\s+(?:[\w']+\s+){{0,2}}?"
    rf"[\w']+'s\s+{_PARTNER_ROLE}\b",
    # "I do not like him" next to a locate verb, in either order (a grievance plus a search for the person)
    rf"\b{_LOCATE_VERB}\b(?:\s+[\w']+){{0,14}}?\s+{_DISLIKE}\b",
    rf"\b{_DISLIKE}\b(?:\s+[\w']+){{0,14}}?\s+{_LOCATE_VERB}\b",
    r"\bdig\w*\s+up\s+(?:some\s+|any\s+|more\s+|all\s+the\s+)?(?:dirt|dirty\s+laundry|skeletons|secrets)\s+"
    rf"(?:on|about)\s+(?:him|her|them|{_THIRD_PARTY}\s+(?:[\w']+\s+){{0,3}}?{_PERSON_NOUN})\b",
)
