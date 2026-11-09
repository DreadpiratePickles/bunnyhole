"""Credential hygiene for PI mode: breach/credential contents are never used, so they are scrubbed on the way in.

``strip_packet_credentials`` empties a ``CaseIntakePacket``'s credential list and scrubs credential-shaped tokens
from its text fields; ``redact_value`` is the final-result safety net. Pure functions; no I/O.

What :func:`scrub_credential_text` recognises (a heuristic safety net, not a guarantee):

* ``email:secret`` (also quoted, and a user:pass whose user is not an email: ``bob_smith:SECRET``);
* ``email`` followed by ``|``, ``;``, ``,``, a tab or ``: `` and a secret, with stricter rules when a space follows a
  comma, semicolon or colon so ordinary lists ("a@b.co, Jane Smith") are left alone;
* keyword forms: ``password: x``, ``pw=x``, ``password is x``, ``password x`` (when ``x`` looks like a secret);
* ``email secret`` separated only by spaces, when a password/secret/cred keyword is within 40 characters;
* URL userinfo (``https://bob:SECRET@acme.com/``): the userinfo is removed and the clean URL kept, so no derived
  selector (an "email" such as ``SECRET@acme.com``) ever sees the password;
* quoted-key JSON (``{"password":"SECRET"}``, also ``pass``, ``passwd``, ``pwd``, ``passcode``, ``secret``, ``token``,
  ``api_key``) and the keywords ``passcode``, ``Passwort``, ``contraseña``, ``mdp``, ``mot de passe``, ``clave``;
* the separators ``-``, ``/``, ``=>``, ``->`` and ``=`` after an email, and ``=``/``=>`` after a handle.

A secret in any other shape (for example a plain lowercase word after ``, `` with no keyword) is not recognised and
can still pass; keep credentials out of intake text.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Sequence, Tuple

REDACTED_CREDENTIAL = "[credential removed]"

# Every repetition below is bounded, and the local part may only start where no local-part character precedes it
# (the look-behind), so a long run of letters, digits or dots is scanned once and not once per start position.
_MAX_VALUE_CHARS = 4096  # longest unquoted secret value matched; anything longer is not a password
_MAX_SPACES = 40  # longest run of spaces or tabs tolerated between the parts of a credential pair
_EMAIL = (
    r"(?<![A-Za-z0-9_.+-])[A-Za-z0-9_.+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,10}"
)
_QUOTED = r"\"[^\"\r\n]{1,200}\"|'[^'\r\n]{1,200}'"
_SP = rf"[ \t]{{0,{_MAX_SPACES}}}"  # optional spaces or tabs
_SP1 = rf"[ \t]{{1,{_MAX_SPACES}}}"  # at least one space or tab

#: ``email:secret``: the secret is quoted, or runs to whitespace or a quote/delimiter. Also the final-result net.
_CREDENTIAL_TOKEN = re.compile(rf"{_EMAIL}:(?:{_QUOTED}|[^\s,;\"']{{1,{_MAX_VALUE_CHARS}}})")

_MIN_GLOBAL_REDACTION_CHARS = 6  # shorter secrets are removed with their token but not blanked everywhere

_EMAIL_FULL_RE = re.compile(rf"^{_EMAIL}$")
_URLISH_RE = re.compile(r"^(?:[a-z][a-z0-9+.-]*://|www\.)", re.IGNORECASE)
_DOMAINISH_RE = re.compile(
    r"^[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,10}\.[A-Za-z]{2,24}(?::\d{1,5})?(?:/\S{0,%d})?$" % _MAX_VALUE_CHARS
)
_PHONEISH_RE = re.compile(r"^\+?[\d().\s-]{7,40}$")
_STOPWORDS_TEXT = (
    "a an and or the is was are of to for with from at in on by as not also but then see cc bcc via i me my our "
    "he she they it this that who which if so no yes n/a na"
)
_STOPWORDS = frozenset(_STOPWORDS_TEXT.split())
_SPECIAL_CHARS = frozenset("!@#$%^&*_=~?")
_HANDLE_LABELS_TEXT = (
    "http https ftp ftps sftp ssh mailto tel sms file note notes re fwd fw subject from to cc bcc date time timeline "
    "version status address phone email mail url link name case ref id source sources title type location website "
    "web wallet eth btc hash tx txid domain username user handle login account host port ip"
)
_HANDLE_LABELS = frozenset(_HANDLE_LABELS_TEXT.split())
_KEYWORD_NAMES = (
    r"password|passwd|passphrase|passcode|passwort|kennwort|pwd|pw|pass|secret|creds?|credentials?|mdp|"
    r"mot\s{1,5}de\s{1,5}passe|contrase(?:ñ|n\u0303|n)a|clave"
)
_STRONG_KEYWORDS = frozenset(
    {"password", "passwd", "passphrase", "passcode", "passwort", "kennwort", "pwd", "pw", "mdp", "mot de passe"}
)
_KEYWORD_WINDOW_RE = re.compile(rf"\b(?:{_KEYWORD_NAMES})\b", re.IGNORECASE)
_PROXIMITY_CHARS = 40


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _is_non_secret_shape(value: str) -> bool:
    """True for a token that is plainly something else: an email, a URL or domain, a phone number, a stopword."""
    return bool(
        _EMAIL_FULL_RE.match(value)
        or _URLISH_RE.match(value)
        or _DOMAINISH_RE.match(value)
        or _PHONEISH_RE.match(value)
        or value.lower() in _STOPWORDS
    )


def _secretish(value: str) -> bool:
    """A token that reads like a secret: 4+ chars with letters and digits, a symbol, or ALL CAPS / MiXeD case."""
    if len(value) < 4 or _is_non_secret_shape(value):
        return False
    has_alpha = any(ch.isalpha() for ch in value)
    has_digit = any(ch.isdigit() for ch in value)
    if has_alpha and has_digit:
        return True
    if any(ch in _SPECIAL_CHARS for ch in value):
        return True
    letters = [ch for ch in value if ch.isalpha()]
    if not letters:
        return False
    if all(ch.isupper() for ch in letters) and len(letters) >= 4:
        return True
    return any(ch.isupper() for ch in letters[1:]) and any(ch.islower() for ch in letters)


_NAME_CONTINUES_RE = re.compile(r"\s{1,40}[A-Z][a-z]{1,40}\b")


def _follows_double_slash(text: str, start: int) -> bool:
    """True when the two characters before ``start`` are ``//`` (URL userinfo); O(1), unlike slicing the prefix."""
    return start >= 2 and text[start - 2:start] == "//"


def _looks_like_a_name_continuing(value: str, text: str, end: int) -> bool:
    """``Jane`` followed by ``Smith``: a Titlecase word followed by another Titlecase word is a name, not a secret.

    ``end`` is the offset in ``text`` just after ``value``.
    """
    if not (value[:1].isupper() and value[1:].isalpha() and value[1:].islower()):
        return False
    return _NAME_CONTINUES_RE.match(text, end) is not None


class _Scrubber:
    """Accumulates the removed tokens, and the bare secrets long enough to blank globally, across the rule passes."""

    def __init__(self) -> None:
        self.found: List[str] = []
        self.secrets: List[str] = []

    def take(self, whole: str, secret: str = "") -> str:
        self.found.append(whole)
        bare = _strip_quotes(secret)
        if len(bare) >= _MIN_GLOBAL_REDACTION_CHARS and bare != whole:
            self.secrets.append(bare)
        return REDACTED_CREDENTIAL


# Each rule is (compiled pattern, decision callback(match, text, scrubber) -> replacement or None to keep).
_RuleFn = Callable[["re.Match[str]", str, "_Scrubber"], "str | None"]


def _rule_email_colon(match: "re.Match[str]", text: str, scrub: _Scrubber) -> "str | None":
    """``email:secret`` (existing shape, now also quoted). Skips URL userinfo like ``ssh://git@host.example:22/x``."""
    if _follows_double_slash(text, match.start()):
        return None
    return scrub.take(match.group(0), match.group("val"))


_EMAIL_COLON_RE = re.compile(rf"(?P<e>{_EMAIL}):(?P<val>{_QUOTED}|[^\s,;\"']{{1,{_MAX_VALUE_CHARS}}})")


def _rule_email_delimited(match: "re.Match[str]", text: str, scrub: _Scrubber) -> "str | None":
    """``email`` then ``|``, ``;``, ``,``, ``:`` or a tab, then a secret.

    No whitespace after the delimiter (``a@b.co;SECRET``) or a quoted value: any token that is not an email, URL,
    domain or phone number. A space after a comma, semicolon or colon: the token must look like a secret. A space
    after a pipe, a space before the delimiter, or a tab: any token except a stopword or a name such as
    ``Jane Smith``.
    """
    value = match.group("val")
    quoted = value[:1] in "\"'"
    if _follows_double_slash(text, match.start()):
        return None  # URL userinfo (ssh://git@host.example:22/repo), not a credential pair
    if quoted:
        return scrub.take(match.group(0), value)
    if _is_non_secret_shape(value):
        return None
    sep = match.group("sep") or "\t"
    spaced = bool(match.group("post")) or sep == "\t"
    if not spaced:
        return scrub.take(match.group(0), value)
    if sep in ",;:" and not match.group("pre"):
        return scrub.take(match.group(0), value) if _secretish(value) else None
    if _looks_like_a_name_continuing(value, text, match.end()):
        return None
    return scrub.take(match.group(0), value)


_VALUE = rf"{_QUOTED}|[^\s\"',;|]{{1,{_MAX_VALUE_CHARS}}}"
_EMAIL_DELIM_RE = re.compile(
    rf"(?P<e>{_EMAIL})(?:(?P<pre>{_SP})(?P<sep>[|;,:])(?P<post>{_SP})|(?P<tab>\t{{1,{_MAX_SPACES}}}))(?P<val>{_VALUE})"
)


def _rule_keyword(match: "re.Match[str]", text: str, scrub: _Scrubber) -> "str | None":
    """``password: x``, ``pw=x``, ``password is x``, ``password x`` and the weaker ``pass:``/``secret=`` forms."""
    value = match.group("val")
    keyword = re.sub(r"\s+", " ", match.group("kw").lower())
    keyword = keyword.replace("contraseña", "contrasena")
    joiner = match.group("join")
    strong = keyword in _STRONG_KEYWORDS or keyword.startswith("contrase")
    if _EMAIL_FULL_RE.match(_strip_quotes(value)):
        return None  # "password: ceo@acme.com SECRET": the email-plus-keyword rule removes the pair
    quoted = value[:1] in "\"'"
    explicit = bool(re.search(r"[:=]|->", joiner))
    if quoted or (strong and explicit) or _secretish(value):
        if not strong and not explicit and not quoted:
            return None
        return scrub.take(match.group(0), value)
    return None


_KEYWORD_RE = re.compile(
    rf"(?<![\w-])(?P<kw>{_KEYWORD_NAMES})\b"
    rf"(?P<join>{_SP}(?:=>|->|[:=]){_SP}|{_SP1}(?:is|was|ist|es|est){_SP1}|{_SP1}[-–—/]{_SP1}|{_SP1})"
    rf"(?P<val>{_VALUE})",
    re.IGNORECASE,
)


def _rule_email_space_secret(match: "re.Match[str]", text: str, scrub: _Scrubber) -> "str | None":
    """``email secret`` with only whitespace between, when a password/secret/cred keyword is nearby."""
    value = match.group("val")
    quoted = value[:1] in "\"'"
    if not quoted and (_is_non_secret_shape(value) or _KEYWORD_WINDOW_RE.fullmatch(value)):
        return None
    window = text[max(0, match.start() - _PROXIMITY_CHARS): match.end() + _PROXIMITY_CHARS]
    if not _KEYWORD_WINDOW_RE.search(window):
        return None
    return scrub.take(match.group(0), value)


_EMAIL_SPACE_RE = re.compile(rf"(?P<e>{_EMAIL}){_SP1}(?:(?:is|was){_SP1})?(?P<val>{_VALUE})")


def _rule_handle_colon(match: "re.Match[str]", text: str, scrub: _Scrubber) -> "str | None":
    """``bob_smith:SECRET``: a non-email username, a colon with no spaces, and a secret-looking value."""
    handle = match.group("u").lstrip("@")
    value = match.group("val")
    quoted = value[:1] in "\"'"
    if handle.lower() in _HANDLE_LABELS:
        return None
    if quoted:
        return scrub.take(match.group(0), value)
    if not _secretish(value):
        return None
    handle_like = bool(re.search(r"[_.\-\d]", handle)) or match.group("u").startswith("@")
    mixed = any(ch.isdigit() for ch in value) and any(ch.isalpha() for ch in value)
    if handle_like or mixed:
        return scrub.take(match.group(0), value)
    return None


_HANDLE_RE = re.compile(
    rf"(?<![\w@./:-])(?P<u>@?[A-Za-z][A-Za-z0-9_.-]{{2,40}}):(?P<val>{_QUOTED}|[^\s\"':,;/]{{4,{_MAX_VALUE_CHARS}}})"
    r"(?![\w/])"
)


# --------------------------------------------------------------------------- third pass: userinfo, JSON, separators

_URL_USERINFO_RE = re.compile(
    r"(?P<scheme>\b[A-Za-z][A-Za-z0-9+.-]{1,15}://)(?P<user>[^\s:/@?#]{0,100})(?::(?P<pass>[^\s/?#]{0,256}))?"
    r"@(?=[^\s@/?#]+)"
)
_USERINFO_TOKEN_MIN_CHARS = 8


def _rule_url_userinfo(match: "re.Match[str]", text: str, scrub: _Scrubber) -> "str | None":
    """``scheme://user:pass@host``: drop the userinfo, keep the clean URL. A lone token user needs to look like one."""
    user = match.group("user")
    password = match.group("pass")
    if password is None:
        if len(user) < _USERINFO_TOKEN_MIN_CHARS or not _secretish(user):
            return None  # ssh://git@host, https://bob@acme.com: a plain username, not a credential
        scrub.take(match.group(0), user)
        return match.group("scheme")
    if not user and not password:
        return None
    scrub.take(match.group(0), password)
    if len(user) >= _MIN_GLOBAL_REDACTION_CHARS:
        scrub.secrets.append(user)
    return match.group("scheme")


_STRONG_JSON_KEYS = frozenset(
    {"password", "passwd", "pwd", "pass", "passcode", "passphrase", "passwort", "kennwort", "contrasena", "mdp",
     "clave"}
)
_WEAK_JSON_KEY_PARTS = ("secret", "token", "api_key", "apikey", "private_key", "privatekey", "auth_key", "access_key")
_JSON_PAIR_RE = re.compile(
    rf"(?P<q>[\"'])(?P<key>[A-Za-z_][\w-]{{0,40}})(?P=q){_SP}:{_SP}"
    rf"(?P<val>{_QUOTED}|[^\s,}}\]\"']{{1,{_MAX_VALUE_CHARS}}})"
)
_JSON_EMPTY_VALUES = frozenset({"null", "none", "true", "false", ""})
_JSON_WEAK_MIN_CHARS = 8


def _rule_json_pair(match: "re.Match[str]", text: str, scrub: _Scrubber) -> "str | None":
    """``"password":"x"`` (also ``'pass': 'x'``): password keys redact any value, secret/token keys need a secret."""
    key = match.group("key").lower().replace("-", "_").replace("ñ", "n")
    value = _strip_quotes(match.group("val"))
    if value.lower() in _JSON_EMPTY_VALUES:
        return None
    strong = key in _STRONG_JSON_KEYS or key.endswith("password") or key.endswith("passwort")
    weak = any(key.endswith(part) or key.startswith(part + "_") for part in _WEAK_JSON_KEY_PARTS)
    if strong or (weak and len(value) >= _JSON_WEAK_MIN_CHARS and " " not in value and _secretish(value)):
        return scrub.take(match.group(0), value)
    return None


_EMAIL_SYMBOL_RE = re.compile(
    rf"(?P<e>{_EMAIL})(?P<pre>{_SP})(?P<sep>=>|->|=|/|[-–—])(?P<post>{_SP})(?P<val>{_VALUE})"
)


def _rule_email_symbol(match: "re.Match[str]", text: str, scrub: _Scrubber) -> "str | None":
    """``email`` then ``=``, ``=>``, ``->`` (any value) or ``/``, ``-``, ``–`` (a secret-looking value)."""
    if _follows_double_slash(text, match.start()):
        return None  # URL userinfo or path (https://ceo@acme.com/page)
    value = match.group("val")
    sep = match.group("sep")
    if value[:1] in "\"'":
        return scrub.take(match.group(0), value)
    if _is_non_secret_shape(value) or _looks_like_a_name_continuing(value, text, match.end()):
        return None
    if sep in ("=", "=>", "->"):
        return scrub.take(match.group(0), value)
    if sep != "/" and not (match.group("pre") and match.group("post")):
        return None  # a dash must be spaced on both sides ("ceo@acme.com - SECRET"), else it is hyphenation
    return scrub.take(match.group(0), value) if _secretish(value) else None


_HANDLE_ASSIGN_RE = re.compile(
    rf"(?<![\w@./:?&%-])(?P<u>@?[A-Za-z][A-Za-z0-9_.-]{{2,40}}){_SP}(?:=>|=){_SP}"
    rf"(?P<val>{_QUOTED}|[^\s\"':,;/&]{{4,{_MAX_VALUE_CHARS}}})(?![\w/])"
)
_LONG_ADDRESS_LIKE_CHARS = 26


def _rule_handle_assign(match: "re.Match[str]", text: str, scrub: _Scrubber) -> "str | None":
    """``bob_smith=SECRET`` and ``bob_smith => SECRET``: a handle-shaped name, then a secret-looking value."""
    handle = match.group("u").lstrip("@")
    value = match.group("val")
    quoted = value[:1] in "\"'"
    if handle.lower() in _HANDLE_LABELS:
        return None
    handle_like = bool(re.search(r"[_.\-\d]", handle)) or match.group("u").startswith("@")
    if not handle_like:
        return None
    if quoted:
        return scrub.take(match.group(0), value)
    if not _secretish(value) or (len(value) >= _LONG_ADDRESS_LIKE_CHARS and value.isalnum()):
        return None  # a wallet address or hash is not a password
    return scrub.take(match.group(0), value)


_RULES: Tuple[Tuple["re.Pattern[str]", _RuleFn], ...] = (
    (_URL_USERINFO_RE, _rule_url_userinfo),
    (_JSON_PAIR_RE, _rule_json_pair),
    (_EMAIL_COLON_RE, _rule_email_colon),
    (_EMAIL_DELIM_RE, _rule_email_delimited),
    (_KEYWORD_RE, _rule_keyword),
    (_EMAIL_SYMBOL_RE, _rule_email_symbol),
    (_EMAIL_SPACE_RE, _rule_email_space_secret),
    (_HANDLE_RE, _rule_handle_colon),
    (_HANDLE_ASSIGN_RE, _rule_handle_assign),
)


def scrub_credential_text(text: str) -> Tuple[str, List[str]]:
    """Replace every credential-shaped token in ``text``; return the clean text and the tokens that were removed.

    A heuristic safety net, not a guarantee (see the module docstring for the recognised shapes). The secret is
    never echoed into the clean text. Ordinary text (an email alone, ``host:8080``, ``12:30``, ``Note: something``)
    is returned unchanged.
    """
    clean, found, _secrets = scrub_credential_text_full(text)
    return clean, found


def scrub_credential_text_full(text: str) -> Tuple[str, List[str], List[str]]:
    """Like :func:`scrub_credential_text`, plus the bare secrets (6+ characters) for the final-result safety net."""
    current = text or ""
    scrub = _Scrubber()
    for pattern, decide in _RULES:
        pieces: List[str] = []
        cursor = 0
        for match in pattern.finditer(current):
            replacement = decide(match, current, scrub)
            if replacement is None:
                continue
            pieces.append(current[cursor:match.start()])
            pieces.append(replacement)
            cursor = match.end()
        if cursor:
            pieces.append(current[cursor:])
            current = "".join(pieces)
    return current, scrub.found, scrub.secrets


def strip_packet_credentials(packet: Any) -> Tuple[Any, int, List[str]]:
    """Return ``(clean_packet, removed_count, redactions)`` for a ``CaseIntakePacket``.

    The packet's ``credentials`` list is emptied and any credential-shaped token is scrubbed from every text and
    list-of-text field (raw omni copies, title, hypothesis, selector lists). Nothing is derived from a dropped
    credential, not even its email half: the pairing itself came from breach data. ``redactions`` are the exact
    strings removed (plus bare secrets of 6+ characters), for the final-result safety net. The input packet is not
    mutated.
    """
    redactions: List[str] = [c.strip() for c in (packet.credentials or []) if c and c.strip()]
    removed = len(redactions)
    updates: Dict[str, Any] = {"credentials": []}
    for name, value in packet:
        if name == "credentials":
            continue
        if isinstance(value, str):
            clean, found, secrets = scrub_credential_text_full(value)
            if found:
                updates[name] = clean
                redactions += found + secrets
                removed += len(found)
        elif isinstance(value, list) and value and all(isinstance(item, str) for item in value):
            cleaned: List[str] = []
            changed = False
            for item in value:
                clean, found, secrets = scrub_credential_text_full(item)
                if found:
                    changed = True
                    redactions += found + secrets
                    removed += len(found)
                if clean.strip() and clean.strip() != REDACTED_CREDENTIAL:
                    cleaned.append(clean)
            if changed:
                updates[name] = cleaned
    return packet.model_copy(update=updates), removed, redactions


def _userinfo_free(match: "re.Match[str]") -> str:
    """The final-result net: a password-bearing URL loses its userinfo; a plain ``user@`` is kept."""
    if match.group("pass") is None and not (
        len(match.group("user")) >= _USERINFO_TOKEN_MIN_CHARS and _secretish(match.group("user"))
    ):
        return match.group(0)
    return match.group("scheme")


def redact_value(value: Any, redactions: Sequence[str]) -> Any:
    """Deep copy of ``value`` (dicts, lists, tuples, strings) with every known credential string removed."""
    ordered = sorted({r for r in redactions if r}, key=len, reverse=True)

    def clean_text(text: str) -> str:
        for secret in ordered:
            text = text.replace(secret, REDACTED_CREDENTIAL)
        return _CREDENTIAL_TOKEN.sub(REDACTED_CREDENTIAL, _URL_USERINFO_RE.sub(_userinfo_free, text))

    def walk(node: Any) -> Any:
        if isinstance(node, str):
            return clean_text(node)
        if isinstance(node, dict):
            return {(clean_text(k) if isinstance(k, str) else k): walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v) for v in node]
        if isinstance(node, tuple):
            return tuple(walk(v) for v in node)
        return node

    return walk(value)


__all__ = ["REDACTED_CREDENTIAL", "redact_value", "scrub_credential_text", "strip_packet_credentials"]
