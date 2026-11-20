"""
Taint tracking: remember where data came from, and check where it is going.

A policy can name some tools as *sources* and give their output a label, e.g.

    "sources": [
      {"tool": "email.read", "label": "untrusted"},
      {"tool": "files.read", "when": [{"arg": "path", "op": "startswith", "value": "hr/"}],
       "label": "confidential"}
    ]

Every time a source runs, its output is remembered for that agent session (one token =
one session). Later, rules can ask about it:

    {"arg": "url", "op": "tainted", "value": "confidential"}   this argument carries data
                                                               from a confidential source
    {"arg": "to", "op": "tainted", "value": "untrusted"}       this address was taken from
                                                               content the agent read
    {"op": "session_tainted", "value": "untrusted"}            the agent has read untrusted
                                                               content at some point

How an argument is matched (a heuristic, not a proof): the argument is URL-decoded and
broken into distinctive pieces: email addresses, URLs, numbers of 5+ digits, runs of four
words, and the whole value when it is short. If any piece appears in labelled source
output, the argument is tainted with that label. Pieces that also appear in trusted text
(the task the human gave in the token, and the human's own identity) never count, so an
address the user typed into the task is not treated as attacker-supplied.

It catches the common case: an agent copying data verbatim (an address, a URL, a customer
record, a salary). It does not catch data the model paraphrases, translates or encodes.
"""

import re
import threading
from collections import OrderedDict
from urllib.parse import unquote_plus

_EMAIL = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}")
_URL = re.compile(r"https?://[^\s<>\"']+")
_NUMBER = re.compile(r"(?<![\d.])\d{5,}(?:\.\d+)?(?![\d])")
_WORD = re.compile(r"[a-z0-9@._%+-]+")
_DIGIT_COMMA = re.compile(r"(?<=\d)[,_](?=\d)")
_SPACE = re.compile(r"\s+")

SHINGLE_WORDS = 4          # runs of this many words count as copied text
WHOLE_VALUE_MIN = 6        # shorter values ("yes", "42") are too common to mean anything
WHOLE_VALUE_MAX = 300


def normalize(text: str) -> str:
    """Lower-case, URL-decode, "42,000" -> "42000", collapse whitespace."""
    text = unquote_plus(str(text)).lower()
    text = _DIGIT_COMMA.sub("", text)
    return _SPACE.sub(" ", text).strip()


def flatten(value) -> list[str]:
    """All the strings inside an argument value (nested lists/dicts included)."""
    if value is None:
        return []
    if isinstance(value, dict):
        return [s for v in value.values() for s in flatten(v)]
    if isinstance(value, (list, tuple, set)):
        return [s for v in value for s in flatten(v)]
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    return [str(value)]


def pieces(value) -> list[str]:
    """The distinctive pieces of an argument value that are worth looking up."""
    found: list[str] = []
    for raw in flatten(value):
        text = normalize(raw)
        if WHOLE_VALUE_MIN <= len(text) <= WHOLE_VALUE_MAX:
            found.append(text)
        found += _EMAIL.findall(text)
        found += [u.rstrip(".,;)") for u in _URL.findall(text)]
        found += _NUMBER.findall(text)
        words = _WORD.findall(text)
        found += [" ".join(words[i:i + SHINGLE_WORDS]) for i in range(len(words) - SHINGLE_WORDS + 1)]
    return list(dict.fromkeys(p for p in found if p))   # unique, order kept


def _contains(haystack: str, piece: str) -> bool:
    if piece.isdigit():                      # 42000 must not match inside 9942000
        return re.search(rf"(?<!\d){piece}(?!\d)", haystack) is not None
    return piece in haystack


class _Session:
    def __init__(self):
        self.trusted: list[str] = []
        self.sources: list[tuple[str, str, str]] = []   # (label, origin tool, normalized text)
        self.chars = 0


class TaintTracker:
    """Per-session memory of labelled tool output. Thread-safe."""

    def __init__(self, max_chars_per_session: int = 2_000_000, max_sessions: int = 1000):
        self.max_chars = max_chars_per_session
        self.max_sessions = max_sessions
        self._sessions: "OrderedDict[str, _Session]" = OrderedDict()
        self._lock = threading.Lock()

    def _session(self, session: str) -> _Session:
        s = self._sessions.get(session)
        if s is None:
            s = self._sessions[session] = _Session()
            while len(self._sessions) > self.max_sessions:
                self._sessions.popitem(last=False)
        self._sessions.move_to_end(session)
        return s

    def trust(self, session: str, *texts) -> None:
        with self._lock:
            s = self._session(session)
            for t in texts:
                if t and (n := normalize(t)) not in s.trusted:
                    s.trusted.append(n)

    def record(self, session: str, label: str, origin: str, output) -> None:
        text = normalize(" ".join(flatten(output)))
        if not text:
            return
        with self._lock:
            s = self._session(session)
            s.sources.append((label, origin, text))
            s.chars += len(text)
            while s.chars > self.max_chars and len(s.sources) > 1:   # forget the oldest
                s.chars -= len(s.sources.pop(0)[2])

    def session_labels(self, session: str) -> set[str]:
        with self._lock:
            s = self._sessions.get(session)
            return {label for label, _, _ in s.sources} if s else set()

    def taint_of(self, session: str, value) -> list[dict]:
        """Evidence that this value carries labelled data: [{label, source, match}]."""
        with self._lock:
            s = self._sessions.get(session)
            if s is None or not s.sources:
                return []
            trusted, sources = list(s.trusted), list(s.sources)
        evidence, seen = [], set()
        for piece in pieces(value):
            if any(_contains(t, piece) for t in trusted):
                continue
            for label, origin, text in sources:
                if (label, piece) not in seen and _contains(text, piece):
                    seen.add((label, piece))
                    evidence.append({"label": label, "source": origin, "match": piece[:80]})
        return evidence


class TaintView:
    """What the policy engine sees for one call: lazily computed, evidence kept for the log."""

    def __init__(self, tracker: TaintTracker, session: str, args: dict):
        self.tracker, self.session, self.args = tracker, session, args
        self._args_cache: dict[str, list[dict]] = {}
        self.evidence: dict[str, list[dict]] = {}

    def arg_labels(self, arg: str) -> set[str]:
        if arg not in self._args_cache:
            self._args_cache[arg] = self.tracker.taint_of(self.session, self.args.get(arg))
        found = self._args_cache[arg]
        if found:
            self.evidence[arg] = found
        return {e["label"] for e in found}

    def session_labels(self) -> set[str]:
        return self.tracker.session_labels(self.session)
