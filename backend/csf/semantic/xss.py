"""Grammar-aware XSS analysis.

The mechanism
-------------
Same principle as the SQL analyser: inject the candidate into HTML contexts
where a benign value is inert text, then ask whether it escaped into an
*executable* position.

A benign value rendered into a page is a text node or an attribute value. It
cannot open a tag, cannot add an event handler, cannot become a URL scheme.
A value that does any of those has escaped its position, and that escape is
the attack — regardless of which payload encoding got it there.

We parse with Python's HTML parser rather than pattern-matching, so encoding
and casing tricks are consumed by the tokeniser. ``<ScRiPt>`` and ``<script>``
produce the same tag; ``&#106;avascript:`` decodes before the scheme is read.

What it cannot do
-----------------
DOM-based XSS that never reaches the server (fragment-only payloads) is
invisible here, as stated in the threat model. Nor can it know the real
rendering context: we probe element-text, attribute, and URL positions, and
a payload dangerous only in a context we do not probe is missed.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

__all__ = ["XssFinding", "XssVerdict", "analyze_xss"]

#: Elements that execute or fetch by themselves.
EXECUTABLE_TAGS = frozenset({
    "script", "iframe", "object", "embed", "applet", "meta", "link",
    "base", "form", "svg", "math", "frame", "frameset", "portal",
    # A value that opens <style> is injecting a stylesheet into the page, not
    # text. That is executable-class on its own: CSS can exfiltrate form
    # contents through attribute selectors, overlay the page for clickjacking,
    # and in the IE-era properties below it ran script outright. It sat in
    # LOADING_TAGS at 3.0, under tau_block, so an injected stylesheet was
    # recorded and never blocked.
    "style",
})

#: Elements that commonly carry an auto-firing handler.
LOADING_TAGS = frozenset({
    "img", "video", "audio", "source", "track", "input", "body",
    "details", "marquee", "isindex", "image", "textarea", "select", "button",
})

#: Attributes whose value a browser resolves as a URL. The decision rule is
#: not "which attributes are famous" but "which ones get fetched or
#: navigated", so the legacy and media-specific ones belong here too.
#:
#: ``dynsrc`` was a measured gap: ``<input type="image" dynsrc="javascript:
#: ...">`` reached only the 3.0 injected-element marker because the scheme in
#: the attribute was never read, leaving it under ``tau_block``.
URL_ATTRS = frozenset({
    "src", "href", "action", "formaction", "data", "poster", "background",
    "xlink:href", "srcdoc", "dynsrc", "lowsrc", "cite", "longdesc", "profile",
    "usemap", "manifest", "archive", "codebase", "code", "movie", "folder",
    "ping", "icon", "classid", "to", "from", "values", "attributename",
})

#: URL schemes that execute.
EXECUTABLE_SCHEMES = ("javascript:", "data:text/html", "vbscript:", "data:application")

#: Scheme names that are never the start of a benign URL, matched independently
#: of the delimiter that follows.
#:
#: Browsers have been inconsistent about what terminates a scheme, and payload
#: lists exploit that: ``javascript#``, ``javascript&colon;`` and
#: ``javascript\t:`` have all navigated somewhere. Requiring the colon means
#: only the canonical spelling is caught. No legitimate URL begins with the
#: bare token ``javascript`` or ``vbscript``, so the token alone is the signal
#: and the delimiter is irrelevant.
_SCRIPT_SCHEME_TOKEN = re.compile(r"^(javascript|vbscript|livescript|mocha)[^a-z0-9]",
                                  re.IGNORECASE)

#: CSS that fetches or executes.
#:
#: ``expression()`` evaluates JScript (IE dynamic properties), ``behavior`` and
#: ``-moz-binding``/``binding`` attach an external component that runs code
#: (HTC, XBL), ``@import`` pulls in another stylesheet, and ``url()`` makes the
#: page fetch an attacker-chosen resource. All of these live in a ``style``
#: attribute or a ``<style>`` element, where the HTML tokeniser sees only an
#: ordinary attribute value — so parsing the markup is not enough, the CSS
#: itself has to be read.
_DANGEROUS_CSS = re.compile(
    r"""expression\s*\(            # IE dynamic property: evaluates script
      | behaviou?r\s*:              # HTC component; both spellings seen
      | (?:-\w+-)?binding\s*:      # XBL / -moz-binding: attaches code
      | @\s*import                  # pulls in another stylesheet
      | url\s*\(                    # fetches an attacker-chosen resource
    """,
    re.IGNORECASE | re.VERBOSE)

#: JavaScript sinks that execute a string.
JS_SINKS = frozenset({
    "eval", "function", "settimeout", "setinterval", "execscript",
    "setimmediate", "import", "requestanimationframe",
})

_EVENT_ATTR = re.compile(r"^on[a-z]+$", re.IGNORECASE)
_SCHEME_STRIP = re.compile(r"[\s\x00-\x20]+")


@dataclass(slots=True)
class XssFinding:
    marker: str
    weight: float
    detail: str

    def __str__(self) -> str:
        return f"{self.marker}(+{self.weight:g}): {self.detail}"


@dataclass(slots=True)
class XssVerdict:
    score: float = 0.0
    findings: list[XssFinding] = field(default_factory=list)
    inert: bool = True

    def add(self, marker: str, weight: float, detail: str) -> None:
        # One finding per marker; the strongest wins.
        for existing in self.findings:
            if existing.marker == marker:
                if weight > existing.weight:
                    self.score += weight - existing.weight
                    existing.weight = weight
                    existing.detail = detail
                return
        self.findings.append(XssFinding(marker, weight, detail))
        self.score += weight
        self.inert = False

    def explain(self) -> str:
        if not self.findings:
            return "no executable construct"
        return "; ".join(str(f) for f in self.findings)


class _Collector(HTMLParser):
    """Records the structure a value produces when parsed as HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.event_attrs: list[tuple[str, str]] = []
        self.url_attrs: list[tuple[str, str]] = []
        self.style_attrs: list[str] = []
        self.had_error = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag.lower())
        for name, value in attrs:
            lowered = name.lower()
            if _EVENT_ATTR.match(lowered):
                self.event_attrs.append((lowered, value or ""))
            elif lowered in URL_ATTRS:
                self.url_attrs.append((lowered, value or ""))
            elif lowered == "style":
                self.style_attrs.append(value or "")

    handle_startendtag = handle_starttag

    def error(self, message: str) -> None:  # noqa: ARG002  # pragma: no cover
        # Required by the pre-3.10 HTMLParser API. We record that markup was
        # malformed but do not treat that as evidence on its own.
        self.had_error = True


def _normalised_scheme(value: str) -> str:
    """Decode and strip a URL so the scheme can be read reliably.

    Browsers ignore leading whitespace and control characters, and decode
    entities, before resolving a scheme. ``java&#115;cript:`` and
    ``java\\tscript:`` both execute. Matching on the raw string would miss both.
    """
    decoded = html.unescape(value)
    return _SCHEME_STRIP.sub("", decoded).lower()


def _scheme_finding(url: str) -> tuple[float, str] | None:
    """Judge a URL-attribute value. Returns (weight, scheme) or None.

    The canonical ``javascript:`` spelling is weighted higher than a
    delimiter variant because the former executes everywhere and the latter
    depends on browser leniency — but both are reported, because neither is
    something a benign URL does.
    """
    scheme = _normalised_scheme(url)
    if scheme.startswith(EXECUTABLE_SCHEMES):
        return 5.0, scheme
    if _SCRIPT_SCHEME_TOKEN.match(scheme):
        return 4.0, scheme
    return None


def _css_findings(css: str, where: str, verdict: XssVerdict) -> None:
    """Record dangerous CSS constructs found in a style attribute or element."""
    for match in set(_DANGEROUS_CSS.findall(html.unescape(css))):
        construct = match.strip()
        # url() is the weakest of the group: it only causes a fetch. The others
        # run code, so they are blocking-strength on their own.
        weight = 3.0 if construct.lower().startswith("url") else 5.0
        verdict.add("dangerous_css", weight,
                    f"{where} contains CSS {construct!r}, which "
                    + ("fetches an attacker-chosen resource"
                       if weight == 3.0 else
                       "executes code or attaches an external component"))


def analyze_xss(value: str) -> XssVerdict:
    """Analyse a candidate value for XSS structure."""
    verdict = XssVerdict()
    if len(value) < 4:
        return verdict

    decoded = html.unescape(value)
    # Cheap pre-filter: without one of these a value cannot open a tag, close
    # an attribute, introduce a scheme, or form a CSS function call.
    if not any(c in decoded for c in "<>\"'`:(#") :
        return verdict

    # --- element-text context -------------------------------------------
    parser = _Collector()
    try:
        parser.feed(value)
        parser.close()
    except Exception:  # noqa: BLE001, S110 - see below
        # Malformed markup is NOT evidence of an attack: benign free text
        # contains stray angle brackets constantly. Whatever the parser
        # managed to collect before failing is still used below.
        pass

    for tag in parser.tags:
        if tag in EXECUTABLE_TAGS:
            verdict.add("executable_element", 5.0,
                        f"value opened a <{tag}> element, which executes or "
                        "fetches by itself")
        elif tag in LOADING_TAGS:
            verdict.add("injected_element", 3.0,
                        f"value opened a <{tag}> element where only text was "
                        "expected")
        else:
            verdict.add("injected_markup", 2.0,
                        f"value opened a <{tag}> element where only text was "
                        "expected")

    for name, handler in parser.event_attrs:
        verdict.add("event_handler", 5.0,
                    f"value introduced the {name} event handler, which runs "
                    f"script on its own: {handler[:40]!r}")

    for name, url in parser.url_attrs:
        judged = _scheme_finding(url)
        if judged is not None:
            weight, scheme = judged
            verdict.add("executable_url", weight,
                        f"value set {name} to an executable scheme: {scheme[:40]!r}")

    for css in parser.style_attrs:
        _css_findings(css, "an injected style attribute", verdict)

    # A <style> element's content is CSS, which the HTML tokeniser hands back
    # as ordinary data. Reading it is the only way to see what the stylesheet
    # would do.
    if "style" in parser.tags:
        _css_findings(decoded, "an injected <style> element", verdict)

    # --- attribute context ------------------------------------------------
    # A value rendered inside an attribute must not be able to close it and
    # start a new one. Probing this separately catches payloads that are inert
    # as element text but dangerous in an attribute.
    attr_probe = _Collector()
    try:
        attr_probe.feed(f'<div data-x="{value}">')
        attr_probe.close()
    except Exception:  # noqa: BLE001, S110 - same reasoning as above
        pass
    for name, handler in attr_probe.event_attrs:
        verdict.add("attribute_escape", 5.0,
                    f"inside an attribute, the value closed it and added "
                    f"{name}={handler[:30]!r}")
    if len(attr_probe.tags) > 1:
        verdict.add("attribute_escape", 5.0,
                    f"inside an attribute, the value closed it and opened "
                    f"<{attr_probe.tags[1]}>")

    # --- URL context ------------------------------------------------------
    judged = _scheme_finding(value)
    if judged is not None:
        weight, scheme = judged
        verdict.add("executable_url", weight,
                    f"value is itself an executable URL scheme: {scheme[:40]!r}")

    # NOT probed: the value as bare CSS, with no tag of its own. Every payload
    # measured reaches CSS through a style attribute or a <style> element,
    # both handled above, and treating any colon-bearing value as a stylesheet
    # would flag benign text on an unmeasured hunch.

    # --- JS sink ----------------------------------------------------------
    # Only meaningful when the value already reached an executable position;
    # on its own, "eval" in free text is not an attack.
    if not verdict.inert:
        lowered = decoded.lower()
        for sink in JS_SINKS:
            if re.search(rf"\b{re.escape(sink)}\s*\(", lowered):
                verdict.add("js_sink", 2.0,
                            f"executable context calls {sink}(), which runs a "
                            "string as code")
                break

    return verdict
