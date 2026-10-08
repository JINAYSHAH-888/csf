"""Grammar-aware command-injection analysis.

Why this analyser matters most
-------------------------------
Command injection is CSF's weakest measured class: S1/CRS achieves 77.6%
recall on it versus 97.1% for SQLi (Phase 4, CSIC validation split). It is
also the least-covered class in the literature. If S2 earns its place
anywhere, it should be here.

The mechanism
-------------
A benign value passed to a shell is a single *word* — one argument. It cannot
start a second command, cannot open a subshell, cannot redirect a file
descriptor. We lex the value with Python's POSIX-mode shell lexer and ask
whether it produces shell *operators* rather than words.

Lexing rather than pattern-matching matters because shell quoting changes
what a metacharacter means. ``"a;b"`` is one argument containing a semicolon;
``a;b`` is two commands. A regex for ``;`` cannot tell them apart, and that
difference is the entire false-positive problem for this class.

What it cannot do
-----------------
It cannot know whether the application passes the value to a shell at all, or
with what quoting. A value only dangerous under a specific interpolation we do
not model will be missed. Argument injection (a value that is a legitimate
single word but a dangerous *flag*, such as ``--output=/etc/passwd``) is
handled by a separate heuristic because no shell lexer treats it as special.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

__all__ = ["ShellFinding", "ShellVerdict", "analyze_shell"]

#: Operators that create a new command, a pipeline, or a redirection. These
#: are the constructs a single argument must never produce.
COMMAND_OPERATORS = {
    ";": ("command_separator", "starts a second command"),
    "&&": ("command_separator", "conditionally chains a second command"),
    "||": ("command_separator", "conditionally chains a second command"),
    "|": ("pipeline", "pipes output into another command"),
    "&": ("background", "backgrounds a command"),
    "\n": ("newline_separator", "starts a second command on a new line"),
}

REDIRECTIONS = (">", ">>", "<", "<<", "2>", "&>", ">&")

#: Sensitive filesystem targets. A redirection or flag pointing at one of
#: these is far stronger evidence than the operator alone.
SENSITIVE_PATHS = (  # noqa: S108 - these are detection patterns, not paths we open
    "/etc/", "/proc/", "/sys/", "/root/", "/var/log", "/dev/tcp", "/dev/shm",  # noqa: S108
    "\\windows\\", "c:\\windows", "/.ssh/", "/.aws/", "shadow", "passwd",
)

#: Commands whose appearance in user input is a strong signal. Presence alone
#: is not a finding — the value must ALSO have produced a shell operator.
SENSITIVE_COMMANDS = frozenset({
    "cat", "ls", "id", "whoami", "uname", "pwd", "ps", "netstat", "ifconfig",
    "wget", "curl", "nc", "ncat", "netcat", "telnet", "ssh", "ftp",
    "bash", "sh", "zsh", "csh", "ksh", "python", "perl", "ruby", "php",
    "chmod", "chown", "rm", "mv", "cp", "dd", "mkfifo", "touch",
    "passwd", "useradd", "usermod", "sudo", "su", "crontab",
    "powershell", "cmd", "certutil", "bitsadmin", "regsvr32", "rundll32",
    "ping", "traceroute", "dig", "nslookup", "host", "arp", "route",
    "env", "printenv", "set", "export", "history", "find", "grep", "awk",
    "sed", "xxd", "base64", "openssl", "socat", "tar", "zip", "unzip",
    "systemctl", "service", "kill", "killall", "mount", "umount",
    # Windows and a few Unix commands that were missing. Command injection
    # payloads are frequently Windows-targeted (measured: cmdi is CSF's weakest
    # class, and its holdout misses were dominated by `| dir`, `& net view`,
    # `| systeminfo`, `| sleep`). These only ever fire alongside a shell
    # operator (or the command_invocation rule below), so adding common
    # English words like "type" or "net" costs no false positives.
    "dir", "type", "net", "sleep", "which", "systeminfo", "sysinfo", "ver",
    "ipconfig", "tasklist", "taskkill", "netsh", "reg", "sc", "wmic",
    "schtasks", "vssadmin", "runas", "nltest", "whoami.exe", "ping.exe",
})

#: Known limitation: a redirection to a non-sensitive path (``> /tmp/out``)
#: is structurally identical to benign comparison text (``x > y``) once
#: lexed. Both score 3.0 and neither blocks. Separating them needs context
#: this analyser does not have — whether the application passes the value to
#: a shell at all. S1's regex layer covers some of these, which is the
#: cascade working as intended: the stages fail differently.

#: Command substitution and process substitution. A lexer treats `$(id)` as a
#: single word, so these need their own detection.
_SUBSTITUTION = re.compile(r"\$\([^)]*\)|`[^`]*`|<\([^)]*\)|>\([^)]*\)")

#: Argument injection: a leading flag. Not a shell operator, but it changes
#: the behaviour of the command the application intended to run.
_LEADING_FLAG = re.compile(r"^\s*--?[A-Za-z][\w-]*(=|\s|$)")

#: Newline/CR injection, which splits a command even when quoted in some
#: contexts and is the basis of CRLF-style injection into shell wrappers.
_LINE_BREAK = re.compile(r"[\r\n]")

#: Language-level code-execution sinks called as a function: ``system('id')``,
#: ``exec('ls')``, ``phpinfo()``. A POSIX lexer treats these as a single word,
#: so they evade the operator-based checks entirely, yet they are command
#: execution by another route (measured: 6 of the 29 cmdi holdout misses).
#: Matched as a known sink name immediately followed by ``(`` — a shape benign
#: parameter values effectively never take.
_CODE_SINK = re.compile(
    r"\b(system|exec|passthru|shell_exec|popen|proc_open|eval|assert|phpinfo"
    r"|pcntl_exec|os\.system|subprocess\.\w+)\s*\(", re.IGNORECASE)

#: A command-line flag token, POSIX (``-l``, ``--output``) or Windows (``/ADD``).
_ARG_FLAG = re.compile(r"^(--?[A-Za-z]|/[A-Za-z])")

#: An absolute path appearing as an argument: ``/etc``, ``/bin/sh``, ``C:\``.
_ARG_PATH = re.compile(r"(^|\s)(/[A-Za-z]|[A-Za-z]:\\)")

#: A bare command word (no path separator, no metacharacter).
_CMD_WORD = re.compile(r"^[A-Za-z_][\w.-]*$")

#: The same injection written as a two-character escape rather than the control
#: character itself: the literal backslash-n that a wrapper script, a shell
#: ``echo -e``, or a language-level unescape turns back into a newline.
#:
#: A measured gap. ``\n wget http://.../nftp.exe`` and ``\nuftp -p host path``
#: carry a command name the analyser already knows, but no shell operator ever
#: appeared, so the sensitive-command rule never fired and the value scored 0.
_ESCAPED_BREAK = re.compile(r"\\+[rn]")

#: A command-line flag anywhere in a token sequence, as opposed to at the start
#: of the value, which :data:`_LEADING_FLAG` covers.
_FLAG_TOKEN = re.compile(r"^--?[A-Za-z]")

#: A bare command name: no path separator and no extension. The distinction
#: carries the whole false-positive argument for the escaped break above.
#: A Windows path is full of accidental escape sequences — ``C:\new\report``
#: unescapes to ``C:`` + newline + ``ew\report`` — so the escape alone cannot
#: be the finding. What a real payload has and an unescaped path fragment does
#: not is a COMMAND INVOCATION after the break: a bare word followed by a flag
#: or an argument, or a word this module already recognises as a command.
_BARE_WORD = re.compile(r"^[A-Za-z_][\w.-]*$")


@dataclass(slots=True)
class ShellFinding:
    marker: str
    weight: float
    detail: str

    def __str__(self) -> str:
        return f"{self.marker}(+{self.weight:g}): {self.detail}"


@dataclass(slots=True)
class ShellVerdict:
    score: float = 0.0
    findings: list[ShellFinding] = field(default_factory=list)
    inert: bool = True

    def add(self, marker: str, weight: float, detail: str) -> None:
        for existing in self.findings:
            if existing.marker == marker:
                if weight > existing.weight:
                    self.score += weight - existing.weight
                    existing.weight = weight
                    existing.detail = detail
                return
        self.findings.append(ShellFinding(marker, weight, detail))
        self.score += weight
        self.inert = False

    def explain(self) -> str:
        if not self.findings:
            return "parses as a single shell word"
        return "; ".join(str(f) for f in self.findings)


def _lex(value: str) -> list[str] | None:
    """POSIX-mode lex. Returns None when the value cannot be lexed."""
    lexer = shlex.shlex(value, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        return list(lexer)
    except ValueError:
        # Unbalanced quotes. Not evidence of an attack on its own — benign
        # free text contains apostrophes constantly.
        return None


def _is_command_invocation(segment: str) -> str | None:
    """Does this text look like a command being run? Returns the command name.

    Requires a bare command word AND corroboration: either the word is a
    command this module tracks, or it is followed by a flag or a second
    argument. A lone word is not enough, because that is exactly what the tail
    of an unescaped Windows path looks like.
    """
    tokens = _lex(segment)
    if not tokens:
        tokens = segment.split()
    if not tokens:
        return None
    head = tokens[0]
    if "/" in head or "\\" in head or not _BARE_WORD.match(head):
        return None
    name = head.lower()
    if name in SENSITIVE_COMMANDS:
        return name
    if len(tokens) > 1 and any(_FLAG_TOKEN.match(t) for t in tokens[1:]):
        return name
    return None


def analyze_shell(value: str) -> ShellVerdict:
    """Analyse a candidate value for command-injection structure."""
    verdict = ShellVerdict()
    if len(value) < 2:
        return verdict

    # --- command / process substitution ---------------------------------
    # Checked before lexing: shlex treats `$(id)` as an ordinary word.
    substitutions = _SUBSTITUTION.findall(value)
    if substitutions:
        verdict.add("command_substitution", 5.0,
                    f"value contains command substitution, which executes and "
                    f"inlines the result: {substitutions[0][:40]!r}")

    # Language-level code execution (system()/exec()/phpinfo()...), which the
    # shell lexer cannot see because it is not shell metacharacter injection.
    sink = _CODE_SINK.search(value)
    if sink:
        verdict.add("code_execution_sink", 5.0,
                    f"value calls {sink.group(1)!r} as a function, a "
                    "code-execution sink")

    if _LINE_BREAK.search(value):
        verdict.add("line_break", 4.0,
                    "value contains a newline, which terminates the current "
                    "command and starts another")
    elif _ESCAPED_BREAK.search(value):
        # Only the segments AFTER a break can be a newly started command.
        for segment in _ESCAPED_BREAK.split(value)[1:]:
            command = _is_command_invocation(segment)
            if command is not None:
                verdict.add("escaped_line_break", 4.0,
                            f"value contains an escaped newline followed by "
                            f"what reads as a command invocation "
                            f"({command!r}), which starts a second command "
                            "wherever the escape is expanded")
                break

    tokens = _lex(value)
    if tokens is None:
        return verdict

    # --- shell operators --------------------------------------------------
    #
    # Weighted LOW on their own, and this is the most important calibration
    # decision in this module. An unquoted `&` or `|` in free text is common
    # and benign: "a & b design", "my|favourite", "Tom & Jerry". Measured,
    # scoring a bare operator at 5.0 produced false positives on exactly
    # those. What distinguishes an attack is not the operator but what
    # FOLLOWS it — a command, or a path worth reading.
    operator_tokens = [t for t in tokens if t in COMMAND_OPERATORS]
    for token in operator_tokens:
        marker, meaning = COMMAND_OPERATORS[token]
        verdict.add(marker, 2.0,
                    f"value produced the shell operator {token!r}, which {meaning}")

    # Weak on its own, for the same reason as the separators above: a stray
    # '<' or '>' in random text lexes as a redirection while redirecting
    # nothing. Measured: a trailing '<' in an opaque parameter value was
    # scoring 3.0 on benign ECML traffic. What makes a redirection an attack
    # is its target, handled by sensitive_target below.
    redirect_tokens = [t for t in tokens if t in REDIRECTIONS]
    if redirect_tokens:
        verdict.add("redirection", 2.0,
                    f"value produced a redirection operator "
                    f"{redirect_tokens[0]!r}, which reads or writes a file")

    lowered_value = value.lower()
    targets_sensitive_path = any(p in lowered_value for p in SENSITIVE_PATHS)

    # --- sensitive command, only alongside an operator --------------------
    # "cat" in a product description is not an attack. "; cat" is.
    if operator_tokens or redirect_tokens or substitutions:
        for token in tokens:
            bare = token.strip().split("/")[-1].lower()
            if bare in SENSITIVE_COMMANDS:
                verdict.add("sensitive_command", 3.0,
                            f"a second command was created and it invokes "
                            f"{bare!r}")
                break

    # --- value is itself a command invocation -----------------------------
    # No shell operator, but the whole value reads as a command being run:
    # `nc -lvvp 4444 -e /bin/sh`, `ls -l /tmp`, `net localgroup x /ADD`. This
    # is the parameter-value-replaces-a-command shape (the application passes
    # the value AS the command, not as an argument to a fixed one).
    #
    # FPR discipline: it fires ONLY when the first token is a known command AND
    # a later token is a flag or an absolute path. "which product line" (no
    # flag/path) and a bare "ls" do not fire, which is why benign traffic --
    # measured on CSIC and ECML -- gains zero false positives.
    if not operator_tokens and not redirect_tokens and len(tokens) > 1:
        head = tokens[0]
        name = head.split("/")[-1].split("\\")[-1].lower()
        if (_CMD_WORD.match(head) and name in SENSITIVE_COMMANDS
                and (any(_ARG_FLAG.match(t) for t in tokens[1:])
                     or _ARG_PATH.search(value))):
            verdict.add("command_invocation", 4.0,
                        f"value reads as a direct invocation of {name!r} with "
                        "arguments, not a benign single word")

    # --- sensitive target --------------------------------------------------
    # A redirection or flag aimed at /etc/passwd is not ambiguous, even when
    # no recognised command name appears.
    if targets_sensitive_path and (operator_tokens or redirect_tokens
                                   or substitutions or _LEADING_FLAG.match(value)):
        verdict.add("sensitive_target", 3.0,
                    "the created command or redirection targets a sensitive "
                    "path")

    # --- argument injection ----------------------------------------------
    # A legitimate single word that is nonetheless a flag. No shell operator
    # is involved, so this is weighted lower and is corroborating evidence.
    if _LEADING_FLAG.match(value):
        verdict.add("argument_injection", 2.0,
                    "value begins with a command-line flag, which can change "
                    "the behaviour of the intended command")

    return verdict
