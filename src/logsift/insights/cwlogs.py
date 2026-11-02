"""Turn a finding's row filter into a CloudWatch Logs Insights query.

Every finding carries a SQL ``WHERE`` fragment that selects its rows in the canonical
table. The fragments are plain boolean expressions over columns (the rules never use
subqueries), so this module parses that small SQL subset into a tree and prints it back
in the Logs Insights query language with the format's own field names:

* a format describes itself with a :class:`QuerySpec`: which Logs Insights field each
  canonical column is, how the derived columns the table builder invented (``is_error``,
  ``client_ip``, ``principal``) can be expressed, which columns are the time axis, and
  whether the fields are discovered by CloudWatch or must be parsed out of ``@message``;
* conditions on the time column are lifted out of the filter into a comment: the console
  has a time picker for that;
* anything that cannot be expressed is dropped from an ``and`` with a note saying the
  query is wider than the finding, so what remains still runs.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from logsift.insights.base import Finding

ROW_LIMIT = 200

# A derived column's translation: called with the operator ("bool" for the bare column,
# "=", "<>", "<", "<=", ">", ">=", "null", "notnull") and the literal it is compared with.
# Returns Logs Insights text, or None when the comparison cannot be expressed.
Derived = Callable[[str, Any], "str | None"]
# A SQL function's translation, given its already-translated arguments.
Func = Callable[[list[str]], "str | None"]

PRIVATE_SUBNETS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")


@dataclass
class QuerySpec:
    """How a format's canonical table maps onto a CloudWatch log group."""

    # canonical column -> Logs Insights field name
    fields: dict[str, str]
    # canonical columns that are the time axis; conditions on them become the time range
    time_columns: tuple[str, ...] = ()
    derived: dict[str, Derived] = field(default_factory=dict)
    funcs: dict[str, Func] = field(default_factory=dict)
    # A "parse @message ..." clause when CloudWatch does not discover the fields itself.
    parse: str = ""
    # Logs Insights fields to list, in order, when the query shows rows.
    display: list[str] = field(default_factory=list)
    # How the log spells a missing value: "-" compares against the dash, "" uses ispresent.
    missing: str = ""
    # Text rewrites applied to the SQL before parsing, for idioms SQL has and Insights lacks.
    rewrites: list[tuple[str, str, str]] = field(default_factory=list)
    # rule name -> a stats clause (with {column} placeholders) that replaces the row listing
    stats: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def fieldf(self, column: str) -> str:
        return self.fields.get(column, column)


# ----------------------------------------------------------------- derived helpers


def boolean(expr: str, negative: str = "") -> Derived:
    """A derived boolean column that is this Insights expression (and ``negative`` when
    it is false, if there is a tidier way to say so than ``not (...)``)."""

    def translate(op: str, value: Any) -> str | None:
        if op == "bool" or (op == "=" and value is True) or (op == "<>" and value is False):
            return expr
        if (op == "=" and value is False) or (op == "<>" and value is True):
            return negative or f"not {paren(expr)}"
        return None

    return translate


def like(fld: str, template: str) -> Derived:
    """Equality on a derived text column becomes a regex match on a real field.

    ``template`` is a regular expression with ``{v}`` where the (escaped) value goes.
    """

    def translate(op: str, value: Any) -> str | None:
        if op not in ("=", "<>") or value is None or isinstance(value, bool):
            return None
        pattern = template.replace("{v}", regex_escape(str(value)))
        text = f"{fld} like /{pattern}/"
        return text if op == "=" else f"not ({text})"

    return translate


def mapped(fld: str, values: dict[Any, str]) -> Derived:
    """Equality on a derived column becomes equality on a real field with mapped values."""

    def translate(op: str, value: Any) -> str | None:
        if op not in ("=", "<>") or value not in values:
            return None
        text = f"{fld} = {values[value]}"
        return text if op == "=" else f"not ({text})"

    return translate


def private_ip(args: list[str]) -> str | None:
    """The ``is_private(ip)`` macro the flow rules define."""
    if len(args) != 1:
        return None
    return "(" + " or ".join(f'isIpv4InSubnet({args[0]}, "{s}")' for s in PRIVATE_SUBNETS) + ")"


def regex_escape(value: str) -> str:
    return re.sub(r"([\\^$.|?*+()\[\]{}/])", r"\\\1", value)


def paren(text: str) -> str:
    """Wrap in parentheses unless one pair already encloses the whole expression."""
    if text.startswith("(") and text.endswith(")"):
        depth = 0
        for i, ch in enumerate(text):
            depth += (ch == "(") - (ch == ")")
            if depth == 0 and i < len(text) - 1:
                break
        else:
            return text
    return f"({text})"


def string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


# -------------------------------------------------------------------------- parsing


@dataclass
class Col:
    name: str


@dataclass
class Lit:
    value: Any  # str, int, float, bool or None
    timestamp: bool = False


@dataclass
class Call:
    name: str
    args: list[Node]


@dataclass
class Not:
    item: Node


@dataclass
class And:
    items: list[Node]


@dataclass
class Or:
    items: list[Node]


@dataclass
class Cmp:
    left: Node
    op: str
    right: Node


@dataclass
class In:
    left: Node
    values: list[Node]
    negated: bool = False


@dataclass
class Between:
    left: Node
    low: Node
    high: Node
    negated: bool = False


@dataclass
class IsNull:
    left: Node
    negated: bool = False


@dataclass
class Like:
    left: Node
    pattern: str
    negated: bool = False
    ignore_case: bool = False


Node = Col | Lit | Call | Not | And | Or | Cmp | In | Between | IsNull | Like

TOKEN_RE = re.compile(
    r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<qid>\"(?:[^\"]|\"\")*\")|(?P<num>-?\d+(?:\.\d+)?)"
    r"|(?P<op><>|!=|<=|>=|=|<|>|\(|\)|,|&)|(?P<id>[A-Za-z_@][A-Za-z0-9_.@]*))"
)
KEYWORDS = {"AND", "OR", "NOT", "IN", "IS", "NULL", "BETWEEN", "LIKE", "ILIKE", "TRUE", "FALSE"}


class UntranslatableError(Exception):
    pass


def tokenize(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    pos = 0
    text = text.strip()
    while pos < len(text):
        m = TOKEN_RE.match(text, pos)
        if not m or m.end() == pos:
            raise UntranslatableError(f"unexpected text at {text[pos : pos + 20]!r}")
        pos = m.end()
        kind = m.lastgroup or ""
        value = m.group(kind)
        if kind == "id" and value.upper() in KEYWORDS:
            kind, value = "kw", value.upper()
        out.append((kind, value))
    return out


class Parser:
    def __init__(self, text: str) -> None:
        self.tokens = tokenize(text)
        self.pos = 0

    def peek(self, kind: str | None = None, value: str | None = None) -> bool:
        if self.pos >= len(self.tokens):
            return False
        k, v = self.tokens[self.pos]
        return (kind is None or k == kind) and (value is None or v == value)

    def take(self, kind: str | None = None, value: str | None = None) -> str:
        if not self.peek(kind, value):
            got = self.tokens[self.pos] if self.pos < len(self.tokens) else ("end", "")
            raise UntranslatableError(f"expected {value or kind}, got {got[1]!r}")
        self.pos += 1
        return self.tokens[self.pos - 1][1]

    def parse(self) -> Node:
        node = self.parse_or()
        if self.pos != len(self.tokens):
            raise UntranslatableError(f"trailing text {self.tokens[self.pos][1]!r}")
        return node

    def parse_or(self) -> Node:
        items = [self.parse_and()]
        while self.peek("kw", "OR"):
            self.take()
            items.append(self.parse_and())
        return items[0] if len(items) == 1 else Or(items)

    def parse_and(self) -> Node:
        items = [self.parse_not()]
        while self.peek("kw", "AND"):
            self.take()
            items.append(self.parse_not())
        return items[0] if len(items) == 1 else And(items)

    def parse_not(self) -> Node:
        if self.peek("kw", "NOT"):
            self.take()
            return Not(self.parse_not())
        return self.parse_comparison()

    def parse_comparison(self) -> Node:
        left = self.parse_primary()
        if self.peek("op") and self.tokens[self.pos][1] in ("=", "<>", "!=", "<", "<=", ">", ">="):
            op = self.take()
            return Cmp(left, "<>" if op == "!=" else op, self.parse_primary())
        if self.peek("kw", "IS"):
            self.take()
            negated = bool(self.peek("kw", "NOT")) and bool(self.take())
            self.take("kw", "NULL")
            return IsNull(left, negated)
        negated = False
        if self.peek("kw", "NOT"):
            self.take()
            negated = True
        if self.peek("kw", "IN"):
            self.take()
            self.take("op", "(")
            values = [self.parse_primary()]
            while self.peek("op", ","):
                self.take()
                values.append(self.parse_primary())
            self.take("op", ")")
            return In(left, values, negated)
        if self.peek("kw", "BETWEEN"):
            self.take()
            low = self.parse_primary()
            self.take("kw", "AND")
            return Between(left, low, self.parse_primary(), negated)
        if self.peek("kw", "LIKE") or self.peek("kw", "ILIKE"):
            ci = self.take() == "ILIKE"
            pattern = self.parse_primary()
            if not isinstance(pattern, Lit) or not isinstance(pattern.value, str):
                raise UntranslatableError("LIKE needs a string pattern")
            return Like(left, pattern.value, negated, ci)
        if negated:
            raise UntranslatableError("NOT without IN, BETWEEN or LIKE")
        return left

    def parse_primary(self) -> Node:
        if self.peek("op", "("):
            self.take()
            node = self.parse_or()
            self.take("op", ")")
            return node
        if self.peek("str"):
            return Lit(self.take()[1:-1].replace("''", "'"))
        if self.peek("num"):
            text = self.take()
            return Lit(float(text) if "." in text else int(text))
        if self.peek("kw", "TRUE") or self.peek("kw", "FALSE"):
            return Lit(self.take() == "TRUE")
        if self.peek("kw", "NULL"):
            self.take()
            return Lit(None)
        if self.peek("qid"):
            return Col(self.take()[1:-1].replace('""', '"'))
        if self.peek("id"):
            name = self.take()
            if name.upper() == "TIMESTAMP" and self.peek("str"):
                return Lit(self.take()[1:-1], timestamp=True)
            if self.peek("op", "("):
                self.take()
                args: list[Node] = []
                if not self.peek("op", ")"):
                    args.append(self.parse_or())
                    while self.peek("op", ","):
                        self.take()
                        args.append(self.parse_or())
                self.take("op", ")")
                return Call(name.lower(), args)
            return Col(name)
        got = self.tokens[self.pos] if self.pos < len(self.tokens) else ("end", "")
        raise UntranslatableError(f"unexpected {got[1]!r}")


# ------------------------------------------------------------------- translation


@dataclass
class Translation:
    filter: str  # "" when nothing is left to filter on
    start: datetime | None = None
    end: datetime | None = None
    dropped: list[str] = field(default_factory=list)
    never: bool = False  # the filter is FALSE: the finding has no rows


class Emitter:
    def __init__(self, spec: QuerySpec) -> None:
        self.spec = spec
        self.out = Translation("")

    def run(self, sql: str) -> Translation:
        for pattern, replacement, _note in self.spec.rewrites:
            sql = re.sub(pattern, replacement, sql)
        try:
            tree = Parser(sql).parse()
        except UntranslatableError as exc:
            self.out.dropped.append(str(exc))
            return self.out
        text = self.conjunction(tree)
        if text == "FALSE":
            self.out.never = True
            text = ""
        self.out.filter = "" if text == "TRUE" else text
        return self.out

    # The top-level AND chain: time conditions move to the range, failures are dropped.
    def conjunction(self, node: Node) -> str:
        items = node.items if isinstance(node, And) else [node]
        kept: list[str] = []
        for item in items:
            if isinstance(item, And):
                text = self.conjunction(item)
                if text == "FALSE":
                    return "FALSE"
                if text not in ("", "TRUE"):
                    kept.append(text)
                continue
            if self.time_condition(item):
                continue
            try:
                text = self.expr(item)
            except UntranslatableError as exc:
                self.out.dropped.append(str(exc))
                continue
            if text == "FALSE":
                return "FALSE"
            if text != "TRUE":
                kept.append(text)
        if not kept:
            return "TRUE"
        return " and ".join(kept)

    def time_condition(self, node: Node) -> bool:
        """Record a comparison against a time column as the range; True when consumed."""
        if isinstance(node, Between) and not node.negated:
            col, lo, hi = node.left, node.low, node.high
            if isinstance(col, Col) and col.name in self.spec.time_columns:
                self.widen(lo, hi, "BETWEEN")
                return True
            return False
        if not isinstance(node, Cmp):
            return False
        left, op, right = node.left, node.op, node.right
        if isinstance(right, Col) and isinstance(left, Lit):
            left, right = right, left
            op = {"<": ">", ">": "<", "<=": ">=", ">=": "<="}.get(op, op)
        if not (isinstance(left, Col) and left.name in self.spec.time_columns):
            return False
        if not isinstance(right, Lit) or op not in ("<", "<=", ">", ">="):
            return False
        when = as_datetime(right)
        if when is None:
            return False
        if op in (">", ">="):
            self.out.start = when if self.out.start is None else max(self.out.start, when)
        else:
            self.out.end = when if self.out.end is None else min(self.out.end, when)
        return True

    def widen(self, lo: Node, hi: Node, what: str) -> None:
        start, end = as_datetime(lo), as_datetime(hi)
        if start is None or end is None:
            raise UntranslatableError(f"{what} needs two timestamps")
        self.out.start = start if self.out.start is None else max(self.out.start, start)
        self.out.end = end if self.out.end is None else min(self.out.end, end)

    # ------------------------------------------------------------ expressions

    def expr(self, node: Node) -> str:
        if isinstance(node, And):
            parts = [self.expr(i) for i in node.items]
            if "FALSE" in parts:
                return "FALSE"
            parts = [p for p in parts if p != "TRUE"]
            return " and ".join(parts) if parts else "TRUE"
        if isinstance(node, Or):
            parts = [self.expr(i) for i in node.items]
            if "TRUE" in parts:
                return "TRUE"
            parts = [
                paren(p) if isinstance(i, And) and p != "FALSE" else p
                for i, p in zip(node.items, parts, strict=True)
                if p != "FALSE"
            ]
            return "(" + " or ".join(parts) + ")" if parts else "FALSE"
        if isinstance(node, Not):
            if isinstance(node.item, Col) and node.item.name in self.spec.derived:
                return self.column_test(node.item.name, "=", False)
            inner = self.expr(node.item)
            if inner in ("TRUE", "FALSE"):
                return "FALSE" if inner == "TRUE" else "TRUE"
            return f"not {paren(inner)}"
        if isinstance(node, Lit):
            if node.value is True:
                return "TRUE"
            if node.value is False:
                return "FALSE"
            raise UntranslatableError(f"a bare literal {node.value!r}")
        if isinstance(node, Col):
            return self.column_test(node.name, "bool", None)
        if isinstance(node, Call):
            return self.call(node)
        if isinstance(node, Cmp):
            return self.comparison(node)
        if isinstance(node, IsNull):
            if isinstance(node.left, Col) and node.left.name in self.spec.derived:
                return self.column_test(node.left.name, "notnull" if node.negated else "null", None)
            fld = self.operand(node.left)
            if self.spec.missing:
                dash = string(self.spec.missing)
                return f"{fld} != {dash}" if node.negated else f"{fld} = {dash}"
            return f"ispresent({fld})" if node.negated else f"not ispresent({fld})"
        if isinstance(node, In):
            values = ", ".join(self.literal(v) for v in node.values)
            return f"{self.operand(node.left)} {'not in' if node.negated else 'in'} [{values}]"
        if isinstance(node, Between):
            fld = self.operand(node.left)
            text = f"({fld} >= {self.literal(node.low)} and {fld} <= {self.literal(node.high)})"
            return f"not {text}" if node.negated else text
        if isinstance(node, Like):
            fld = self.operand(node.left)
            pattern = ("(?i)" if node.ignore_case else "") + sql_like_to_regex(node.pattern)
            return f"{fld} {'not like' if node.negated else 'like'} /{pattern}/"
        raise UntranslatableError("unsupported expression")

    def comparison(self, node: Cmp) -> str:
        left, op, right = node.left, node.op, node.right
        if isinstance(left, Lit) and not isinstance(right, Lit):
            left, right = right, left
            op = {"<": ">", ">": "<", "<=": ">=", ">=": "<="}.get(op, op)
        # coalesce(column, default) = value is column = value, or also missing when equal.
        if isinstance(left, Call) and left.name == "coalesce" and len(left.args) == 2:
            col, default = left.args
            if isinstance(right, Lit) and isinstance(default, Lit):
                plain = self.comparison(Cmp(col, op, right))
                if default.value != right.value:
                    return plain
                missing = self.expr(IsNull(col, negated=op != "="))
                return f"({plain} {'or' if op == '=' else 'and'} {missing})"
        if isinstance(left, Col) and isinstance(right, Lit):
            if left.name in self.spec.derived:
                return self.column_test(left.name, op, right.value)
            if right.value is None:
                return self.expr(IsNull(left, negated=op == "<>"))
            if left.name not in self.spec.fields:
                raise UntranslatableError(f"no CloudWatch field for {left.name}")
            return f"{self.spec.fieldf(left.name)} {insights_op(op)} {self.literal(right)}"
        return f"{self.operand(left)} {insights_op(op)} {self.operand(right)}"

    def column_test(self, name: str, op: str, value: Any) -> str:
        derived = self.spec.derived.get(name)
        if derived is not None:
            text = derived(op, value)
            if text is None:
                raise UntranslatableError(f"{name} cannot be expressed in Logs Insights")
            return text
        if name not in self.spec.fields:
            raise UntranslatableError(f"no CloudWatch field for {name}")
        fld = self.spec.fieldf(name)
        if op == "bool":
            return f"{fld} = 1"
        if op in ("null", "notnull"):
            return self.expr(IsNull(Col(name), negated=op == "notnull"))
        return f"{fld} {insights_op(op)} {self.literal(Lit(value))}"

    def call(self, node: Call) -> str:
        func = self.spec.funcs.get(node.name)
        if func is None:
            raise UntranslatableError(f"the function {node.name}() has no Logs Insights equivalent")
        text = func([self.operand(a) for a in node.args])
        if text is None:
            raise UntranslatableError(f"the function {node.name}() has no Logs Insights equivalent")
        return text

    def operand(self, node: Node) -> str:
        if isinstance(node, Col):
            if node.name in self.spec.derived or node.name not in self.spec.fields:
                raise UntranslatableError(f"no CloudWatch field for {node.name}")
            return self.spec.fieldf(node.name)
        if isinstance(node, Lit):
            return self.literal(node)
        if isinstance(node, Call):
            return self.call(node)
        raise UntranslatableError("an expression where a field was expected")

    def literal(self, node: Node) -> str:
        if not isinstance(node, Lit):
            raise UntranslatableError("a literal was expected")
        v = node.value
        if v is None:
            raise UntranslatableError("NULL in a comparison")
        if isinstance(v, bool):
            return "1" if v else "0"
        if isinstance(v, int | float):
            return repr(v)
        return string(str(v))


def insights_op(op: str) -> str:
    return "!=" if op == "<>" else op


def sql_like_to_regex(pattern: str) -> str:
    out = []
    for ch in pattern:
        if ch == "%":
            out.append(".*")
        elif ch == "_":
            out.append(".")
        else:
            out.append(regex_escape(ch))
    return "^" + "".join(out) + "$"


def as_datetime(node: Node) -> datetime | None:
    """A timestamp literal, a 'YYYY-MM-DD HH:MM[:SS]' string or an epoch number as UTC."""
    if not isinstance(node, Lit):
        return None
    v = node.value
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, int | float):
        return datetime.fromtimestamp(float(v), UTC).replace(tzinfo=None)
    text = str(v).strip().replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


# ------------------------------------------------------------------ the query text


def fmt_range(start: datetime | None, end: datetime | None) -> str:
    def f(t: datetime) -> str:
        return t.strftime("%Y-%m-%d %H:%M:%S") if t.second else t.strftime("%Y-%m-%d %H:%M")

    if start and end:
        return f"{f(start)} to {f(end)} UTC"
    if start:
        return f"from {f(start)} UTC"
    if end:
        return f"until {f(end)} UTC"
    return ""


def build_query(
    finding: Finding,
    spec: QuerySpec,
    file_range: tuple[datetime | None, datetime | None] = (None, None),
) -> str:
    """The Logs Insights query that selects the rows behind ``finding``."""
    tr = Emitter(spec).run(finding.row_filter)
    lines = [f"# {finding.title}"]
    start, end = tr.start, tr.end
    if start or end:
        lines.append(f"# Time range: {fmt_range(start, end)}. Set it in the console's time picker.")
    elif file_range[0] or file_range[1]:
        lines.append(f"# Time range: this file covers {fmt_range(*file_range)}.")
    for note in spec.notes:
        lines.append(f"# {note}")
    for pattern, _replacement, note in spec.rewrites:
        if note and re.search(pattern, finding.row_filter):
            lines.append(f"# {note}")
    if tr.never:
        lines.append("# The finding has no rows of its own; this lists the log as it is.")
    if tr.dropped:
        lines.append(
            "# Not expressed here, so this returns more rows than the finding: "
            + "; ".join(tr.dropped)
        )
    stats = spec.stats.get(finding.rule)
    commands: list[str] = []
    if stats:
        stats = re.sub(r"\{(\w+)\}", lambda m: spec.fieldf(m.group(1)), stats)
    else:
        shown = ", ".join(["@timestamp", *spec.display]) if spec.display else "@timestamp, @message"
        commands.append(f"fields {shown}")
    if spec.parse:
        commands.append(spec.parse)
    if tr.filter:
        commands.append(f"filter {tr.filter}")
    if stats:
        commands.extend(stats.split(" | "))
    else:
        commands.append("sort @timestamp desc")
        commands.append(f"limit {ROW_LIMIT}")
    lines.append("\n| ".join(commands))
    return "\n".join(lines)


def parse_clause(
    names: list[str], quoted: set[str] | None = None, brackets: set[str] | None = None
) -> str:
    """A ``parse @message`` clause for a space-separated log with these fields in order.

    Fields in ``quoted`` are written between double quotes in the log, ``brackets`` ones
    between square brackets.
    """
    quoted = quoted or set()
    brackets = brackets or set()
    globs = []
    for n in names:
        if n in quoted:
            globs.append('"*"')
        elif n in brackets:
            globs.append("[*]")
        else:
            globs.append("*")
    pattern = " ".join(globs)
    return f"parse @message '{pattern}' as {', '.join(names)}"
