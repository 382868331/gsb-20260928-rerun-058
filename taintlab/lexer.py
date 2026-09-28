from __future__ import annotations

from dataclasses import dataclass

from .locations import Loc


class LexerError(Exception):
    def __init__(self, message: str, loc: Loc) -> None:
        super().__init__(f"{loc}: 词法错误: {message}")
        self.loc = loc


KEYWORDS = {
    "def",
    "if",
    "else",
    "return",
    "true",
    "false",
}

# (token 类型, 文本)；长操作符放在短操作符之前。
OPERATORS = [
    ("EQ", "=="),
    ("NE", "!="),
    ("LE", "<="),
    ("GE", ">="),
    ("AND", "&&"),
    ("OR", "||"),
    ("LPAREN", "("),
    ("RPAREN", ")"),
    ("LBRACE", "{"),
    ("RBRACE", "}"),
    ("SEMI", ";"),
    ("COMMA", ","),
    ("ASSIGN", "="),
    ("LT", "<"),
    ("GT", ">"),
    ("PLUS", "+"),
    ("MINUS", "-"),
    ("STAR", "*"),
    ("SLASH", "/"),
    ("BANG", "!"),
]


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    loc: Loc


def tokenize(source: str) -> list[Token]:
    tokens: list[Token] = []
    i, line, col = 0, 1, 1
    n = len(source)

    def loc_here() -> Loc:
        return Loc(line, col, i)

    def advance(ch: str) -> None:
        nonlocal i, line, col
        i += 1
        if ch == "\n":
            line += 1
            col = 1
        else:
            col += 1

    while i < n:
        ch = source[i]
        if ch in " \t\r\n":
            advance(ch)
            continue
        if ch == "#":
            while i < n and source[i] != "\n":
                advance(source[i])
            continue
        start = loc_here()
        if ch.isalpha() or ch == "_":
            j = i
            while j < n and (source[j].isalnum() or source[j] == "_"):
                j += 1
            text = source[i:j]
            while i < j:
                advance(source[i])
            kind = "KEYWORD" if text in KEYWORDS else "IDENT"
            tokens.append(Token(kind, text, start))
            continue
        if ch.isdigit():
            j = i
            while j < n and source[j].isdigit():
                j += 1
            text = source[i:j]
            while i < j:
                advance(source[i])
            tokens.append(Token("NUMBER", text, start))
            continue
        if ch == '"':
            advance(ch)
            buf: list[str] = []
            escapes = {"n": "\n", "t": "\t", "\\": "\\", '"': '"'}
            while i < n and source[i] != '"':
                c = source[i]
                if c == "\n":
                    raise LexerError("字符串字面量不能跨行", loc_here())
                if c == "\\":
                    advance(c)
                    if i >= n:
                        raise LexerError("字符串转义未结束", loc_here())
                    e = source[i]
                    if e not in escapes:
                        raise LexerError(f"未知的转义序列 \\{e}", loc_here())
                    buf.append(escapes[e])
                    advance(e)
                else:
                    buf.append(c)
                    advance(c)
            if i >= n:
                raise LexerError("字符串未闭合", start)
            advance('"')
            tokens.append(Token("STRING", "".join(buf), start))
            continue
        matched = False
        for kind, text in OPERATORS:
            if source.startswith(text, i):
                for c in text:
                    advance(c)
                tokens.append(Token(kind, text, start))
                matched = True
                break
        if not matched:
            raise LexerError(f"无法识别的字符 {ch!r}", start)
    tokens.append(Token("EOF", "", loc_here()))
    return tokens
