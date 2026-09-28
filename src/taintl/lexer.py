from __future__ import annotations

from dataclasses import dataclass
from .positions import Position, Span


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    span: Span


class LexError(ValueError):
    pass


SIMPLE = {
    "(": "LPAREN",
    ")": "RPAREN",
    "{": "LBRACE",
    "}": "RBRACE",
    ",": "COMMA",
    ";": "SEMICOLON",
}

KEYWORDS = {"fn", "let", "return", "if", "else", "true", "false"}


def _is_ident_start(ch: str) -> bool:
    return ch.isalpha() or ch == "_"


def _is_ident_part(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def tokenize(source: str) -> list[Token]:
    tokens: list[Token] = []
    index = 0
    line = 1
    column = 1

    def position() -> Position:
        return Position(index, line, column)

    def advance() -> str:
        nonlocal index, line, column
        ch = source[index]
        index += 1
        if ch == "\n":
            line += 1
            column = 1
        else:
            column += 1
        return ch

    while index < len(source):
        ch = source[index]
        if ch in " \t\r\n":
            advance()
            continue
        if source.startswith("//", index):
            while index < len(source) and source[index] != "\n":
                advance()
            continue

        start = position()
        if ch in SIMPLE:
            value = advance()
            tokens.append(Token(SIMPLE[value], value, Span(start, position())))
            continue

        if ch in "=!<>+-*/":
            value = advance()
            if index < len(source) and source[index] == "=" and value in "=!<>":
                value += advance()
            tokens.append(Token("OP", value, Span(start, position())))
            continue

        if ch.isdigit():
            start_index = index
            while index < len(source) and source[index].isdigit():
                advance()
            value = source[start_index:index]
            tokens.append(Token("NUMBER", value, Span(start, position())))
            continue

        if ch == '"':
            advance()
            value_chars: list[str] = []
            escapes = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}
            while index < len(source) and source[index] != '"':
                current = source[index]
                if current == "\n":
                    raise LexError(f"{line}:{column}: unterminated string")
                if current == "\\" and index + 1 < len(source):
                    advance()
                    following = advance()
                    value_chars.append(escapes.get(following, following))
                else:
                    value_chars.append(advance())
            if index >= len(source):
                raise LexError(f"{line}:{column}: unterminated string")
            advance()
            tokens.append(Token("STRING", "".join(value_chars), Span(start, position())))
            continue

        if _is_ident_start(ch):
            start_index = index
            while index < len(source) and _is_ident_part(source[index]):
                advance()
            value = source[start_index:index]
            kind = "KEYWORD" if value in KEYWORDS else "IDENT"
            tokens.append(Token(kind, value, Span(start, position())))
            continue

        raise LexError(f"{line}:{column}: unexpected character {ch!r}")

    tokens.append(Token("EOF", "", Span(position(), position())))
    return tokens
