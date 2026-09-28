from __future__ import annotations

from .ast_nodes import (
    Assign, Binary, Boolean, Call, ExpressionStatement, Function, Identifier,
    If, Let, Number, Program, Return, Span, String, Unary,
)
from .lexer import Token, tokenize


class ParseError(ValueError):
    pass


class Parser:
    def __init__(self, tokens: list[Token]):
        self.tokens = tokens
        self.index = 0

    @property
    def token(self) -> Token:
        return self.tokens[self.index]

    def take(self) -> Token:
        token = self.token
        if token.kind != "EOF":
            self.index += 1
        return token

    def expect(self, kind: str, value: str | None = None) -> Token:
        token = self.token
        if token.kind != kind or (value is not None and token.value != value):
            expected = value or kind.lower()
            raise ParseError(
                f"{token.span.start.line}:{token.span.start.column}: expected {expected!r}, found {token.value!r}"
            )
        return self.take()

    def parse_program(self) -> Program:
        start = self.token.span.start
        functions = []
        while self.token.kind != "EOF":
            functions.append(self.parse_function())
        return Program(Span(start, self.token.span.end), tuple(functions))

    def parse_function(self) -> Function:
        start = self.expect("KEYWORD", "fn").span.start
        name = self.expect("IDENT").value
        self.expect("LPAREN")
        parameters: list[str] = []
        if self.token.kind != "RPAREN":
            while True:
                parameters.append(self.expect("IDENT").value)
                if self.token.kind == "COMMA":
                    self.take()
                else:
                    break
        self.expect("RPAREN")
        self.expect("LBRACE")
        body = self.parse_block_until_rbrace()
        end = self.expect("RBRACE").span.end
        return Function(Span(start, end), name, tuple(parameters), tuple(body))

    def parse_block_until_rbrace(self):
        statements = []
        while self.token.kind != "RBRACE":
            if self.token.kind == "EOF":
                raise ParseError("unexpected end of file inside block")
            statements.append(self.parse_statement())
        return statements

    def parse_statement(self):
        start = self.token.span.start
        if self.token.kind == "KEYWORD" and self.token.value == "let":
            self.take()
            name = self.expect("IDENT").value
            self.expect("OP", "=")
            value = self.parse_expression()
            end = self.expect("SEMICOLON").span.end
            return Let(Span(start, end), name, value)
        if self.token.kind == "KEYWORD" and self.token.value == "return":
            self.take()
            value = None if self.token.kind == "SEMICOLON" else self.parse_expression()
            end = self.expect("SEMICOLON").span.end
            return Return(Span(start, end), value)
        if self.token.kind == "KEYWORD" and self.token.value == "if":
            return self.parse_if()
        if (
            self.token.kind == "IDENT"
            and self.tokens[self.index + 1].kind == "OP"
            and self.tokens[self.index + 1].value == "="
        ):
            name = self.take().value
            self.take()
            value = self.parse_expression()
            end = self.expect("SEMICOLON").span.end
            return Assign(Span(start, end), name, value)
        expression = self.parse_expression()
        end = self.expect("SEMICOLON").span.end
        return ExpressionStatement(Span(start, end), expression)

    def parse_if(self) -> If:
        start = self.expect("KEYWORD", "if").span.start
        self.expect("LPAREN")
        condition = self.parse_expression()
        self.expect("RPAREN")
        self.expect("LBRACE")
        then_body = tuple(self.parse_block_until_rbrace())
        self.expect("RBRACE")
        else_body: tuple = ()
        if self.token.kind == "KEYWORD" and self.token.value == "else":
            self.take()
            if self.token.kind == "KEYWORD" and self.token.value == "if":
                else_body = (self.parse_if(),)
            else:
                self.expect("LBRACE")
                else_body = tuple(self.parse_block_until_rbrace())
                self.expect("RBRACE")
        return If(Span(start, self.token.span.start), condition, then_body, else_body)

    def parse_expression(self):
        return self.parse_comparison()

    def _binary_chain(self, next_parser, operators):
        left = next_parser()
        while self.token.kind == "OP" and self.token.value in operators:
            operator = self.take().value
            right = next_parser()
            left = Binary(Span(left.span.start, right.span.end), left, operator, right)
        return left

    def parse_comparison(self):
        return self._binary_chain(self.parse_additive, {"==", "!=", "<", ">", "<=", ">="})

    def parse_additive(self):
        return self._binary_chain(self.parse_multiplicative, {"+", "-"})

    def parse_multiplicative(self):
        return self._binary_chain(self.parse_unary, {"*", "/"})

    def parse_unary(self):
        if self.token.kind == "OP" and self.token.value in {"!", "-"}:
            token = self.take()
            return Unary(token.span, token.value, self.parse_unary())
        return self.parse_primary()

    def parse_primary(self):
        token = self.token
        if token.kind == "NUMBER":
            self.take()
            return Number(token.span, int(token.value))
        if token.kind == "STRING":
            self.take()
            return String(token.span, token.value)
        if token.kind == "KEYWORD" and token.value in {"true", "false"}:
            self.take()
            return Boolean(token.span, token.value == "true")
        if token.kind == "IDENT":
            start = token.span.start
            name = self.take().value
            if self.token.kind == "LPAREN":
                self.take()
                arguments = []
                if self.token.kind != "RPAREN":
                    while True:
                        arguments.append(self.parse_expression())
                        if self.token.kind == "COMMA":
                            self.take()
                        else:
                            break
                self.expect("RPAREN")
                return Call(Span(start, self.token.span.end), name, tuple(arguments))
            return Identifier(token.span, name)
        if token.kind == "LPAREN":
            self.take()
            expression = self.parse_expression()
            self.expect("RPAREN")
            return expression
        raise ParseError(f"{token.span.start.line}:{token.span.start.column}: unexpected token {token.value!r}")


def parse_source(source: str) -> Program:
    return Parser(tokenize(source)).parse_program()
