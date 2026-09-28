from __future__ import annotations

from .ast_nodes import (
    AssignStmt,
    Binary,
    BoolLit,
    Call,
    Expr,
    ExprStmt,
    FuncDef,
    IfStmt,
    NumberLit,
    Program,
    ReturnStmt,
    Span,
    Stmt,
    StringLit,
    Unary,
    Var,
)
from .lexer import Token, tokenize
from .locations import Loc


class ParseError(Exception):
    def __init__(self, message: str, loc: Loc) -> None:
        super().__init__(f"{loc}: 语法错误: {message}")
        self.loc = loc


class Parser:
    def __init__(self, source: str) -> None:
        self.tokens: list[Token] = tokenize(source)
        self.pos = 0

    def peek(self) -> Token:
        return self.tokens[self.pos]

    def next(self) -> Token:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def expect(self, kind: str, what: str) -> Token:
        tok = self.peek()
        if tok.kind != kind:
            raise ParseError(f"期望 {what}，但遇到 {(tok.value or tok.kind)!r}", tok.loc)
        return self.next()

    def parse_program(self) -> Program:
        funcs: list[FuncDef] = []
        seen: set[str] = set()
        while self.peek().kind != "EOF":
            func = self.parse_func()
            if func.name in seen:
                raise ParseError(f"函数 {func.name!r} 重复定义", func.loc)
            seen.add(func.name)
            funcs.append(func)
        return Program(tuple(funcs))

    def parse_func(self) -> FuncDef:
        start = self.expect("KEYWORD", "def")
        if self.peek().value != "def" and start.value != "def":
            raise ParseError("期望 def", start.loc)
        name_tok = self.expect("IDENT", "函数名")
        self.expect("LPAREN", "(")
        params: list[str] = []
        if self.peek().kind != "RPAREN":
            while True:
                p = self.expect("IDENT", "参数名")
                if p.value in params:
                    raise ParseError(f"参数名 {p.value!r} 重复", p.loc)
                params.append(p.value)
                if self.peek().kind == "COMMA":
                    self.next()
                    continue
                break
        self.expect("RPAREN", ")")
        body, end_loc = self.parse_block()
        span = Span(start.loc, end_loc)
        return FuncDef(start.loc, name_tok.value, tuple(params), tuple(body), span)

    def parse_block(self) -> tuple[list[Stmt], Loc]:
        open_tok = self.expect("LBRACE", "{")
        stmts: list[Stmt] = []
        while self.peek().kind != "RBRACE":
            if self.peek().kind == "EOF":
                raise ParseError("代码块未闭合", open_tok.loc)
            stmts.append(self.parse_stmt())
        close = self.next()
        return stmts, close.loc

    def parse_stmt(self) -> Stmt:
        tok = self.peek()
        if tok.kind == "KEYWORD" and tok.value == "if":
            return self.parse_if()
        if tok.kind == "KEYWORD" and tok.value == "return":
            self.next()
            value = None
            if self.peek().kind != "SEMI":
                value = self.parse_expr()
            self.expect("SEMI", ";")
            return ReturnStmt(tok.loc, value)
        if tok.kind == "IDENT" and self.tokens[self.pos + 1].kind == "ASSIGN":
            self.next()
            self.next()
            value = self.parse_expr()
            self.expect("SEMI", ";")
            return AssignStmt(tok.loc, tok.value, value)
        expr = self.parse_expr()
        if not isinstance(expr, Call):
            raise ParseError("表达式语句只能是函数调用", tok.loc)
        self.expect("SEMI", ";")
        return ExprStmt(tok.loc, expr)

    def parse_if(self) -> IfStmt:
        tok = self.next()
        self.expect("LPAREN", "(")
        cond = self.parse_expr()
        self.expect("RPAREN", ")")
        then_body, _ = self.parse_block()
        else_body: list[Stmt] = []
        if self.peek().kind == "KEYWORD" and self.peek().value == "else":
            self.next()
            else_body, _ = self.parse_block()
        return IfStmt(tok.loc, cond, tuple(then_body), tuple(else_body))

    # ----- 表达式（优先级爬升） -----

    def parse_expr(self, min_bp: int = 0) -> Expr:
        left = self.parse_unary()
        while True:
            tok = self.peek()
            info = BIN_PREC.get(tok.kind)
            if info is None:
                break
            lbp, rbp = info
            if lbp < min_bp:
                break
            self.next()
            right = self.parse_expr(rbp)
            left = Binary(tok.loc, tok.value, left, right)
        return left

    def parse_unary(self) -> Expr:
        tok = self.peek()
        if tok.kind in ("MINUS", "BANG"):
            self.next()
            return Unary(tok.loc, tok.value, self.parse_expr(UNARY_BP))
        return self.parse_primary()

    def parse_primary(self) -> Expr:
        tok = self.next()
        if tok.kind == "NUMBER":
            return NumberLit(tok.loc, int(tok.value))
        if tok.kind == "STRING":
            return StringLit(tok.loc, tok.value)
        if tok.kind == "KEYWORD" and tok.value in ("true", "false"):
            return BoolLit(tok.loc, tok.value == "true")
        if tok.kind == "IDENT":
            if self.peek().kind == "LPAREN":
                self.next()
                args: list[Expr] = []
                if self.peek().kind != "RPAREN":
                    while True:
                        args.append(self.parse_expr())
                        if self.peek().kind == "COMMA":
                            self.next()
                            continue
                        break
                self.expect("RPAREN", ")")
                return Call(tok.loc, tok.value, tuple(args))
            return Var(tok.loc, tok.value)
        if tok.kind == "LPAREN":
            expr = self.parse_expr()
            self.expect("RPAREN", ")")
            return expr
        raise ParseError(f"意外的记号 {(tok.value or tok.kind)!r}", tok.loc)


# (左结合优先级, 右操作数起始优先级)
BIN_PREC = {
    "OR": (1, 2),
    "AND": (3, 4),
    "EQ": (5, 6),
    "NE": (5, 6),
    "LT": (7, 8),
    "GT": (7, 8),
    "LE": (7, 8),
    "GE": (7, 8),
    "PLUS": (9, 10),
    "MINUS": (9, 10),
    "STAR": (11, 12),
    "SLASH": (11, 12),
}

UNARY_BP = 13


def parse(source: str) -> Program:
    return Parser(source).parse_program()
