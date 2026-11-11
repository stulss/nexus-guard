# -*- coding: utf-8 -*-
"""NEXUS-GUARD Core: AST(Abstract Syntax Tree) 정적 분석 기반 SQL 질의 린터.

이것은 개발 시점 정적 검사기(린터)이며 런타임 차단기가 아니다. 보장 범위:
  - 대상 호출: execute / executemany / executescript / execute_rowcount / query_all / query_one / query / mogrify
    (이 저장소의 db 래퍼 포함). 첫 위치 인자 또는 query=/sql=/statement= 키워드 인자를 검사한다.
  - 상수 문자열만 통과. f-string, % 포맷, .format(), + 연결, "x".join(), 그리고 함수 안에서 위 방식으로 만든
    변수를 execute(q) 로 넘기는 경우(변수 경유)를 적발한다.
  - 한계: 다른 함수/모듈에서 만든 문자열을 매개변수로 받아 그대로 넘기는 경우(호출자 쪽에서 검사해야 함),
    getattr/동적 호출, 문자열 외 객체(SQLAlchemy 표현식) 는 보지 않는다.
"""
import ast
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

SQL_CALLS = {"execute", "executemany", "executescript", "execute_rowcount", "query_all", "query_one", "query", "mogrify"}
SQL_KWARGS = {"query", "sql", "statement", "stmt"}


class AstQueryGuard:
    """파이썬 코드베이스의 SQL 질의가 상수 문자열(+ 파라미터 바인딩)만 쓰는지 AST 로 검사한다."""

    FORBIDDEN_CALLS = SQL_CALLS

    @classmethod
    def inspect_file(cls, filepath: Path) -> List[Tuple[int, str]]:
        try:
            tree = ast.parse(Path(filepath).read_text(encoding="utf-8"), filename=str(filepath))
        except Exception as e:
            return [(0, f"AST 파싱 실패: {e}")]
        return cls.inspect_tree(tree)

    @classmethod
    def inspect_tree(cls, tree: ast.AST) -> List[Tuple[int, str]]:
        parents: Dict[ast.AST, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
        violations: List[Tuple[int, str]] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""
            if name not in SQL_CALLS:
                continue
            arg = node.args[0] if node.args else next((k.value for k in node.keywords if k.arg in SQL_KWARGS), None)
            if arg is None:
                continue
            scope = cls._scope(node, parents, tree)
            msg = cls._classify(arg, scope, set())
            if msg:
                violations.append((node.lineno, msg))
        return violations

    @staticmethod
    def _scope(node, parents, tree):
        cur = node
        while cur in parents:
            cur = parents[cur]
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return cur
        return tree

    @classmethod
    def _assignments(cls, scope, name: str) -> List[ast.AST]:
        out: List[ast.AST] = []
        for n in ast.walk(scope):
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
                out.append(n.value)
            elif isinstance(n, (ast.AugAssign, ast.AnnAssign)) and isinstance(n.target, ast.Name) and n.target.id == name:
                if n.value is not None:
                    out.append(n.value if isinstance(n, ast.AnnAssign) else ast.BinOp(left=ast.Constant(""), op=n.op, right=n.value))
        return out

    @classmethod
    def _classify(cls, expr, scope, seen: Set[str]) -> Optional[str]:
        """위험하면 메시지, 안전(또는 판단 불가한 매개변수 전달)이면 None."""
        if isinstance(expr, ast.Constant):
            return None if isinstance(expr.value, str) else "SQL 인자가 문자열 상수가 아님"
        if isinstance(expr, ast.JoinedStr):
            if any(isinstance(v, ast.FormattedValue) for v in expr.values):
                return "f-string 기반 동적 SQL 조합 탐지 (위험)"
            return None
        if isinstance(expr, ast.BinOp):
            if isinstance(expr.op, ast.Mod):
                return "% 포맷팅 기반 동적 SQL 조합 탐지 (위험)"
            if isinstance(expr.op, ast.Add):
                for side in (expr.left, expr.right):
                    if cls._classify(side, scope, seen) is not None or not cls._is_const_like(side, scope):
                        return "문자열 연결(+) 기반 동적 SQL 조합 탐지 (위험)"
                return None
            return "지원하지 않는 SQL 식 (위험)"
        if isinstance(expr, ast.Call):
            attr = getattr(expr.func, "attr", "")
            if attr == "format":
                return ".format() 기반 동적 SQL 조합 탐지 (위험)"
            if attr == "join":
                return "join() 기반 동적 SQL 조합 탐지 (위험)"
            return "SQL 인자가 상수가 아닌 호출 결과 (위험)"
        if isinstance(expr, ast.Name):
            if expr.id in seen:
                return None
            assigned = cls._assignments(scope, expr.id)
            if not assigned and scope is not None:
                return None  # 매개변수/외부 이름: 호출자 쪽에서 검사해야 한다(한계)
            for value in assigned:
                msg = cls._classify(value, scope, seen | {expr.id})
                if msg:
                    return "변수 경유 " + msg
            return None
        return "SQL 인자가 상수 문자열이 아님 (위험)"

    @classmethod
    def _is_const_like(cls, expr, scope) -> bool:
        if isinstance(expr, ast.Constant):
            return True
        if isinstance(expr, ast.Name):
            assigned = cls._assignments(scope, expr.id)
            return bool(assigned) and all(isinstance(v, ast.Constant) for v in assigned)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            return cls._is_const_like(expr.left, scope) and cls._is_const_like(expr.right, scope)
        return False
