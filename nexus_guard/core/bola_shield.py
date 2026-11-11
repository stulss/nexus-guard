# -*- coding: utf-8 -*-
"""NEXUS-GUARD Core: 비즈니스 로직 인가(BOLA/IDOR) 및 순차 승인 무결성 방어 실드."""
from typing import Any, Dict, List, Optional


class BolaShield:
    """전자결재 순차 승인 및 중요 객체 접근 제어(BOLA/IDOR) 방어기."""

    def __init__(self):
        # 직급 및 권한 계층
        self.role_hierarchy = {
            "admin": 100,
            "director": 50,
            "manager": 30,
            "user": 10,
        }

    def verify_approval_step(
        self,
        current_step: int,
        requested_step: int,
        user_role: str,
        required_role: str,
    ) -> bool:
        """결재 라인 새치기(BOLA)를 방어합니다.
        
        규칙:
        1. 요청한 단계(requested_step)는 반드시 현재 단계(current_step)와 정확히 일치해야 함.
        2. 사용자의 권한 레벨이 해당 단계가 요구하는 권한 레벨 이상이어야 함.
        """
        if requested_step != current_step:
            # 순서를 건너뛰려고 시도함 (새치기 공격)
            return False

        # 알 수 없는 역할은 fail-closed (이전: 둘 다 0 으로 취급해 오타 난 required_role 이 모두 통과)
        if user_role not in self.role_hierarchy or required_role not in self.role_hierarchy:
            return False
        return self.role_hierarchy[user_role] >= self.role_hierarchy[required_role]

    def verify_financial_integrity(
        self,
        item_amounts: List[int],
        claimed_total: int,
    ) -> bool:
        """지출결의서 등 재무 문서의 클라이언트 위조를 방어합니다.
        
        서버에서 품목별 금액을 전수 재합산하여 단 1원의 불일치도 허용하지 않습니다.
        """
        # 음수·bool·비정수 품목으로 합계를 상쇄하는 위조를 거부한다
        for amount in list(item_amounts) + [claimed_total]:
            if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
                return False
        return sum(item_amounts) == claimed_total

    def verify_object_ownership(
        self,
        current_user_id: int,
        target_owner_id: int,
        user_role: str,
        allow_roles: Optional[List[str]] = None,
    ) -> bool:
        """IDOR(Insecure Direct Object Reference) 방어.
        
        소유자가 일치하거나, 허용된 관리자 역할이어야 접근 가능.
        """
        if current_user_id is None or target_owner_id is None:
            return False  # None == None 으로 익명이 소유자 없는 객체에 접근하는 것을 막는다
        if current_user_id == target_owner_id:
            return True
        if allow_roles and user_role in allow_roles:
            return True
        return False
