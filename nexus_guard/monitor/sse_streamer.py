# -*- coding: utf-8 -*-
"""NEXUS-GUARD Monitor: Server-Sent Events (SSE) 기반 실시간 보안 관제 스트리머."""
import json
import queue
import re
import threading
import time
from typing import Generator, List


class SseAuditStreamer:
    """다중 브라우저 관제관에게 0.1초 만에 보안 이벤트 및 모드 변경을 단방향 푸시하는 스트리머."""

    def __init__(self):
        self._subscribers: List[queue.Queue] = []
        self._lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        """새로운 웹 관제 세션이 접속할 때 큐를 발급합니다."""
        q = queue.Queue(maxsize=100)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        """연결이 끊어진 관제 큐를 정리합니다."""
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def broadcast(self, event_type: str, data: dict) -> int:
        """모든 접속 중인 관제 브라우저에 0.1초 만에 실시간 브로드캐스트합니다."""
        # event 이름에 개행이 들어가면 SSE 프레임을 위조(이벤트 주입)할 수 있으므로 안전한 문자만 남긴다
        event_type = re.sub(r"[^A-Za-z0-9_.-]", "_", str(event_type))[:64] or "message"
        payload = f"event: {event_type}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
        count = 0
        dead_queues = []

        with self._lock:
            subscribers = list(self._subscribers)
        for q in subscribers:
            try:
                q.put_nowait(payload)
                count += 1
            except queue.Full:
                dead_queues.append(q)

        for dq in dead_queues:
            self.unsubscribe(dq)

        return count

    def generate_events(self, q: queue.Queue) -> Generator[str, None, None]:
        """Flask Response(stream_with_context)용 제너레이터."""
        yield ": ping\n\n"
        while True:
            try:
                msg = q.get(timeout=20)
                yield msg
            except queue.Empty:
                yield ": keepalive\n\n"
