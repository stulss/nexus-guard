"""새로 설치한 DB(db/init.sh + schema.sql + grants.sql)에서 앱 계정(nexus_app)이 보안 인시던트·AI-XDR 경로를 실제로 쓸 수 있는지 확인한다.

사용(임시 컨테이너 예, 사용자 DB 에는 쓰지 말 것):
  docker run -d --name nexus-mysql-fresh -p 127.0.0.1:3398:3307 -e MYSQL_ROOT_PASSWORD=... -e NEXUS_APP_PASSWORD=... \
      -e NEXUS_CONF_PASSWORD=... -v db/init.sh:/docker-entrypoint-initdb.d/10-init.sh:ro -v db/schema.sql:/seed/schema.sql:ro \
      -v db/grants.sql:/seed/grants.sql:ro mysql:8.4 --port=3307
  DB_HOST=127.0.0.1 DB_PORT=3398 MYSQL_ROOT_PASSWORD=... NEXUS_APP_PASSWORD=... NEXUS_CONF_PASSWORD=... \
      .venv\\Scripts\\python scripts/verify_fresh_install.py

앱 코드(decoy.py·incidents.py·ai_xdr.py)를 nexus_app 으로 그대로 실행해 SELECT/INSERT/UPDATE 가 모두 되는지 보고,
최소권한(열 단위 UPDATE, DELETE 없음, 표 전체 ALL 없음)이 유지되는지도 확인한다. 시험 행은 끝에 root 로 지운다.
실패하면 종료 코드 1. 모든 SQL 은 상수 문자열 + params 이다."""
import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pymysql  # noqa: E402

TEST_IP = "198.51.100.77"
TICKET_KEY = f"decoy:ip:{TEST_IP}"
TABLES = ("security_incident_tickets", "security_xdr_events", "security_xdr_assessments")
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS " if ok else "FAIL ") + name + (f"  -- {detail}" if detail and not ok else ""))


def root_connection():
    return pymysql.connect(host=os.environ.get("DB_HOST", "127.0.0.1"), port=int(os.environ.get("DB_PORT", "3307")), user="root",
                           password=os.environ["MYSQL_ROOT_PASSWORD"], database=os.environ.get("DB_NAME", "nexus"),
                           charset="utf8mb4", autocommit=True)


def check_grants(root):
    with root.cursor() as cur:
        cur.execute("SHOW GRANTS FOR 'nexus_app'@'%'")
        grants = [row[0] for row in cur.fetchall()]
    check("no ALL PRIVILEGES / GRANT OPTION for nexus_app", not any("ALL PRIVILEGES" in g or "WITH GRANT OPTION" in g for g in grants))
    for table in TABLES:
        mine = [g for g in grants if f".`{table}`" in g]
        check(f"{table}: has grants", bool(mine))
        check(f"{table}: no DELETE", not any(" DELETE" in g.split(" ON ")[0] for g in mine))
        # 표 전체 UPDATE(열 목록 없는 UPDATE)가 없어야 한다: SHOW GRANTS 에서 열 단위는 "UPDATE (`열`,...)" 로 나온다
        heads = [g.split(" ON ")[0] for g in mine]
        check(f"{table}: UPDATE is column-level only", not any(re.search(r"UPDATE(?!\s*\()", h) for h in heads), str(heads))
    for table in ("security_incident_alerts", "security_discord_rate_limit"):
        check(f"{table}: not granted to nexus_app (n8n only)", not any(f".`{table}`" in g for g in grants))


def run_app_paths(root):
    from app import ai_xdr, create_app, db, decoy, incidents

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as logs:
        app = create_app({"TESTING": True, "LOG_DIR": Path(logs), "SESSION_COOKIE_SECURE": False, "GRAYLOG_GELF_ENABLED": False,
                          "XDR_TRIAGE_WINDOW_SECONDS": 60})
        # 1) 허니팟 Ticket: 생성(INSERT) 후 같은 IP 재접근(UPDATE 열: event_count/last_seen/latest_event/responses)
        with app.test_request_context("/"):
            decoy.create_decoy_incident_ticket(TEST_IP, "/.env", "verify-script", minutes=1)
            decoy.create_decoy_incident_ticket(TEST_IP, "/.git/config", "verify-script", minutes=1)
            db.commit()
        with app.test_request_context("/"):
            row = db.query_one("SELECT id, event_count FROM security_incident_tickets WHERE ticket_key = %s", (TICKET_KEY,))
            check("decoy ticket created then updated (event_count == 2)", row is not None and row["event_count"] == 2, str(row))
            ticket_id = row["id"] if row else None

        # 2) 관리자 인시던트 화면이 읽는 함수
        with app.test_request_context("/"):
            tickets = incidents.list_tickets(limit=10)
            check("incidents.list_tickets sees the ticket", any(t.get("id") == ticket_id for t in tickets))
            check("incidents.get_ticket", ticket_id is not None and incidents.get_ticket(ticket_id) is not None)
            incidents.latest_assessments_for_tickets(tickets)
            check("incidents.latest_assessments_for_tickets (reads security_xdr_assessments)", True)

        # 3) AI-XDR: 이벤트 수집(INSERT) -> 창 처리(SELECT/INSERT/UPDATE) -> 판정 목록(SELECT) -> 결정(UPDATE)
        event = {
            "schema_version": "1.1", "alert_id": "verify-fresh-1", "rule_id": "R8", "timestamp": "2026-10-26T01:00:00Z",
            "ticket_id": f"NX-DB-{ticket_id:06d}" if ticket_id else "",
            "rule": {"id": "R8", "severity": "info"},
            "event": {"event_type": "not_found", "src_ip": TEST_IP, "user": "scanner", "path": "/verify", "count": 4, "severity": "info"},
        }
        with app.test_request_context("/"):
            first = ai_xdr.ingest_event(event)
            db.commit()
            check("ai_xdr.ingest_event inserts security_xdr_events", first.get("duplicate") is False, str(first))
        with root.cursor() as cur:   # 창이 닫힌 것으로 보이게 시험 이벤트의 창 시작을 10분 앞으로 당긴다(시험 준비는 root 로)
            cur.execute("UPDATE security_xdr_events SET window_start = window_start - INTERVAL 10 MINUTE WHERE src_ip = %s", (TEST_IP,))
        original_triage = ai_xdr.triage
        ai_xdr.triage = lambda summary, assessment_id: ai_xdr.fail_safe_result(assessment_id)   # 외부 AI 호출 없이 판정 기록 경로만 시험
        try:
            with app.test_request_context("/"):
                done = ai_xdr.process_ready_windows(limit=1)
                db.commit()
                check("ai_xdr.process_ready_windows writes an assessment", done.get("processed") == 1, str(done))
        finally:
            ai_xdr.triage = original_triage
        with app.test_request_context("/"):
            assessments = ai_xdr.list_assessments(limit=10)
            check("ai_xdr.list_assessments sees it", any(a.get("src_ip") == TEST_IP for a in assessments))
            mine = next((a for a in assessments if a.get("src_ip") == TEST_IP), None)
        if mine:
            with root.cursor() as cur:   # 관리자 결정 경로를 보려고 대기(PENDING) 상태로 만든다(시험 준비는 root 로)
                cur.execute("UPDATE security_xdr_assessments SET status = 'PENDING' WHERE assessment_id = %s", (mine["assessment_id"],))
            with app.test_request_context("/"):
                ai_xdr.decide_assessment(mine["assessment_id"], "REJECTED", 1, "verify-script")
                db.commit()
            with root.cursor() as cur:
                cur.execute("SELECT status, decided_by FROM security_xdr_assessments WHERE assessment_id = %s", (mine["assessment_id"],))
                status, decided_by = cur.fetchone()
            check("ai_xdr.decide_assessment updates status/decided_by/decided_at", status == "REJECTED" and decided_by == 1, f"{status},{decided_by}")

        # 4) 최소권한: 원본 열 수정·삭제는 막혀야 한다
        with app.test_request_context("/"):
            for label, query in (
                ("UPDATE assessments.src_ip denied", "UPDATE security_xdr_assessments SET src_ip = 'x'"),
                ("UPDATE tickets.status denied", "UPDATE security_incident_tickets SET status = 'closed'"),
                ("UPDATE tickets.src_ip denied", "UPDATE security_incident_tickets SET src_ip = 'x'"),
                ("DELETE tickets denied", "DELETE FROM security_incident_tickets"),
                ("DELETE events denied", "DELETE FROM security_xdr_events"),
                ("SELECT incident_alerts denied", "SELECT COUNT(*) FROM security_incident_alerts"),
            ):
                try:
                    db.query_all(query) if query.startswith("SELECT") else db.execute(query)
                    check(label, False, "statement was allowed")
                except pymysql.err.OperationalError as exc:
                    check(label, exc.args[0] in (1142, 1143), str(exc.args))
                db.app_db().rollback()


def cleanup(root):
    with root.cursor() as cur:
        cur.execute("DELETE FROM security_xdr_events WHERE src_ip = %s", (TEST_IP,))
        cur.execute("DELETE FROM security_xdr_assessments WHERE src_ip = %s", (TEST_IP,))
        cur.execute("DELETE FROM security_incident_tickets WHERE ticket_key = %s", (TICKET_KEY,))
        cur.execute("DELETE FROM blocked_ips WHERE ip_address = %s", (TEST_IP,))


def main():
    for needed in ("MYSQL_ROOT_PASSWORD", "NEXUS_APP_PASSWORD", "NEXUS_CONF_PASSWORD"):
        if not os.environ.get(needed):
            sys.exit(f"{needed} 환경변수가 필요하다(사용자 DB 가 아닌 새 시험 컨테이너 값).")
    root = root_connection()
    try:
        check_grants(root)
        run_app_paths(root)
    finally:
        cleanup(root)
        root.close()
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
