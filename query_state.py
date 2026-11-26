#!/usr/bin/env python3
"""View the live state of the pipeline.  python query_state.py [--watch]"""
import sys
import time

import orchestrator.postgresql.db as db
from psycopg2 import extras


def show():
    with db.conn() as c, c.cursor(cursor_factory=extras.RealDictCursor) as cur:
        cur.execute("SELECT state, count(*) n FROM emails GROUP BY state ORDER BY state")
        print("States:", {r["state"]: r["n"] for r in cur.fetchall()})
        cur.execute("""SELECT left(message_id, 8) id, state, severity, score, quarantined, action_taken,
                              to_char(updated_at, 'HH24:MI:SS') updated
                       FROM emails ORDER BY id DESC LIMIT 15""")
        for r in cur.fetchall():
            print(dict(r))
        cur.execute("SELECT address, suspended, reason FROM accounts WHERE suspended")
        print("Suspended accounts:", [dict(r) for r in cur.fetchall()])


if __name__ == "__main__":
    db.init_db()
    while True:
        show()
        if "--watch" not in sys.argv:
            break
        print("-" * 60)
        time.sleep(2)