"""SQL built only from the program's own constants (ARB-164): table names in
module constants, loops over literal lists, helpers that only format their
constant arguments, placeholder lists and allowlisted sort columns. Nothing
a caller supplies reaches the statement text."""
import sqlite3

_TABLE = "jobs"
_TABLES = ("jobs", "runs")
_RENAMES = [("job", "jobs"), ("run", "runs")]


def count_rows(conn: sqlite3.Connection) -> int:
    return conn.execute(f"SELECT COUNT(*) FROM {_TABLE}").fetchone()[0]


def purge(conn: sqlite3.Connection) -> None:
    for table in _TABLES:
        conn.execute(f"DELETE FROM {table}")
    for table in ("audit", "outbox"):
        conn.execute(f"DELETE FROM {table}")


def policy_name(table: str) -> str:
    return f"rls_{table}"


def drop_policy(conn: sqlite3.Connection) -> None:
    conn.execute(f"DROP POLICY {policy_name('jobs')} ON {_TABLE}")


def _rename(conn: sqlite3.Connection, old: str, new: str) -> None:
    conn.execute(f'ALTER TABLE "{old}" RENAME TO "{new}"')


def migrate(conn: sqlite3.Connection) -> None:
    for old, new in _RENAMES:
        _rename(conn, old, new)


def find(conn: sqlite3.Connection, owner: str | None, ids: list[int]):
    conditions = ["deleted = 0"]
    params: list = []
    if owner is not None:
        conditions.append("owner = ?")
        params.append(owner)
    if ids:
        placeholders = ",".join("?" for _ in ids)
        conditions.append(f"id IN ({placeholders})")
        params.extend(ids)
    where = " AND ".join(conditions)
    return conn.execute(f"SELECT id FROM {_TABLE} WHERE {where}", params).fetchall()


SORTABLE = {"id", "created_at"}


def page(conn: sqlite3.Connection, sort_by: str, order: str):
    if sort_by not in SORTABLE:
        sort_by = "id"
    if order.lower() not in ("asc", "desc"):
        order = "desc"
    return conn.execute(f"SELECT id FROM {_TABLE} ORDER BY {sort_by} {order.upper()}").fetchall()


_EVENT_COLUMNS = {"read": "read_at", "done": "done_at"}


def mark_from_view(conn: sqlite3.Connection, request) -> None:
    column = _EVENT_COLUMNS.get(request.POST.get("event"), "read_at")
    conn.execute(f"UPDATE {_TABLE} SET {column} = 1")
