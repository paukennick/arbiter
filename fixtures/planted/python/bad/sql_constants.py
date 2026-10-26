"""SQL whose spliced values come from callers (ARB-164): each mirrors a
constant-built lookalike in good/sql_constants.py that must stay silent."""
import sqlite3

_TABLE = "jobs"


def count_rows(conn: sqlite3.Connection, table: str) -> int:
    # a public function's parameter: any caller decides the table
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # expect: arbiter/python.sql-injection


def purge(conn: sqlite3.Connection, tables: list[str]) -> None:
    for table in tables:
        conn.execute(f"DELETE FROM {table}")  # expect: arbiter/python.sql-injection


def policy_name(table: str) -> str:
    return f"rls_{table}"


def drop_policy(conn: sqlite3.Connection, table: str) -> None:
    conn.execute(f"DROP POLICY {policy_name(table)} ON {_TABLE}")  # expect: arbiter/python.sql-injection


def _rename(conn: sqlite3.Connection, old: str, new: str) -> None:
    conn.execute(f'ALTER TABLE "{old}" RENAME TO "{new}"')  # expect: arbiter/python.sql-injection


def rename_from_request(conn: sqlite3.Connection, request) -> None:
    _rename(conn, "jobs", request.args["name"])


def find(conn: sqlite3.Connection, owner: str | None, name: str | None):
    conditions = ["deleted = 0"]
    params = []
    if owner is not None:
        conditions.append("owner = ?")
        params.append(owner)
    if name is not None:
        conditions.append(f"name = '{name}'")
    where = " AND ".join(conditions)
    return conn.execute(f"SELECT id FROM {_TABLE} WHERE {where}", params).fetchall()  # expect: arbiter/python.sql-injection


SORTABLE = {"id", "created_at"}


def page(conn: sqlite3.Connection, sort_by: str):
    if sort_by not in SORTABLE:
        print("unknown sort column", sort_by)
    return conn.execute(f"SELECT id FROM {_TABLE} ORDER BY {sort_by}").fetchall()  # expect: arbiter/python.sql-injection
