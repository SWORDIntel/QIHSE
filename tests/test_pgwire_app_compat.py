"""Source-backed pgwire application compatibility checks."""

import ast
import importlib.util
import os
import ssl
import sys
from datetime import datetime, timezone
from decimal import Decimal
from uuid import UUID
from pathlib import Path
from urllib.parse import urlsplit

from test_pgwire_client_fixture import pgwire_target

import pytest

SOURCE = Path(os.environ.get("DIRECTEYE_SOURCE", Path.home() / "DIRECTEYE"))
SERVICE = SOURCE / "services" / "postgres_service.py"

# Method and literal execute-call index from the real application source.
CORPUS = (
    ("get_osint_by_identifier", 0, ("id", "identifier")),
    ("get_auth_stats", 0, ("total_attempts", "successful", "failed", "unique_ips")),
    ("get_auth_stats", 1, ("ip_address", "attempts")),
)
MIGRATION = SOURCE / "migration/01_setup_postgresql.py"


def _migration_statements():
    """Preserve create_tables() source order, including its literal index loop."""
    try:
        tree = ast.parse(MIGRATION.read_text(encoding="utf-8"))
    except FileNotFoundError:
        pytest.fail(f"DIRECTEYE migration source missing: {MIGRATION}")
    function = next((node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name == "create_tables"), None)
    if function is None:
        pytest.fail("DIRECTEYE create_tables() migration missing")
    assignments = sorted((node for node in ast.walk(function)
                          if isinstance(node, ast.Assign)
                          and any(isinstance(target, ast.Name) and target.id == "indexes"
                                  for target in node.targets)), key=lambda node: node.lineno)
    statements = []
    for node in ast.walk(function):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "execute" and node.args):
            continue
        value = node.args[0]
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            statements.append((node.lineno, value.value))
        elif isinstance(value, ast.Name) and value.id == "idx":
            source = next((item.value for item in reversed(assignments)
                           if item.lineno < node.lineno), None)
            if not isinstance(source, (ast.List, ast.Tuple)) or not all(
                    isinstance(item, ast.Constant) and isinstance(item.value, str)
                    for item in source.elts):
                pytest.fail("DIRECTEYE migration index loop changed shape")
            statements.extend((node.lineno, item.value) for item in source.elts)
        else:
            pytest.fail(f"DIRECTEYE migration has dynamic SQL at line {node.lineno}")
    statements.sort(key=lambda item: item[0])
    if len(statements) < 10 or "CREATE EXTENSION" not in statements[0][1].upper():
        pytest.fail("DIRECTEYE migration ordering changed; review schema corpus")
    assert len(statements) == 26, "source migration statement count changed"
    return statements


def _statements(method):
    try:
        tree = ast.parse(SERVICE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        pytest.skip("DIRECTEYE application source unavailable: set DIRECTEYE_SOURCE")
    service = next((node for node in tree.body
                    if isinstance(node, ast.ClassDef) and node.name == "PostgresService"), None)
    if service is None:
        pytest.fail("DIRECTEYE PostgresService missing; refresh the source corpus")
    function = next((node for node in service.body
                     if isinstance(node, ast.FunctionDef) and node.name == method), None)
    if function is None:
        pytest.fail(f"DIRECTEYE method {method} missing; refresh the source corpus")
    return [node.args[0].value for node in ast.walk(function)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute" and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)]


@pytest.fixture(scope="module")
def corpus():
    result = []
    for method, index, columns in CORPUS:
        statements = _statements(method)
        assert len(statements) > index, f"{method}: literal SQL missing"
        sql = statements[index]
        assert sql.lstrip().upper().startswith("SELECT "), method
        assert ";" not in sql, method
        result.append((method, index, sql, columns))
    assert "FROM osint_records" in result[0][2]
    assert "WHERE identifier = %s" in result[0][2]
    assert "ORDER BY updated_at DESC" in result[0][2]
    assert "FROM auth_events" in result[1][2]
    assert "WHERE created_at > %s" in result[1][2]
    assert "FROM auth_events" in result[2][2]
    assert "HAVING COUNT(*) > 2" in result[2][2]
    return result


def _dsn():
    if os.environ.get("QIHSE_PGWIRE_APP_COMPAT_ISOLATED") != "1":
        pytest.skip("isolated disposable pgwire target not explicitly confirmed")
    dsn = os.environ.get("QIHSE_PGWIRE_APP_COMPAT_DSN")
    if not dsn:
        pytest.skip("QIHSE_PGWIRE_APP_COMPAT_DSN not set")
    parsed = urlsplit(dsn)
    if parsed.scheme not in ("postgresql", "postgres") or parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        pytest.fail("DSN must be a PostgreSQL URL on loopback (never a remote/live target)")
    if (not parsed.path.strip("/") or "/" in parsed.path.strip("/") or
            not parsed.username or not parsed.password or not parsed.port):
        pytest.fail("DSN requires explicit database, username, password and port")
    if parsed.query or parsed.fragment:
        pytest.fail("DSN query/fragment is forbidden; TLS settings come from the test fixture")
    ca = os.environ.get("QIHSE_PGWIRE_APP_COMPAT_CA")
    if not ca:
        pytest.skip("QIHSE_PGWIRE_APP_COMPAT_CA not set; verified TLS required")
    if not Path(ca).is_file():
        pytest.fail("QIHSE_PGWIRE_APP_COMPAT_CA must be an existing CA certificate")
    return dsn, ca


def _args(method):
    if method == "get_osint_by_identifier":
        return ("pgwire-app-compat-known",)
    from datetime import datetime
    return (datetime.now(),)


def _migrate_cursor(conn, driver):
    module = __import__(driver)
    with conn.cursor() as cur:
        for index, (line, ddl) in enumerate(_migration_statements(), 1):
            try:
                cur.execute(ddl)
            except module.Error as exc:
                code = exc.pgcode if driver == "psycopg2" else exc.sqlstate
                pytest.fail(f"ephemeral readiness probe, source migration step {index} at line {line}: "
                            f"SQLSTATE {code}: {exc.diag.message_primary}")
    conn.commit()


async def _migrate_async(conn):
    import asyncpg
    async with conn.transaction():
        for index, (line, ddl) in enumerate(_migration_statements(), 1):
            try:
                await conn.execute(ddl)
            except asyncpg.PostgresError as exc:
                pytest.fail(f"ephemeral readiness probe, source migration step {index} at line {line}: "
                            f"SQLSTATE {exc.sqlstate}: {exc.message}")


OSINT_ROWS = (
    ("pgwire-app-compat-known", datetime(2024, 1, 1, tzinfo=timezone.utc)),
    ("pgwire-app-compat-known", datetime(2025, 1, 1, tzinfo=timezone.utc)),
    ("other-identifier", datetime(2026, 1, 1, tzinfo=timezone.utc)),
)
OSINT_INSERT = ("INSERT INTO osint_records "
                "(source, record_type, identifier, data, updated_at) "
                "VALUES (%s, %s, %s, %s, %s)")


def _seed_cursor(conn, driver):
    if driver == "psycopg2":
        from psycopg2.extras import Json
    else:
        from psycopg.types.json import Jsonb as Json
    with conn.cursor() as cur:
        for identifier, updated_at in OSINT_ROWS:
            cur.execute(OSINT_INSERT, ("fixture", "synthetic", identifier,
                                       Json({"name": "fixture"}), updated_at))
    conn.commit()


async def _seed_async(conn):
    import json
    sql = OSINT_INSERT.replace("%s", "${}")
    sql = sql.format(*range(1, 6))
    for identifier, updated_at in OSINT_ROWS:
        await conn.execute(sql, "fixture", "synthetic", identifier,
                           json.dumps({"name": "fixture"}), updated_at)


@pytest.mark.parametrize("driver", ["psycopg2", "psycopg", "asyncpg"])
@pytest.mark.parametrize("case", CORPUS, ids=lambda case: f"{case[0]}[{case[1]}]")
def test_directeye_read_only_corpus(corpus, case, driver, pgwire_target):
    target = pgwire_target
    ca = target["ca"]
    method, index, sql, columns = corpus[CORPUS.index(case)]
    assert sql.count("%s") == 1, (method, index)
    label = f"{driver} {method}[{index}]"
    if importlib.util.find_spec(driver) is None:
        pytest.skip(f"{driver} driver not installed")
    if driver == "asyncpg":
        import asyncio
        import asyncpg

        async def probe():
            tls = ssl.create_default_context(cafile=ca)
            conn = await asyncpg.connect(host=target["host"], port=target["port"],
                                         user=target["user"], password=target["password"],
                                         database=target["database"], timeout=30, ssl=tls)
            try:
                await _migrate_async(conn)
                if method == "get_osint_by_identifier":
                    await _seed_async(conn)
                try:
                    statement = await conn.prepare(sql.replace("%s", "$1"))
                    names = {attr.name for attr in statement.get_attributes()}
                    assert set(columns).issubset(names), (label, names)
                    rows = await statement.fetch(*_args(method))
                except asyncpg.PostgresError as exc:
                    pytest.fail(f"{label}: SQLSTATE {exc.sqlstate}: {exc.message}")
                if method == "get_osint_by_identifier":
                    assert len(rows) == 1, label
                    assert rows[0]["identifier"] == "pgwire-app-compat-known", label
                    assert UUID(str(rows[0]["id"])), label
                    assert rows[0]["updated_at"].year == 2025, label
                elif index == 0:
                    assert len(rows) == 1, label
                    assert isinstance(rows[0]["total_attempts"], int), label
                else:
                    assert rows == [], label
            finally:
                if sys.exc_info()[0] is None:
                    await conn.close()
                else:
                    conn.terminate()

        asyncio.run(probe())
    else:
        module = __import__(driver)
        conn = module.connect(host=target["host"], port=target["port"],
                              user=target["user"], password=target["password"],
                              dbname=target["database"], connect_timeout=30,
                              sslmode="verify-full", sslrootcert=ca)
        try:
            _migrate_cursor(conn, driver)
            if method == "get_osint_by_identifier":
                _seed_cursor(conn, driver)
            with conn.cursor() as cur:
                try:
                    cur.execute(sql, _args(method))
                except module.Error as exc:
                    pytest.fail(f"{label}: SQLSTATE {exc.pgcode if driver == 'psycopg2' else exc.sqlstate}: {exc.diag.message_primary}")
                names = [field[0] for field in cur.description]
                assert set(columns).issubset(names), (label, names)
                rows = cur.fetchall()
                if method == "get_osint_by_identifier":
                    assert len(rows) == 1, label
                    assert rows[0][names.index("identifier")] == "pgwire-app-compat-known", label
                    assert UUID(str(rows[0][names.index("id")])), label
                    assert rows[0][names.index("updated_at")].year == 2025, label
                elif index == 0:
                    assert len(rows) == 1, label
                    assert isinstance(rows[0][names.index("total_attempts")], int), label
                else:
                    assert rows == [], label
        finally:
            try:
                if sys.exc_info()[0] is None:
                    conn.rollback()
            finally:
                conn.close()


@pytest.mark.parametrize("driver", ["psycopg2", "psycopg", "asyncpg"])
def test_low_clearance_cannot_read_high_data(driver, pgwire_target):
    if importlib.util.find_spec(driver) is None:
        pytest.skip(f"{driver} driver not installed")
    target = pgwire_target
    queries = ("SELECT * FROM protected_records",
               "SELECT * FROM protected_records WHERE id = 7",
               "SELECT note FROM protected_records WHERE id = 7")
    if driver == "asyncpg":
        import asyncio
        import asyncpg

        async def check():
            conn = await asyncpg.connect(host=target["host"], port=target["port"],
                                         user=target["guest"], password=target["password"],
                                         database=target["database"], timeout=30,
                                         ssl=ssl.create_default_context(cafile=target["ca"]))
            try:
                for sql in queries:
                    with pytest.raises(asyncpg.PostgresError) as error:
                        await conn.fetch(sql)
                    assert error.value.sqlstate == "42501", (error.value.sqlstate, str(error.value))
                    assert "DIRECTEYE-HIGH-SECRET-MARKER" not in str(error.value)
            finally:
                if sys.exc_info()[0] is None:
                    await conn.close()
                else:
                    conn.terminate()
        asyncio.run(check())
    else:
        module = __import__(driver)
        conn = module.connect(host=target["host"], port=target["port"],
                              user=target["guest"], password=target["password"],
                              dbname=target["database"], connect_timeout=30,
                              sslmode="verify-full", sslrootcert=target["ca"])
        conn.autocommit = True  # exercise ACL, not unsupported transactional SELECT
        try:
            for sql in queries:
                with conn.cursor() as cur:
                    with pytest.raises(module.Error) as error:
                        cur.execute(sql)
                    assert (error.value.pgcode if driver == "psycopg2" else error.value.sqlstate) == "42501"
                    assert "DIRECTEYE-HIGH-SECRET-MARKER" not in str(error.value)
                conn.rollback()
        finally:
            conn.close()


def test_indexed_high_data_stays_hidden_from_guest(pgwire_target):
    import psycopg2
    target = pgwire_target
    options = dict(host=target["host"], port=target["port"],
                   password=target["password"], dbname=target["database"],
                   connect_timeout=30, sslmode="verify-full", sslrootcert=target["ca"])
    owner = psycopg2.connect(**{**options, "user": target["user"]})
    owner.autocommit = True
    try:
        with owner.cursor() as cur:
            cur.execute("CREATE INDEX idx_protected_note ON protected_records(note)")
            cur.execute("SELECT note FROM protected_records WHERE note = %s",
                        ("DIRECTEYE-HIGH-SECRET-MARKER",))
            assert cur.fetchone()[0] == "DIRECTEYE-HIGH-SECRET-MARKER"
    finally:
        owner.close()
    guest = psycopg2.connect(**{**options, "user": target["guest"]})
    guest.autocommit = True
    try:
        with guest.cursor() as cur:
            for sql, args in (("SELECT note FROM protected_records WHERE note = %s",
                               ("DIRECTEYE-HIGH-SECRET-MARKER",)),
                              ("SELECT id, note FROM protected_records WHERE id = %s", (7,))):
                with pytest.raises(psycopg2.Error) as error:
                    cur.execute(sql, args)
                assert error.value.pgcode == "42501"
                assert "DIRECTEYE-HIGH-SECRET-MARKER" not in str(error.value)
    finally:
        guest.close()


def test_tls_identity_and_password_are_enforced(pgwire_target):
    psycopg2 = pytest.importorskip("psycopg2")
    target = pgwire_target
    options = dict(host=target["host"], hostaddr="127.0.0.1", port=target["port"],
                   user=target["user"], password=target["password"],
                   dbname=target["database"], connect_timeout=30,
                   sslmode="verify-full", sslrootcert=target["ca"])
    with pytest.raises(psycopg2.OperationalError, match="certificate"):
        psycopg2.connect(**{**options, "host": "wrong.example"})
    with pytest.raises(psycopg2.OperationalError) as error:
        psycopg2.connect(**{**options, "password": "wrong-password"})
    assert "password authentication failed" in str(error.value)


def test_directeye_migration_is_source_backed():
    statements = _migration_statements()
    assert len(statements) == 26
    assert "CREATE EXTENSION" in statements[0][1].upper()
    assert any("CREATE TABLE IF NOT EXISTS osint_records" in ddl for _, ddl in statements)
    assert any("CREATE TABLE IF NOT EXISTS auth_events" in ddl for _, ddl in statements)
    assert any("CREATE INDEX IF NOT EXISTS idx_osint_identifier" in ddl
               for _, ddl in statements)


def test_source_migration_rolls_back_as_one_transaction(pgwire_target):
    import psycopg2
    target = pgwire_target
    options = dict(host=target["host"], port=target["port"], user=target["user"],
                   password=target["password"], dbname=target["database"],
                   connect_timeout=30, sslmode="verify-full", sslrootcert=target["ca"])
    conn = psycopg2.connect(**options)
    try:
        with conn.cursor() as cur:
            statements = _migration_statements()
            for _, ddl in statements[:3]:
                cur.execute(ddl)
            with pytest.raises(psycopg2.Error):
                cur.execute("CREATE TABLE osint_records (this is not valid SQL)")
        conn.rollback()
    finally:
        conn.close()
    conn = psycopg2.connect(**options)
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema = 'public' ORDER BY table_name")
            names = {row[0] for row in cur.fetchall()}
            assert "osint_records" not in names
            assert "auth_events" not in names
    finally:
        conn.close()


def test_directeye_defaults_generated_numeric_trigger_view_and_indexes(pgwire_target):
    import psycopg2
    from psycopg2.extras import Json
    target = pgwire_target
    options = dict(host=target["host"], port=target["port"], user=target["user"],
                   password=target["password"], dbname=target["database"],
                   connect_timeout=30, sslmode="verify-full", sslrootcert=target["ca"])
    conn = psycopg2.connect(**options)
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema = 'public' ORDER BY table_name")
            names = {row[0] for row in cur.fetchall()}
            assert "osint_records" not in names and "auth_events" not in names
        conn.autocommit = False
        _migrate_cursor(conn, "psycopg2")
        with conn.cursor() as cur:
            cur.execute("INSERT INTO osint_records (source, record_type, identifier, data, updated_at) "
                        "VALUES (%s, %s, %s, %s, %s)",
                        ("fixture", "person", "indexed-person", Json({"name": "Original", "email": "first@example.com"}),
                         datetime(2020, 1, 1, tzinfo=timezone.utc)))
            cur.execute("INSERT INTO osint_records (source, record_type, identifier, data) "
                        "VALUES (%s, %s, %s, %s)",
                        ("fixture", "person", "indexed-person-2", Json({"name": "Other", "email": "first@example.com"})))
            cur.execute("SELECT id, search_vector, updated_at FROM osint_records "
                        "WHERE identifier = %s ORDER BY updated_at DESC LIMIT 1",
                        ("indexed-person",))
            first_id, first_vector, first_updated = cur.fetchone()
            assert UUID(str(first_id)).version == 4
            assert "origin" in str(first_vector).lower()
            assert first_updated.year == 2020
            cur.execute("SELECT id FROM osint_records WHERE identifier = %s",
                        ("indexed-person-2",))
            second_id = cur.fetchone()[0]
            assert UUID(str(second_id)).version == 4 and second_id != first_id
            cur.execute("UPDATE osint_records SET data = %s WHERE identifier = %s",
                        (Json({"name": "Changed", "email": "first@example.com"}), "indexed-person"))
            cur.execute("SELECT search_vector, updated_at FROM osint_records WHERE id = %s",
                        (first_id,))
            vector, updated = cur.fetchone()
            assert "chang" in str(vector).lower()
            assert "origin" not in str(vector).lower()
            assert updated > first_updated
            cur.execute("SELECT source, record_type, record_count FROM osint_stats "
                        "WHERE source = %s", ("fixture",))
            assert cur.fetchall() == []  # Materialized view is a snapshot, not a live SELECT.
            cur.execute("REFRESH MATERIALIZED VIEW osint_stats")
            cur.execute("SELECT record_count, unique_emails FROM osint_stats WHERE source = %s "
                        "AND record_type = %s", ("fixture", "person"))
            assert tuple(cur.fetchone()) == (2, 1)
            cur.execute("INSERT INTO osint_records (source, record_type, identifier, data) "
                        "VALUES (%s, %s, %s, %s)",
                        ("fixture", "person", "indexed-person-3", Json({"name": "Third", "email": "third@example.com"})))
            cur.execute("SELECT record_count, unique_emails FROM osint_stats WHERE source = %s "
                        "AND record_type = %s", ("fixture", "person"))
            assert tuple(cur.fetchone()) == (2, 1)
            cur.execute("REFRESH MATERIALIZED VIEW osint_stats")
            cur.execute("SELECT record_count, unique_emails FROM osint_stats WHERE source = %s "
                        "AND record_type = %s", ("fixture", "person"))
            assert tuple(cur.fetchone()) == (3, 2)
            cur.execute("INSERT INTO leakosint_queries (query, query_type, cost) "
                        "VALUES (%s, %s, %s)", ("test", "email", Decimal("0.1000")))
            cur.execute("SELECT cost FROM leakosint_queries WHERE query = %s", ("test",))
            assert cur.description[0].type_code == 1700
            cost = cur.fetchone()[0]
            assert isinstance(cost, Decimal) and cost.as_tuple().exponent == -4
            assert cost == Decimal("0.1000")
        conn.commit()
        conn.autocommit = True
        with conn.cursor() as cur:
            with pytest.raises(psycopg2.Error):
                cur.execute("UPDATE osint_records SET search_vector = 'override' "
                            "WHERE identifier = 'indexed-person'")
            for sql, args in (("INSERT INTO osint_records "
                               "(id, source, record_type, data) VALUES (%s, %s, %s, %s)",
                               (None, "fixture", "person", Json({"name": "null"}))),
                              ("INSERT INTO leakosint_queries (query, query_type, cost) "
                               "VALUES (%s, %s, %s)",
                               ("overflow", "email", Decimal("1000000.0000")))):
                with pytest.raises(psycopg2.Error):
                    cur.execute(sql, args)
    finally:
        conn.close()
    conn = psycopg2.connect(**options)
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT indexname FROM pg_indexes WHERE schemaname = 'public' "
                        "ORDER BY indexname")
            names = {row[0] for row in cur.fetchall()}
            assert {"idx_osint_identifier", "idx_osint_data_gin", "idx_osint_search",
                    "idx_osint_stats_source"}.issubset(names)
            cur.execute("SELECT id, search_vector FROM osint_records WHERE identifier = %s",
                        ("indexed-person",))
            row = cur.fetchone()
            assert str(row[0]) == str(first_id) and "chang" in str(row[1]).lower()
            cur.execute("SELECT id FROM osint_records WHERE data->>'email' = %s",
                        ("first@example.com",))
            assert {str(row[0]) for row in cur.fetchall()} == {str(first_id), str(second_id)}
            cur.execute("SELECT record_count, unique_emails FROM osint_stats WHERE source = %s "
                        "AND record_type = %s", ("fixture", "person"))
            assert tuple(cur.fetchone()) == (3, 2)
    finally:
        conn.close()


def test_source_materialized_view_starts_populated(pgwire_target):
    import psycopg2
    from psycopg2.extras import Json

    target = pgwire_target
    conn = psycopg2.connect(host=target["host"], port=target["port"],
                            user=target["user"], password=target["password"],
                            dbname=target["database"], connect_timeout=30,
                            sslmode="verify-full", sslrootcert=target["ca"])
    try:
        statements = _migration_statements()
        view_steps = [i for i, (_, ddl) in enumerate(statements)
                      if "CREATE MATERIALIZED VIEW" in ddl.upper()]
        assert len(view_steps) == 1
        view_step = view_steps[0]
        with conn.cursor() as cur:
            for _, ddl in statements[:view_step]:
                cur.execute(ddl)
        conn.commit()
        with conn.cursor() as cur:
            for identifier, email in (("view-one", "same@example.com"),
                                      ("view-two", "same@example.com")):
                cur.execute(OSINT_INSERT, ("fixture", "person", identifier,
                                          Json({"email": email}),
                                          datetime(2024, 1, 1, tzinfo=timezone.utc)))
        conn.commit()
        with conn.cursor() as cur:
            cur.execute(statements[view_step][1])  # Actual source SELECT, not a substitute.
        conn.commit()
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("SELECT record_count, unique_emails FROM osint_stats "
                        "WHERE source = %s AND record_type = %s", ("fixture", "person"))
            assert tuple(cur.fetchone()) == (2, 1)
            cur.execute(OSINT_INSERT, ("fixture", "person", "view-three",
                                      Json({"email": "new@example.com"}),
                                      datetime(2025, 1, 1, tzinfo=timezone.utc)))
            cur.execute("SELECT record_count, unique_emails FROM osint_stats "
                        "WHERE source = %s AND record_type = %s", ("fixture", "person"))
            assert tuple(cur.fetchone()) == (2, 1)
            cur.execute("REFRESH MATERIALIZED VIEW osint_stats")
            cur.execute("SELECT record_count, unique_emails FROM osint_stats "
                        "WHERE source = %s AND record_type = %s", ("fixture", "person"))
            assert tuple(cur.fetchone()) == (3, 2)
    finally:
        conn.close()


def test_directeye_creates_its_schema(pgwire_target):
    psycopg2 = pytest.importorskip("psycopg2")
    target = pgwire_target
    conn = psycopg2.connect(host=target["host"], port=target["port"],
                            user=target["user"], password=target["password"],
                            dbname=target["database"], connect_timeout=30,
                            sslmode="verify-full", sslrootcert=target["ca"])
    try:
        _migrate_cursor(conn, "psycopg2")
    finally:
        conn.close()


def test_authenticated_client_creates_bounded_table(pgwire_target):
    psycopg2 = pytest.importorskip("psycopg2")
    target = pgwire_target
    conn = psycopg2.connect(host=target["host"], port=target["port"],
                            user=target["user"], password=target["password"],
                            dbname=target["database"], connect_timeout=30,
                            sslmode="verify-full", sslrootcert=target["ca"])
    try:
        conn.autocommit = True  # Only the supported autocommit DDL subset.
        with conn.cursor() as cur:
            ddl = "CREATE TABLE IF NOT EXISTS fixture_created_by_client (id INT PRIMARY KEY, note TEXT)"
            cur.execute(ddl)
            cur.execute(ddl)
            cur.execute("SELECT id, note FROM fixture_created_by_client")
            assert cur.description[0].type_code == 23
            assert cur.fetchall() == []
    finally:
        conn.close()


def test_authenticated_client_transactional_schema_is_atomic(pgwire_target):
    psycopg2 = pytest.importorskip("psycopg2")
    target = pgwire_target
    conn = psycopg2.connect(host=target["host"], port=target["port"],
                            user=target["user"], password=target["password"],
                            dbname=target["database"], connect_timeout=30,
                            sslmode="verify-full", sslrootcert=target["ca"])
    catalog = ("SELECT table_name FROM information_schema.tables "
               "WHERE table_schema = 'public' ORDER BY table_name")
    try:
        with conn.cursor() as cur:
            cur.execute("CREATE TABLE txn_rolled_back (id INT PRIMARY KEY)")
        conn.rollback()
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(catalog)
            assert "txn_rolled_back" not in [row[0] for row in cur.fetchall()]
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute("CREATE TABLE txn_created_a (id INT PRIMARY KEY)")
            cur.execute("CREATE TABLE IF NOT EXISTS txn_created_a (id INT PRIMARY KEY)")
            cur.execute("CREATE TABLE txn_created_b (id BIGINT PRIMARY KEY)")
        conn.commit()
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(catalog)
            names = [row[0] for row in cur.fetchall()]
            assert "txn_created_a" in names and "txn_created_b" in names
            cur.execute("SELECT id FROM txn_created_b")
            assert cur.description[0].type_code == 20
            assert cur.fetchall() == []
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute("CREATE TABLE txn_refused (id INT)")
            with pytest.raises(psycopg2.Error) as refused:
                cur.execute("CREATE TABLE txn_unsupported (id INT CHECK (id > 0))")
            assert refused.value.pgcode == "0A000"
        conn.commit()  # PostgreSQL resolves an aborted transaction as ROLLBACK.
        with conn.cursor() as cur:
            cur.execute("CREATE TABLE txn_mixed (id INT)")
            with pytest.raises(psycopg2.Error) as refused:
                cur.execute("INSERT INTO txn_created_a VALUES (1)")
            assert refused.value.pgcode == "0A000"
        conn.rollback()
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(catalog)
            names = [row[0] for row in cur.fetchall()]
            assert "txn_refused" not in names and "txn_mixed" not in names
            cur.execute("SELECT id FROM txn_created_a")
            assert cur.fetchall() == []
    finally:
        conn.close()


def test_authenticated_catalog_lists_only_visible_committed_tables(pgwire_target):
    psycopg2 = pytest.importorskip("psycopg2")
    target = pgwire_target
    options = dict(host=target["host"], port=target["port"],
                   password=target["password"], dbname=target["database"],
                   connect_timeout=30, sslmode="verify-full", sslrootcert=target["ca"])
    sql = """SELECT table_name
             FROM information_schema.tables
             WHERE table_schema = 'public'
             ORDER BY table_name;"""
    index_sql = ("SELECT indexname FROM pg_indexes WHERE schemaname = 'public' "
                 "AND tablename = 'protected_records' ORDER BY indexname")
    owner = psycopg2.connect(**{**options, "user": target["user"]})
    owner.autocommit = True
    try:
        with owner.cursor() as cur:
            cur.execute("CREATE TABLE catalog_client_created (id INT PRIMARY KEY)")
            cur.execute("CREATE INDEX fixture_protected_idx ON protected_records(id)")
            cur.execute(index_sql)
            assert [row[0] for row in cur.fetchall()] == ["fixture_protected_idx"]
            cur.execute(sql)
            names = [row[0] for row in cur.fetchall()]
            assert names == sorted(names)
            assert "catalog_client_created" in names
            assert "protected_records" in names
            assert "osint_records" not in names
            with pytest.raises(psycopg2.Error) as refused:
                cur.execute("SELECT * FROM information_schema.tables")
            assert refused.value.pgcode == "0A000"
        owner.autocommit = False
        with owner.cursor() as cur:
            with pytest.raises(psycopg2.Error) as refused:
                cur.execute(sql)
            assert refused.value.pgcode == "0A000"
        owner.rollback()
        owner.close()  # The disposable listener serves one client at a time.
        guest = psycopg2.connect(**{**options, "user": target["guest"]})
        guest.autocommit = True
        try:
            with guest.cursor() as cur:
                cur.execute(sql)
                visible = [row[0] for row in cur.fetchall()]
                assert "protected_records" not in visible
                assert "catalog_client_created" not in visible
                assert "DIRECTEYE-HIGH-SECRET-MARKER" not in repr(visible)
                cur.execute(index_sql)
                assert cur.fetchall() == []
                cur.execute("SELECT indexname FROM pg_indexes WHERE schemaname = 'public' "
                            "ORDER BY indexname")
                assert cur.fetchall() == []
                with pytest.raises(psycopg2.Error) as refused:
                    cur.execute("SELECT * FROM pg_indexes")
                assert refused.value.pgcode == "0A000"
                assert "fixture_protected_idx" not in str(refused.value)
                assert "DIRECTEYE-HIGH-SECRET-MARKER" not in str(refused.value)
        finally:
            guest.close()
    finally:
        owner.close()


def test_directeye_corpus_is_source_backed(corpus):
    assert len(corpus) == len(CORPUS)
    assert [(method, index) for method, index, _, _ in corpus] == [
        (method, index) for method, index, _ in CORPUS]
