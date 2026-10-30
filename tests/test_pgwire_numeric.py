"""Exact NUMERIC predicates through authenticated, verified-TLS real clients."""
import asyncio
import ssl
from decimal import Decimal

import pytest

from test_pgwire_client_fixture import pgwire_target


VALUES = [(1, Decimal("0")), (2, Decimal("-2.50")),
          (3, Decimal("90071992547409931234567890.12")),
          (4, Decimal("90071992547409931234567890.13")), (5, None)]


def _options(target):
    return dict(host=target["host"], port=target["port"],
                user=target["user"], password=target["password"],
                dbname=target["database"], sslmode="verify-full",
                sslrootcert=target["ca"], connect_timeout=30)


@pytest.mark.parametrize("driver", ["psycopg2", "psycopg"])
def test_numeric_text_and_binary_clients(pgwire_target, driver):
    module = pytest.importorskip(driver)
    conn = module.connect(**_options(pgwire_target))
    conn.autocommit = True
    # psycopg3 %b explicitly exercises binary parameter decoding; psycopg2 uses text.
    placeholder = "%b" if driver == "psycopg" else "%s"
    try:
        with conn.cursor() as cur:
            cur.execute("CREATE TABLE numeric_zero (id INT, amount NUMERIC(10,0))")
            for i, value in enumerate(["0", "-0", "+000"]):
                cur.execute(f"INSERT INTO numeric_zero VALUES ({i}, '{value}')")
            cur.execute(f"INSERT INTO numeric_zero VALUES (3, {placeholder})", (Decimal("0"),))
            cur.execute("CREATE TABLE numeric_fraction (id INT, amount NUMERIC(4,4))")
            cur.execute("INSERT INTO numeric_fraction VALUES (1, '0.9999')")
            cur.execute(f"INSERT INTO numeric_fraction VALUES (2, {placeholder})", (Decimal("0.0000"),))
            cur.execute("SELECT amount FROM numeric_fraction WHERE id = 2")
            assert cur.fetchone() == (Decimal("0.0000"),)
            with pytest.raises(module.Error):
                cur.execute("INSERT INTO numeric_fraction VALUES (3, '1.0000')")
            cur.execute("CREATE INDEX numeric_zero_idx ON numeric_zero(amount)")
            cur.execute(f"SELECT id FROM numeric_zero WHERE amount = {placeholder}", (Decimal("-0"),))
            assert {row[0] for row in cur.fetchall()} == {0, 1, 2, 3}
            for indexed in [False, True]:
                table = "numeric_indexed" if indexed else "numeric_plain"
                cur.execute(f"CREATE TABLE {table} (id INT, amount NUMERIC(38,2))")
                for row in VALUES:
                    cur.execute(f"INSERT INTO {table} VALUES (%s, {placeholder})", row)
                if indexed:
                    cur.execute(f"CREATE INDEX {table}_idx ON {table}(amount)")
                for operator, value, expected in [
                    ("=", Decimal("-0.000"), {1}),
                    ("=", Decimal("0.001"), set()),
                    ("=", Decimal("9999999999999999999999999999999999999999"), set()),
                    (">", VALUES[2][1], {4}),
                    (">=", VALUES[3][1], {4}),
                    ("<", Decimal("-2.49"), {2}),
                    ("<=", Decimal("-2.50"), {2}),
                    ("!=", Decimal("0"), {2, 3, 4}),
                    ("=", None, set()),
                ]:
                    cur.execute(f"SELECT id FROM {table} WHERE amount {operator} {placeholder}", (value,))
                    assert {row[0] for row in cur.fetchall()} == expected
                cur.execute(f"UPDATE {table} SET amount = {placeholder} WHERE amount = {placeholder}",
                            (Decimal("1.25"), Decimal("0")))
                assert cur.rowcount == 1
                cur.execute(f"DELETE FROM {table} WHERE amount < {placeholder}", (Decimal("0"),))
                assert cur.rowcount == 1
                cur.execute(f"SELECT amount FROM {table} WHERE id = 1")
                assert cur.fetchone() == (Decimal("1.25"),)
    finally:
        conn.close()


def test_numeric_asyncpg_binary(pgwire_target):
    asyncpg = pytest.importorskip("asyncpg")
    target = pgwire_target

    async def probe():
        context = ssl.create_default_context(cafile=target["ca"])
        conn = await asyncpg.connect(host=target["host"], port=target["port"],
                                     user=target["user"], password=target["password"],
                                     database=target["database"], ssl=context, timeout=30)
        try:
            await conn.execute("CREATE TABLE numeric_zero_binary (id INT, amount NUMERIC(10,0))")
            await conn.execute("INSERT INTO numeric_zero_binary VALUES ($1, $2)", 1, Decimal("0"))
            await conn.execute("CREATE INDEX numeric_zero_binary_idx ON numeric_zero_binary(amount)")
            rows = await conn.fetch("SELECT id FROM numeric_zero_binary WHERE amount = $1", Decimal("-0"))
            assert [row["id"] for row in rows] == [1]
            for indexed in [False, True]:
                table = "numeric_binary_indexed" if indexed else "numeric_binary_plain"
                await conn.execute(f"CREATE TABLE {table} (id INT, amount NUMERIC(38,2))")
                for row in VALUES:
                    await conn.execute(f"INSERT INTO {table} VALUES ($1, $2)", *row)
                if indexed:
                    await conn.execute(f"CREATE INDEX {table}_idx ON {table}(amount)")
                for operator, value, expected in [
                    ("=", Decimal("-0.000"), {1}),
                    ("=", Decimal("0.001"), set()),
                    ("=", Decimal("9999999999999999999999999999999999999999"), set()),
                    (">", VALUES[2][1], {4}),
                    ("<", Decimal("-2.49"), {2}),
                    ("!=", Decimal("0"), {2, 3, 4}),
                    ("=", None, set()),
                ]:
                    rows = await conn.fetch(f"SELECT id FROM {table} WHERE amount {operator} $1", value)
                    assert {row["id"] for row in rows} == expected
                assert await conn.execute(f"UPDATE {table} SET amount = $1 WHERE amount = $2",
                                          Decimal("1.25"), Decimal("0")) == "UPDATE 1"
                assert await conn.execute(f"DELETE FROM {table} WHERE amount < $1", Decimal("0")) == "DELETE 1"
                rows = await conn.fetch(f"SELECT amount FROM {table} WHERE id = 1")
                assert [row["amount"] for row in rows] == [Decimal("1.25")]
        finally:
            await conn.close()

    asyncio.run(probe())


def test_malformed_numeric_binary_is_refused(pgwire_target):
    import struct
    psycopg = pytest.importorskip("psycopg")
    from psycopg.adapt import Dumper
    from psycopg.pq import Format

    class BinaryNumeric(bytes):
        pass

    class NumericDumper(Dumper):
        oid = 1700
        format = Format.BINARY

        def dump(self, value):
            return bytes(value)

    vectors = [
        b"", struct.pack("!hhhh", 1, 0, 0, 0),
        struct.pack("!hhhhH", 1, 0, 0, 0, 10000),
        struct.pack("!hhHhH", 1, 0, 0xC000, 0, 0),
        struct.pack("!hhhhH", 1, 0, 1, 0, 1),
        struct.pack("!hhhhH", 1, -1, 0, 0, 1),
        struct.pack("!hhhhH", 1, -1, 0, 1, 1),
        struct.pack("!hhhhH", 1, 32767, 0, 0, 1),
        struct.pack("!hhhhH", 1, 0, 0, 16384, 1),
        struct.pack("!hhhhH", 2, 0, 0, 0, 1),
    ]
    with psycopg.connect(**_options(pgwire_target), autocommit=True) as conn:
        conn.adapters.register_dumper(BinaryNumeric, NumericDumper)
        with conn.cursor() as cur:
            cur.execute("CREATE TABLE numeric_malformed (id INT, amount NUMERIC(38,2))")
            cur.execute("INSERT INTO numeric_malformed VALUES (1, '1.25')")
            for vector in vectors:
                with pytest.raises(psycopg.Error) as error:
                    cur.execute("SELECT id FROM numeric_malformed WHERE amount = %b",
                                (BinaryNumeric(vector),))
                assert error.value.sqlstate in {"0A000", "22P03"}
                cur.execute("SELECT amount FROM numeric_malformed WHERE id = 1")
                assert cur.fetchall() == [(Decimal("1.25"),)]
            valid = struct.pack("!hhhhHH", 2, 0, 0, 2, 1, 2500)
            cur.execute("SELECT id FROM numeric_malformed WHERE amount = %b", (BinaryNumeric(valid),))
            assert cur.fetchall() == [(1,)]
