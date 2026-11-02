from __future__ import annotations

from pathlib import Path

import duckdb
import pytest

from logsift.loader import detect_delimiter, detect_header, load, load_more, sniff
from tests.conftest import write

SALES = 'name,qty,price\nbeans,3,7.50\n"tea, loose",12,4.20\nmug,1,16.00\n'


@pytest.mark.parametrize(
    ("delim", "name"),
    [(",", "comma"), ("\t", "tab"), (";", "semicolon"), ("|", "pipe"), (" ", "space")],
)
def test_detect_each_delimiter(tmp_path: Path, delim: str, name: str) -> None:
    text = "\n".join(delim.join(["a", "b", "c"]) for _ in range(5)) + "\n"
    text = delim.join(["x", "y", "z"]) + "\n" + text
    sn = sniff(write(tmp_path, "f.txt", text))
    assert sn.delimiter == delim
    assert sn.delimiter_name == name
    assert len(sn.columns) == 3


def test_quoted_fields_with_embedded_delimiter(tmp_path: Path) -> None:
    sn = sniff(write(tmp_path, "q.csv", SALES))
    assert sn.delimiter == ","
    assert sn.has_header
    assert sn.columns == ["name", "qty", "price"]
    con = duckdb.connect()
    res = load(con, tmp_path / "q.csv", sn)
    names = [r[0] for r in con.execute("SELECT name FROM raw ORDER BY name").fetchall()]
    assert "tea, loose" in names
    assert res.rows == 3


def test_space_delimited_text_with_spaces_prefers_comma() -> None:
    lines = ["city,country,notes", "New York,United States,big city", "Rome,Italy,old city"]
    delim, _ = detect_delimiter(lines)
    assert delim == ","


def test_bom_and_gzip(tmp_path: Path) -> None:
    plain = sniff(write(tmp_path, "bom.csv", SALES, bom=True))
    assert plain.bom and not plain.gzip
    assert plain.columns[0] == "name"
    gz = sniff(write(tmp_path, "data.csv.gz", SALES, gz=True))
    assert gz.gzip and not gz.bom
    con = duckdb.connect()
    res = load(con, tmp_path / "data.csv.gz", gz)
    assert res.rows == 3
    assert any("gzip" in n for n in res.notes)
    res2 = load(duckdb.connect(), tmp_path / "bom.csv", plain)
    assert any("byte order mark" in n for n in res2.notes)


def test_header_detection() -> None:
    assert detect_header([["name", "qty"], ["beans", "3"], ["tea", "12"]])
    assert not detect_header([["2", "123456789012", "eni-1"], ["2", "123456789012", "eni-2"]])
    assert detect_header([["@timestamp", "@message"], ["2026-01-01", "hello"]])
    # All-text file with a header-looking first row.
    assert detect_header([["city", "country"], ["Rome", "Italy"], ["Oslo", "Norway"]])


def test_ragged_lines_are_reported(tmp_path: Path) -> None:
    text = "a,b,c\n1,2,3\n4,5\n6,7,8,9\n10,11,12\n"
    path = write(tmp_path, "ragged.csv", text)
    con = duckdb.connect()
    res = load(con, path)
    # The short line is padded with NULL, the long line is rejected and reported.
    assert res.rows == 3
    assert res.rejected_lines == 1
    assert any("could not be parsed" in w for w in res.warnings)
    assert any("do not have 3 fields" in w for w in res.warnings)


def test_type_inference(tmp_path: Path) -> None:
    header = "i,f,d,ts,b,zip,mixed,text\n"
    rows = [
        f"{n},{n}.50,2025-01-{n % 28 + 1:02d},2025-01-01 10:{n % 60:02d}:00,"
        f"{'true' if n % 2 else 'false'},0{n:04d},{n},word{n}\n"
        for n in range(1, 401)
    ]
    rows[5] = "6,6.50,2025-01-07,2025-01-01 10:06:00,true,00006,oops,word6\n"
    path = write(tmp_path, "types.csv", header + "".join(rows))
    con = duckdb.connect()
    res = load(con, path)
    types = {c.name: c.sql_type for c in res.columns}
    assert types["i"] == "BIGINT"
    assert types["f"] == "DOUBLE"  # "6.50" must not become an integer
    assert types["d"] == "DATE"
    assert types["ts"] == "TIMESTAMP"  # a full timestamp must not collapse to a date
    assert types["b"] == "BOOLEAN"
    assert types["zip"] == "VARCHAR"  # leading zeros stay text
    assert types["mixed"] == "BIGINT"  # one bad value in 400 is tolerated and reported
    assert types["text"] == "VARCHAR"
    mixed = next(c for c in res.columns if c.name == "mixed")
    assert mixed.bad_values == 1
    assert any("Column mixed: 1 values" in w for w in res.warnings)


def test_mostly_text_column_stays_text(tmp_path: Path) -> None:
    text = "v\n" + "".join(f"{n}\n" if n % 2 else f"x{n}\n" for n in range(50))
    res = load(duckdb.connect(), write(tmp_path, "m.csv", text))
    assert res.columns[0].sql_type == "VARCHAR"
    assert res.columns[0].bad_values == 0


def test_no_header_names_columns(tmp_path: Path) -> None:
    res = load(duckdb.connect(), write(tmp_path, "nh.csv", "1,2,3\n4,5,6\n"))
    assert [c.name for c in res.columns] == ["column_1", "column_2", "column_3"]
    assert any("No header row" in n for n in res.notes)


def numbered(n: int, header: str = "n,word\n") -> str:
    return header + "".join(f"{i},w{i}\n" for i in range(n))


def test_small_chunks_keep_row_order_and_match_a_single_chunk(tmp_path: Path) -> None:
    text = numbered(5000)
    path = write(tmp_path, "many.csv", text)
    one = duckdb.connect()
    whole = load(one, path)
    many = duckdb.connect()
    seen: list[tuple[int, int]] = []
    res = load(many, path, chunk_bytes=4096, progress=lambda p: seen.append((p.rows, p.bytes_read)))
    assert res.rows == whole.rows == 5000
    assert [c.sql_type for c in res.columns] == [c.sql_type for c in whole.columns]
    assert res.complete and res.bytes_read == path.stat().st_size
    assert len(seen) > 5
    assert seen == sorted(seen) and seen[-1] == (5000, path.stat().st_size)
    order = [r[0] for r in many.execute("SELECT n FROM raw").fetchall()]
    assert order == list(range(5000))


def test_limit_stops_early_and_load_more_resumes(tmp_path: Path) -> None:
    from logsift.loader import load_more, sniff

    path = write(tmp_path, "limited.csv", numbered(3000))
    sn = sniff(path)
    con = duckdb.connect()
    res = load(con, path, sn, limit=1000, chunk_bytes=2048)
    assert res.rows == 1000 and not res.complete
    assert 0 < res.bytes_read < path.stat().st_size
    assert con.execute("SELECT max(n) FROM raw").fetchone() == (999,)
    load_more(con, path, sn, res, chunk_bytes=2048)
    assert res.rows == 3000 and res.complete
    assert res.bytes_read == path.stat().st_size
    assert [r[0] for r in con.execute("SELECT n FROM raw").fetchall()] == list(range(3000))
    # Resuming a complete load is a no-op.
    assert load_more(con, path, sn, res) is res and res.rows == 3000


def test_limit_on_the_last_row_is_complete(tmp_path: Path) -> None:
    path = write(tmp_path, "exact.csv", numbered(100))
    res = load(duckdb.connect(), path, limit=100)
    assert res.rows == 100 and res.complete


def test_gzip_loads_in_chunks_and_resumes(tmp_path: Path) -> None:
    from logsift.loader import load_more, sniff

    path = write(tmp_path, "many.csv.gz", numbered(4000), gz=True)
    sn = sniff(path)
    con = duckdb.connect()
    res = load(con, path, sn, limit=1500, chunk_bytes=8192)
    assert res.rows == 1500 and not res.complete
    assert res.bytes_read <= path.stat().st_size
    load_more(con, path, sn, res, chunk_bytes=8192)
    assert res.rows == 4000 and res.complete and res.bytes_read == path.stat().st_size
    assert [r[0] for r in con.execute("SELECT n FROM raw").fetchall()] == list(range(4000))


def test_quoted_newline_is_not_split_across_chunks(tmp_path: Path) -> None:
    rows = [f'{i},"line one\nline two {i}"\n' for i in range(400)]
    path = write(tmp_path, "multiline.csv", "n,text\n" + "".join(rows))
    con = duckdb.connect()
    res = load(con, path, chunk_bytes=1024)
    assert res.rows == 400 and res.rejected_lines == 0
    assert con.execute("SELECT text FROM raw WHERE n = 7").fetchone() == ("line one\nline two 7",)


def test_bad_values_and_rejects_add_up_across_chunks(tmp_path: Path) -> None:
    lines = ["n,v\n"]
    for i in range(2000):
        if i % 500 == 7:
            lines.append(f"{i},oops\n")  # not an integer
        elif i % 700 == 3:
            lines.append(f"{i},1,2,3\n")  # too many fields
        else:
            lines.append(f"{i},{i * 2}\n")
    path = write(tmp_path, "mixed.csv", "".join(lines))
    res = load(duckdb.connect(), path, chunk_bytes=2048)
    v = next(c for c in res.columns if c.name == "v")
    assert v.sql_type == "BIGINT" and v.bad_values == 4
    assert res.rejected_lines == 3
    assert res.rows == 2000 - 3
    assert any(w.startswith("3 lines could not be parsed") for w in res.warnings)
    assert any("Column v: 4 values" in w for w in res.warnings)
    assert res.reject_examples[0][0] == 5  # header is line 1, i=3 is line 5


def test_empty_file_and_header_only(tmp_path: Path) -> None:
    res = load(duckdb.connect(), write(tmp_path, "header.csv", "a,b\n"))
    assert res.rows == 0 and res.complete and [c.name for c in res.columns] == ["a", "b"]


def test_json_lines_load_as_one_text_column(tmp_path: Path) -> None:
    import json

    records = [
        {"query_name": "a.example.com.", "rcode": "NOERROR", "answers": [{"Rdata": "192.0.2.9"}]},
        {"query_name": "x.example.net.", "rcode": "NXDOMAIN", "answers": [], "note": 'say "hi"'},
        {"query_name": "y.example.net.", "rcode": "NOERROR", "answers": [{"Rdata": "a,b"}]},
    ]
    text = "".join(json.dumps(r) + "\n" for r in records)
    for gz in (False, True):
        path = write(tmp_path, "q.json.gz" if gz else "q.json", text * 40, gz=gz)
        sn = sniff(path)
        assert sn.json_lines and sn.columns == ["line"] and not sn.has_header
        assert sn.layout == "JSON lines" and sn.rows[0] == [json.dumps(records[0])]
        con = duckdb.connect()
        res = load(con, path, sn, chunk_bytes=256)
        assert res.rows == 120 and res.warnings == []
        assert [c.name for c in res.columns] == ["line"]
        got = con.execute(
            "SELECT count(*) FILTER (WHERE json_valid(line)), "
            "count(*) FILTER (WHERE line->>'$.rcode' = 'NXDOMAIN'), "
            "count(*) FILTER (WHERE line->>'$.note' = 'say \"hi\"') FROM raw"
        ).fetchone()
        assert got == (120, 40, 40)
        con.close()
    # A limit and a resume work the same way as for delimited files.
    con = duckdb.connect()
    res = load(con, path, sn, limit=50, chunk_bytes=256)
    assert res.rows == 50 and not res.complete
    load_more(con, path, sn, res, chunk_bytes=256)
    assert res.rows == 120 and res.complete
    con.close()


def test_json_lines_detection_is_strict(tmp_path: Path) -> None:
    assert not sniff(write(tmp_path, "a.csv", "a,b\n{x},2\n")).json_lines
    assert not sniff(write(tmp_path, "b.txt", "{not json}\n{still not}\n")).json_lines
    assert not sniff(write(tmp_path, "c.txt", "[1, 2]\n[3, 4]\n")).json_lines
    sn = sniff(write(tmp_path, "d.json", '{"a": 1}\n\n{"a": 2}\n'))
    assert sn.json_lines and sn.field_counts == {1: 2}
