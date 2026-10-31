from __future__ import annotations

from pathlib import Path

import duckdb
import pytest

from logsift.loader import detect_delimiter, detect_header, load, sniff
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
