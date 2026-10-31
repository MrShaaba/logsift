from __future__ import annotations

import csv
from pathlib import Path

from logsift.formats import Format, canonical, detect_format
from logsift.loader import sniff
from tests.conftest import write


def test_sample_formats(samples: Path) -> None:
    expect = {
        "vpc_flow_logs_v2.log": Format.VPC_V2,
        "vpc_flow_logs_v2.log.gz": Format.VPC_V2,
        "vpc_flow_logs_custom_v5.log": Format.VPC_CUSTOM,
        "cloudwatch_insights_export.csv": Format.CW_INSIGHTS,
        "daily_sales.csv": Format.GENERIC,
        "alb_access_logs.log": Format.ALB,
        "nlb_access_logs.log": Format.NLB,
    }
    for name, kind in expect.items():
        info = detect_format(sniff(samples / name))
        assert info.kind == kind, name
        assert info.label
        assert info.reasons


def test_v2_maps_positional_columns(samples: Path) -> None:
    info = detect_format(sniff(samples / "vpc_flow_logs_v2.log"))
    assert info.flow_source == "columns"
    assert info.flow_columns["column_4"] == "srcaddr"
    assert info.flow_columns["column_14"] == "log_status"


def test_custom_header_maps_v5_fields(samples: Path) -> None:
    info = detect_format(sniff(samples / "vpc_flow_logs_custom_v5.log"))
    assert info.flow_columns["tcp-flags"] == "tcp_flags"
    assert info.flow_columns["pkt-srcaddr"] == "pkt_srcaddr"
    assert info.flow_columns["flow-direction"] == "flow_direction"
    assert info.flow_columns["traffic-path"] == "traffic_path"


def test_cloudwatch_message_source(samples: Path) -> None:
    info = detect_format(sniff(samples / "cloudwatch_insights_export.csv"))
    assert info.flow_source == "message"
    assert info.message_column == "@message"


def test_cloudwatch_parsed_columns_only(tmp_path: Path) -> None:
    text = "@timestamp,srcAddr,dstAddr,dstPort,action\n" + "".join(
        f"2026-03-10 08:0{i}:00.000,10.0.0.{i},10.0.1.{i},443,ACCEPT\n" for i in range(9)
    )
    info = detect_format(sniff(write(tmp_path, "cw.csv", text)))
    assert info.kind == Format.CW_INSIGHTS
    assert info.flow_source == "columns"
    assert info.flow_columns == {
        "srcAddr": "srcaddr",
        "dstAddr": "dstaddr",
        "dstPort": "dstport",
        "action": "action",
    }


def test_cloudwatch_without_flow_fields_is_not_a_flow_log(tmp_path: Path) -> None:
    text = "@timestamp,@message\n2026-03-10 08:00:00.000,hello world\n"
    info = detect_format(sniff(write(tmp_path, "cw.csv", text)))
    assert info.kind == Format.CW_INSIGHTS
    assert not info.is_flow_log


def test_tab_separated_custom_flow_log(tmp_path: Path) -> None:
    text = "srcaddr\tdstaddr\tdstport\taction\tbytes\n" + "".join(
        f"10.0.0.{i}\t10.0.1.{i}\t443\tACCEPT\t{i * 10}\n" for i in range(9)
    )
    info = detect_format(sniff(write(tmp_path, "fl.tsv", text)))
    assert info.kind == Format.VPC_CUSTOM


def test_generic_is_not_mistaken_for_flow_log(samples: Path) -> None:
    info = detect_format(sniff(samples / "daily_sales.csv"))
    assert not info.is_flow_log


def fields_of(line: str) -> list[str]:
    return next(csv.reader([line], delimiter=" "))


def join_fields(fields: list[str]) -> str:
    return " ".join(f'"{f}"' if " " in f or not f else f for f in fields)


def test_alb_maps_positional_columns(samples: Path) -> None:
    info = detect_format(sniff(samples / "alb_access_logs.log"))
    assert info.is_lb_log and not info.is_flow_log and info.has_rules
    assert info.lb_columns["column_1"] == "type"
    assert info.lb_columns["column_13"] == "request"
    assert info.lb_columns["column_30"] == "conn_trace_id"
    assert len(info.lb_columns) == 30


def test_nlb_maps_positional_columns(samples: Path) -> None:
    info = detect_format(sniff(samples / "nlb_access_logs.log"))
    assert info.lb_columns["column_12"] == "incoming_tls_alert"
    assert info.lb_columns["column_22"] == "tls_connection_creation_time"
    assert len(info.lb_columns) == 22


def test_older_alb_log_with_fewer_fields(samples: Path, tmp_path: Path) -> None:
    lines = (samples / "alb_access_logs.log").read_text().splitlines()[:20]
    older = [join_fields(fields_of(ln)[:25]) for ln in lines]
    info = detect_format(sniff(write(tmp_path, "old.log", "\n".join(older) + "\n")))
    assert info.kind == Format.ALB
    assert info.lb_columns["column_25"] == "error_reason"
    assert "conn_trace_id" not in info.lb_columns.values()


def test_newer_nlb_log_with_extra_fields(samples: Path, tmp_path: Path) -> None:
    lines = (samples / "nlb_access_logs.log").read_text().splitlines()[:20]
    newer = [ln + " future-field" for ln in lines]
    info = detect_format(sniff(write(tmp_path, "new.log", "\n".join(newer) + "\n")))
    assert info.kind == Format.NLB
    assert info.lb_columns["column_23"] == "extra_1"


def test_space_delimited_file_without_lb_shape_is_generic(tmp_path: Path) -> None:
    text = "".join(f"2026-03-10T08:00:0{i}Z host{i} 200 ok\n" for i in range(9))
    info = detect_format(sniff(write(tmp_path, "plain.log", text)))
    assert info.kind == Format.GENERIC


def test_canonical_names() -> None:
    assert canonical("interface-id") == "interface_id"
    assert canonical("interfaceId") == "interface_id"
    assert canonical("log_status") == "log_status"
    assert canonical("revenue") is None
