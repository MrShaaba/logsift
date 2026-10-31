from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from logsift.dataset import Dataset

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"


@pytest.fixture(scope="session")
def samples() -> Path:
    return SAMPLES


@pytest.fixture(scope="session")
def flow_ds() -> Dataset:
    return Dataset.open(SAMPLES / "vpc_flow_logs_custom_v5.log")


@pytest.fixture(scope="session")
def v2_ds() -> Dataset:
    return Dataset.open(SAMPLES / "vpc_flow_logs_v2.log")


@pytest.fixture(scope="session")
def cw_ds() -> Dataset:
    return Dataset.open(SAMPLES / "cloudwatch_insights_export.csv")


@pytest.fixture(scope="session")
def sales_ds() -> Dataset:
    return Dataset.open(SAMPLES / "daily_sales.csv")


@pytest.fixture(scope="session")
def alb_ds() -> Dataset:
    return Dataset.open(SAMPLES / "alb_access_logs.log")


@pytest.fixture(scope="session")
def nlb_ds() -> Dataset:
    return Dataset.open(SAMPLES / "nlb_access_logs.log")


def write(tmp_path: Path, name: str, text: str, *, bom: bool = False, gz: bool = False) -> Path:
    data = text.encode("utf-8")
    if bom:
        data = b"\xef\xbb\xbf" + data
    path = tmp_path / name
    if gz:
        with gzip.open(path, "wb") as fh:
            fh.write(data)
    else:
        path.write_bytes(data)
    return path
