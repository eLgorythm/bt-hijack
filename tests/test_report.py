from bthj.cli import _parse_channel_range
from bthj.models import Report


def test_parse_channel_range():
    assert _parse_channel_range("1-3") == [1, 2, 3]
    assert _parse_channel_range("2,5") == [2, 5]
    assert _parse_channel_range("1-3,7") == [1, 2, 3, 7]
    assert _parse_channel_range("bogus") == []
    assert _parse_channel_range("") == []


def test_channel_range_clamps():
    r = _parse_channel_range("0-70")
    assert min(r) >= 1 and max(r) == 63


def test_report_events_timeline():
    report = Report(source="test", cmd="probe")
    report.add_event("info", "first", k=1)
    report.add_event("open", "second")
    d = report.to_dict()
    assert len(d["events"]) == 2
    assert d["events"][0]["t"] <= d["events"][1]["t"]
    assert d["events"][0]["k"] == 1
    assert d["events"][1]["level"] == "open"
    assert d["events"][1]["msg"] == "second"


def test_report_error_and_finished():
    report = Report(source="test", cmd="rfcomm")
    report.error = "boom"
    report.finished_at = report.started_at + 1.0
    d = report.to_dict()
    assert d["error"] == "boom"
    assert d["finished_at"] > d["started_at"]