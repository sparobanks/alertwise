from pathlib import Path

from aw.parse import parse_file, parse_line

ROOT = Path(__file__).resolve().parents[1]


def test_parse_failed_password():
    line = ("Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for invalid user "
            "webmaster from 173.234.31.186 port 38926 ssh2")
    ev = parse_line(0, line)
    assert ev.kind == "fail"
    assert ev.user == "webmaster"
    assert ev.ip == "173.234.31.186"


def test_parse_accepted():
    line = "Jan 12 09:03:11 srv-app01 sshd[5123]: Accepted password for aisha.khan from 81.2.3.4 port 51000 ssh2"
    ev = parse_line(0, line)
    assert ev.kind == "accept"
    assert ev.user == "aisha.khan"
    assert ev.ip == "81.2.3.4"


def test_parse_real_sample_if_present():
    real = ROOT / "data" / "real" / "OpenSSH_2k.log"
    if not real.exists():
        return
    events = parse_file(real)
    assert len(events) > 100
    assert any(e.kind == "fail" for e in events)
    assert all(e.ip is None or e.ip.count(".") == 3 for e in events)
