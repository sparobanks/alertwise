from aw.redact import contains_pii, redact


def test_masks_ip_user_email():
    users = ["aisha.khan"]
    text = "User aisha.khan from 45.155.1.9 emailed aisha.khan@corp.example"
    r = redact(text, users)
    assert "aisha.khan" not in r.masked
    assert "45.155.1.9" not in r.masked
    assert "aisha.khan@corp.example" not in r.masked
    assert "ADDR_1" in r.masked
    assert not contains_pii(r.masked, users)


def test_same_value_same_token():
    r = redact("45.155.1.9 and again 45.155.1.9", [])
    assert r.masked.count("ADDR_1") == 2


def test_restore_round_trips():
    users = ["ben.smith"]
    text = "ben.smith from 81.2.3.4"
    r = redact(text, users)
    assert r.restore(r.masked) == text


def test_contains_pii_detects_leak():
    assert contains_pii("talk to 10.0.0.5")
    assert not contains_pii("talk to ADDR_1")
