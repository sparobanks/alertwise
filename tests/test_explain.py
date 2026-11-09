from aw.detect import Burst
from aw.explain import check_grounded, explain, facts_from


def _burst(**kw):
    base = dict(ip="45.155.1.9", country="RU", start_idx=0, end_idx=9, t_start="", t_end="",
                n_events=50, n_fail=48, n_accept=0, n_invalid=0, distinct_users=1,
                success_after_fail=0, max_fail_1min=30, span_seconds=600, external=1,
                users=["aisha.khan"], line_idxs=list(range(10)))
    base.update(kw)
    return Burst(**base)


def test_brute_force_explanation_has_action():
    ex = explain(_burst(), "brute_force")
    assert ex.severity == "medium"
    assert "action" in ex.technical.lower()
    assert ex.manager and ex.manager != ex.technical
    assert ex.grounded


def test_compromise_is_high_and_urgent():
    ex = explain(_burst(n_accept=1, success_after_fail=1), "account_compromise")
    assert ex.severity == "high"
    assert "urgent" in ex.manager.lower()


def test_grounding_rejects_invented_numbers():
    f = facts_from(_burst(), "brute_force")
    good = "There were 48 failed attempts over 10 minutes."
    bad = "There were 9999 failed attempts."
    assert check_grounded(good, f)
    assert not check_grounded(bad, f)


class FakeWriter:
    """A model that invents a number; the pipeline must reject it."""
    def write(self, f, audience):
        return "A massive 9999 attempts were seen."


def test_llm_output_rejected_when_not_grounded():
    ex = explain(_burst(), "brute_force", writer=FakeWriter())
    assert ex.source == "template"   # fell back because the model invented 9999
