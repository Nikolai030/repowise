import pytest

from repowise.core.analysis.security.calls import _call_findings


def scan(code):
    return _call_findings("example.py", code, lambda: code)


def test_direct_eval_is_reported():
    assert any(finding["kind"] == "eval_call" for finding in scan("eval(user_input)"))


def test_object_eval_is_not_reported():
    assert scan("model.eval()") == []


def test_builtins_eval_is_reported():
    assert any(finding["kind"] == "eval_call" for finding in scan("builtins.eval(user_input)"))


def test_direct_exec_is_reported():
    assert any(finding["kind"] == "exec_call" for finding in scan("exec(code)"))


def test_chained_model_eval_is_not_reported():
    assert scan("model = Net().to(device).eval()") == []


def test_object_exec_still_reported():
    assert any(finding["kind"] == "exec_call" for finding in scan("obj.exec(command)"))


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("eval(user_input", ["eval_call"]),
        ("builtins.eval(user_input", ["eval_call"]),
        ("model.eval(", []),
        ("net.to(device).eval(", []),
        ("other.builtins.eval(", []),
        ("model . eval(", []),
    ],
)
def test_eval_lexical_fallback(code, expected):
    assert [f["kind"] for f in scan(code)] == expected
