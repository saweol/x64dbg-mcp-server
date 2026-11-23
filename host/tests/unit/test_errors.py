"""Public error codes (errors.py): shared InvalidArgument, BackendThrottled, uniqueness."""

from __future__ import annotations

import inspect

from x64dbg_vm_gateway import app, errors
from x64dbg_vm_gateway.errors import BackendError, BackendThrottled, GatewayError, InvalidArgument


def _error_classes() -> list[type[GatewayError]]:
    return [c for _, c in inspect.getmembers(errors, inspect.isclass)
            if issubclass(c, GatewayError) and c.__module__ == errors.__name__]


def test_invalid_argument_is_shared_with_the_orchestrator():
    assert InvalidArgument.code == "INVALID_ARGUMENT"
    assert app.InvalidArgument is InvalidArgument  # the old import path keeps working
    assert issubclass(InvalidArgument, GatewayError) and InvalidArgument.retryable is False


def test_backend_throttled_is_a_retryable_backend_error_with_retry_after():
    e = BackendThrottled("locked out", retry_after_s=42)
    assert isinstance(e, BackendError)
    assert e.code == "BACKEND_THROTTLED" and e.retryable is True
    assert e.details["retry_after_s"] == 42
    assert e.to_dict()["details"]["retry_after_s"] == 42


def test_backend_throttled_without_retry_after_says_so():
    e = BackendThrottled("locked out", details={"backend": "x64"})
    assert e.details == {"backend": "x64", "retry_after_s": None}


def test_backend_throttled_keeps_an_explicit_detail():
    e = BackendThrottled("x", details={"retry_after_s": 5}, retry_after_s=None)
    assert e.details["retry_after_s"] == 5


def test_error_codes_are_unique():
    codes = [c.code for c in _error_classes()]
    assert len(codes) == len(set(codes)), sorted(c for c in codes if codes.count(c) > 1)
