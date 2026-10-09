"""Finite exception-chain evidence for the authored transport recovery test."""

import json
import ssl
from functools import wraps

from bluefire.runner_lifecycle import RunnerLifecycleError
from bluefire.runner_transport_errors import RunnerAuthenticationError, RunnerConnectionError

CATEGORIES = (
    (RunnerLifecycleError, "RunnerLifecycleError"),
    (RunnerAuthenticationError, "RunnerAuthenticationError"),
    (RunnerConnectionError, "RunnerConnectionError"),
    (TimeoutError, "TimeoutError"),
    (ssl.SSLError, "SSLError"),
    (OSError, "OSError"),
)


def _summary(error):
    chain, seen = [], set()
    for _ in range(8):
        if not isinstance(error, BaseException) or id(error) in seen:
            break
        seen.add(id(error))
        category = next((label for kind, label in CATEGORIES if isinstance(error, kind)), "unknown")
        following = error.__cause__ if error.__cause__ is not None else error.__context__
        chain.append(
            {
                "category": category,
                "next": (
                    "cause"
                    if error.__cause__ is not None
                    else "context" if following is not None else "none"
                ),
                "context_suppressed": error.__suppress_context__ is True,
            }
        )
        error = following
    return {
        "fixture": "authenticated_transport_recovery",
        "exception_chain": chain,
        "chain_truncated_or_cycle": isinstance(error, BaseException),
    }


def _report(error):
    print("Transport recovery diagnostic: " + json.dumps(_summary(error), sort_keys=True))


def diagnose_transport_recovery(test):
    @wraps(test)
    def checked(*args, **kwargs):
        try:
            return test(*args, **kwargs)
        except BaseException as error:
            try:
                _report(error)
            except BaseException:
                pass
            raise

    return checked
