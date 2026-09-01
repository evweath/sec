"""error_guard — standardized error handling ("try/catch/throw" + circuit
breaker) for the evw security scripts. Import side-effect free.

    try/catch : guard_run("<label>", fn, *args, **kwargs)  or  @guarded("<label>")
    throw     : throw("<message>")   -> raises GuardError

Circuit breaker: each label has its own consecutive-failure counter, reset by
any success of that label. When a label fails EVW_GUARD_MAX times in a row
(default 10), the breaker trips and the user gets a choice:

    [a]bort entire script   -> SystemExit(1)
    [s]kip to next function -> counter resets, guard_run returns the SKIP
                               sentinel and the script continues

Config (environment, read at call time so scripts may set it programmatically):
    EVW_GUARD_MAX     consecutive failures before the breaker trips (default 10)
    EVW_GUARD_POLICY  ask | abort | continue
                        unset    -> ask when stdin is a TTY, abort otherwise
                        ask      -> always prompt (piped answers on stdin work;
                                    EOF/empty answer means abort)
                        abort    -> never prompt, SystemExit(1) on trip
                        continue -> never prompt, log + SKIP on trip (daemons)

Return values of guard_run: the wrapped function's result on success, None on
an ordinary (counted) failure, SKIP when the breaker tripped and skip was
chosen. SystemExit and KeyboardInterrupt raised by the wrapped function are
never swallowed.
"""

import functools
import os
import sys
import time


class GuardError(RuntimeError):
    """Uniform error type raised by throw() (the 'throw' half of try/throw)."""


class _Skip:
    def __repr__(self):
        return "SKIP"

    def __bool__(self):
        return False


SKIP = _Skip()

_fails = {}


def _max():
    try:
        return int(os.environ.get("EVW_GUARD_MAX", "10"))
    except (TypeError, ValueError):
        return 10


def _policy():
    policy = os.environ.get("EVW_GUARD_POLICY", "").strip().lower()
    if policy:
        return policy
    return "ask" if sys.stdin.isatty() else "abort"


def _trip(label, exc):
    policy = _policy()
    limit = _max()
    if policy == "ask":
        print(
            "error-guard: '%s' failed %d times in a row (last: %r)."
            % (label, limit, exc),
            file=sys.stderr,
        )
        try:
            ans = input(
                "  [a]bort entire script / [s]kip to next function? [a] "
            ).strip().lower()
        except EOFError:
            ans = ""
        if ans in ("s", "skip"):
            print(
                "error-guard: skipping '%s'; continuing with next function." % label,
                file=sys.stderr,
            )
            _fails[label] = 0
            return SKIP
        print("error-guard: aborting on user choice.", file=sys.stderr)
        raise SystemExit(1)
    if policy == "continue":
        print(
            "error-guard: '%s' failed %d times in a row; "
            "EVW_GUARD_POLICY=continue, skipping." % (label, limit),
            file=sys.stderr,
        )
        _fails[label] = 0
        return SKIP
    print(
        "error-guard: '%s' failed %d times in a row; aborting (policy=%s)."
        % (label, limit, policy),
        file=sys.stderr,
    )
    raise SystemExit(1)


def guard_run(label, fn, *args, **kwargs):
    """Run fn(*args, **kwargs) inside the try/catch + circuit breaker."""
    try:
        result = fn(*args, **kwargs)
    except (SystemExit, KeyboardInterrupt):
        raise
    except Exception as exc:  # noqa: BLE001 - the guard catches everything else
        limit = _max()
        n = _fails.get(label, 0) + 1
        _fails[label] = n
        print(
            "error-guard: [%s] '%s' failed (%d/%d): %r"
            % (time.strftime("%H:%M:%S"), label, n, limit, exc),
            file=sys.stderr,
        )
        if n >= limit:
            return _trip(label, exc)
        return None
    _fails[label] = 0
    return result


def guarded(label=None):
    """Decorator form of guard_run: @guarded('step-name') def step(...): ..."""

    def deco(fn):
        name = label or fn.__name__

        @functools.wraps(fn)
        def wrapper(*a, **kw):
            return guard_run(name, fn, *a, **kw)

        return wrapper

    return deco


def throw(msg):
    """The 'throw' analog: raise a GuardError with context."""
    raise GuardError(str(msg))


def reset(label=None):
    """Reset one label's counter, or all counters when label is None."""
    if label is None:
        _fails.clear()
    else:
        _fails.pop(label, None)
