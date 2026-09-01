# lib/error-guard.sh — standardized error handling ("try/catch/throw" + circuit
# breaker) for the evw security scripts. Source this file; it only defines
# functions and two tunables, it executes nothing.
#
#   try/catch : guard_run "<label>" <cmd> [args...]
#   throw     : guard_throw "<message>"        (logs + returns 1)
#
# Circuit breaker: each <label> has its own consecutive-failure counter, reset
# by any success of that label. When a label fails EVW_GUARD_MAX times in a row
# (default 10), the breaker trips and the user gets a choice:
#
#   [a]bort entire script  -> exit 1
#   [s]kip to next function -> counter resets, guard_run returns 99 and the
#                              script continues with the next statement
#
# Config (environment, may be set before or after sourcing):
#   EVW_GUARD_MAX     consecutive failures before the breaker trips (default 10)
#   EVW_GUARD_POLICY  ask | abort | continue
#                       unset    -> ask when stdin is a TTY, abort otherwise
#                       ask      -> always prompt (piped answers on stdin work;
#                                   EOF/empty answer means abort)
#                       abort    -> never prompt, exit 1 on trip
#                       continue -> never prompt, log + skip on trip (daemons)
#
# Return codes of guard_run: 0 = success, 99 = breaker tripped + skip chosen,
# anything else = the wrapped command's own exit status.
#
# Usage notes:
#   - Under `set -e`, call as:  guard_run "label" cmd || true
#     (the guard has already logged and counted the failure; `|| true` keeps
#     an ordinary failure from aborting the script — the breaker decides).
#   - Loop-based daemons:  guard_run "probe" probe || [ $? -eq 99 ] && continue
#   - This file is bash-3.2 compatible (macOS /bin/bash): no assoc arrays.

: "${EVW_GUARD_MAX:=10}"
: "${EVW_GUARD_POLICY:=}"

# Sanitize a label into a safe variable name for its counter.
_guard_var() {
    printf '_GUARD_N_%s' "$(printf '%s' "$1" | tr -c 'A-Za-z0-9_' '_')"
}

_guard_reset() {  # $1 = sanitized var
    eval "$1=0"
}

_guard_incr() {  # $1 = sanitized var; new value in $_GUARD_LAST (no subshell!)
    local _n
    eval "_n=\${$1:-0}"
    _n=$((_n + 1))
    eval "$1=$_n"
    _GUARD_LAST="$_n"
}

# Breaker tripped: decide abort vs skip. $1=label $2=var $3=command text
_guard_trip() {
    local _label="$1" _var="$2" _policy="$3" _ans

    if [ -z "$_policy" ]; then
        if [ -t 0 ]; then _policy="ask"; else _policy="abort"; fi
    fi

    case "$_policy" in
        ask)
            printf "error-guard: '%s' failed %s times in a row.\n" \
                "$_label" "${EVW_GUARD_MAX:-10}" >&2
            printf "  [a]bort entire script / [s]kip to next function? [a] " >&2
            read -r _ans
            case "$_ans" in
                s|S|skip)
                    printf "error-guard: skipping '%s'; continuing with next function.\n" "$_label" >&2
                    _guard_reset "$_var"
                    return 99
                    ;;
                *)
                    printf "error-guard: aborting on user choice.\n" >&2
                    exit 1
                    ;;
            esac
            ;;
        continue)
            printf "error-guard: '%s' failed %s times in a row; EVW_GUARD_POLICY=continue, skipping.\n" \
                "$_label" "${EVW_GUARD_MAX:-10}" >&2
            _guard_reset "$_var"
            return 99
            ;;
        *)
            printf "error-guard: '%s' failed %s times in a row; aborting (policy=%s).\n" \
                "$_label" "${EVW_GUARD_MAX:-10}" "${_policy:-abort}" >&2
            exit 1
            ;;
    esac
}

guard_run() {
    local _label="$1" _rc _var _n
    shift
    _var="$(_guard_var "$_label")"

    # `if` context: immune to the caller's `set -e`, so a failure is caught
    # here instead of killing the script before we can count it. The `else`
    # branch is required: only there does $? still hold the command's own
    # status (after a bare `fi` it would be the if-compound's 0).
    if "$@"; then
        _guard_reset "$_var"
        return 0
    else
        _rc=$?
    fi

    _guard_incr "$_var"
    _n="$_GUARD_LAST"
    printf "error-guard: [%s] '%s' failed (%s/%s, rc=%s): %s\n" \
        "$(date +%H:%M:%S 2>/dev/null)" "$_label" "$_n" "${EVW_GUARD_MAX:-10}" "$_rc" "$*" >&2

    if [ "$_n" -ge "${EVW_GUARD_MAX:-10}" ]; then
        _guard_trip "$_label" "$_var" "$EVW_GUARD_POLICY"
        return $?
    fi
    return "$_rc"
}

guard_throw() {
    printf 'error-guard: throw: %s (%s:%s)\n' \
        "$*" "${BASH_SOURCE[1]:-unknown}" "${BASH_LINENO[0]:-?}" >&2
    return 1
}
