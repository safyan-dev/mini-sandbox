"""Run the sandbox test suite.

Each test returns (name, ok, detail) tuples. Tests that mutate the sandbox are
run one at a time; nothing runs in parallel because they share one Docker VM.

    python3 -m tests
    python3 -m tests security
    python3 -m tests execution
"""

from __future__ import annotations

import sys

from . import execution_test, security_test
from .support import all_pass, checks_report

SECURITY = {
    "filesystem": security_test.filesystem,
    "execution": security_test.execution,
    "network": security_test.network,
    "memory": security_test.memory,
    "processes": security_test.processes,
    "cpu": security_test.cpu,
    "timeout": security_test.timeout,
}

EXECUTION = {
    "hello": execution_test.hello,
    "streams": execution_test.streams,
    "exit_codes": execution_test.exit_codes,
    "crash": execution_test.crash,
    "program_args": execution_test.program_args,
    "teardown": execution_test.teardown,
    "destroyed_on_failure": execution_test.destroyed_on_failure,
}

GROUPS = {"security": SECURITY, "execution": EXECUTION}


def main(argv: list | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv and argv[0] not in GROUPS:
        print("unknown group: %s" % argv[0])
        print("groups: %s" % ", ".join(GROUPS))
        return 2

    groups = [argv[0]] if argv else list(GROUPS)

    failures = 0
    for group in groups:
        print("\n== %s ==" % group)
        for name, test in GROUPS[group].items():
            try:
                results = test()
            except Exception as exc:
                results = [(name, False, "%s: %s" % (type(exc).__name__, exc))]

            ok = all_pass(results)
            print("\n  %s" % name)
            print(checks_report(results))
            if not ok:
                failures += 1

    print()
    if failures:
        print("%d test(s) failed" % failures)
        return 1
    print("all tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
