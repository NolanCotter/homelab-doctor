# Writing a check

Checks live in `internal/checks` and are invoked through `checks.Run`. Keep collection read-only: do not use commands that restart, clean, prune, alter permissions, or make an unrequested network request. Host commands must go through `execx.Runner`, allowing tests to use a fake runner.

Use a stable, namespaced ID such as `docker.restart_loop`. A check must return a `report.Finding` with profile, status, severity, evidence, explanation, and a safe remediation. Treat unavailable files, socket access, unsupported commands, and malformed output as `skipped` or clearly bounded evidence—not as a passing state. Redact any values copied from a command before placing them in a report.

Filesystem walks must have a strict entry limit and must not follow symlinks. Add a fixture under `internal/checks/testdata/fixtures` and a unit test covering success, failure, and malformed input where applicable.
