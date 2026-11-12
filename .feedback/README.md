# Feedback task starting environment

Upstream: https://github.com/python-zeroconf/python-zeroconf
Upstream commit: `a8ed0a8b6fac3d0acd7aa037985a74e7a2d816ef`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.

The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC SKIP_CYTHON=1 UV_NO_CONFIG=1

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= -o asyncio_default_fixture_loop_scope=function tests/test_cache.py tests/services/test_registry.py
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-12): `45 passed in 1.38s`
Whole-command wall time: 1.746 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
