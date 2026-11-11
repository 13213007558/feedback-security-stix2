# Feedback task starting environment

Upstream: https://github.com/oasis-open/cti-python-stix2
Upstream commit: `2270361774215de49717c1a6028a80c91075b400`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.
The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC UV_NO_CONFIG=1

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= stix2/test/v21/test_granular_markings.py stix2/test/v21/test_deterministic_ids.py
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-11): `114 passed in 0.15s`
Whole-command wall time: 1.427 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
