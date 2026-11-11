"""Migration helpers for converting STIX 2.0 content to STIX 2.1.

The first migration path targets STIX 2.0 observed-data objects, whose
embedded ``objects`` mapping of cyber observables (linked by numeric string
keys) becomes a set of standalone STIX 2.1 SCOs plus an observed-data that
references them through ``object_refs``.

Public entry points:

* :func:`migrate_observed_data` -- migrate one observed-data object.
* :func:`migrate_bundle` -- migrate every observed-data (and its markings)
  in a STIX 2.0 bundle.
* :class:`MigrationResult` -- migrated objects plus any issues that need
  human review.
* :class:`MigrationError` / :class:`MigrationIssue` -- error and report
  types.
"""

from .core import (
    MigrationResult, migrate_bundle, migrate_observed_data,
)
from .exceptions import MigrationError, MigrationIssue

__all__ = [
    "MigrationError",
    "MigrationIssue",
    "MigrationResult",
    "migrate_bundle",
    "migrate_observed_data",
]
