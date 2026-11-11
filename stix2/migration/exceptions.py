"""Exceptions and issue records used by the STIX 2.0 -> 2.1 migration code."""

from ..exceptions import STIXError


class MigrationError(STIXError):
    """A STIX 2.0 object cannot be reliably migrated to STIX 2.1.

    This is raised for blocking conditions only: content that would have to
    be silently dropped or rewritten without an equivalent STIX 2.1
    representation.  When migration is run in non-strict mode, the same
    conditions are collected as :class:`MigrationIssue` objects instead.
    """


class MigrationIssue(object):
    """A record of content the migration could not handle automatically.

    Issues are never raised.  They describe a specific piece of input that
    needs a human decision, so callers can review the list instead of
    discovering lost data by diffing bundles.

    Attributes:
        code (str): Stable machine-readable category, e.g.
            ``"unknown-observable-type"``.
        message (str): Human-readable explanation.
        observed_data_id (str): ID of the observed-data the issue belongs to,
            if known.
        object_key (str): The numeric ``objects`` key of the SCO involved, if
            any.
        path (str): Property path inside the offending object, if any.
    """

    def __init__(self, code, message, observed_data_id=None, object_key=None,
                 path=None):
        self.code = code
        self.message = message
        self.observed_data_id = observed_data_id
        self.object_key = object_key
        self.path = path

    def __eq__(self, other):
        if not isinstance(other, MigrationIssue):
            return NotImplemented
        return (
            self.code == other.code
            and self.message == other.message
            and self.observed_data_id == other.observed_data_id
            and self.object_key == other.object_key
            and self.path == other.path
        )

    def __repr__(self):
        return (
            "MigrationIssue(code={0.code!r}, message={0.message!r}, "
            "observed_data_id={0.observed_data_id!r}, "
            "object_key={0.object_key!r}, path={0.path!r})".format(self)
        )

    def to_dict(self):
        return {
            "code": self.code,
            "message": self.message,
            "observed_data_id": self.observed_data_id,
            "object_key": self.object_key,
            "path": self.path,
        }
