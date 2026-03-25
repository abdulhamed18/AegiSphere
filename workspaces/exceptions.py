"""
Custom exceptions for workspace join governance (Phase 3).
Callers can catch these for specific handling; do not use for general validation.
"""


class JoinGovernanceError(Exception):
    """Base for join/governance service errors."""

    pass


class PermissionDenied(JoinGovernanceError):
    """Actor does not have required permission for this action."""

    pass


class CooldownViolation(JoinGovernanceError):
    """Action blocked by cooldown (e.g. rejected request within 7 days, left org within 3 days)."""

    pass


class AlreadyMember(JoinGovernanceError):
    """User is already an active member of the workspace."""

    pass


class InviteInvalid(JoinGovernanceError):
    """Invite does not exist, is expired, already used, or user does not match."""

    pass


class RequestExpired(JoinGovernanceError):
    """Join request has expired."""

    pass
