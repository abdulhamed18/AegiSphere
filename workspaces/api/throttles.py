"""
Custom throttles for join governance API.
"""

from rest_framework.throttling import UserRateThrottle


class JoinRequestThrottle(UserRateThrottle):
    scope = "join"


class InviteThrottle(UserRateThrottle):
    scope = "invite"
