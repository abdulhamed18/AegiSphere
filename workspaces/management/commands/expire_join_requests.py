"""
Expire pending organization join requests (Phase 3 – scheduled job).

Idempotent: safe to run multiple times or concurrently.
Calls expire_old_join_requests() and logs a system-level audit event.

Scheduled job (Option B – no Celery):
  Run daily at 00:00 via cron, e.g.:
    0 0 * * * cd /path/to/project && python manage.py expire_join_requests

If using Celery, register a periodic task that calls expire_old_join_requests() daily.
"""

import logging

from django.core.management.base import BaseCommand

from workspaces.audit import log_governance_action
from workspaces.join_governance_service import expire_old_join_requests
from workspaces.notifications import NotificationEvent


class Command(BaseCommand):
    help = "Expire pending organization join requests."

    def handle(self, *args, **options):
        count = expire_old_join_requests()
        try:
            log_governance_action(
                actor=None,
                workspace=None,
                action_type=NotificationEvent.SYSTEM_EXPIRE_JOIN_REQUESTS,
                metadata={"expired_count": count},
            )
        except Exception:
            logging.getLogger("aegisphere.audit").exception("audit_failed")
        self.stdout.write(self.style.SUCCESS(f"Expired {count} join request(s)."))
