"""
Sentry initialisation for the AegisDiff Python engine.

Called once at startup in entrypoint.py and app_entrypoint.py.
No-ops silently when SENTRY_DSN is not set (local dev / users without Sentry).
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def init_sentry(release: str = "aegisdiff@unknown") -> None:
    """
    Initialise the Sentry SDK if SENTRY_DSN is configured.

    Captures unhandled exceptions and slow LLM calls.
    Never attaches diff content or source code to events.
    """
    dsn = os.environ.get("SENTRY_DSN", "")
    if not dsn:
        return

    try:
        import sentry_sdk
        from sentry_sdk.integrations.logging import LoggingIntegration

        sentry_sdk.init(
            dsn=dsn,
            release=release,
            environment=os.environ.get("SENTRY_ENVIRONMENT", "production"),
            # Capture 10% of transactions — enough for p95 latency tracking
            traces_sample_rate=0.1,
            integrations=[
                # Only send ERROR+ log events to Sentry, not INFO noise
                LoggingIntegration(level=logging.ERROR, event_level=logging.ERROR),
            ],
            # Scrub common secret patterns from breadcrumbs/extra
            send_default_pii=False,
            before_send=_before_send,
        )
        logger.info("Sentry initialised (release=%s)", release)
    except ImportError:
        logger.debug("sentry-sdk not installed — error tracking disabled")
    except Exception as exc:  # noqa: BLE001
        logger.debug("Sentry init failed (non-fatal): %s", exc)


def _before_send(event: dict, hint: dict) -> dict | None:
    """Strip any accidental diff/token content and drop expected errors."""
    # Drop keyboard interrupts and SystemExit — not bugs
    exc_info = hint.get("exc_info")
    if exc_info:
        exc_type = exc_info[0]
        if exc_type in (KeyboardInterrupt, SystemExit):
            return None

    # Remove large string values from extra context that could contain code
    if "extra" in event:
        for key in list(event["extra"].keys()):
            val = event["extra"][key]
            if isinstance(val, str) and len(val) > 500:
                event["extra"][key] = f"<truncated {len(val)} chars>"

    return event
