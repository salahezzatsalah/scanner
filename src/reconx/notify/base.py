"""Notification delivery.

The point of running continuously is being told when something changes. A new
subdomain on a wildcard program is worth knowing about within the hour, not at
the end of the week.

Notifications go to endpoints you configure. They carry target hostnames, URLs
and finding titles, so the channel you point them at should be one only you can
read.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum

import httpx

from reconx.config import Settings, get_settings

__all__ = ["Urgency", "Notification", "Notifier", "NotifierHub", "build_notifiers"]


class Urgency(StrEnum):
    INFO = "info"
    NOTABLE = "notable"
    URGENT = "urgent"

    @property
    def colour(self) -> int:
        """A colour for channels that support it."""
        return {"info": 0x3498DB, "notable": 0xF39C12, "urgent": 0xE74C3C}[self.value]

    @property
    def emoji(self) -> str:
        return {"info": "ℹ️", "notable": "⚠️", "urgent": "\U0001f6a8"}[
            self.value
        ]


@dataclass
class Notification:
    """One thing worth telling the researcher about."""

    title: str
    lines: list[str] = field(default_factory=list)
    urgency: Urgency = Urgency.INFO
    program: str = ""
    footer: str = ""

    def as_text(self) -> str:
        parts = [f"{self.urgency.emoji} {self.title}"]
        if self.program:
            parts.append(f"Program: {self.program}")
        parts.extend(self.lines)
        if self.footer:
            parts.append(self.footer)
        return "\n".join(parts)

    def as_markdown(self) -> str:
        parts = [f"{self.urgency.emoji} **{self.title}**"]
        if self.program:
            parts.append(f"_{self.program}_")
        parts.extend(self.lines)
        if self.footer:
            parts.append(f"\n{self.footer}")
        return "\n".join(parts)


class Notifier(ABC):
    """One delivery channel."""

    name: str = "notifier"

    def __init__(self, *, timeout: float = 15.0) -> None:
        self._timeout = timeout

    @property
    @abstractmethod
    def configured(self) -> bool:
        """True when this channel has what it needs to send."""

    @abstractmethod
    async def send(self, notification: Notification) -> None:
        """Deliver, or raise."""

    async def _post(self, url: str, *, json_body: dict) -> None:
        async with httpx.AsyncClient(timeout=self._timeout, trust_env=True) as client:
            response = await client.post(url, json=json_body)
            if response.status_code >= 400:
                raise RuntimeError(
                    f"{self.name} returned HTTP {response.status_code}: "
                    f"{response.text[:200]}"
                )


class NotifierHub:
    """Sends to every configured channel, and never lets delivery break a scan."""

    def __init__(self, notifiers: list[Notifier] | None = None) -> None:
        self._notifiers = [n for n in (notifiers or []) if n.configured]
        self.sent: int = 0
        self.failures: dict[str, str] = {}

    @property
    def channels(self) -> list[str]:
        return [notifier.name for notifier in self._notifiers]

    @property
    def enabled(self) -> bool:
        return bool(self._notifiers)

    async def broadcast(self, notification: Notification) -> dict[str, bool]:
        """Send to all channels. A failure is recorded, not raised.

        A monitoring run that dies because a webhook is down would be worse than
        a missed message: the scan results still matter.
        """
        results: dict[str, bool] = {}
        for notifier in self._notifiers:
            try:
                await notifier.send(notification)
                results[notifier.name] = True
                self.sent += 1
            except Exception as exc:
                results[notifier.name] = False
                self.failures[notifier.name] = f"{type(exc).__name__}: {exc}"
        return results


def build_notifiers(settings: Settings | None = None) -> NotifierHub:
    """Build the hub from configuration. Unconfigured channels are skipped."""
    resolved = settings or get_settings()
    from reconx.notify.discord import DiscordNotifier
    from reconx.notify.slack import SlackNotifier
    from reconx.notify.telegram import TelegramNotifier
    from reconx.notify.webhook import WebhookNotifier

    return NotifierHub(
        [
            DiscordNotifier(resolved.discord_webhook),
            SlackNotifier(resolved.slack_webhook),
            TelegramNotifier(resolved.telegram_bot_token, resolved.telegram_chat_id),
            WebhookNotifier(resolved.generic_webhook),
        ]
    )
