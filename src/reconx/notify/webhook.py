"""Generic webhook delivery.

Posts the notification as structured JSON rather than formatted text, so it can
feed a dashboard, a ticket system, or anything else you already run.
"""

from __future__ import annotations

from reconx.notify.base import Notification, Notifier

__all__ = ["WebhookNotifier"]


class WebhookNotifier(Notifier):
    name = "webhook"

    def __init__(self, url: str = "", **kwargs) -> None:
        super().__init__(**kwargs)
        self._url = url.strip()

    @property
    def configured(self) -> bool:
        return self._url.startswith(("http://", "https://"))

    async def send(self, notification: Notification) -> None:
        await self._post(
            self._url,
            json_body={
                "source": "reconx",
                "title": notification.title,
                "program": notification.program,
                "urgency": notification.urgency.value,
                "lines": list(notification.lines),
                "footer": notification.footer,
                "text": notification.as_text(),
            },
        )
