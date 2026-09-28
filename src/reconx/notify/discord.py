"""Discord webhook delivery."""

from __future__ import annotations

from reconx.notify.base import Notification, Notifier

__all__ = ["DiscordNotifier"]

_MAX_DESCRIPTION = 4000


class DiscordNotifier(Notifier):
    name = "discord"

    def __init__(self, webhook_url: str = "", **kwargs) -> None:
        super().__init__(**kwargs)
        self._url = webhook_url.strip()

    @property
    def configured(self) -> bool:
        return self._url.startswith("https://")

    async def send(self, notification: Notification) -> None:
        description = "\n".join(notification.lines)[:_MAX_DESCRIPTION]
        embed: dict = {
            "title": notification.title[:256],
            "description": description,
            "color": notification.urgency.colour,
        }
        if notification.program:
            embed["author"] = {"name": notification.program[:256]}
        if notification.footer:
            embed["footer"] = {"text": notification.footer[:2048]}

        await self._post(
            self._url,
            json_body={"username": "ReconX", "embeds": [embed]},
        )
