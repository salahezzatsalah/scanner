"""Slack incoming-webhook delivery."""

from __future__ import annotations

from reconx.notify.base import Notification, Notifier

__all__ = ["SlackNotifier"]


class SlackNotifier(Notifier):
    name = "slack"

    def __init__(self, webhook_url: str = "", **kwargs) -> None:
        super().__init__(**kwargs)
        self._url = webhook_url.strip()

    @property
    def configured(self) -> bool:
        return self._url.startswith("https://")

    async def send(self, notification: Notification) -> None:
        blocks: list[dict] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{notification.urgency.emoji} {notification.title}"[:150],
                },
            }
        ]
        if notification.program:
            blocks.append(
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": f"*{notification.program}*"[:2000]}
                    ],
                }
            )
        body = "\n".join(notification.lines)
        if body:
            blocks.append(
                {"type": "section", "text": {"type": "mrkdwn", "text": body[:2900]}}
            )
        if notification.footer:
            blocks.append(
                {
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": notification.footer[:2000]}],
                }
            )

        await self._post(
            self._url,
            json_body={"text": notification.as_text()[:3000], "blocks": blocks},
        )
