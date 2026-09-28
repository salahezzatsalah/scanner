"""Telegram bot delivery."""

from __future__ import annotations

from reconx.notify.base import Notification, Notifier

__all__ = ["TelegramNotifier"]

_API = "https://api.telegram.org/bot{token}/sendMessage"
_MAX_MESSAGE = 4000


class TelegramNotifier(Notifier):
    name = "telegram"

    def __init__(self, bot_token: str = "", chat_id: str = "", **kwargs) -> None:
        super().__init__(**kwargs)
        self._token = bot_token.strip()
        self._chat_id = chat_id.strip()

    @property
    def configured(self) -> bool:
        return bool(self._token and self._chat_id)

    async def send(self, notification: Notification) -> None:
        await self._post(
            _API.format(token=self._token),
            json_body={
                "chat_id": self._chat_id,
                "text": notification.as_text()[:_MAX_MESSAGE],
                "disable_web_page_preview": True,
            },
        )
