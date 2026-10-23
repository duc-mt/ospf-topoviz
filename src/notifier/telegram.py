"""Production-grade Telegram notification dispatcher."""

from __future__ import annotations

import hashlib
import html
import io
import json
import logging
import mimetypes
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.notifier.base import BaseNotifier

logger = logging.getLogger("ospf_tracker.notifier.telegram")

SEVERITY_LEVELS = {"info": 0, "warning": 1, "critical": 2}
SEVERITY_ICONS = {
    "info": "🟢 [INFO]",
    "warning": "🟡 [WARNING]",
    "critical": "🔴 [CRITICAL]",
}


@dataclass
class TelegramConfig:
    """Telegram configuration parameters."""

    enabled: bool = False
    bot_token: str = ""
    chat_id: str | int = ""
    thread_id: int | None = None
    min_severity: str = "warning"
    cooldown_seconds: int = 300
    silent: bool = False
    send_image: bool = True
    proxy: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> TelegramConfig:
        """Create configuration from dictionary with environment variable fallback."""
        data = data or {}

        def _env_or_val(env_key: str, val: Any, default: Any = None) -> Any:
            env_val = os.getenv(env_key)
            if env_val is not None:
                return env_val
            if val is not None:
                return val
            return default

        enabled_raw = _env_or_val("TELEGRAM_ENABLED", data.get("enabled"), False)
        if isinstance(enabled_raw, str):
            enabled = enabled_raw.strip().lower() in ("true", "1", "yes", "on")
        else:
            enabled = bool(enabled_raw)

        bot_token = str(
            _env_or_val("TELEGRAM_BOT_TOKEN", data.get("bot_token"), "")
        ).strip()
        chat_id_val = _env_or_val("TELEGRAM_CHAT_ID", data.get("chat_id"), "")
        chat_id = str(chat_id_val).strip() if chat_id_val != "" else ""

        thread_id_val = _env_or_val(
            "TELEGRAM_MESSAGE_THREAD_ID", data.get("thread_id")
        )
        thread_id: int | None = None
        if thread_id_val is not None and str(thread_id_val).strip() != "":
            try:
                thread_id = int(thread_id_val)
            except ValueError:
                logger.warning(
                    "Invalid Telegram thread_id '%s'; ignoring", thread_id_val
                )

        min_severity = str(
            _env_or_val("TELEGRAM_MIN_SEVERITY", data.get("min_severity"), "warning")
        ).lower()
        if min_severity not in SEVERITY_LEVELS:
            min_severity = "warning"

        cooldown_raw = _env_or_val(
            "TELEGRAM_COOLDOWN_SECONDS", data.get("cooldown_seconds"), 300
        )
        try:
            cooldown_seconds = int(cooldown_raw)
        except ValueError:
            cooldown_seconds = 300

        silent_raw = _env_or_val("TELEGRAM_SILENT", data.get("silent"), False)
        silent = (
            silent_raw.strip().lower() in ("true", "1", "yes", "on")
            if isinstance(silent_raw, str)
            else bool(silent_raw)
        )

        send_image_raw = _env_or_val(
            "TELEGRAM_SEND_IMAGE", data.get("send_image"), True
        )
        send_image = (
            send_image_raw.strip().lower() in ("true", "1", "yes", "on")
            if isinstance(send_image_raw, str)
            else bool(send_image_raw)
        )

        proxy_val = _env_or_val("TELEGRAM_PROXY_URL", data.get("proxy"))
        proxy = str(proxy_val).strip() if proxy_val else None

        return cls(
            enabled=enabled,
            bot_token=bot_token,
            chat_id=chat_id,
            thread_id=thread_id,
            min_severity=min_severity,
            cooldown_seconds=cooldown_seconds,
            silent=silent,
            send_image=send_image,
            proxy=proxy,
        )


class TelegramNotifier(BaseNotifier):
    """Non-blocking, resilient Telegram notification client."""

    def __init__(self, config: TelegramConfig | None = None) -> None:
        self.config = config or TelegramConfig()
        self._cooldown_cache: dict[str, float] = {}

    def _mask_token(self, token: str) -> str:
        if not token:
            return ""
        if len(token) <= 8:
            return "***"
        return f"{token[:4]}...{token[-4:]}"

    def _is_rate_limited(self, level: str, title: str) -> bool:
        if self.config.cooldown_seconds <= 0:
            return False
        fingerprint = hashlib.md5(f"{level}:{title}".encode()).hexdigest()
        now = time.time()
        last_sent = self._cooldown_cache.get(fingerprint)
        if last_sent and (now - last_sent) < self.config.cooldown_seconds:
            return True
        self._cooldown_cache[fingerprint] = now
        # Periodic cleanup of old cache entries
        if len(self._cooldown_cache) > 256:
            expiry = now - self.config.cooldown_seconds
            self._cooldown_cache = {
                k: v for k, v in self._cooldown_cache.items() if v >= expiry
            }
        return False

    def _build_html_text(
        self,
        title: str,
        message: str,
        level: str,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        icon = SEVERITY_ICONS.get(level.lower(), "ℹ️ [EVENT]")
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        target = "N/A"
        footer = None
        if metadata:
            if "target" in metadata:
                target = str(metadata["target"])
            elif "device" in metadata:
                target = str(metadata["device"])
            elif "router" in metadata:
                target = str(metadata["router"])
            footer = metadata.get("footer") or metadata.get("hint")

        lines = [
            f"<b>{icon} {html.escape(title)}</b>",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━",
            f"• <b>Time:</b> {html.escape(now_str)}",
            f"• <b>Target:</b> <code>{html.escape(target)}</code>",
            f"• <b>Severity:</b> {html.escape(level.upper())}",
            f"• <b>Event:</b> {html.escape(message)}",
        ]
        if footer:
            lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━")
            lines.append(f"<i>{html.escape(str(footer))}</i>")

        return "\n".join(lines)

    def _get_opener(self) -> urllib.request.OpenerDirector:
        handlers: list[urllib.request.BaseHandler] = []
        if self.config.proxy:
            proxy_handler = urllib.request.ProxyHandler(
                {"http": self.config.proxy, "https": self.config.proxy}
            )
            handlers.append(proxy_handler)
        return urllib.request.build_opener(*handlers)

    def _http_request(
        self,
        endpoint: str,
        data: bytes | None,
        headers: dict[str, str],
        timeout: float = 15.0,
    ) -> dict[str, Any] | None:
        url = f"https://api.telegram.org/bot{self.config.bot_token}/{endpoint}"
        req = urllib.request.Request(url, data=data, headers=headers)
        opener = self._get_opener()

        for attempt in range(2):
            try:
                with opener.open(req, timeout=timeout) as resp:
                    raw = resp.read().decode("utf-8")
                    return json.loads(raw)
            except urllib.error.HTTPError as exc:
                try:
                    err_body = json.loads(exc.read().decode("utf-8"))
                except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                    err_body = {}

                # Rate limiting 429
                if exc.code == 429 and attempt == 0:
                    retry_after = (
                        err_body.get("parameters", {}).get("retry_after", 2)
                        if isinstance(err_body, dict)
                        else 2
                    )
                    retry_after = min(max(int(retry_after), 1), 5)
                    logger.warning(
                        "Telegram rate limit hit (429). Retrying after %d s",
                        retry_after,
                    )
                    time.sleep(retry_after)
                    continue

                masked = self._mask_token(self.config.bot_token)
                logger.warning(
                    "Telegram API HTTP %d for bot %s: %s",
                    exc.code,
                    masked,
                    err_body or exc.reason,
                )
                return None
            except urllib.error.URLError as exc:
                logger.warning(
                    "Telegram connection error to bot endpoint %s: %s",
                    endpoint,
                    exc.reason,
                )
                return None
            except Exception as exc:  # noqa: BLE001
                logger.warning("Unexpected error communicating with Telegram: %s", exc)
                return None
        return None

    def _send_text(self, text: str) -> bool:
        payload: dict[str, Any] = {
            "chat_id": self.config.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_notification": self.config.silent,
        }
        if self.config.thread_id is not None:
            payload["message_thread_id"] = self.config.thread_id

        data = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        resp = self._http_request("sendMessage", data=data, headers=headers)
        return bool(resp and resp.get("ok"))

    def _encode_multipart(
        self,
        fields: dict[str, Any],
        file_field: str,
        file_name: str,
        file_bytes: bytes,
        mime_type: str,
    ) -> tuple[bytes, str]:
        boundary = f"----WebKitFormBoundary{hashlib.md5(str(time.time()).encode()).hexdigest()[:16]}"
        buffer = io.BytesIO()

        for key, value in fields.items():
            if value is None:
                continue
            buffer.write(f"--{boundary}\r\n".encode())
            buffer.write(
                f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode()
            )
            buffer.write(f"{value}\r\n".encode())

        buffer.write(f"--{boundary}\r\n".encode())
        buffer.write(
            f'Content-Disposition: form-data; name="{file_field}"; filename="{file_name}"\r\n'.encode()
        )
        buffer.write(f"Content-Type: {mime_type}\r\n\r\n".encode())
        buffer.write(file_bytes)
        buffer.write(f"\r\n--{boundary}--\r\n".encode())

        content_type = f"multipart/form-data; boundary={boundary}"
        return buffer.getvalue(), content_type

    def _send_file(
        self,
        endpoint: str,
        file_field: str,
        file_name: str,
        file_bytes: bytes,
        mime_type: str,
        caption: str | None = None,
    ) -> bool:
        fields: dict[str, Any] = {
            "chat_id": self.config.chat_id,
            "disable_notification": self.config.silent,
        }
        if self.config.thread_id is not None:
            fields["message_thread_id"] = self.config.thread_id
        if caption:
            fields["caption"] = caption
            fields["parse_mode"] = "HTML"

        body, content_type = self._encode_multipart(
            fields, file_field, file_name, file_bytes, mime_type
        )
        headers = {
            "Content-Type": content_type,
            "Content-Length": str(len(body)),
        }
        resp = self._http_request(endpoint, data=body, headers=headers)
        return bool(resp and resp.get("ok"))

    def send_alert(
        self,
        title: str,
        message: str,
        level: str = "warning",
        attachment_path: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Send formatted alert to Telegram."""
        if not self.config.enabled:
            return False
        if not self.config.bot_token or not self.config.chat_id:
            logger.warning(
                "Telegram notifier is enabled but bot_token or chat_id is missing."
            )
            return False

        # Severity filter
        configured_level = SEVERITY_LEVELS.get(self.config.min_severity.lower(), 1)
        alert_level = SEVERITY_LEVELS.get(level.lower(), 1)
        if alert_level < configured_level:
            return False

        # Cooldown filter
        if self._is_rate_limited(level, title):
            logger.debug(
                "Alert '%s' suppressed due to cooldown (%d s)",
                title,
                self.config.cooldown_seconds,
            )
            return False

        try:
            formatted_html = self._build_html_text(title, message, level, metadata)

            # Check attachment
            valid_attachment: Path | None = None
            if attachment_path:
                p = Path(attachment_path)
                if p.is_file():
                    valid_attachment = p
                else:
                    logger.warning(
                        "Attachment path '%s' does not exist; falling back to text",
                        attachment_path,
                    )

            if valid_attachment:
                mime, _ = mimetypes.guess_type(str(valid_attachment))
                mime = mime or "application/octet-stream"
                file_bytes = valid_attachment.read_bytes()

                is_image = mime.startswith("image/") and valid_attachment.suffix.lower() in (
                    ".png",
                    ".jpg",
                    ".jpeg",
                )

                if is_image and self.config.send_image:
                    # Photo caption limit is 1024 chars
                    caption = formatted_html
                    if len(caption) > 1024:
                        caption = caption[:1000] + "... [truncated]"
                    return self._send_file(
                        endpoint="sendPhoto",
                        file_field="photo",
                        file_name=valid_attachment.name,
                        file_bytes=file_bytes,
                        mime_type=mime,
                        caption=caption,
                    )

                # Non-image document or image when send_image is False
                caption = formatted_html
                if len(caption) > 1024:
                    caption = caption[:1000] + "... [truncated]"
                return self._send_file(
                    endpoint="sendDocument",
                    file_field="document",
                    file_name=valid_attachment.name,
                    file_bytes=file_bytes,
                    mime_type=mime,
                    caption=caption,
                )

            # Plain text delivery
            # If formatted_html exceeds 4096 chars, upload as document
            if len(formatted_html) > 4096:
                doc_bytes = formatted_html.encode("utf-8")
                truncated_caption = (
                    formatted_html[:1000]
                    + "\n\n<i>[Alert text exceeded 4096 chars; full log attached]</i>"
                )
                return self._send_file(
                    endpoint="sendDocument",
                    file_field="document",
                    file_name="alert_details.html",
                    file_bytes=doc_bytes,
                    mime_type="text/html",
                    caption=truncated_caption,
                )

            return self._send_text(formatted_html)

        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to dispatch Telegram alert safely: %s", exc)
            return False
