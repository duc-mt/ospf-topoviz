"""Base notifier abstract interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseNotifier(ABC):
    """Abstract base class for notification dispatchers."""

    @abstractmethod
    def send_alert(
        self,
        title: str,
        message: str,
        level: str = "warning",
        attachment_path: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Dispatch an alert message.

        Args:
            title: Short alert title/headline.
            message: Informational details or event summary.
            level: Severity ("info", "warning", or "critical").
            attachment_path: Optional path to an image or file on disk.
            metadata: Optional dictionary with extra context (device, timestamps, etc.).

        Returns:
            True if delivered successfully, False if skipped, rate-limited, or failed.
        """
