"""结构化日志。

设计取舍：为什么不用 print / 裸 logging？
扫描器是长时运行的并发程序，日志必须能回答「哪个任务、对哪个目标、干了多久、结果如何」。
这里统一成 ``key=value`` 的结构化风格，既能人读，也方便后续接 ELK / Loki。
"""

from __future__ import annotations

import logging
import sys
from typing import Any

_LOGGER_NAME = "asp"

#: 日志格式：时间 | 级别 | 模块 | 消息
_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)-28s | %(message)s"
_DATEFMT = "%H:%M:%S"


class _ColorFormatter(logging.Formatter):
    """给终端加一点 ANSI 颜色 —— 只为可读性，不改变输出内容。

    遵循 NO_COLOR 约定，非 TTY 时自动降级为纯文本。
    """

    _COLORS = {
        "DEBUG": "\033[38;5;245m",
        "INFO": "\033[38;5;39m",
        "WARNING": "\033[38;5;214m",
        "ERROR": "\033[38;5;203m",
        "CRITICAL": "\033[38;5;199m",
    }
    _RESET = "\033[0m"

    def __init__(self, *, use_color: bool = True) -> None:
        super().__init__(fmt=_FORMAT, datefmt=_DATEFMT)
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        text = super().format(record)
        if not self.use_color:
            return text
        color = self._COLORS.get(record.levelname)
        return f"{color}{text}{self._RESET}" if color else text


def setup_logging(level: str = "INFO", *, quiet: bool = False) -> logging.Logger:
    """初始化全局日志器。

    Args:
        level: 日志级别字符串（DEBUG/INFO/WARNING/ERROR）。
        quiet: 静默模式，只输出 WARNING 及以上 —— 用于管道输出场景。

    Returns:
        配置好的 ``asp`` 根日志器。
    """
    logger = logging.getLogger(_LOGGER_NAME)
    logger.handlers.clear()
    logger.propagate = False

    resolved = "WARNING" if quiet else level.upper()
    logger.setLevel(getattr(logging, resolved, logging.INFO))

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        _ColorFormatter(use_color=sys.stderr.isatty())
    )
    logger.addHandler(handler)
    return logger


def get_logger(name: str) -> logging.Logger:
    """获取子模块日志器，自动挂在 ``asp`` 命名空间下。"""
    if name.startswith(_LOGGER_NAME):
        return logging.getLogger(name)
    return logging.getLogger(f"{_LOGGER_NAME}.{name}")


def log_event(logger: logging.Logger, event: str, **fields: Any) -> None:
    """输出一条结构化事件日志。

    Example:
        >>> log_event(logger, "source_done", source="crtsh", count=42)
        14:03:11 | INFO    | asp.discover.crtsh        | source_done source=crtsh count=42
    """
    if not fields:
        logger.info(event)
        return
    detail = " ".join(f"{k}={v}" for k, v in fields.items())
    logger.info("%s %s", event, detail)
