"""统一异常体系。

设计取舍：为什么不用内置异常？
内置异常无法携带「哪个模块、对哪个目标、失败原因是什么」这类上下文，
导致上层无法区分「该重试」和「该放弃」。自定义异常树让调度器能做决策。

    AspError                    所有异常的基类
    ├── ConfigError             配置问题，启动即失败
    ├── SourceError             资产源失败（可降级，不该中断整次扫描）
    │   └── SourceTimeoutError  超时，可重试
    ├── HttpError               HTTP 层失败
    │   └── RateLimitError      被限速，需要退避
    ├── PluginError             PoC 插件问题
    │   └── PoCParseError       YAML/结构不合法
    └── EngineError             检测引擎执行失败
"""

from __future__ import annotations

from typing import Any


class AspError(Exception):
    """所有 ASP 异常的基类。

    统一带上 ``context`` 字段，方便日志结构化输出与上层做决策。
    """

    #: 该异常是否代表「可重试的临时故障」
    retryable: bool = False

    def __init__(self, message: str, **context: Any) -> None:
        super().__init__(message)
        self.message = message
        self.context: dict[str, Any] = context

    def __str__(self) -> str:
        if not self.context:
            return self.message
        detail = " ".join(f"{k}={v!r}" for k, v in self.context.items())
        return f"{self.message} ({detail})"


class ConfigError(AspError):
    """配置文件缺失、字段非法或取值越界。"""


class SourceError(AspError):
    """资产源失败。单个源失败只降级，不中断整体扫描。"""

    def __init__(self, message: str, source: str = "", **context: Any) -> None:
        super().__init__(message, source=source, **context)
        self.source = source


class SourceTimeoutError(SourceError):
    """资产源超时 —— 可重试。"""

    retryable = True


class HttpError(AspError):
    """HTTP 请求失败。"""


class RateLimitError(HttpError):
    """被目标或数据源限速（429 / 403 频控）—— 必须退避后重试。"""

    retryable = True


class PluginError(AspError):
    """PoC 插件在加载或执行阶段出问题。"""

    def __init__(self, message: str, poc_id: str = "", **context: Any) -> None:
        super().__init__(message, poc_id=poc_id, **context)
        self.poc_id = poc_id


class PoCParseError(PluginError):
    """YAML 语法错误或字段结构不合法 —— 不应重试，直接告警并跳过。"""


class EngineError(AspError):
    """检测引擎内部错误。"""
