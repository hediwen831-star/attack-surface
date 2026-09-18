"""配置加载与校验。

设计取舍：
1. 配置优先级 —— 环境变量 > 配置文件 > 代码默认值。
   这样 CI 与本地开发可以用同一份 config.yaml，靠环境变量覆盖密钥。
2. 强校验 + 提前失败 —— 配置错误必须在启动时炸掉，而不是跑到一半才发现
   并发数是字符串。
3. 不引入 pydantic —— 保持依赖精简，手写校验足够且逻辑透明。
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from .exceptions import ConfigError

try:  # PyYAML 是硬依赖，但给出友好提示
    import yaml
except ImportError as exc:  # pragma: no cover - 依赖缺失属于部署问题
    raise ConfigError("缺少 PyYAML，请先执行 pip install -r requirements.txt") from exc


#: 环境变量前缀，如 ASP_CONCURRENCY=200
ENV_PREFIX = "ASP_"


@dataclass
class HttpConfig:
    """HTTP 客户端行为。"""

    timeout: float = 10.0
    """单次请求超时（秒）。"""

    retries: int = 2
    """失败重试次数（不含首次）。"""

    verify_ssl: bool = False
    """是否校验 TLS 证书。测绘场景默认关闭 —— 大量自签名证书会导致漏报。"""

    user_agent: str = "Mozilla/5.0 (compatible; ASP/0.1; +https://github.com/)"
    """默认 UA。伪装成常见浏览器可降低被 WAF 直接拦截的概率。"""


@dataclass
class DiscoverConfig:
    """资产发现行为。"""

    sources: list[str] = field(default_factory=lambda: ["crtsh"])
    """启用的子域名来源，顺序即执行顺序。"""

    concurrency: int = 100
    """并发协程数上限。"""

    rate_limit: float = 50.0
    """每秒最大请求数（令牌桶）。测绘必须限速，否则会打挂目标或触发封禁。"""

    wordlist: str | None = None
    """字典爆破使用的字典文件路径，为空则跳过爆破源。"""

    brute_concurrency: int = 200
    """DNS 爆破并发数 —— DNS 查询轻量，可以比其他源高。"""

    # ------------------------------------------------------------ 端口扫描

    ports: str = "top"
    """端口范围表达式。

    支持 ``"top"``（内置常见端口表）、``"all"``（1-65535）、
    ``"80,443"``、``"8000-8010"`` 以及逗号混合写法。
    """

    port_concurrency: int = 200
    """端口扫描并发连接数。"""

    port_timeout: float = 3.0
    """单端口连接超时（秒）。

    内网目标可以调到 1.0 提速；跨公网目标建议 3.0 以上，
    否则会把「响应慢」误判成 ``filtered``。
    """

    # ------------------------------------------------------------ 指纹识别

    fingerprint_enabled: bool = True
    """是否启用 Web 指纹识别。"""

    fingerprint_rules: list[str] = field(default_factory=lambda: ["rules"])
    """指纹规则目录。相对路径相对于 asp 包目录解析。"""


@dataclass
class EngineConfig:
    """PoC 检测引擎行为。"""

    poc_dirs: list[str] = field(default_factory=lambda: ["pocs"])
    """PoC 目录列表。

    相对路径**相对于 asp 包目录**解析（而非当前工作目录），
    这样无论从哪个目录执行 ``asp`` 命令都能找到内置 PoC。
    需要把自研 PoC 与社区 PoC 分开管理时，往这个列表里追加绝对路径即可。
    """

    severity: list[str] = field(
        default_factory=lambda: ["critical", "high", "medium", "low", "info"]
    )
    """只执行指定严重级别的 PoC。"""

    tags: list[str] = field(default_factory=list)
    """按标签过滤，空列表表示不过滤。"""


@dataclass
class LLMConfig:
    """LLM 辅助告警降噪配置。

    不配 API key 也能用（降级为启发式规则）；配了就启用语义研判。
    key 建议用环境变量 ``ASP_LLM_API_KEY`` 提供，不要写进配置文件 ——
    配置文件很容易被一起提交到仓库里。
    """

    provider: str = "auto"
    """``auto`` / ``heuristic`` / ``openai``。auto 会在有 key 时用 LLM。"""

    base_url: str = "https://api.openai.com/v1"
    """OpenAI 兼容接口地址。DeepSeek / 通义 / Ollama 等改这里即可。"""

    model: str = "gpt-4o-mini"
    """模型名。"""

    api_key: str = ""
    """API key。留空则读环境变量 ASP_LLM_API_KEY。"""

    timeout: float = 30.0
    """单次请求超时（秒）。"""

    max_findings: int = 100
    """单次研判的最大条数 —— 防止误操作把几百条发现全送去打 API。"""


@dataclass
class Config:
    """顶层配置对象。"""

    http: HttpConfig = field(default_factory=HttpConfig)
    discover: DiscoverConfig = field(default_factory=DiscoverConfig)
    engine: EngineConfig = field(default_factory=EngineConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    database: str = "asp.db"
    """SQLite 数据库路径。"""

    log_level: str = "INFO"

    # ---------------------------------------------------------------- 加载

    @classmethod
    def from_file(cls, path: str | Path) -> Config:
        """从 YAML 文件加载配置，并叠加环境变量覆盖。

        Args:
            path: 配置文件路径。

        Raises:
            ConfigError: 文件不存在、YAML 语法错误或字段类型不合法。
        """
        config_path = Path(path)
        if not config_path.exists():
            raise ConfigError("配置文件不存在", path=str(config_path))

        try:
            raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError("YAML 语法错误", path=str(config_path), detail=str(exc)) from exc

        if not isinstance(raw, dict):
            raise ConfigError("配置文件根节点必须是映射", path=str(config_path))

        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> Config:
        """从字典构造配置，未知字段直接报错（防止拼错 key 静默失效）。"""
        known = {f.name for f in fields(cls)}
        unknown = set(raw) - known
        if unknown:
            raise ConfigError(
                "配置中存在未知字段",
                unknown=sorted(unknown),
                allowed=sorted(known),
            )

        nested = {
            "http": (HttpConfig, raw.get("http", {})),
            "discover": (DiscoverConfig, raw.get("discover", {})),
            "engine": (EngineConfig, raw.get("engine", {})),
            "llm": (LLMConfig, raw.get("llm", {})),
        }
        kwargs: dict[str, Any] = {}
        for name, (klass, payload) in nested.items():
            kwargs[name] = _build_section(klass, payload)

        for scalar in ("database", "log_level"):
            if scalar in raw:
                kwargs[scalar] = raw[scalar]

        config = cls(**kwargs)
        config._apply_env_overrides()
        config.validate()
        return config

    def _apply_env_overrides(self) -> None:
        """用 ``ASP_<SECTION>_<FIELD>`` 形式的环境变量覆盖配置。

        例：``ASP_DISCOVER_CONCURRENCY=300`` 覆盖 ``discover.concurrency``。
        """
        for section_name in ("http", "discover", "engine", "llm"):
            section = getattr(self, section_name)
            for f in fields(section):
                env_key = f"{ENV_PREFIX}{section_name.upper()}_{f.name.upper()}"
                if env_key not in os.environ:
                    continue
                setattr(section, f.name, _coerce(os.environ[env_key], f.type))

        for f in fields(self):
            if f.name in ("http", "discover", "engine", "llm"):
                continue
            env_key = f"{ENV_PREFIX}{f.name.upper()}"
            if env_key in os.environ:
                setattr(self, f.name, _coerce(os.environ[env_key], f.type))

    # ---------------------------------------------------------------- 校验

    def validate(self) -> None:
        """语义级校验 —— 字段存在不代表取值合理。"""
        if self.discover.concurrency < 1:
            raise ConfigError("discover.concurrency 必须 >= 1", got=self.discover.concurrency)
        if self.discover.rate_limit <= 0:
            raise ConfigError("discover.rate_limit 必须 > 0", got=self.discover.rate_limit)
        if self.discover.port_concurrency < 1:
            raise ConfigError(
                "discover.port_concurrency 必须 >= 1", got=self.discover.port_concurrency
            )
        if self.discover.port_timeout <= 0:
            raise ConfigError(
                "discover.port_timeout 必须 > 0", got=self.discover.port_timeout
            )
        if not str(self.discover.ports).strip():
            raise ConfigError("discover.ports 不能为空")
        if self.http.timeout <= 0:
            raise ConfigError("http.timeout 必须 > 0", got=self.http.timeout)
        if self.http.retries < 0:
            raise ConfigError("http.retries 不能为负", got=self.http.retries)

        valid_providers = {"auto", "heuristic", "openai"}
        if self.llm.provider.strip().lower() not in valid_providers:
            raise ConfigError(
                "llm.provider 取值非法",
                got=self.llm.provider,
                allowed=sorted(valid_providers),
            )
        if self.llm.timeout <= 0:
            raise ConfigError("llm.timeout 必须 > 0", got=self.llm.timeout)
        if self.llm.max_findings < 1:
            raise ConfigError("llm.max_findings 必须 >= 1", got=self.llm.max_findings)

        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.log_level.upper() not in valid_levels:
            raise ConfigError(
                "log_level 取值非法",
                got=self.log_level,
                allowed=sorted(valid_levels),
            )


def _build_section(klass: type, payload: Any):
    """构造嵌套配置段，字段名或类型不对就抛 ConfigError。"""
    if payload is None:
        payload = {}
    if not isinstance(payload, Mapping):
        raise ConfigError(f"{klass.__name__} 必须是映射", got=type(payload).__name__)

    allowed = {f.name for f in fields(klass)}
    unknown = set(payload) - allowed
    if unknown:
        raise ConfigError(
            f"{klass.__name__} 存在未知字段",
            unknown=sorted(unknown),
            allowed=sorted(allowed),
        )

    kwargs = {}
    for key, value in payload.items():
        expected = next(f.type for f in fields(klass) if f.name == key)
        kwargs[key] = _coerce(value, expected)
    return klass(**kwargs)


def _coerce(value: Any, expected: Any):
    """把配置值转成目标类型 —— 环境变量永远是字符串，必须转换。"""
    if isinstance(expected, str):
        if expected == "float":
            return float(value)
        if expected == "int":
            return int(value)
        if expected == "bool":
            return str(value).lower() in {"1", "true", "yes", "on"}
        return value
    if expected is bool:
        return str(value).lower() in {"1", "true", "yes", "on"}
    if expected is int:
        return int(value)
    if expected is float:
        return float(value)
    return value


def load_config(path: str | Path | None = None) -> Config:
    """便捷入口：给了路径就读文件，否则用默认配置。

    默认配置会查找当前目录与包目录下的 ``conf/config.yaml``。
    """
    if path is not None:
        return Config.from_file(path)

    candidates = [
        Path.cwd() / "conf" / "config.yaml",
        Path.cwd() / "config.yaml",
    ]
    for candidate in candidates:
        if candidate.exists():
            return Config.from_file(candidate)

    config = Config()
    config._apply_env_overrides()
    config.validate()
    return config
