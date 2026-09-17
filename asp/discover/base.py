"""资产源抽象。

设计取舍：为什么把「来源」抽象成一等公民？

不同来源的可信度、速率、覆盖度差异极大：
- 证书透明日志（crt.sh）：覆盖广、零流量打在目标上，但滞后且可能有历史记录
- 字典爆破：实时性强，但只能发现字典里有名字的子域名
- 被动 DNS：快，但多数商业源需要 API Key

把它们统一成 ``Source`` 接口后：
1. 新增来源只需写一个类，不动编排逻辑 —— 这就是「可插拔」
2. 单个源失败只降级，不影响其他源（``SourceError`` 被编排层吞掉并记日志）
3. 可以按来源标注可信度，为后续「多源确认则提权」留接口
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..config import Config
from ..core.http import AsyncHttpClient
from ..logger import get_logger

logger = get_logger("discover.base")


@dataclass(slots=True)
class DiscoveredAsset:
    """一条被发现（尚未验证）的资产。

    这是源层与解析层之间的契约：源只负责「我看到了这个名字」，
    不做解析、不判存活 —— 职责分离让每个源都简单到不可能出错。
    """

    value: str
    """资产值：域名或 IP。"""

    source: str
    """发现来源标识。"""

    type: str = "domain"
    """asset 类型（domain / ip）。"""

    resolved_ip: str | None = None
    """解析结果，由解析层回填。"""

    metadata: dict[str, str] = field(default_factory=dict)
    """来源附加信息（如证书颁发者、证书时间），报告里有用。"""

    @staticmethod
    def normalize(value: str) -> str:
        """规范化域名。

        证书透明日志返回的数据经常带通配符前缀、大写、结尾点，
        这些形式在去重时会被当成不同资产 —— 必须统一。
        """
        value = value.strip().lower().rstrip(".")
        # 去掉 wildcard 前缀：*.example.com → example.com 的 wildcard 记录
        if value.startswith("*."):
            value = value[2:]
        return value

    def __post_init__(self) -> None:
        self.value = self.normalize(self.value)


class Source(ABC):
    """资产源基类。

    子类只需实现 ``fetch``，重试/限速/日志由基类统一处理。
    """

    #: 源标识，用于日志与资产来源标注
    name: str = "base"

    #: 该源是否依赖外网。纯本地源（字典爆破）在网络受限时仍可用。
    requires_network: bool = True

    def __init__(self, config: Config, client: AsyncHttpClient | None = None) -> None:
        """
        Args:
            config: 全局配置。
            client: 共享的 HTTP 客户端。为 None 时由源自行创建（不推荐，
                因为会绕过全局限速器）。
        """
        self.config = config
        self.client = client

    @abstractmethod
    async def fetch(self, domain: str) -> list[DiscoveredAsset]:
        """执行发现，返回去重后的资产列表。

        Args:
            domain: 根域名，如 ``example.com``。

        Raises:
            SourceError: 源不可用。编排层会捕获并降级。
        """

    async def discover(self, domain: str) -> list[DiscoveredAsset]:
        """``fetch`` 的安全包装：统一异常处理、日志与去重。

        这是编排层唯一调用的方法 —— 子类不要去重写它。
        """
        import time

        started = time.monotonic()
        try:
            results = await self.fetch(domain)
        except Exception as exc:  # noqa: BLE001 - 单源失败必须降级而非中断
            logger.warning("source_failed source=%s domain=%s error=%s", self.name, domain, exc)
            return []

        # 源内部可能返回重复项（多张证书指向同一域名），这里统一去重
        unique: dict[str, DiscoveredAsset] = {}
        for item in results:
            unique.setdefault(item.value, item)

        elapsed = time.monotonic() - started
        logger.info(
            "source_done source=%s domain=%s found=%d unique=%d elapsed=%.2fs",
            self.name,
            domain,
            len(results),
            len(unique),
            elapsed,
        )
        return list(unique.values())


__all__ = ["Source", "DiscoveredAsset"]
