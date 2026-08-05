"""证书透明日志（Certificate Transparency）资产源。

原理：CA 签发每张 TLS 证书都必须写入公开的 CT 日志。
查询 ``crt.sh`` 的日志索引，就能拿到某个域名下**所有曾被签发过证书的子域名**。

这是一个「零流量打在目标上」的被动收集手段 ——
我们查的是第三方公开数据库，目标服务器完全感知不到。
这正是被动信息收集相对于主动扫描的价值。

局限（README 里也要写，体现对数据源的理解）：
1. 滞后性 —— 新部署的子域名要等证书签发并写入日志才可见
2. 历史噪声 —— 三年前签过证书但现在已下线的域名也会返回，必须靠存活验证过滤
3. 单点依赖 —— crt.sh 本身会限速甚至 502，所以要有重试与其他源兜底
"""

from __future__ import annotations

import json
import re

from ..exceptions import SourceError, SourceTimeoutError
from ..logger import get_logger
from .base import DiscoveredAsset, Source

logger = get_logger("discover.crtsh")

#: crt.sh 查询接口。%25 是 SQL LIKE 的 ``%`` 通配符的 URL 编码，
#: 表示「任意前缀」——即所有子域名。
CRTSH_ENDPOINT = "https://crt.sh/"

#: 域名合法性校验。CT 日志里会混进邮箱、非法字符等噪声，先挡掉。
_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


class CrtshSource(Source):
    """从证书透明日志收集子域名。"""

    name = "crtsh"
    requires_network = True

    def __init__(self, config, client=None, *, include_expired: bool = True) -> None:
        """
        Args:
            config: 全局配置。
            client: 共享 HTTP 客户端。
            include_expired: 是否包含已过期证书里的域名。
                默认 True —— 过期域名往往意味着「曾经存在、可能仍在运行」，
                是攻击面里最容易被忽略的部分。
        """
        super().__init__(config, client)
        self.include_expired = include_expired

    async def fetch(self, domain: str) -> list[DiscoveredAsset]:
        """查询 crt.sh 并解析返回结果。"""
        if self.client is None:
            raise SourceError("CrtshSource 需要共享的 HTTP 客户端", source=self.name)

        params = {"q": f"%.{domain}", "output": "json", "exclude": "expired"}
        if not self.include_expired:
            params["exclude"] = "expired"

        try:
            resp = await self.client.get(CRTSH_ENDPOINT, params=params)
        except Exception as exc:  # noqa: BLE001
            raise SourceTimeoutError("crt.sh 请求异常", source=self.name, detail=str(exc)) from exc

        if not resp.ok:
            raise SourceError("crt.sh 请求失败", source=self.name, error=resp.error)

        # crt.sh 在高负载时会返回 HTML 错误页而不是 JSON —— 必须防御性解析
        if resp.status != 200:
            raise SourceError("crt.sh 返回非 200", source=self.name, status=resp.status)

        text = resp.text.strip()
        if not text.startswith("["):
            raise SourceError(
                "crt.sh 返回了非 JSON 内容（通常是限速页面）",
                source=self.name,
                preview=text[:120],
            )

        try:
            records = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SourceError("crt.sh 返回 JSON 解析失败", source=self.name) from exc

        if not isinstance(records, list):
            raise SourceError("crt.sh 返回结构异常", source=self.name, got=type(records).__name__)

        return self._parse_records(records, domain)

    def _parse_records(self, records: list, domain: str) -> list[DiscoveredAsset]:
        """从 CT 记录中提取合法子域名。

        一条记录里的 ``name_value`` 可能包含多个换行分隔的域名，
        ``common_name`` 又是另一个字段 —— 两个都要看，否则会漏。
        """
        assets: list[DiscoveredAsset] = []
        seen: set[str] = set()

        for record in records:
            if not isinstance(record, dict):
                continue

            # name_value 是换行分隔的多值字段
            raw_names: list[str] = []
            for key in ("name_value", "common_name"):
                value = record.get(key)
                if isinstance(value, str):
                    raw_names.extend(value.splitlines())

            # 保留证书时间作为元数据，报告里可以展示「这个域名什么时候被签过证书」
            issuer = str(record.get("issuer_name", ""))[:120]
            not_before = str(record.get("not_before", ""))[:32]

            for name in raw_names:
                name = DiscoveredAsset.normalize(name)
                if not name or name in seen:
                    continue
                # 只保留目标域名的子域，过滤掉无关域与非法格式
                if not name.endswith(domain):
                    continue
                if not _DOMAIN_RE.match(name):
                    continue

                seen.add(name)
                assets.append(
                    DiscoveredAsset(
                        value=name,
                        source=self.name,
                        type="domain",
                        metadata={"issuer": issuer, "not_before": not_before},
                    )
                )

        return assets


__all__ = ["CrtshSource", "CRTSH_ENDPOINT"]
