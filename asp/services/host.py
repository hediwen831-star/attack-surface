"""主机资产测绘编排。

把「端口扫描 → HTTP 探测 → 指纹识别 → 落地数据模型」串成一条流水线：

    host
     │
     ├─ scan_host(ports)              TCP 连接扫描 + banner 抓取 + 服务识别
     │       │
     │       └─ 得到 [PortResult]，其中 open 的进入下一阶段
     │
     ├─ 对 open 的 HTTP 类端口：
     │       ├─ GET /            → 响应头 / 正文 / Cookie → 指纹规则匹配
     │       └─ GET /favicon.ico → mmh3 哈希（同源系统识别的最强单特征）
     │
     └─ 持久化：Asset(ip) → Port → Service → Component

## 设计取舍：为什么端口扫描和指纹识别要分开成两个模块

端口扫描回答「有什么东西在监听」（网络层事实），
指纹识别回答「那是什么系统」（应用层推断）。

两者失败模式完全不同：端口扫描可能被防火墙过滤（误判为关闭），
指纹识别可能因为站点返回通用页面而误判（误报组件）。
混在一起写，会让「为什么这条结论不可信」变得难以追溯。
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path

from ..config import Config
from ..core.database import (
    Asset,
    Component,
    Port,
    ScanTask,
    Service,
    create_db_engine,
    init_db,
    session_scope,
)
from ..core.http import AsyncHttpClient, Response
from ..discover.fingerprint import (
    ComponentResult,
    favicon_hash,
    load_rules,
    match_fingerprints,
)
from ..discover.portscan import (
    HTTP_LIKE_PORTS,
    PortResult,
    parse_ports,
    scan_host,
)
from ..logger import get_logger

logger = get_logger("services.host")

#: 这些端口默认走 HTTPS
HTTPS_PORTS: frozenset[int] = frozenset({443, 8443, 9443})


@dataclass
class HostReport:
    """一台主机的完整测绘结果。"""

    host: str
    ports: list[PortResult] = field(default_factory=list)
    components: dict[int, list[ComponentResult]] = field(default_factory=dict)
    favicons: dict[int, int] = field(default_factory=dict)
    elapsed: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def open_ports(self) -> list[int]:
        """开放端口号列表。"""
        return [p.port for p in self.ports if p.is_open]

    @property
    def all_components(self) -> list[ComponentResult]:
        """所有端口上识别出的组件（去重合并）。

        ⚠️ **必须返回新对象，不能原地修改 self.components 里的 ComponentResult。**

        踩过的坑：最初写的是 `existing.confidence += item.confidence`，
        直接改了原始对象 —— 于是**每调用一次这个方法，置信度就再累加一次**：

            第 1 次读 → 0.60（正确）
            第 2 次读 → 0.90
            第 3 次读 → 1.00

        后果是同一份报告被读取多次（比如「生成日志」和「写数据库」各读一次）
        会得到不同的数值，而且越读越离谱。

        **property 应该无副作用** —— 这是它和方法最本质的区别。
        带累加语义的聚合逻辑如果要暴露成属性，就必须先复制再合并。
        """
        merged: dict[str, ComponentResult] = {}
        for items in self.components.values():
            for item in items:
                existing = merged.get(item.name)
                if existing is None:
                    # 复制一份，避免后续的累加写回原始对象
                    merged[item.name] = replace(item, evidence=list(item.evidence))
                else:
                    existing.confidence = min(1.0, existing.confidence + item.confidence)
                    existing.evidence.extend(
                        e for e in item.evidence if e not in existing.evidence
                    )
        return sorted(merged.values(), key=lambda c: (-c.confidence, c.name))

    def by_service(self) -> dict[str, int]:
        """按服务名统计开放端口数。"""
        stats: dict[str, int] = {}
        for result in self.ports:
            if not result.is_open:
                continue
            name = result.service.name or "unknown"
            stats[name] = stats.get(name, 0) + 1
        return stats


# ------------------------------------------------------------------ HTTP 探测


def _scheme_for(port: int) -> str:
    """根据端口判断用 http 还是 https。"""
    return "https" if port in HTTPS_PORTS else "http"


async def _fetch_favicon(
    client: AsyncHttpClient, host: str, port: int
) -> tuple[int | None, str]:
    """获取并计算 favicon 哈希。

    Returns:
        (哈希值或 None, 说明)。失败不抛异常 —— favicon 拿不到是常态
        （很多站点直接 404），不应该影响整体流程。
    """
    url = f"{_scheme_for(port)}://{host}:{port}/favicon.ico"
    try:
        resp = await client.get(url)
    except Exception as exc:  # noqa: BLE001
        return None, f"请求失败: {exc}"

    if not resp.ok or resp.status != 200:
        return None, f"HTTP {resp.status}"

    content = resp.content or b""
    if len(content) < 16:
        # 空文件或占位响应，哈希没有区分度
        return None, "favicon 过小，忽略"

    return favicon_hash(content), f"{len(content)} 字节"


async def probe_http(
    host: str,
    port: int,
    client: AsyncHttpClient,
    *,
    rules: Sequence | None = None,
    with_favicon: bool = True,
) -> tuple[list[ComponentResult], int | None, str]:
    """对单个 HTTP 端口做指纹识别。

    Returns:
        (组件列表, favicon 哈希或 None, 说明)
    """
    scheme = _scheme_for(port)
    url = f"{scheme}://{host}:{port}/"

    try:
        resp: Response = await client.get(url)
    except Exception as exc:  # noqa: BLE001
        return [], None, f"请求失败: {exc}"

    if not resp.ok:
        return [], None, f"请求异常: {resp.error}"

    components = match_fingerprints(rules or [], resp) if rules else []

    favicon: int | None = None
    favicon_note = ""
    if with_favicon:
        favicon, favicon_note = await _fetch_favicon(client, host, port)

    return components, favicon, f"HTTP {resp.status}{'; favicon ' + favicon_note if favicon_note else ''}"


# ------------------------------------------------------------------ 编排


async def scan_and_fingerprint(
    host: str,
    config: Config,
    *,
    ports: str | Sequence[int] | None = None,
    rules_dirs: Sequence[str | Path] | None = None,
    with_favicon: bool = True,
) -> HostReport:
    """对一台主机做完整的端口扫描 + 指纹识别。

    Args:
        host: 目标主机（IP 或域名）。
        config: 全局配置。
        ports: 端口表达式或列表，None 用配置中的默认值。
        rules_dirs: 指纹规则目录，None 用配置中的默认值。
        with_favicon: 是否获取 favicon 哈希（会多发一个请求）。

    Returns:
        ``HostReport``。
    """
    started = time.monotonic()
    report = HostReport(host=host)

    port_list = parse_ports(ports if ports is not None else config.discover.ports)

    # ---- 阶段 1：端口扫描 ----
    report.ports = await scan_host(
        host,
        port_list,
        concurrency=config.discover.port_concurrency,
        timeout=config.discover.port_timeout,
        grab_banner=True,
    )

    open_ports = [p for p in report.ports if p.is_open]
    if not open_ports:
        report.elapsed = time.monotonic() - started
        logger.info("host_no_open_port host=%s scanned=%d", host, len(port_list))
        return report

    # ---- 阶段 2：对 HTTP 类端口做指纹识别 ----
    rule_dirs = rules_dirs if rules_dirs is not None else config.discover.fingerprint_rules
    rules = load_rules(rule_dirs) if config.discover.fingerprint_enabled else []

    http_ports = [
        p.port
        for p in open_ports
        if p.port in HTTP_LIKE_PORTS or p.service.name == "http"
    ]

    if http_ports:
        async with AsyncHttpClient(
            concurrency=min(20, config.discover.concurrency),
            rate_limit=config.discover.rate_limit,
            timeout=config.http.timeout,
            retries=config.http.retries,
            verify_ssl=False,      # 测绘场景大量自签名证书，必须关闭校验
            user_agent=config.http.user_agent,
        ) as client:
            results = await asyncio.gather(
                *(
                    probe_http(host, port, client, rules=rules, with_favicon=with_favicon)
                    for port in http_ports
                ),
                return_exceptions=True,
            )

        for port, outcome in zip(http_ports, results, strict=False):
            if isinstance(outcome, BaseException):
                report.errors.append(f"{host}:{port} 探测异常: {outcome}")
                logger.warning("http_probe_failed host=%s port=%d error=%s", host, port, outcome)
                continue

            components, favicon, note = outcome
            report.components[port] = components
            if favicon is not None:
                report.favicons[port] = favicon
            logger.info(
                "http_probed host=%s port=%d components=%d favicon=%s note=%s",
                host, port, len(components), favicon, note,
            )

    report.elapsed = time.monotonic() - started
    logger.info(
        "host_scanned host=%s open=%d components=%d elapsed=%.2fs",
        host, len(open_ports), len(report.all_components), report.elapsed,
    )
    return report


# ------------------------------------------------------------------ 持久化


def persist_host_report(report: HostReport, config: Config) -> int:
    """把主机测绘结果写入数据库，返回组件记录数。

    沿用与子域名收集一致的策略：每次扫描新建一个 ScanTask，
    保留历史快照以支持后续的资产变更 diff。
    """
    engine = create_db_engine(config.database)
    init_db(engine)

    component_count = 0

    with session_scope(engine) as session:
        task = ScanTask(
            target=report.host,
            status="success",
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
        )
        task.set_stats(
            open_ports=report.open_ports,
            components=len(report.all_components),
            favicons=report.favicons,
            elapsed=round(report.elapsed, 2),
        )
        session.add(task)
        session.flush()

        # 主机本身作为一条 ip 类型资产
        asset = Asset(
            task_id=task.id,
            type="ip",
            value=report.host,
            root_domain=report.host,
            alive=bool(report.open_ports),
            fingerprint=Asset.make_fingerprint(report.host, "ip"),
        )
        session.add(asset)
        session.flush()

        for port_result in report.ports:
            if not port_result.is_open:
                continue

            port_row = Port(
                asset_id=asset.id,
                number=port_result.port,
                protocol="tcp",
                state="open",
                banner=port_result.banner[:2000],
            )
            session.add(port_row)
            session.flush()

            service_row = Service(
                port_id=port_row.id,
                name=port_result.service.name or "unknown",
                product=port_result.service.product,
                version=port_result.service.version,
                favicon_hash=str(report.favicons.get(port_result.port, "")),
            )

            # 从 banner 里再捞一次 HTTP 标题，报告里最直观
            title = _extract_title(port_result.banner)
            if title:
                service_row.http_title = title[:255]

            session.add(service_row)
            session.flush()

            for component in report.components.get(port_result.port, []):
                session.add(
                    Component(
                        service_id=service_row.id,
                        name=component.name,
                        version=component.version,
                        category=component.category,
                        confidence=component.confidence,
                        evidence="; ".join(component.evidence)[:2000],
                    )
                )
                component_count += 1

        session.commit()

    logger.info("host_persisted host=%s components=%d", report.host, component_count)
    return component_count


def _extract_title(banner: str) -> str:
    """从 HTTP 响应里提取 <title>。"""
    import re

    match = re.search(r"<title[^>]*>(.*?)</title>", banner, re.I | re.S)
    if not match:
        return ""
    return " ".join(match.group(1).split())[:200]


__all__ = [
    "HostReport",
    "scan_and_fingerprint",
    "probe_http",
    "persist_host_report",
    "HTTPS_PORTS",
]
