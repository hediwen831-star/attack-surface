"""子域名收集编排。

这一层负责回答「如何把多个源拼成一条流水线」：

    ┌─ crtsh ─┐
    │         ├─→ 聚合去重 ─→ DNS 解析验证 ─→ 存活过滤 ─→ 持久化 ─→ 报告
    └─ brute ─┘

关键设计取舍：

1. **为什么源要并发跑而不是串行？**
   crt.sh 一次查询实测 4~5 秒（网络延迟为主），如果串行跑 3 个源就是 15 秒
   纯等待。并发跑总耗时 ≈ 最慢的那个源。

2. **为什么解析验证要独立成一层，而不是让源自己解析？**
   源返回的是「候选名字」，其中混有大量历史域名和泛解析噪声。
   把验证集中到一层，才能统一做并发控制、去重和统计 ——
   否则每个源都要重复实现一遍。

3. **为什么保留 source 字段？**
   实战中常会问「这个资产你是怎么发现的」。多源交叉验证是提升可信度的手段：
   同时出现在 crt.sh 和爆破结果里的域名，比单一来源的可信度高得多。
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Config
from ..core.database import Asset, ScanTask, create_db_engine, init_db, session_scope
from ..core.http import AsyncHttpClient
from ..discover.base import DiscoveredAsset, Source
from ..discover.bruteforce import BruteForceSource, resolve_host
from ..discover.crtsh import CrtshSource
from ..logger import get_logger

logger = get_logger("services.subdomain")

#: 源注册表。新增来源只需在这里加一行映射 —— 这就是「可插拔」的落点。
SOURCE_REGISTRY: dict[str, type[Source]] = {
    "crtsh": CrtshSource,
    "brute": BruteForceSource,
}


def build_sources(
    names: Sequence[str],
    config: Config,
    client: AsyncHttpClient,
    *,
    wordlist: str | None = None,
) -> list[Source]:
    """根据名字列表实例化资产源。

    Args:
        names: 源标识列表，如 ``["crtsh", "brute"]``。
        config: 全局配置。
        client: 共享 HTTP 客户端。
        wordlist: 爆破字典路径（仅 brute 源使用）。

    Returns:
        实例化后的源列表。未知名称会被跳过并告警 —— 不该因为拼错一个名字就整体失败。
    """
    sources: list[Source] = []
    for name in names:
        key = name.strip().lower()
        klass = SOURCE_REGISTRY.get(key)
        if klass is None:
            logger.warning("unknown_source name=%s available=%s", name, ",".join(SOURCE_REGISTRY))
            continue

        if klass is BruteForceSource:
            sources.append(klass(config, client, wordlist=wordlist or config.discover.wordlist))
        else:
            sources.append(klass(config, client))
    return sources


@dataclass
class SubdomainReport:
    """一次子域名收集的结果报告。"""

    root: str
    assets: list[DiscoveredAsset] = field(default_factory=list)
    sources_used: list[str] = field(default_factory=list)
    wildcard_ips: set[str] = field(default_factory=set)
    elapsed: float = 0.0
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def count(self) -> int:
        """存活资产数量。"""
        return len(self.assets)

    def by_source(self) -> dict[str, int]:
        """按来源统计发现量。"""
        stats: dict[str, int] = {}
        for asset in self.assets:
            for src in asset.metadata.get("sources", asset.source).split(","):
                stats[src] = stats.get(src, 0) + 1
        return stats

    def multi_source(self) -> list[DiscoveredAsset]:
        """被多个源同时确认的资产 —— 优先级最高，应最先人工复核。"""
        return [a for a in self.assets if len(a.metadata.get("sources", "").split(",")) > 1]


async def collect_subdomains(
    target: str,
    config: Config,
    *,
    sources: Sequence[str] | None = None,
    wordlist: str | None = None,
    verify: bool = True,
) -> SubdomainReport:
    """执行子域名收集全流程。

    Args:
        target: 根域名，如 ``example.com``。
        config: 全局配置。
        sources: 要启用的源，None 则取配置默认值。
        wordlist: 爆破字典路径。
        verify: 是否做 DNS 解析验证。关闭可加速，但会引入大量死域名。

    Returns:
        ``SubdomainReport`` 结果报告。
    """
    import time

    started = time.monotonic()
    source_names = list(sources or config.discover.sources)
    report = SubdomainReport(root=target, sources_used=source_names)

    async with AsyncHttpClient(
        concurrency=config.discover.concurrency,
        rate_limit=config.discover.rate_limit,
        timeout=config.http.timeout,
        retries=config.http.retries,
        verify_ssl=config.http.verify_ssl,
        user_agent=config.http.user_agent,
    ) as client:
        built = build_sources(source_names, config, client, wordlist=wordlist)
        if not built:
            logger.error("no_valid_source given=%s available=%s", source_names, list(SOURCE_REGISTRY))
            report.elapsed = time.monotonic() - started
            return report

        # 源之间并发执行。单个源内部已做异常收敛（Source.discover），
        # 所以这里不需要 return_exceptions —— 每个源最多返回空列表。
        results = await asyncio.gather(*(src.discover(target) for src in built))

        # 聚合去重：同一域名可能被多个源发现，把来源合并成一个列表。
        merged: dict[str, DiscoveredAsset] = {}
        for src_result in results:
            for asset in src_result:
                existing = merged.get(asset.value)
                if existing is None:
                    asset.metadata.setdefault("sources", asset.source)
                    merged[asset.value] = asset
                else:
                    sources_csv = existing.metadata.get("sources", existing.source)
                    if asset.source not in sources_csv.split(","):
                        existing.metadata["sources"] = f"{sources_csv},{asset.source}"
                    if asset.resolved_ip and not existing.resolved_ip:
                        existing.resolved_ip = asset.resolved_ip

        candidates = list(merged.values())
        logger.info(
            "aggregate_done target=%s candidates=%d multi_source=%d",
            target,
            len(candidates),
            sum(1 for a in candidates if len(a.metadata.get("sources", "").split(",")) > 1),
        )

        # 收集泛解析基线，供报告展示与后续判断使用
        for src in built:
            wildcard = getattr(src, "wildcard_ips", None)
            if wildcard:
                report.wildcard_ips |= set(wildcard)

        if verify:
            report.assets = await _verify_assets(candidates, config)
        else:
            report.assets = candidates

    report.assets.sort(key=lambda a: (a.value.count("."), a.value))
    report.elapsed = time.monotonic() - started

    logger.info(
        "collect_done target=%s alive=%d wildcard_ips=%d elapsed=%.2fs",
        target,
        report.count,
        len(report.wildcard_ips),
        report.elapsed,
    )
    return report


async def _verify_assets(
    candidates: list[DiscoveredAsset], config: Config
) -> list[DiscoveredAsset]:
    """并发验证候选资产的解析情况，丢弃解析失败的。

    这里重新解析一遍而不是复用源返回的结果，是为了**统一验证时点**：
    源返回的结果可能来自几分钟前的查询，重新解析能反映当下状态。
    """
    if not candidates:
        return []

    concurrency = config.discover.brute_concurrency
    semaphore = asyncio.Semaphore(concurrency)

    async def _check(asset: DiscoveredAsset) -> DiscoveredAsset | None:
        async with semaphore:
            ips = await resolve_host(asset.value)
        if not ips:
            return None
        asset.resolved_ip = sorted(ips)[0]
        asset.metadata["all_ips"] = ",".join(sorted(ips))
        return asset

    checked = await asyncio.gather(*(_check(a) for a in candidates))
    alive = [a for a in checked if a is not None]
    logger.info("verify_done candidates=%d alive=%d dropped=%d", len(candidates), len(alive), len(candidates) - len(alive))
    return alive


# ------------------------------------------------------------------ 持久化


def persist_report(report: SubdomainReport, config: Config) -> int:
    """把结果写入数据库，返回资产记录数。

    写入策略：每次收集创建一个新的 ``ScanTask``，而不是覆盖旧数据。
    这是「资产变更 diff」的基础 —— 只有保留历史快照，才能算出
    「相比上次扫描新增/消失了哪些资产」，而这正是攻击面管理平台的核心价值。
    """
    engine = create_db_engine(config.database)
    init_db(engine)

    with session_scope(engine) as session:
        task = ScanTask(
            target=report.root,
            status="success",
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
        )
        task.set_stats(
            total=report.count,
            sources=report.sources_used,
            wildcard_ips=sorted(report.wildcard_ips),
            elapsed=round(report.elapsed, 2),
        )
        session.add(task)
        session.flush()  # 拿到 task.id

        for asset in report.assets:
            session.add(
                Asset(
                    task_id=task.id,
                    type=asset.type,
                    value=asset.value,
                    root_domain=report.root,
                    resolved_ip=asset.resolved_ip,
                    source=asset.metadata.get("sources", asset.source),
                    alive=True,
                    fingerprint=Asset.make_fingerprint(asset.value, asset.type),
                )
            )
        session.commit()
        return report.count


def diff_tasks(config: Config, target: str, limit: int = 2) -> dict[str, list[str]]:
    """对比最近两次扫描，输出资产变更。

    Returns:
        ``{"added": [...], "removed": [...], "unchanged": [...]}``

    这是甲方最买账的功能：从「一次扫描的快照」升级为「持续的资产变化监控」。
    """
    engine = create_db_engine(config.database)
    init_db(engine)

    with session_scope(engine) as session:
        tasks = session.execute(
            select(ScanTask)
            .where(ScanTask.target == target, ScanTask.status == "success")
            .order_by(ScanTask.id.desc())
            .limit(limit)
        ).scalars().all()

        if len(tasks) < 2:
            logger.warning("diff_insufficient_history target=%s tasks=%d", target, len(tasks))
            return {"added": [], "removed": [], "unchanged": []}

        newest, previous = tasks[0], tasks[1]
        current = _asset_values(session, newest.id)
        baseline = _asset_values(session, previous.id)

    return {
        "added": sorted(current - baseline),
        "removed": sorted(baseline - current),
        "unchanged": sorted(current & baseline),
    }


def _asset_values(session: Session, task_id: int) -> set[str]:
    """读取某个任务下的全部资产值。"""
    rows = session.execute(
        select(Asset.value).where(Asset.task_id == task_id)
    ).scalars().all()
    return set(rows)


__all__ = [
    "collect_subdomains",
    "persist_report",
    "diff_tasks",
    "build_sources",
    "SubdomainReport",
    "SOURCE_REGISTRY",
]
