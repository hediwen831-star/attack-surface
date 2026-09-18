"""漏洞结果持久化。

把 PoC 引擎的执行结果写入数据库，让「扫描 → 漏洞 → 报告」形成闭环。

## 为什么漏洞记录要允许 component_id 为空

数据模型里漏洞挂在 `Component` 下（组件 → 漏洞），这在「先做指纹识别、
再按组件匹配 CVE」的流程里是自然的。

但实际使用中还有另一条路径：直接对目标跑一遍 PoC（`asp poc run`），
此时根本没有组件记录 —— 我们没有先做指纹识别，只是拿 PoC 试了一下。

如果把 `component_id` 设成非空，这条路径的发现就**写不进数据库**，
于是报告里永远是「发现漏洞 0 个」。这不是数据模型该有的限制 ——
**发现本身是有价值的，不该因为没有上游记录就被丢掉。**
"""

from __future__ import annotations

from datetime import UTC, datetime

from ..config import Config
from ..core.database import (
    Asset,
    ScanTask,
    Vuln,
    create_db_engine,
    init_db,
    session_scope,
)
from ..logger import get_logger
from ..plugins.engine import EngineResult

logger = get_logger("services.vuln")


def persist_engine_result(result: EngineResult, config: Config) -> int:
    """把一次 PoC 扫描的结果写入数据库。

    Args:
        result: 引擎执行结果。
        config: 全局配置。

    Returns:
        写入的漏洞记录数。
    """
    engine = create_db_engine(config.database)
    init_db(engine)

    # target 归一化成主机名，让 `asp poc run http://1.2.3.4:8080` 与
    # `asp portscan 1.2.3.4` 的结果能聚合进同一份报告。
    # 完整 URL 信息没有丢失 —— 它保留在每条 Vuln.target 字段里。
    host = normalize_target(result.target)

    with session_scope(engine) as session:
        task = ScanTask(
            target=host,
            status="success",
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
        )
        task.set_stats(
            pocs=result.poc_count,
            hits=result.hit_count,
            by_severity=result.by_severity(),
            elapsed=round(result.elapsed, 2),
            errors=len(result.errors),
        )
        session.add(task)
        session.flush()

        # 目标本身作为一条资产（即便没有做端口/指纹识别，也要留下记录）
        asset = Asset(
            task_id=task.id,
            type="ip" if _looks_like_ip(host) else "domain",
            value=host,
            root_domain=host,
            alive=True,
            fingerprint=Asset.make_fingerprint(host, "target"),
        )
        session.add(asset)
        session.flush()

        for vuln in result.vulns:
            session.add(
                Vuln(
                    task_id=task.id,          # 直接挂任务，报告按 task 聚合时才能查到
                    component_id=None,        # 独立 PoC 扫描没有上游组件记录
                    poc_id=vuln.poc_id,
                    name=vuln.name,
                    severity=vuln.severity,
                    target=vuln.target[:512],
                    matched_at=(vuln.evidence[0] if vuln.evidence else "")[:512],
                    evidence="\n".join(vuln.evidence)[:4000],
                    detail=_detail_json(vuln.extracted, vuln.tags),
                    confidence=vuln.confidence,
                    verified=vuln.verified,
                )
            )

        session.commit()
        count = len(result.vulns)

    logger.info("vulns_persisted target=%s count=%d", result.target, count)
    return count


def _detail_json(extracted: dict[str, str], tags: list[str]) -> str:
    """把提取器结果与标签打包成 JSON 字符串。"""
    import json

    return json.dumps(
        {"extracted": extracted, "tags": tags}, ensure_ascii=False
    )[:4000]


def normalize_target(target: str) -> str:
    """把任意形式的 target 归一化成主机名。

    聚合的前提：同一台主机无论用什么形式指定，都应该归到同一个 target 下，
    否则报告会碎成好几份，diff 也失去意义。

        http://1.2.3.4:8080/path  →  1.2.3.4
        https://example.com/      →  example.com
        example.com:443           →  example.com
        [::1]:8080                →  ::1

    Args:
        target: 任意形式的 target。

    Returns:
        归一化后的主机名。
    """
    raw = target.strip()

    # 去掉协议
    if "://" in raw:
        raw = raw.split("://", 1)[1]

    # 去掉路径与查询串
    raw = raw.split("/")[0].split("?")[0]

    # 去掉认证信息（user:pass@host）
    if "@" in raw:
        raw = raw.rsplit("@", 1)[1]

    # IPv6 字面量用方括号包裹
    if raw.startswith("["):
        return raw.split("]", 1)[0].lstrip("[")

    # 去掉端口。注意 IPv6 未加括号时含多个冒号，不能简单 split(":")
    if raw.count(":") == 1:
        raw = raw.split(":", 1)[0]

    return raw.rstrip(".").lower()


def _looks_like_ip(value: str) -> bool:
    """粗略判断目标是不是 IP（含 IPv6 的简单情形）。

    不追求完备 —— 这里只影响资产记录的 `type` 字段，判错也不会有严重后果。
    """
    host = value.split("://")[-1].split("/")[0].split(":")[0]
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return ":" in host


__all__ = ["persist_engine_result", "normalize_target"]
