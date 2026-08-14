"""报告生成：JSON / Markdown / HTML。

## 为什么报告要能导出三种格式

| 格式 | 真实用途 |
|---|---|
| **JSON** | 喂给下一个环节 —— CI、工单系统、自研看板。是「数据」而非「文档」 |
| **Markdown** | 贴进 issue / 知识库 / 群聊，以及让 Git diff 有意义（可版本化追踪） |
| **HTML** | 给不装工具的人看。可以当附件发，也可以直接挂在静态站点上 |

三者不是「同一个东西换个皮」，而是服务于完全不同的消费场景。

## 报告的正确性来源

这里刻意**从数据库读**而不是从内存对象读：

- 从内存读只能反映「本次扫描」，而攻击面管理的价值在于**跨时间的对比**
- 从库读能天然拿到「上一次扫描是什么时候」「哪些资产是新增的」
- 而且报告生成与扫描解耦 —— 可以随时对历史任务重新出报告，不用重扫

这也是为什么 `ScanTask` 要保留历史快照，而不是每次覆盖。
"""

from __future__ import annotations

import html
import json
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import or_, select

from .config import Config
from .core.database import (
    Asset,
    Component,
    Port,
    ScanTask,
    Service,
    Vuln,
    create_db_engine,
    init_db,
    session_scope,
)
from .logger import get_logger

logger = get_logger("report")

#: 严重级别 → (中文名, 颜色)。红涨绿跌不适用，这里按「越危险越红」的国际惯例。
SEVERITY_META: dict[str, tuple[str, str]] = {
    "critical": ("严重", "#b91c1c"),
    "high": ("高危", "#dc2626"),
    "medium": ("中危", "#d97706"),
    "low": ("低危", "#2563eb"),
    "info": ("信息", "#6b7280"),
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


# ------------------------------------------------------------------ 数据加载


def load_target_report(config: Config, target: str, *, task_limit: int = 2) -> dict[str, Any]:
    """从数据库汇总某个目标的最近一次扫描结果。

    Args:
        config: 全局配置。
        target: 目标标识（根域名或主机）。
        task_limit: 取最近 N 次任务用于对比（用于计算新增/消失资产）。

    Returns:
        可直接交给渲染函数的结构化数据。
    """
    engine = create_db_engine(config.database)
    init_db(engine)

    with session_scope(engine) as session:
        # 取该 target 下的【全部】成功任务用于聚合。
        #
        # 踩过的坑：最初只取最近一次任务，结果 `asp poc run` 落库的漏洞
        # （属于另一个 task）在报告里完全看不到，报告永远显示「发现漏洞 0 个」。
        # 同一目标的不同扫描链路（端口/指纹/PoC）本来就该聚合成一份报告。
        tasks: Sequence[ScanTask] = session.execute(
            select(ScanTask)
            .where(ScanTask.target == target, ScanTask.status == "success")
            .order_by(ScanTask.id.desc())
        ).scalars().all()

        if not tasks:
            logger.warning("report_no_task target=%s", target)
            return {
                "target": target,
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "has_data": False,
                "assets": [],
                "ports": [],
                "components": [],
                "vulns": [],
                "stats": {},
                "diff": {},
            }

        current = tasks[0]
        task_ids = [t.id for t in tasks]

        # 汇总所有任务的资产，按 (类型, 值) 去重 —— 同一资产会被多次扫描重复记录，
        # 但报告里应该只出现一次。按 id 倒序保证保留最新一次观测的属性。
        raw_assets = session.execute(
            select(Asset)
            .where(Asset.task_id.in_(task_ids))
            .order_by(Asset.id.desc())
        ).scalars().all()

        seen_asset_keys: set[tuple[str, str]] = set()
        assets: list[Asset] = []
        for asset in raw_assets:
            key = (asset.type, asset.value)
            if key in seen_asset_keys:
                continue
            seen_asset_keys.add(key)
            assets.append(asset)
        assets.sort(key=lambda a: a.value)

        # 关键：查端口/服务必须用【未去重】的全部 asset id。
        #
        # 去重后的 assets 只保留了每个值的最新一条记录，但端口数据可能挂在
        # 被丢弃的那条上 —— 例如 portscan 创建的 asset 与 poc run 创建的 asset
        # 值相同但是两行不同记录。用去重后的 id 查端口，结果永远是 0。
        all_asset_ids = [a.id for a in raw_assets]
        asset_value_by_id = {a.id: a.value for a in raw_assets}

        ports: list[Port] = []
        if all_asset_ids:
            raw_ports = session.execute(
                select(Port)
                .where(Port.asset_id.in_(all_asset_ids))
                .order_by(Port.id.desc())
            ).scalars().all()
            # 按 (资产值, 端口号) 去重，而不是按 (asset_id, 端口号) ——
            # 同一台主机可能有多条 asset 记录，但它们描述的是同一台机器。
            seen_port_keys: set[tuple[str, int]] = set()
            for port in raw_ports:
                key = (asset_value_by_id.get(port.asset_id, ""), port.number)
                if key in seen_port_keys:
                    continue
                seen_port_keys.add(key)
                ports.append(port)
            ports.sort(key=lambda p: p.number)

        port_ids = [p.id for p in ports]
        services: list[Service] = []
        if port_ids:
            services = session.execute(
                select(Service).where(Service.port_id.in_(port_ids))
            ).scalars().all()

        service_ids = [s.id for s in services]
        components: list[Component] = []
        if service_ids:
            components = session.execute(
                select(Component)
                .where(Component.service_id.in_(service_ids))
                .order_by(Component.confidence.desc())
            ).scalars().all()

        # 漏洞两条路径都要查：
        #   ① 按 task_id —— 覆盖独立 PoC 扫描产生的漏洞（无上游组件）
        #   ② 按 component_id —— 覆盖挂在组件上的漏洞（指纹识别后再测出来的）
        # 只查其中一条都会漏掉另一半，这是修过一次的 bug。
        vuln_conditions = [Vuln.task_id.in_(task_ids)]
        if service_ids:
            vuln_conditions.append(Vuln.component_id.in_(service_ids))
        vulns: list[Vuln] = session.execute(
            select(Vuln).where(or_(*vuln_conditions)).order_by(Vuln.severity)
        ).scalars().all()

        # 上一次任务的资产集合，用于计算新增
        diff: dict[str, list[str]] = {"added": [], "removed": []}
        if len(tasks) >= 2:
            previous_values = set(
                session.execute(
                    select(Asset.value).where(Asset.task_id == tasks[1].id)
                ).scalars().all()
            )
            current_values = {a.value for a in assets}
            diff["added"] = sorted(current_values - previous_values)
            diff["removed"] = sorted(previous_values - current_values)

        service_by_port = {s.port_id: s for s in services}
        asset_by_id = {a.id: a for a in raw_assets}

        payload = {
            "target": target,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "has_data": True,
            "task_id": current.id,
            "scanned_at": current.started_at.strftime("%Y-%m-%d %H:%M:%S")
            if current.started_at
            else "",
            "duration": round(current.duration, 2) if current.duration else None,
            "assets": [
                {
                    "value": a.value,
                    "type": a.type,
                    "root_domain": a.root_domain,
                    "resolved_ip": a.resolved_ip or "",
                    "source": a.source,
                    "alive": a.alive,
                }
                for a in assets
            ],
            "ports": [
                {
                    "host": asset_by_id[p.asset_id].value if p.asset_id in asset_by_id else "",
                    "number": p.number,
                    "protocol": p.protocol,
                    "state": p.state,
                    "service": service_by_port[p.id].name if p.id in service_by_port else "",
                    "product": service_by_port[p.id].product if p.id in service_by_port else "",
                    "version": service_by_port[p.id].version if p.id in service_by_port else "",
                    "title": service_by_port[p.id].http_title if p.id in service_by_port else "",
                    "banner": (p.banner or "")[:200],
                }
                for p in ports
            ],
            "components": [
                {
                    "name": c.name,
                    "version": c.version,
                    "category": c.category,
                    "confidence": round(c.confidence, 2),
                    "evidence": c.evidence,
                }
                for c in components
            ],
            "vulns": [
                {
                    "poc_id": v.poc_id,
                    "name": v.name,
                    "severity": v.severity,
                    "target": v.target,
                    "confidence": round(v.confidence, 2),
                    "verified": v.verified,
                    "evidence": v.evidence,
                }
                for v in vulns
            ],
            "diff": diff,
            "stats": {
                "asset_count": len(assets),
                "open_port_count": len(ports),
                "component_count": len(components),
                "vuln_count": len(vulns),
                "by_severity": _count_by_severity(vulns),
                "by_category": _count_by(list(components), "category"),
            },
        }

    return payload


def _count_by_severity(vulns: Sequence[Vuln]) -> dict[str, int]:
    """统计各严重级别的漏洞数。"""
    stats: dict[str, int] = {}
    for vuln in vulns:
        stats[vuln.severity] = stats.get(vuln.severity, 0) + 1
    return stats


def _count_by(items: list, attribute: str) -> dict[str, int]:
    """按某个属性分组计数。"""
    stats: dict[str, int] = {}
    for item in items:
        key = getattr(item, attribute, "") or "unknown"
        stats[key] = stats.get(key, 0) + 1
    return stats


# ------------------------------------------------------------------ 渲染


def to_json(data: dict[str, Any]) -> str:
    """渲染为 JSON。"""
    return json.dumps(data, ensure_ascii=False, indent=2)


def to_markdown(data: dict[str, Any]) -> str:
    """渲染为 Markdown 报告。"""
    if not data.get("has_data"):
        return f"# 攻击面报告 · {data['target']}\n\n> 该目标暂无扫描记录。\n"

    stats = data.get("stats", {})
    lines: list[str] = []

    lines.append(f"# 攻击面测绘报告 · {data['target']}")
    lines.append("")
    lines.append(f"- 生成时间：{data['generated_at']}")
    lines.append(f"- 扫描时间：{data.get('scanned_at', '-')}")
    if data.get("duration"):
        lines.append(f"- 扫描耗时：{data['duration']} 秒")
    lines.append("")

    lines.append("## 概览")
    lines.append("")
    lines.append("| 指标 | 数值 |")
    lines.append("| --- | --- |")
    lines.append(f"| 资产数 | {stats.get('asset_count', 0)} |")
    lines.append(f"| 开放端口 | {stats.get('open_port_count', 0)} |")
    lines.append(f"| 识别组件 | {stats.get('component_count', 0)} |")
    lines.append(f"| 发现漏洞 | {stats.get('vuln_count', 0)} |")
    lines.append("")

    by_severity = stats.get("by_severity", {})
    if by_severity:
        lines.append("严重级别分布：")
        lines.append("")
        for level in SEVERITY_ORDER:
            count = by_severity.get(level, 0)
            if count:
                label, _ = SEVERITY_META.get(level, (level, ""))
                lines.append(f"- **{label}**（{level}）：{count}")
        lines.append("")

    diff = data.get("diff", {})
    if diff and (diff.get("added") or diff.get("removed")):
        lines.append("## 相比上次扫描的变化")
        lines.append("")
        if diff.get("added"):
            lines.append(f"新增 {len(diff['added'])} 项：")
            lines.append("")
            for value in diff["added"][:30]:
                lines.append(f"- `+` {value}")
            lines.append("")
        if diff.get("removed"):
            lines.append(f"消失 {len(diff['removed'])} 项：")
            lines.append("")
            for value in diff["removed"][:30]:
                lines.append(f"- `-` {value}")
            lines.append("")

    if data.get("vulns"):
        lines.append("## 漏洞详情")
        lines.append("")
        for vuln in data["vulns"]:
            label, _ = SEVERITY_META.get(vuln["severity"], (vuln["severity"], ""))
            lines.append(f"### [{label}] {vuln['name']}")
            lines.append("")
            lines.append(f"- PoC：`{vuln['poc_id']}`")
            lines.append(f"- 目标：`{vuln['target']}`")
            lines.append(f"- 置信度：{vuln['confidence']}")
            lines.append(f"- 二次验证：{'通过' if vuln.get('verified') else '未执行'}")
            if vuln.get("evidence"):
                lines.append(f"- 证据：`{vuln['evidence'][:200]}`")
            lines.append("")

    if data.get("ports"):
        lines.append("## 开放端口与服务")
        lines.append("")
        lines.append("| 主机 | 端口 | 服务 | 产品 | 版本 | 标题 |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for port in data["ports"]:
            lines.append(
                f"| {port['host']} | {port['number']}/{port['protocol']} | "
                f"{port['service'] or '-'} | {port['product'] or '-'} | "
                f"{port['version'] or '-'} | {(port['title'] or '-')[:40]} |"
            )
        lines.append("")

    if data.get("components"):
        lines.append("## 识别到的组件")
        lines.append("")
        lines.append("| 组件 | 版本 | 类别 | 置信度 |")
        lines.append("| --- | --- | --- | --- |")
        for comp in data["components"]:
            lines.append(
                f"| {comp['name']} | {comp['version'] or '-'} | "
                f"{comp['category'] or '-'} | {comp['confidence']} |"
            )
        lines.append("")

    if data.get("assets"):
        lines.append("## 资产清单")
        lines.append("")
        lines.append("| 资产 | 类型 | 解析 IP | 来源 |")
        lines.append("| --- | --- | --- | --- |")
        for asset in data["assets"][:200]:
            lines.append(
                f"| {asset['value']} | {asset['type']} | "
                f"{asset['resolved_ip'] or '-'} | {asset['source'] or '-'} |"
            )
        if len(data["assets"]) > 200:
            lines.append("")
            lines.append(f"> 仅显示前 200 条，共 {len(data['assets'])} 条。")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("> 本报告由 ASP（攻击面测绘平台）生成，仅用于授权范围内的安全评估。")
    return "\n".join(lines)


def to_html(data: dict[str, Any]) -> str:
    """渲染为独立 HTML 报告（内联 CSS，无外部依赖，可直接作为附件发送）。"""
    target = html.escape(str(data.get("target", "")))

    if not data.get("has_data"):
        return (
            "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
            f"<title>攻击面报告 · {target}</title></head><body>"
            f"<h1>攻击面报告 · {target}</h1><p>该目标暂无扫描记录。</p></body></html>"
        )

    stats = data.get("stats", {})
    by_severity = stats.get("by_severity", {})

    # ---- 严重级别分布条 ----
    severity_rows = []
    total_vulns = max(1, stats.get("vuln_count", 0))
    for level in SEVERITY_ORDER:
        count = by_severity.get(level, 0)
        if not count:
            continue
        label, color = SEVERITY_META.get(level, (level, "#6b7280"))
        width = count / total_vulns * 100
        severity_rows.append(
            f'<div style="margin-bottom:8px">'
            f'<div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:4px">'
            f'<span style="color:{color};font-weight:500">{label}</span>'
            f'<span style="color:#6b7280">{count}</span></div>'
            f'<div style="height:6px;background:#f1f1f4;border-radius:3px;overflow:hidden">'
            f'<div style="width:{width:.1f}%;height:100%;background:{color};border-radius:3px"></div>'
            f"</div></div>"
        )

    # ---- 概览卡片 ----
    cards = [
        ("资产数", stats.get("asset_count", 0)),
        ("开放端口", stats.get("open_port_count", 0)),
        ("识别组件", stats.get("component_count", 0)),
        ("发现漏洞", stats.get("vuln_count", 0)),
    ]
    cards_html = "".join(
        f'<div style="background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:16px">'
        f'<div style="font-size:13px;color:#6b7280;margin-bottom:6px">{name}</div>'
        f'<div style="font-size:24px;font-weight:500">{value}</div></div>'
        for name, value in cards
    )

    # ---- 漏洞列表 ----
    vuln_html = ""
    if data.get("vulns"):
        items = []
        for vuln in data["vulns"]:
            label, color = SEVERITY_META.get(vuln["severity"], (vuln["severity"], "#6b7280"))
            evidence = html.escape(str(vuln.get("evidence", ""))[:300])
            items.append(
                f'<div style="border:1px solid #e5e7eb;border-radius:10px;padding:14px 16px;margin-bottom:10px">'
                f'<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">'
                f'<span style="background:{color};color:#fff;font-size:12px;padding:2px 8px;border-radius:4px">{label}</span>'
                f'<b style="font-size:14px">{html.escape(vuln["name"])}</b>'
                f'<span style="margin-left:auto;font-size:12px;color:#6b7280">置信度 {vuln["confidence"]}</span>'
                f"</div>"
                f'<div style="font-family:Consolas,monospace;font-size:12px;color:#374151;word-break:break-all;margin-bottom:6px">'
                f'{html.escape(vuln["target"])}</div>'
                + (
                    f'<div style="font-family:Consolas,monospace;font-size:12px;color:#6b7280;'
                    f'background:#f9fafb;padding:8px;border-radius:6px">证据：{evidence}</div>'
                    if evidence
                    else ""
                )
                + "</div>"
            )
        vuln_html = "".join(items)

    # ---- 端口表 ----
    ports_html = ""
    if data.get("ports"):
        rows = "".join(
            f"<tr><td>{html.escape(port['host'])}</td>"
            f'<td style="font-family:Consolas,monospace">{port["number"]}/{html.escape(port["protocol"])}</td>'
            f"<td>{html.escape(port['service'] or '-')}</td>"
            f"<td>{html.escape(port['product'] or '-')}</td>"
            f"<td>{html.escape(port['version'] or '-')}</td>"
            f"<td>{html.escape((port['title'] or '-')[:50])}</td></tr>"
            for port in data["ports"]
        )
        ports_html = (
            "<table><thead><tr><th>主机</th><th>端口</th><th>服务</th>"
            f"<th>产品</th><th>版本</th><th>标题</th></tr></thead><tbody>{rows}</tbody></table>"
        )

    # ---- 组件表 ----
    components_html = ""
    if data.get("components"):
        rows = "".join(
            f"<tr><td>{html.escape(comp['name'])}</td>"
            f"<td>{html.escape(comp['version'] or '-')}</td>"
            f"<td>{html.escape(comp['category'] or '-')}</td>"
            f'<td><div style="display:flex;align-items:center;gap:8px">'
            f'<div style="flex:1;height:5px;background:#f1f1f4;border-radius:3px;overflow:hidden">'
            f'<div style="width:{comp["confidence"] * 100:.0f}%;height:100%;background:#2563eb"></div></div>'
            f'<span style="font-size:12px;color:#6b7280">{comp["confidence"]}</span></div></td></tr>'
            for comp in data["components"]
        )
        components_html = (
            "<table><thead><tr><th>组件</th><th>版本</th><th>类别</th><th>置信度</th>"
            f"</tr></thead><tbody>{rows}</tbody></table>"
        )

    # ---- 资产表 ----
    assets_html = ""
    if data.get("assets"):
        shown = data["assets"][:300]
        rows = "".join(
            f"<tr><td>{html.escape(asset['value'])}</td>"
            f"<td>{html.escape(asset['type'])}</td>"
            f'<td style="font-family:Consolas,monospace">{html.escape(asset["resolved_ip"] or "-")}</td>'
            f"<td>{html.escape(asset['source'] or '-')}</td></tr>"
            for asset in shown
        )
        more = (
            f'<p style="color:#6b7280;font-size:13px">仅显示前 300 条，共 {len(data["assets"])} 条。</p>'
            if len(data["assets"]) > 300
            else ""
        )
        assets_html = (
            "<table><thead><tr><th>资产</th><th>类型</th><th>解析 IP</th><th>来源</th>"
            f"</tr></thead><tbody>{rows}</tbody></table>{more}"
        )

    # ---- 变更 ----
    diff_html = ""
    diff = data.get("diff", {})
    if diff and (diff.get("added") or diff.get("removed")):
        added = "".join(f"<li><code>+ {html.escape(v)}</code></li>" for v in diff["added"][:50])
        removed = "".join(f"<li><code>- {html.escape(v)}</code></li>" for v in diff["removed"][:50])
        diff_html = (
            "<h2>相比上次扫描的变化</h2>"
            f'<div style="display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(240px,1fr))">'
            f'<div style="background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:14px">'
            f'<b style="color:#059669">新增 {len(diff["added"])}</b><ul style="font-size:12px">{added or "<li>-</li>"}</ul></div>'
            f'<div style="background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:14px">'
            f'<b style="color:#dc2626">消失 {len(diff["removed"])}</b><ul style="font-size:12px">{removed or "<li>-</li>"}</ul></div>'
            f"</div>"
        )

    def section(title: str, content: str) -> str:
        return f"<h2>{title}</h2>{content}" if content else ""

    duration_line = (
        f'<span>耗时 {data["duration"]} 秒</span>' if data.get("duration") else ""
    )

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>攻击面测绘报告 · {target}</title>
<style>
*{{box-sizing:border-box}}
body{{margin:0;background:#f7f8fa;color:#1f2328;
  font:15px/1.65 -apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;
  -webkit-font-smoothing:antialiased}}
.wrap{{max-width:1000px;margin:0 auto;padding:40px 24px 80px}}
h1{{font-size:26px;font-weight:500;letter-spacing:-.02em;margin:0 0 8px}}
h2{{font-size:17px;font-weight:500;margin:36px 0 14px;letter-spacing:-.01em}}
.meta{{color:#6b7280;font-size:14px;display:flex;gap:18px;flex-wrap:wrap;margin-bottom:26px}}
.cards{{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));margin-bottom:8px}}
table{{width:100%;border-collapse:collapse;font-size:14px;background:#fff;
  border:1px solid #e5e7eb;border-radius:10px;overflow:hidden}}
th,td{{text-align:left;padding:10px 13px;border-bottom:1px solid #f0f1f4}}
th{{background:#fafbfc;color:#6b7280;font-weight:500;font-size:13px}}
tr:last-child td{{border-bottom:none}}
code{{background:#f1f1f4;padding:1px 6px;border-radius:4px;font-family:Consolas,monospace;font-size:12px}}
ul{{padding-left:18px;margin:8px 0 0}}
li{{margin:3px 0}}
.note{{margin-top:36px;padding-top:18px;border-top:1px solid #e5e7eb;color:#9ca3af;font-size:13px}}
.panel{{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:18px 20px}}
</style>
</head>
<body>
<div class="wrap">
  <h1>攻击面测绘报告</h1>
  <div class="meta">
    <span>目标 <b>{target}</b></span>
    <span>扫描时间 {data.get('scanned_at') or '-'}</span>
    <span>生成时间 {data['generated_at']}</span>
    {duration_line}
  </div>

  <div class="cards">{cards_html}</div>

  {f'<h2>严重级别分布</h2><div class="panel">{chr(10).join(severity_rows)}</div>' if severity_rows else ''}

  {diff_html}

  {section('漏洞详情', vuln_html)}
  {section('开放端口与服务', ports_html)}
  {section('识别到的组件', components_html)}
  {section('资产清单', assets_html)}

  <div class="note">
    <p>本报告由 <b>ASP</b>（外网攻击面自动化测绘与漏洞验证平台）生成。</p>
    <p>⚠️ 报告内容仅用于授权范围内的安全评估。工具本身不判断授权状态，使用者需自行确保合规。</p>
  </div>
</div>
</body>
</html>
"""


RENDERERS = {
    "json": to_json,
    "md": to_markdown,
    "markdown": to_markdown,
    "html": to_html,
}


def render(data: dict[str, Any], fmt: str) -> str:
    """按格式渲染报告。

    Args:
        data: ``load_target_report`` 的返回值。
        fmt: ``json`` / ``md`` / ``markdown`` / ``html``。

    Raises:
        ValueError: 不支持的格式。
    """
    key = fmt.strip().lower()
    renderer = RENDERERS.get(key)
    if renderer is None:
        raise ValueError(f"不支持的报告格式: {fmt}（可选：{', '.join(sorted(RENDERERS))}）")
    return renderer(data)


__all__ = [
    "load_target_report",
    "to_json",
    "to_markdown",
    "to_html",
    "render",
    "RENDERERS",
    "SEVERITY_META",
    "SEVERITY_ORDER",
]
