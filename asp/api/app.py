"""FastAPI 接口与 Web 看板后端。

## ⚠️ 这个模块的安全模型（重要）

这个 API **能触发主动扫描**。一个无认证、可被公网访问的扫描接口，
等于把工具变成了别人手里的攻击跳板 —— 而且流量从你的 IP 出去。

所以设了三道约束：

1. **默认只绑定 127.0.0.1** —— 除非显式指定，否则外部访问不到
2. **绑定非回环地址时强制要求 token** —— 没设置 `ASP_API_TOKEN` 直接拒绝启动，
   而不是"警告后照常运行"（警告没人看）
3. **所有会发起网络请求的端点都要带 `X-API-Token` 头** —— 只读端点不强制，
   因为看报告本身不产生流量

这是「安全工具自身必须安全」的又一处体现：工具的能力边界，
本身就是它最大的攻击面。

## 为什么 Web 部分是可选依赖

核心能力只需要 3 个运行时依赖（httpx / SQLAlchemy / PyYAML）。
把 FastAPI + uvicorn 做成 `[api]` extra，是为了让「只想用命令行」的人
不必为此装一整套 Web 框架。

装法：`pip install -e ".[api]"`，然后 `asp serve`。
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Any

from .. import __version__
from ..config import Config, load_config
from ..logger import get_logger
from ..plugins.loader import load_pocs
from ..report import load_target_report
from ..report import render as render_report

logger = get_logger("api")

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Query
    from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
    from pydantic import BaseModel, Field
except ImportError as exc:  # pragma: no cover - 部署期错误
    raise ImportError(
        "Web 接口需要额外依赖，请先安装：\n"
        '    pip install -e ".[api]"\n'
        "然后运行：asp serve"
    ) from exc


STATIC_DIR = Path(__file__).resolve().parent / "static"

#: 触发主动扫描的端点共用的鉴权依赖说明
TOKEN_HEADER = "X-API-Token"


# ------------------------------------------------------------------ 请求模型


class SubdomainRequest(BaseModel):
    """子域名收集请求。"""

    domain: str = Field(..., description="根域名，如 example.com", min_length=1)
    sources: list[str] | None = Field(None, description="来源列表，缺省用配置默认值")
    wordlist: str | None = Field(None, description="爆破字典路径")
    save: bool = Field(True, description="是否写入数据库")


class PortscanRequest(BaseModel):
    """端口扫描请求。"""

    host: str = Field(..., description="目标主机（IP 或域名）", min_length=1)
    ports: str | None = Field(None, description="端口表达式：top / all / 80,443 / 8000-8010")
    with_favicon: bool = Field(True, description="是否获取 favicon 哈希")
    save: bool = Field(True, description="是否写入数据库")


class PocScanRequest(BaseModel):
    """PoC 漏洞验证请求。"""

    target: str = Field(..., description="目标 URL 或主机", min_length=1)
    poc_ids: list[str] | None = Field(None, description="只执行指定 PoC")
    severity: list[str] | None = Field(None, description="按严重级别过滤")
    poc_dirs: list[str] | None = Field(
        None,
        description="额外 PoC 目录（例如配套靶场的基准 PoC：../vulnlab/pocs）",
    )
    negative_control: bool = Field(True, description="是否启用负向对照校验")
    save: bool = Field(True, description="是否写入数据库")


class ScanTriggered(BaseModel):
    """扫描完成后的统一响应。"""

    ok: bool
    target: str
    summary: dict[str, Any]
    elapsed: float


# ------------------------------------------------------------------ 认证


def _is_loopback(host: str) -> bool:
    """判断绑定地址是否为回环地址。"""
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_bind_safety(host: str, token: str | None) -> None:
    """校验绑定地址与 token 的组合是否安全。

    Raises:
        SystemExit: 绑定了非回环地址但没设 token —— 直接拒绝启动。
    """
    if _is_local_or_none(host) and not token:
        return

    if not _is_loopback(host) and not token:
        raise SystemExit(
            f"\n[拒绝启动] 绑定地址 {host} 不是回环地址，但没有设置 API token。\n\n"
            "  这个接口能发起主动扫描 —— 无认证地暴露出去，等于把工具\n"
            "  变成别人手里的攻击跳板，而且流量从你的 IP 出去。\n\n"
            "  如果确实需要远程访问，请设置 token：\n"
            "      export ASP_API_TOKEN=<一串足够长的随机值>\n"
            "  然后客户端请求时带上头：\n"
            f"      {TOKEN_HEADER}: <同一个值>\n\n"
            "  只想本机使用的话，去掉 --host 参数即可（默认 127.0.0.1）。\n"
        )


def _is_local_or_none(host: str) -> bool:
    return _is_loopback(host)


def make_token_dependency(token: str | None):
    """生成 token 校验依赖。

    未配置 token 时（本地模式）依赖直接放行；配置了则必须匹配。
    用 ``hmac.compare_digest`` 做恒定时间比较，避免通过响应时间侧信道爆破 token。
    """

    async def _verify(x_api_token: str | None = Header(default=None)) -> None:
        if not token:
            return
        import hmac

        provided = x_api_token or ""
        if not hmac.compare_digest(provided, token):
            raise HTTPException(status_code=401, detail=f"缺少或错误的 {TOKEN_HEADER} 头")

    return _verify


# ------------------------------------------------------------------ 应用


def create_app(config: Config | None = None, *, token: str | None = None) -> FastAPI:
    """构造 FastAPI 应用。

    Args:
        config: 全局配置，None 则自动加载。
        token: API token，None 则从环境变量 ``ASP_API_TOKEN`` 读取。

    Returns:
        配置好的 FastAPI 实例。
    """
    cfg = config or load_config()
    api_token = token or os.environ.get("ASP_API_TOKEN") or None
    require_token = make_token_dependency(api_token)

    app = FastAPI(
        title="ASP — 攻击面测绘平台",
        description=(
            "外网攻击面自动化测绘与漏洞验证平台的 Web 接口。\n\n"
            "⚠️ 会发起主动扫描的端点需要携带 X-API-Token 头（若服务端配置了 token）。"
        ),
        version=__version__,
    )
    app.state.config = cfg
    app.state.token = api_token

    # ---------------------------------------------------------- 只读端点

    @app.get("/api/health", summary="健康检查")
    async def health() -> dict[str, Any]:
        """返回服务状态与能力开关。"""
        return {
            "status": "ok",
            "version": __version__,
            "auth_required": bool(api_token),
            "database": cfg.database,
            "capabilities": {
                "subdomain": True,
                "portscan": True,
                "fingerprint": cfg.discover.fingerprint_enabled,
                "poc_engine": True,
            },
        }

    @app.get("/api/stats", summary="全局统计")
    async def stats() -> dict[str, Any]:
        """汇总数据库中的目标数、资产数、漏洞数等。"""
        return _collect_global_stats(cfg)

    @app.get("/api/targets", summary="目标列表")
    async def list_targets() -> dict[str, Any]:
        """列出所有被扫描过的目标及其概览。"""
        return {"targets": _collect_targets(cfg)}

    @app.get("/api/targets/{target}", summary="目标详情")
    async def target_detail(target: str) -> dict[str, Any]:
        """单个目标的完整测绘结果（端口 / 组件 / 漏洞 / 变更）。"""
        data = load_target_report(cfg, target)
        if not data.get("has_data"):
            raise HTTPException(status_code=404, detail=f"目标 {target} 没有扫描记录")
        return data

    @app.get("/api/targets/{target}/report", summary="导出报告")
    async def target_report(
        target: str,
        fmt: str = Query("markdown", alias="format", pattern="^(json|md|markdown|html)$"),
    ):
        """按指定格式导出报告。"""
        data = load_target_report(cfg, target)
        if not data.get("has_data"):
            raise HTTPException(status_code=404, detail=f"目标 {target} 没有扫描记录")

        text = render_report(data, fmt)
        media = {
            "json": "application/json",
            "md": "text/markdown; charset=utf-8",
            "markdown": "text/markdown; charset=utf-8",
            "html": "text/html; charset=utf-8",
        }[fmt]
        return PlainTextResponse(text, media_type=media)

    @app.get("/api/pocs", summary="PoC 列表")
    async def list_pocs() -> dict[str, Any]:
        """列出可用的检测插件。"""
        dirs = _poc_dirs(cfg)
        pocs = load_pocs(dirs)
        return {
            "count": len(pocs),
            "pocs": [
                {
                    "id": p.id,
                    "name": p.info.name,
                    "severity": p.info.severity,
                    "tags": p.info.tags,
                }
                for p in pocs
            ],
        }

    # ---------------------------------------------------------- 扫描端点

    @app.post(
        "/api/scan/subdomain",
        response_model=ScanTriggered,
        summary="执行子域名收集",
        dependencies=[Depends(require_token)],
    )
    async def scan_subdomain(payload: SubdomainRequest) -> ScanTriggered:
        """收集目标根域名下的子域名。"""
        from ..services.subdomain import collect_subdomains, persist_report

        report = await collect_subdomains(
            payload.domain,
            cfg,
            sources=payload.sources or None,
            wordlist=payload.wordlist,
        )
        if payload.save:
            persist_report(report, cfg)

        return ScanTriggered(
            ok=True,
            target=report.root,
            summary={
                "count": report.count,
                "sources": report.sources_used,
                "wildcard_ips": sorted(report.wildcard_ips),
                "by_source": report.by_source(),
                "multi_source": len(report.multi_source()),
            },
            elapsed=round(report.elapsed, 2),
        )

    @app.post(
        "/api/scan/portscan",
        response_model=ScanTriggered,
        summary="执行端口扫描与指纹识别",
        dependencies=[Depends(require_token)],
    )
    async def scan_portscan(payload: PortscanRequest) -> ScanTriggered:
        """扫描主机端口、抓取 banner 并识别服务与 Web 组件。"""
        from ..services.host import persist_host_report, scan_and_fingerprint

        report = await scan_and_fingerprint(
            payload.host,
            cfg,
            ports=payload.ports,
            with_favicon=payload.with_favicon,
        )
        if payload.save:
            persist_host_report(report, cfg)

        return ScanTriggered(
            ok=True,
            target=report.host,
            summary={
                "open_ports": report.open_ports,
                "by_service": report.by_service(),
                "components": [c.to_dict() for c in report.all_components],
                "favicons": {str(k): v for k, v in report.favicons.items()},
            },
            elapsed=round(report.elapsed, 2),
        )

    @app.post(
        "/api/scan/poc",
        response_model=ScanTriggered,
        summary="执行漏洞验证",
        dependencies=[Depends(require_token)],
    )
    async def scan_poc(payload: PocScanRequest) -> ScanTriggered:
        """对目标执行 PoC 检测。"""
        from ..core.http import AsyncHttpClient
        from ..plugins.engine import scan_target
        from ..services.vuln import persist_engine_result

        # 支持请求级追加 PoC 目录（例如把配套靶场的基准 PoC 一起加载）
        dirs = _poc_dirs(cfg)
        if payload.poc_dirs:
            dirs.extend(_resolve_extra_dirs(payload.poc_dirs))

        pocs = load_pocs(dirs, severities=payload.severity or None)
        if payload.poc_ids:
            wanted = set(payload.poc_ids)
            pocs = [p for p in pocs if p.id in wanted]
        if not pocs:
            raise HTTPException(status_code=400, detail="没有匹配的 PoC")

        async with AsyncHttpClient(
            concurrency=cfg.discover.concurrency,
            rate_limit=cfg.discover.rate_limit,
            timeout=cfg.http.timeout,
            retries=cfg.http.retries,
            verify_ssl=cfg.http.verify_ssl,
            user_agent=cfg.http.user_agent,
        ) as client:
            result = await scan_target(
                payload.target,
                pocs,
                client,
                negative_control=payload.negative_control,
            )

        if payload.save:
            persist_engine_result(result, cfg)

        return ScanTriggered(
            ok=True,
            target=result.target,
            summary={
                "poc_count": result.poc_count,
                "hit_count": result.hit_count,
                "by_severity": result.by_severity(),
                "vulns": [v.to_dict() for v in result.vulns],
                "errors": result.errors[:10],
            },
            elapsed=round(result.elapsed, 2),
        )

    # ---------------------------------------------------------- 看板

    @app.get("/", include_in_schema=False)
    async def dashboard():
        """返回可视化看板页面。"""
        index = STATIC_DIR / "index.html"
        if not index.exists():
            return JSONResponse(
                status_code=500,
                content={"detail": f"看板文件缺失: {index}"},
            )
        return FileResponse(index, media_type="text/html; charset=utf-8")

    @app.exception_handler(Exception)
    async def unhandled(request, exc):  # pragma: no cover - 兜底
        """把未处理异常收敛成结构化响应，避免把栈回溯暴露给客户端。"""
        logger.error("api_unhandled_error path=%s error=%s", request.url.path, exc)
        return JSONResponse(
            status_code=500, content={"detail": "服务内部错误，详见服务端日志"}
        )

    return app


# ------------------------------------------------------------------ 辅助


def _poc_dirs(config: Config) -> list[Path]:
    """解析 PoC 目录（相对路径按 asp 包目录解析）。"""
    package_dir = Path(__file__).resolve().parent.parent
    resolved: list[Path] = []
    for entry in config.engine.poc_dirs:
        candidate = Path(entry)
        if candidate.is_absolute():
            resolved.append(candidate)
        elif candidate.exists():
            resolved.append(candidate.resolve())
        else:
            resolved.append(package_dir / entry)
    return resolved


def _resolve_extra_dirs(entries: list[str]) -> list[Path]:
    """解析请求里指定的额外目录。

    相对路径按**当前工作目录**解析（而不是包目录）——
    调用方给的是他自己环境里的路径，按包目录解析会指向一个他不认识的地方，
    然后他会看到「0 个 PoC」却不知道为什么。
    """
    resolved: list[Path] = []
    for entry in entries:
        candidate = Path(entry).expanduser()
        if not candidate.is_absolute():
            candidate = (Path.cwd() / candidate).resolve()
        resolved.append(candidate)
    return resolved


def _collect_targets(config: Config) -> list[dict[str, Any]]:
    """从数据库汇总所有目标。"""
    from sqlalchemy import func, select

    from ..core.database import Asset, ScanTask, Vuln, create_db_engine, init_db, session_scope

    engine = create_db_engine(config.database)
    init_db(engine)

    with session_scope(engine) as session:
        rows = session.execute(
            select(
                ScanTask.target,
                func.count(func.distinct(ScanTask.id)).label("task_count"),
                func.max(ScanTask.created_at).label("last_scan"),
            )
            .where(ScanTask.status == "success")
            .group_by(ScanTask.target)
            .order_by(func.max(ScanTask.created_at).desc())
        ).all()

        targets: list[dict[str, Any]] = []
        for target, task_count, last_scan in rows:
            # 该目标下的资产数
            asset_count = session.execute(
                select(func.count(func.distinct(Asset.value)))
                .join(ScanTask, Asset.task_id == ScanTask.id)
                .where(ScanTask.target == target)
            ).scalar_one()

            # 该目标下各严重级别漏洞数
            severity_rows = session.execute(
                select(Vuln.severity, func.count(Vuln.id))
                .join(ScanTask, Vuln.task_id == ScanTask.id)
                .where(ScanTask.target == target)
                .group_by(Vuln.severity)
            ).all()

            targets.append(
                {
                    "target": target,
                    "task_count": task_count,
                    "asset_count": asset_count,
                    "last_scan": last_scan.strftime("%Y-%m-%d %H:%M:%S") if last_scan else "",
                    "vulns": dict(severity_rows),
                    "vuln_total": sum(cnt for _, cnt in severity_rows),
                }
            )
        return targets


def _collect_global_stats(config: Config) -> dict[str, Any]:
    """全局统计。"""
    from sqlalchemy import func, select

    from ..core.database import (
        Asset,
        Component,
        Port,
        ScanTask,
        Vuln,
        create_db_engine,
        init_db,
        session_scope,
    )

    engine = create_db_engine(config.database)
    init_db(engine)

    with session_scope(engine) as session:
        def count(model) -> int:
            return session.execute(select(func.count(model.id))).scalar_one()

        severity_rows = session.execute(
            select(Vuln.severity, func.count(Vuln.id)).group_by(Vuln.severity)
        ).all()

        return {
            "targets": session.execute(
                select(func.count(func.distinct(ScanTask.target)))
            ).scalar_one(),
            "tasks": count(ScanTask),
            "assets": count(Asset),
            "ports": count(Port),
            "components": count(Component),
            "vulns": count(Vuln),
            "by_severity": dict(severity_rows),
        }


# ------------------------------------------------------------------ 启动


def serve(config: Config, host: str = "127.0.0.1", port: int = 8000) -> None:
    """启动 Web 服务。

    Args:
        config: 全局配置。
        host: 绑定地址。非回环地址时必须设置 ``ASP_API_TOKEN``。
        port: 监听端口。
    """
    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover
        raise SystemExit('缺少 uvicorn，请先安装：pip install -e ".[api]"') from exc

    token = os.environ.get("ASP_API_TOKEN") or None
    check_bind_safety(host, token)

    app = create_app(config, token=token)

    display_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    print()
    print("  ASP Web 看板")
    print(f"    地址      http://{display_host}:{port}")
    print(f"    接口文档  http://{display_host}:{port}/docs")
    if token:
        print(f"    鉴权      已启用（请求需带 {TOKEN_HEADER} 头）")
    else:
        print("    鉴权      未启用（仅本机可访问）")
    print()
    print("  停止      Ctrl+C")
    print()

    uvicorn.run(app, host=host, port=port, log_level="warning")


__all__ = ["create_app", "serve", "check_bind_safety", "SubdomainRequest", "PortscanRequest", "PocScanRequest"]
