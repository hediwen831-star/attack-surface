"""PoC 执行引擎。

## 引擎的职责边界

引擎**不关心**「这个漏洞是什么」，它只做四件事：

1. 把 PoC 里的 ``{{BaseURL}}`` 之类的变量替换成真实地址
2. 发请求（复用带限速/重试的 HTTP 客户端）
3. 跑匹配器，判定是否命中
4. **做负向对照校验**，把误报挡在结果之外

第 4 点是最容易被忽略、但对报告质量影响最大的一环，下面单独说明。

## 负向对照校验（Negative Control）

问题：很多站点对所有路径都返回 200 + 一个通用页面（SPA 的 index.html
回退、自定义 404 页、WAF 的拦截页）。此时一个只写了
``type: status, status: [200]`` 的 PoC 会命中**所有** URL，包括不存在的路径。

解法：命中之后，再发一个请求到同一层级下的**随机路径**，例如：

    命中的是: GET /admin/config.php     → 200 + "[core]"
    对照请求: GET /admin/asp-ctl-a1b2c3 → 200 + "[core]"   ← 同样命中

对照请求也命中了，说明这个特征是「页面的通用特征」而非「该路径的特殊特征」→ 判定为误报，丢弃。

对照请求没命中，说明 ``/admin/config.php`` 确实特殊 → 保留。

这一步把「存在 X 漏洞」从「这个特征出现了」升级为
「这个特征**只在这个路径**出现」，是自研引擎相对脚本拼凑的核心差异点。

## 已知局限

- 对于目标会返回随机内容的场景（如每次响应都带随机 token），
  对照会不稳定 —— 此时应该用 ``type: regex`` 匹配稳定的结构而非动态值。
- 对照请求会给目标增加一倍流量。对脆弱目标建议关闭（``negative_control=False``）。
"""

from __future__ import annotations

import asyncio
import json
import random
import string
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from ..core.http import AsyncHttpClient, Response
from ..exceptions import PluginError
from ..logger import get_logger
from .loader import PoC, PoCRequest
from .matchers import evaluate_matchers, run_extractors

logger = get_logger("plugins.engine")

#: 随机对照路径的前缀 —— 同样带上可识别前缀，方便目标方识别我们的探测行为
CONTROL_PREFIX = "asp-ctl-"


@dataclass
class VulnResult:
    """一条漏洞命中记录。"""

    poc_id: str
    name: str
    severity: str
    target: str
    """命中的完整 URL。"""

    confidence: float = 1.0
    verified: bool = False
    """是否通过负向对照校验。"""

    evidence: list[str] = field(default_factory=list)
    extracted: dict[str, str] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """转成可序列化的字典（报告/JSON 输出用）。"""
        return {
            "poc_id": self.poc_id,
            "name": self.name,
            "severity": self.severity,
            "target": self.target,
            "confidence": self.confidence,
            "verified": self.verified,
            "evidence": self.evidence,
            "extracted": self.extracted,
            "tags": self.tags,
        }


@dataclass
class EngineResult:
    """一次目标扫描的汇总结果。"""

    target: str
    vulns: list[VulnResult] = field(default_factory=list)
    tested: int = 0
    """执行的请求数（含对照请求）。"""

    poc_count: int = 0
    elapsed: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def hit_count(self) -> int:
        """漏洞条目数。"""
        return len(self.vulns)

    def by_severity(self) -> dict[str, int]:
        """按严重级别统计。"""
        stats: dict[str, int] = {}
        for vuln in self.vulns:
            stats[vuln.severity] = stats.get(vuln.severity, 0) + 1
        return stats


# ------------------------------------------------------------------- 变量


def build_variables(target: str) -> dict[str, str]:
    """构造 PoC 模板变量。

    支持 ``{{BaseURL}}`` / ``{{RootURL}}`` / ``{{Hostname}}`` / ``{{Port}}`` / ``{{Scheme}}``。

    对没有写协议的 target（``example.com``）自动补 ``http://`` ——
    因为用户输入的往往是域名而不是 URL，不该让他为此报错。
    """
    raw = target.strip()
    if "://" not in raw:
        raw = f"http://{raw}"

    parsed = urlparse(raw)
    scheme = parsed.scheme or "http"
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)

    # RootURL 不含端口（用于 Host 匹配），BaseURL 含端口（用于实际请求）
    root = f"{scheme}://{hostname}"
    base = f"{scheme}://{parsed.netloc}" if parsed.netloc else root

    return {
        "BaseURL": base,
        "RootURL": root,
        "Hostname": hostname,
        "Port": str(port),
        "Scheme": scheme,
        "Host": parsed.netloc or hostname,
    }


def render(template: str, variables: dict[str, str]) -> str:
    """替换模板变量。

    实现取舍：用简单的字符串替换而不是 Jinja2。
    原因：PoC 是外部输入，模板引擎的表达式求值是额外的攻击面；
    我们只需要 ``{{Var}}`` 这一种语法，手写替换既够用又安全。
    """
    result = template
    for key, value in variables.items():
        result = result.replace(f"{{{{{key}}}}}", value)
    return result


# ------------------------------------------------------------------- 校验


def _random_control_url(url: str) -> str:
    """基于命中 URL 生成同层级的随机对照 URL。

    保留目录部分，只替换最后一段为随机串。
    这样对照请求落在同一个应用路由下 —— 如果该应用有「统一 200 回退」，
    对照请求也会命中，从而暴露误报。
    """
    parsed = urlparse(url)
    path = parsed.path
    # 只保留目录部分，把最后一段（文件名）换成随机串。
    # 形如 /a/b/c.php → /a/b/；/c.php → /
    directory = path.rsplit("/", 1)[0] if "/" in path.rsplit("?", 1)[0][1:] else ""
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    control_path = f"{directory}/{CONTROL_PREFIX}{suffix}"
    return f"{parsed.scheme}://{parsed.netloc}{control_path}"


async def _negative_control(
    request: PoCRequest, hit_url: str, client: AsyncHttpClient
) -> bool:
    """负向对照校验。

    Returns:
        True 表示通过校验（是真漏洞）；False 表示对照也命中（误报）。
    """
    control_url = _random_control_url(hit_url)

    try:
        resp = await client.request(
            request.method,
            control_url,
            headers=request.headers or None,
            content=request.body.encode() if request.body else None,
        )
    except Exception as exc:  # noqa: BLE001 - 对照失败不能算误报，保守放过
        logger.debug("control_request_failed url=%s error=%s", control_url, exc)
        return True

    if not resp.ok:
        # 对照请求本身失败（超时/连不上），无法判定，保守认为通过
        return True

    try:
        outcome = evaluate_matchers(
            request.matchers, resp, condition=request.matchers_condition
        )
    except PluginError:
        return True

    if outcome.matched:
        logger.debug(
            "negative_control_rejected url=%s control=%s evidence=%s",
            hit_url,
            control_url,
            outcome.evidences,
        )
        return False
    return True


# ------------------------------------------------------------------- 执行


async def run_request(
    request: PoCRequest,
    variables: dict[str, str],
    client: AsyncHttpClient,
    *,
    poc_id: str = "",
    negative_control: bool = True,
    errors: list[str] | None = None,
) -> list[tuple[str, Response, Any]]:
    """执行一条 PoCRequest，返回所有命中的 ``(url, response, outcome)``。

    Args:
        errors: 可选的错误收集器。PoC 内部的匹配器写错时，
            错误会被记录进去而不是静默丢弃 ——
            「检测没结果」和「PoC 写错了」是两种完全不同的情况，
            用户必须能区分。这是踩过坑之后加上的设计。
    """
    hits: list[tuple[str, Response, Any]] = []

    for path_template in request.paths:
        url = render(path_template, variables)
        if not url.startswith(("http://", "https://")):
            message = f"渲染后的 URL 不合法: {url}"
            if errors is not None:
                errors.append(f"[{poc_id}] {message}")
            raise PluginError(message, poc_id=poc_id, url=url)

        try:
            resp = await client.request(
                request.method,
                url,
                headers=request.headers or None,
                content=request.body.encode() if request.body else None,
            )
        except Exception as exc:  # noqa: BLE001 - 单条请求失败不影响其他 path
            logger.debug("poc_request_failed poc=%s url=%s error=%s", poc_id, url, exc)
            if errors is not None:
                errors.append(f"[{poc_id}] 请求失败 {url}: {exc}")
            continue

        if not resp.ok:
            # 网络层失败：不算命中，但要记录下来，否则会静默漏报
            logger.debug("poc_request_error poc=%s url=%s error=%s", poc_id, url, resp.error)
            if errors is not None:
                errors.append(f"[{poc_id}] 请求异常 {url}: {resp.error}")
            continue

        try:
            outcome = evaluate_matchers(
                request.matchers, resp, condition=request.matchers_condition
            )
        except PluginError as exc:
            logger.warning("matcher_failed poc=%s url=%s error=%s", poc_id, url, exc)
            if errors is not None:
                errors.append(f"[{poc_id}] 匹配器错误 @ {url}: {exc}")
            continue

        if not outcome.matched:
            continue

        hits.append((url, resp, outcome))

    return hits


async def run_poc(
    poc: PoC,
    target: str,
    client: AsyncHttpClient,
    *,
    negative_control: bool = True,
    errors: list[str] | None = None,
) -> list[VulnResult]:
    """对单个目标执行一个 PoC。

    Args:
        poc: 要执行的 PoC。
        target: 目标地址（域名或 URL）。
        client: 共享 HTTP 客户端。
        negative_control: 是否启用负向对照校验。
        errors: 可选的错误收集器，用于把 PoC 自身的错误暴露给上层。

    Returns:
        命中的漏洞列表（可能为空，也可能多条 —— 一个 PoC 可以有多个 path）。
    """
    variables = build_variables(target)
    results: list[VulnResult] = []

    for request in poc.requests:
        try:
            hits = await run_request(
                request,
                variables,
                client,
                poc_id=poc.id,
                negative_control=negative_control,
                errors=errors,
            )
        except PluginError as exc:
            logger.warning("poc_exec_failed poc=%s error=%s", poc.id, exc)
            if errors is not None:
                errors.append(f"[{poc.id}] 执行失败: {exc}")
            continue

        for url, resp, outcome in hits:
            verified = True
            if negative_control:
                verified = await _negative_control(request, url, client)

            if not verified:
                logger.info("false_positive_filtered poc=%s url=%s", poc.id, url)
                continue

            try:
                extracted = run_extractors(request.extractors, resp) if request.extractors else {}
            except PluginError as exc:
                logger.warning("extractor_failed poc=%s error=%s", poc.id, exc)
                extracted = {}

            results.append(
                VulnResult(
                    poc_id=poc.id,
                    name=poc.info.name,
                    severity=poc.info.severity,
                    target=url,
                    confidence=outcome.confidence,
                    verified=verified,
                    evidence=list(outcome.evidences),
                    extracted=extracted,
                    tags=list(poc.info.tags),
                )
            )

    return results


async def scan_target(
    target: str,
    pocs: Sequence[PoC],
    client: AsyncHttpClient,
    *,
    concurrency: int = 20,
    negative_control: bool = True,
) -> EngineResult:
    """对单个目标执行一批 PoC。

    并发策略：用信号量限制**同时执行的 PoC 数量**。
    为什么不无限并发？因为每个 PoC 内部可能有多条 path 与对照请求，
    再乘上目标数量，实际连接数会被放大数倍。
    """
    started = time.monotonic()
    result = EngineResult(target=target, poc_count=len(pocs))
    semaphore = asyncio.Semaphore(concurrency)

    async def _run(poc: PoC) -> list[VulnResult]:
        async with semaphore:
            # 每个 PoC 用独立的错误收集器，避免多协程并发 append 时交错串味。
            # 收集完再统一并入 result.errors。
            poc_errors: list[str] = []
            try:
                return await run_poc(
                    poc,
                    target,
                    client,
                    negative_control=negative_control,
                    errors=poc_errors,
                )
            except Exception as exc:  # noqa: BLE001 - 单 PoC 失败不中断整体
                logger.warning("poc_error poc=%s target=%s error=%s", poc.id, target, exc)
                poc_errors.append(f"[{poc.id}] 未捕获异常: {exc}")
                return []
            finally:
                result.errors.extend(poc_errors)

    batches = await asyncio.gather(*(_run(poc) for poc in pocs))

    for batch in batches:
        result.vulns.extend(batch)

    # 排序：先按严重级别，再按置信度 —— 报告里高危且高置信的排最前
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    result.vulns.sort(key=lambda v: (severity_order.get(v.severity, 9), -v.confidence))

    result.tested = len(pocs)
    result.elapsed = time.monotonic() - started

    logger.info(
        "target_scanned target=%s pocs=%d hits=%d elapsed=%.2fs",
        target,
        len(pocs),
        result.hit_count,
        result.elapsed,
    )
    return result


def to_json(result: EngineResult) -> str:
    """把扫描结果序列化成 JSON。"""
    return json.dumps(
        {
            "target": result.target,
            "poc_count": result.poc_count,
            "hit_count": result.hit_count,
            "by_severity": result.by_severity(),
            "elapsed": round(result.elapsed, 3),
            "vulns": [v.to_dict() for v in result.vulns],
        },
        ensure_ascii=False,
        indent=2,
    )


__all__ = [
    "VulnResult",
    "EngineResult",
    "run_poc",
    "run_request",
    "scan_target",
    "build_variables",
    "render",
    "to_json",
]
