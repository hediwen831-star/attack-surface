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

    responses_ok: int = 0
    """成功拿到可用 HTTP 响应的请求数（不含连接失败、超时、5xx 网关错误）。

    用途是回答一个比命中数更基础的问题：**这次到底扫到目标了吗？**

    没有它会出现这种情况：目标不可达（DNS 失败、连接被拒、被代理挡成 502），
    所有 PoC 都打不出去，于是 hit_count=0 ——
    输出上写「未发现漏洞」，**和「扫过了，确实没有漏洞」完全无法区分**。

    这是静默失败里危害最大的一种：使用者拿着这份报告以为目标干净。
    所以宁可把「一个响应都没拿到」当成错误上报，也不能当成「无漏洞」。
    """

    responses_server_error: int = 0
    """命中 5xx 的响应数。

    单独统计而不是直接算进 responses_ok，原因是实测踩过一个很隐蔽的坑：

    本机跑着 HTTP 代理时，向已关闭的端口发请求【不会】得到"连接被拒"，
    而是代理返回 **502 Bad Gateway**。502 是一个结构完整的 HTTP 响应，
    如果只看"拿到响应了吗"，会误判成目标可达 —— 然后报告「未发现漏洞」。

    所以「拿到了 5xx」和「拿到了 2xx/3xx/4xx」必须分开数。
    """

    @property
    def target_reachable(self) -> bool:
        """是否至少成功读到过一个「非服务端错误」的响应。

        为什么排除 5xx：
          · 5xx 表示服务端自己出问题了（或中间网关没能把请求送达上游），
            它不能证明「我们扫的是一个正常工作的应用」。
          · 404 之类的 4xx 反而是好信号 —— 说明应用确实在处理路由，
            只是这个路径不存在，属于正常扫描过程的一部分。
          · 实测：代理返回 502 时，所有 PoC 都"拿到了响应"却全部无效。

        保守之处：只有【全部】响应都是 5xx 才判不可达。
        只要有一个非 5xx 响应，就认为目标可达 ——
        因为扫描过程中个别路径返回 500 是常见的，不能因此否定整次扫描。
        """
        return self.responses_ok - self.responses_server_error > 0

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
    reachability: list[int] | None = None,
) -> list[tuple[str, Response, Any]]:
    """执行一条 PoCRequest，返回所有命中的 ``(url, response, outcome)``。

    Args:
        errors: 可选的错误收集器。PoC 内部的匹配器写错时，
            错误会被记录进去而不是静默丢弃 ——
            「检测没结果」和「PoC 写错了」是两种完全不同的情况，
            用户必须能区分。这是踩过坑之后加上的设计。
        reachability: 长度 1 的可变计数器（``[0]``），每拿到一个可用响应就 +1。
            用 list 是为了在协程间共享可变状态 —— 每个 PoC 并发执行，
            但都会往同一个目标发请求，所以"目标可达吗"这件事要汇总看。
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

        # 到这里说明真的读到了一个 HTTP 响应。
        # 5xx 要单独计数 —— 代理挡下的 502 会让"目标可达"判断失真。
        # 注意 Response 的字段名是 status（不是 httpx 的 status_code）。
        if reachability is not None:
            reachability[0] += 1
            if 500 <= resp.status < 600:
                reachability[1] += 1

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
    reachability: list[int] | None = None,
) -> list[VulnResult]:
    """对单个目标执行一个 PoC。

    Args:
        poc: 要执行的 PoC。
        target: 目标地址（域名或 URL）。
        client: 共享 HTTP 客户端。
        negative_control: 是否启用负向对照校验。
        errors: 可选的错误收集器，用于把 PoC 自身的错误暴露给上层。
        reachability: 可选的共享计数器，用于统计成功读到的响应数。

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
                reachability=reachability,
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
    # 共享计数器：[读到响应的总数, 其中 5xx 的数量]
    # 所有 PoC 并发执行，但"目标是否可达"要汇总判断。
    # 用 list 而不是两个 int，是为了让协程能修改同一个对象。
    reachability = [0, 0]

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
                    reachability=reachability,
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
    result.responses_ok = reachability[0]
    result.responses_server_error = reachability[1]
    result.elapsed = time.monotonic() - started

    # ------------------------------------------------------------------
    # 可达性兜底：一个响应都没读到，必须显式报错
    #
    # 不加这一段的话，目标不可达时 hit_count=0，输出是「未发现漏洞」——
    # 与「扫过了，确实没洞」在观感上完全一致。
    # 实测踩到过：本机靶场进程被回收后，PoC 报告「命中 0、未发现漏洞」，
    # 而真实原因是连不上，跟漏洞存不存在毫无关系。
    #
    # 宁可把这种情况当错误上报，也不要给出一份看起来干净的假报告。
    # ------------------------------------------------------------------
    if pocs and not result.target_reachable:
        if result.responses_ok and result.responses_server_error:
            message = (
                f"目标 {target} 的所有响应都是 5xx（{result.responses_server_error}/"
                f"{result.responses_ok}）—— 本次结果无效，不能据此判断「没有漏洞」。"
                "常见原因：目标服务未启动、反向代理/HTTP 代理返回 502、"
                "或上游应用崩溃。"
            )
        else:
            message = (
                f"目标 {target} 没有任何请求成功 —— "
                "本次结果无效，不能据此判断「没有漏洞」。"
                "请检查目标是否可达、端口是否正确、是否有代理/防火墙拦截。"
            )
        logger.error(
            "target_unreachable target=%s responses_ok=%d server_error=%d",
            target,
            result.responses_ok,
            result.responses_server_error,
        )
        result.errors.append(message)

    logger.info(
        "target_scanned target=%s pocs=%d hits=%d responses_ok=%d 5xx=%d elapsed=%.2fs",
        target,
        len(pocs),
        result.hit_count,
        result.responses_ok,
        result.responses_server_error,
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
            # 把可达性与错误也放进 JSON ——
            # 自动化流水线（CI、报告生成）同样需要区分
            # 「没扫到」和「扫了但没洞」，只给 hit_count 是不够的。
            "target_reachable": result.target_reachable,
            "responses_ok": result.responses_ok,
            "errors": result.errors,
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
