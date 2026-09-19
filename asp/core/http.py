"""统一异步 HTTP 客户端。

测绘场景对 HTTP 客户端有三个硬要求，这也是本模块存在的理由：

1. **限速** —— 不限速的扫描器等于 DDoS 工具，会打挂目标、触发 WAF、被封 IP。
   这里用令牌桶做全局限速，所有协程共享一个桶。
2. **并发上限** —— 没有信号量约束时，几千个协程同时开 socket 会耗尽文件描述符。
3. **可重试** —— 超时与 5xx 是临时故障，直接算「目标不存在」会造成漏报。

另外统一关闭 TLS 校验：测绘会遇到大量自签名证书，
证书错误不代表资产不存在，这里必须容忍。
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..exceptions import HttpError, RateLimitError
from ..logger import get_logger

logger = get_logger("core.http")


class RateLimiter:
    """异步令牌桶限速器。

    为什么不用「每次请求后 sleep(1/rate)」？
    那个做法把「启动到第一次请求」也串行化了，且并发一高就退化成串行。
    令牌桶允许短时突发（burst），整体速率仍受控，更接近人类操作行为。

    Example:
        >>> limiter = RateLimiter(rate=50)
        >>> await limiter.acquire()   # 不到 50 QPS 就不会阻塞
    """

    def __init__(self, rate: float, burst: int | None = None) -> None:
        if rate <= 0:
            raise ValueError("rate 必须大于 0")
        self.rate = rate
        self.capacity = float(burst if burst is not None else max(1, int(rate)))
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        """获取令牌，不足则等到足够为止。

        Raises:
            ValueError: 请求的令牌数超过桶容量。

                ⚠️ 这不是「多等一会儿就能满足」的情况 ——
                桶容量是**补充的上限**，永远不可能同时持有超过容量的令牌。

                踩过的坑：最初没有这个校验，于是 `acquire(tokens=4)` 配
                `burst=2` 会让 while 循环永远转下去：每次补到 2 就发现不够 4，
                于是继续 sleep 等补充 —— **死循环**。

                **一个能静默死循环的 API，比一个会抛异常的 API 危险得多。**
                所以这里显式拒绝，把配置错误暴露在调用点。
        """
        if tokens > self.capacity:
            raise ValueError(
                f"请求的令牌数 {tokens} 超过桶容量 {self.capacity} —— "
                f"这在语义上无法满足（容量是补充上限），请调大 burst"
            )

        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._updated
                self._updated = now
                # 按流逝时间补充令牌，上限为桶容量
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)

                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return

                # 需要等待的时间：补满差额令牌所需秒数
                deficit = tokens - self._tokens
                await asyncio.sleep(deficit / self.rate)


@dataclass
class Response:
    """标准化的响应对象。

    直接透传 httpx.Response 会让上层耦合到具体 HTTP 库，
    这里收敛成最小字段集，未来换 aiohttp 时上层无需改动。
    """

    url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    content: bytes = b""
    elapsed: float = 0.0
    error: str | None = None

    @property
    def ok(self) -> bool:
        """请求是否成功完成（不代表业务上的「存在」）。"""
        return self.error is None

    @property
    def text(self) -> str:
        """尽力解码正文 —— 忽略非法字节，避免一个坏字符毁掉整次检测。"""
        return self.content.decode("utf-8", errors="ignore")

    def header(self, name: str, default: str = "") -> str:
        """大小写不敏感地取响应头。"""
        target = name.lower()
        for key, value in self.headers.items():
            if key.lower() == target:
                return value
        return default


class AsyncHttpClient:
    """带限速、并发控制与重试的异步 HTTP 客户端。

    Example:
        >>> async with AsyncHttpClient(concurrency=100, rate_limit=50) as client:
        ...     resp = await client.get("https://example.com")
        ...     print(resp.status)
    """

    def __init__(
        self,
        *,
        concurrency: int = 100,
        rate_limit: float = 50.0,
        timeout: float = 10.0,
        retries: int = 2,
        verify_ssl: bool = False,
        user_agent: str = "Mozilla/5.0 (compatible; ASP/0.1)",
        follow_redirects: bool = False,
        max_body: int = 2 * 1024 * 1024,
    ) -> None:
        """
        Args:
            concurrency: 同时进行的请求数上限。
            rate_limit: 每秒请求数上限。
            timeout: 单次请求超时（秒）。
            retries: 失败重试次数。
            verify_ssl: 是否校验 TLS 证书。测绘场景建议 False。
            user_agent: 默认 User-Agent。
            follow_redirects: 是否跟随跳转。默认关闭 —— 我们要看到跳转本身。
            max_body: 单次响应最大读取字节数，防止遇到大文件把内存吃满。
        """
        self.concurrency = concurrency
        self.timeout = timeout
        self.retries = retries
        self.max_body = max_body
        self._semaphore = asyncio.Semaphore(concurrency)
        self._limiter = RateLimiter(rate_limit)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            verify=verify_ssl,
            follow_redirects=follow_redirects,
            headers={
                "User-Agent": user_agent,
                "Accept": "*/*",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Connection": "close",
            },
            limits=httpx.Limits(max_connections=concurrency, max_keepalive_connections=0),
        )

    # -------------------------------------------------------------- 上下文

    async def __aenter__(self) -> AsyncHttpClient:
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """关闭底层连接池。"""
        await self._client.aclose()

    # -------------------------------------------------------------- 请求

    async def request(self, method: str, url: str, **kwargs: Any) -> Response:
        """发起请求，内部完成限速、并发控制与重试。

        重试策略采用**指数退避 + 抖动**：
        固定间隔重试会在服务端形成「整齐的脉冲」，反而更容易被识别为扫描行为。
        """
        last_error: Exception | None = None

        for attempt in range(self.retries + 1):
            await self._limiter.acquire()
            async with self._semaphore:
                started = time.monotonic()
                try:
                    resp = await self._client.request(method, url, **kwargs)
                    elapsed = time.monotonic() - started

                    if resp.status_code == 429 or resp.status_code == 503:
                        raise RateLimitError(
                            "被限速", url=url, status=resp.status_code
                        )

                    return Response(
                        url=str(resp.url),
                        status=resp.status_code,
                        headers=dict(resp.headers),
                        content=resp.content[: self.max_body],
                        elapsed=elapsed,
                    )
                except RateLimitError as exc:
                    last_error = exc
                    # 限速退避要更长，且必须生效再重试
                    await asyncio.sleep(min(30.0, 2.0 ** attempt * 2))
                except (httpx.TimeoutException, httpx.TransportError) as exc:
                    last_error = exc
                    await self._backoff(attempt)
                except httpx.HTTPError as exc:
                    last_error = exc
                    await self._backoff(attempt)

        logger.debug("request_failed url=%s attempts=%d error=%s", url, self.retries + 1, last_error)
        return Response(url=url, status=0, error=str(last_error) if last_error else "unknown")

    @staticmethod
    async def _backoff(attempt: int) -> None:
        """指数退避 + 抖动，避免重试风暴同步化。"""
        import random

        delay = min(8.0, 0.5 * (2**attempt))
        await asyncio.sleep(delay * (0.5 + random.random() * 0.5))

    async def get(self, url: str, **kwargs: Any) -> Response:
        """GET 请求。"""
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> Response:
        """HEAD 请求 —— 快速探活时比 GET 省流量。"""
        return await self.request("HEAD", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> Response:
        """POST 请求。"""
        return await self.request("POST", url, **kwargs)

    # -------------------------------------------------------------- 批量

    async def gather(
        self, urls: list[str], *, method: str = "GET"
    ) -> list[Response]:
        """并发请求一批 URL。

        注意：这里不做 ``return_exceptions=True`` 的静默吞异常 ——
        ``request()`` 已经把异常收敛进 ``Response.error``，所以上层永远拿到等长列表，
        索引与入参一一对应，便于把结果映射回资产。
        """
        tasks = [self.request(method, url) for url in urls]
        return await asyncio.gather(*tasks)


__all__ = ["AsyncHttpClient", "RateLimiter", "Response", "HttpError"]
