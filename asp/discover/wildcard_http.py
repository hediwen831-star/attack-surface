"""用 HTTP 响应指纹区分「泛解析噪音」与「共用 IP 的真实资产」。

纯 IP 比对有一个绕不过去的场景：CDN。真实域名和泛解析都指向同一组边缘 IP，
按 IP 过滤会把真实资产一起删掉。这时只能看内容：

    泛解析页面：任意编造的子域名都返回同一张默认页（状态码、正文基本一致）
    真实站点：  返回自己的页面，和默认页明显不同

所以对「IP 落在泛解析基线里」的候选，再抓一次 HTTP 指纹做二次判定。
抓不到（端口关闭、超时）就维持原判（过滤），避免把噪音全放进来。

指纹比较用正文归一化后的 difflib 相似度，不用哈希：CDN 默认页常带随机
trace id、时间戳、回显的 Host，逐字节哈希永远不相等。
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

from ..core.http import AsyncHttpClient
from ..logger import get_logger

logger = get_logger("discover.wildcard_http")

#: 正文参与比较的字符数。默认页通常很短，前 2KB 足够区分。
SAMPLE_CHARS = 2048

#: 相似度阈值：≥ 该值判为「同一个默认页」，即泛解析噪音。
SIMILARITY_THRESHOLD = 0.90

_VOLATILE = re.compile(r"[0-9a-f]{16,}|\d{10,}")


@dataclass(slots=True)
class Fingerprint:
    """一次 HTTP 探测的最小特征集。"""

    status: int
    sample: str
    server: str = ""

    @property
    def empty(self) -> bool:
        return self.status == 0


def normalize_body(text: str) -> str:
    """归一化正文，压掉与「哪个主机」无关的噪声。

    去掉长十六进制串（trace id）、长数字（时间戳）、连续空白，
    这样同一张默认页在不同子域名下的相似度会接近 1。
    """
    text = _VOLATILE.sub("", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()[:SAMPLE_CHARS]


async def fetch_fingerprint(
    client: AsyncHttpClient, host: str, *, timeout: float = 5.0
) -> Fingerprint:
    """抓一次 HTTP 指纹。先 https 再 http，都失败返回空指纹。

    不跟随跳转：跳转目标本身就是泛解析的强特征（所有子域名跳到同一处）。
    """
    for scheme in ("https", "http"):
        try:
            response = await client.get(f"{scheme}://{host}/", timeout=timeout)
        except Exception:  # noqa: BLE001 - 探测失败是常态，不向上抛
            continue
        if response.error or response.status == 0:
            continue
        return Fingerprint(
            status=response.status,
            sample=normalize_body(response.text),
            server=response.header("server"),
        )
    return Fingerprint(status=0, sample="")


def similarity(left: Fingerprint, right: Fingerprint) -> float:
    """两个指纹的相似度，0 到 1。状态码不同直接判 0。"""
    if left.empty or right.empty:
        return 0.0
    if left.status != right.status:
        return 0.0
    if not left.sample and not right.sample:
        return 1.0
    return difflib.SequenceMatcher(None, left.sample, right.sample).ratio()


def looks_like_wildcard(
    candidate: Fingerprint,
    baselines: list[Fingerprint],
    *,
    threshold: float = SIMILARITY_THRESHOLD,
) -> bool:
    """候选页面是否和任一泛解析基线的页面相同。

    只要跟任意一个随机标签的页面高度相似，就说明这是同一张默认页。
    """
    if not baselines:
        return True
    return any(similarity(candidate, base) >= threshold for base in baselines)
