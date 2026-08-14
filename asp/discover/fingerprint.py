"""Web 指纹识别。

## 为什么 favicon 哈希是强特征

页面标题、响应头、正文关键字都能被轻易修改或伪造，但 `favicon.ico` 通常
**从模板或产品原样拷贝**，很少有人会替换它。所以只要两个站点用了同一套系统，
favicon 的哈希就大概率相同 —— 这是识别同源系统最可靠的单点特征。

Shodan / FOFA 都用这个思路建索引。具体算法是：

    hash = mmh3.hash(base64.encodebytes(favicon_bytes))

注意两点（都容易踩坑）：
1. 是 **mmh3（MurmurHash3 x86 32-bit）**，不是 md5，也不是 Python 内置 hash
2. base64 用的是 **带换行的 encodebytes**（等价于 MIME 编码），
   不是 `b64encode`。两者结果不同，用错了就查不到任何已知指纹

## 为什么自己实现 mmh3 而不用 pip 装

`mmh3` 是 C 扩展，在部分平台需要编译。本项目坚持「运行时依赖只有 3 个」，
而 MurmurHash3 是个公开的确定性算法，纯 Python 实现只有 40 行 —— 收益大于成本。

## 置信度累加而非布尔判定

单一特征（尤其单个关键字）误报率很高：正文里出现 "wordpress" 可能只是
一篇提到 WordPress 的文章。所以规则命中后累加置信度，只有累积到阈值
才认为组件存在。这与 PoC 引擎的置信度设计是同一个思路。
"""

from __future__ import annotations

import base64
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.http import Response
from ..logger import get_logger

logger = get_logger("discover.fingerprint")

#: asp 包目录 —— 用于把配置里的相对路径（如 "rules"）解析成绝对路径。
#: 踩过的坑：直接用相对路径会让「cwd 不是项目根」时规则数静默变成 0，
#: 而且没有任何报错 —— 扫描照跑，只是什么组件都识别不出来。
PACKAGE_DIR = Path(__file__).resolve().parent.parent

#: 组件类别
CATEGORY_CMS = "cms"
CATEGORY_FRAMEWORK = "framework"
CATEGORY_MIDDLEWARE = "middleware"
CATEGORY_LANGUAGE = "language"
CATEGORY_JS = "javascript"
CATEGORY_CACHE = "cache"
CATEGORY_OTHER = "other"

#: 判定组件存在所需的置信度阈值。
#: 单条弱规则（0.3）命中不会判定存在，需要多条累加或一条强规则（≥0.6）。
DEFAULT_CONFIDENCE_THRESHOLD = 0.5


# ------------------------------------------------------- MurmurHash3 实现


def murmurhash3_x86_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit 的纯 Python 实现。

    返回**有符号** 32 位整数 —— 与 Python 的 ``mmh3.hash()`` 行为一致。
    这一点很重要：Shodan 等平台记录的都是有符号值，
    如果返回无符号值，比对时会全部对不上。

    Args:
        data: 要哈希的字节串。
        seed: 种子，默认为 0。

    Returns:
        有符号 32 位整数。
    """
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    length = len(data)
    h1 = seed
    mask = 0xFFFFFFFF

    # ---- 主体：按 4 字节分组处理 ----
    rounded_end = length & ~0x3
    for i in range(0, rounded_end, 4):
        k1 = (
            (data[i] & 0xFF)
            | ((data[i + 1] & 0xFF) << 8)
            | ((data[i + 2] & 0xFF) << 16)
            | ((data[i + 3] & 0xFF) << 24)
        )

        k1 = (k1 * c1) & mask
        k1 = ((k1 << 15) | (k1 >> 17)) & mask     # ROTL32(k1, 15)
        k1 = (k1 * c2) & mask

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & mask     # ROTL32(h1, 13)
        h1 = (h1 * 5 + 0xE6546B64) & mask

    # ---- 尾部：处理不足 4 字节的余数 ----
    k1 = 0
    tail = length & 0x3
    if tail == 3:
        k1 ^= (data[rounded_end + 2] & 0xFF) << 16
    if tail >= 2:
        k1 ^= (data[rounded_end + 1] & 0xFF) << 8
    if tail >= 1:
        k1 ^= data[rounded_end] & 0xFF
        k1 = (k1 * c1) & mask
        k1 = ((k1 << 15) | (k1 >> 17)) & mask
        k1 = (k1 * c2) & mask
        h1 ^= k1

    # ---- 收尾混合 ----
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & mask
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & mask
    h1 ^= h1 >> 16

    # 转成有符号整数（与 mmh3 库一致）
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


def favicon_hash(content: bytes) -> int:
    """计算 Shodan 风格的 favicon 哈希。

    Args:
        content: favicon.ico 的原始字节。

    Returns:
        有符号 32 位整数哈希值。内容为空时返回 0。

    Example:
        >>> favicon_hash(Path("favicon.ico").read_bytes())
        116323821
    """
    if not content:
        return 0
    # 关键：用 encodebytes（带换行）而不是 b64encode。
    # 换行会参与哈希计算，用错就与所有公开指纹库对不上。
    encoded = base64.encodebytes(content)
    return murmurhash3_x86_32(encoded)


# --------------------------------------------------------------- 规则模型


@dataclass
class FingerprintRule:
    """一条指纹识别规则。"""

    name: str
    category: str = CATEGORY_OTHER
    confidence: float = 0.5
    """本条规则命中时贡献的置信度（0~1）。"""

    headers: list[str] = field(default_factory=list)
    """响应头正则列表。"""

    body: list[str] = field(default_factory=list)
    """正文正则列表。"""

    cookies: list[str] = field(default_factory=list)
    """Cookie 名正则列表。Cookie 名往往直接暴露技术栈（如 PHPSESSID / JSESSIONID）。"""

    favicon_hashes: list[str] = field(default_factory=list)
    """favicon 哈希（字符串形式，便于 YAML 书写）。"""

    version_regex: str = ""
    """可选：从正文/头部提取版本号的正则（第一个捕获组作为版本）。"""

    def matches(
        self, *, headers: str, body: str, cookies: str, favicon: int | None
    ) -> list[str]:
        """检查规则是否命中，返回命中证据列表（空列表表示未命中）。

        任一维度命中即算命中 —— 但置信度只在**任一命中时加一次**，
        而不是按命中维度数累乘。理由：同一规则的不同维度往往高度相关
        （比如 Server 头写 nginx、正文也含 nginx），累乘会虚高置信度。
        """
        evidence: list[str] = []

        for pattern in self.headers:
            found = re.search(pattern, headers, re.I)
            if found:
                evidence.append(f"header:{found.group(0)[:60]}")

        for pattern in self.cookies:
            found = re.search(pattern, cookies, re.I)
            if found:
                evidence.append(f"cookie:{found.group(0)[:60]}")

        for pattern in self.body:
            found = re.search(pattern, body, re.I)
            if found:
                evidence.append(f"body:{found.group(0)[:60]}")

        if (
            favicon is not None
            and self.favicon_hashes
            and str(favicon) in {str(h).strip() for h in self.favicon_hashes}
        ):
            evidence.append(f"favicon:{favicon}")

        return evidence

    def extract_version(self, text: str) -> str:
        """按规则提取版本号。"""
        if not self.version_regex:
            return ""
        found = re.search(self.version_regex, text, re.I)
        return (found.group(1) if found and found.groups() else "").strip()[:32]


@dataclass
class ComponentResult:
    """识别出的组件。"""

    name: str
    version: str = ""
    category: str = CATEGORY_OTHER
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "category": self.category,
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence,
        }


# ------------------------------------------------------------------ 加载


def parse_rule(raw: dict[str, Any], *, source: str = "") -> FingerprintRule:
    """从字典解析一条规则。"""
    name = str(raw.get("name", "")).strip()
    if not name:
        raise ValueError(f"指纹规则缺少 name 字段（来源 {source}）")

    def _as_list(key: str) -> list[str]:
        value = raw.get(key, [])
        if isinstance(value, str):
            return [value]
        return [str(v) for v in value]

    confidence = float(raw.get("confidence", 0.5))
    if not 0 < confidence <= 1:
        raise ValueError(f"规则 {name} 的 confidence 必须在 (0, 1] 区间，当前 {confidence}")

    return FingerprintRule(
        name=name,
        category=str(raw.get("category", CATEGORY_OTHER)),
        confidence=confidence,
        headers=_as_list("headers"),
        body=_as_list("body"),
        cookies=_as_list("cookies"),
        favicon_hashes=_as_list("favicon_hashes"),
        version_regex=str(raw.get("version_regex", "")),
    )


def load_rules_from_file(path: str | Path) -> list[FingerprintRule]:
    """从 YAML 文件加载规则。"""
    import yaml

    rule_path = Path(path)
    if not rule_path.exists():
        logger.warning("fingerprint_rules_missing path=%s", rule_path)
        return []

    raw = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        logger.warning("fingerprint_rules_bad_format path=%s（应为列表）", rule_path)
        return []

    rules: list[FingerprintRule] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        try:
            rules.append(parse_rule(item, source=f"{rule_path.name}#{index}"))
        except ValueError as exc:
            logger.warning("fingerprint_rule_skipped error=%s", exc)
    return rules


def resolve_rule_dirs(dirs: Iterable[str | Path]) -> list[Path]:
    """把规则目录解析成绝对路径。

    相对路径按「相对于 asp 包目录」解析 —— 与 PoC 目录的处理方式保持一致，
    保证从任意工作目录执行都能找到内置规则。
    """
    resolved: list[Path] = []
    for entry in dirs:
        candidate = Path(entry)
        if candidate.is_absolute():
            resolved.append(candidate)
        elif candidate.exists():
            # 相对当前工作目录存在 → 优先用它（方便指定自己的规则目录）
            resolved.append(candidate.resolve())
        else:
            resolved.append(PACKAGE_DIR / entry)
    return resolved


def load_rules(dirs: Iterable[str | Path]) -> list[FingerprintRule]:
    """从多个目录加载全部 YAML 规则文件。"""
    rules: list[FingerprintRule] = []
    for base in resolve_rule_dirs(dirs):
        if not base.exists():
            logger.warning("fingerprint_rule_dir_missing dir=%s", base)
            continue
        if base.is_file():
            rules.extend(load_rules_from_file(base))
            continue
        for path in sorted(base.rglob("*.yaml")):
            if path.name.startswith("_"):
                continue
            rules.extend(load_rules_from_file(path))
    logger.info("fingerprint_rules_loaded count=%d dirs=%s", len(rules), list(dirs))
    return rules


# ------------------------------------------------------------------ 匹配


def match_fingerprints(
    rules: Sequence[FingerprintRule],
    response: Response,
    *,
    favicon: int | None = None,
    threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
) -> list[ComponentResult]:
    """对一次响应做指纹匹配。

    同一组件名被多条规则命中时，置信度**累加**（上限 1.0），证据合并。
    这能区分「只有一个弱特征命中」和「三个独立特征同时命中」。

    Args:
        rules: 指纹规则列表。
        response: HTTP 响应。
        favicon: favicon 哈希，None 表示未获取。
        threshold: 置信度阈值，低于此值不输出。

    Returns:
        按置信度降序排列的组件列表。
    """
    headers = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
    body = response.text
    cookie_header = response.header("set-cookie") or ""
    # Cookie 名比整条 Cookie 更稳定（值会变），所以提取 name= 的 name 部分
    cookies = " ".join(re.findall(r"([\w\-_.]+)=", cookie_header)) or cookie_header

    accumulated: dict[str, ComponentResult] = {}

    for rule in rules:
        evidence = rule.matches(
            headers=headers, body=body, cookies=cookies, favicon=favicon
        )
        if not evidence:
            continue

        existing = accumulated.get(rule.name)
        version = rule.extract_version(f"{headers}\n{body}")

        if existing is None:
            accumulated[rule.name] = ComponentResult(
                name=rule.name,
                version=version,
                category=rule.category,
                confidence=min(1.0, rule.confidence),
                evidence=evidence,
            )
        else:
            # 累加置信度，但设上限 1.0 —— 多条规则命中同一组件是强信号
            existing.confidence = min(1.0, existing.confidence + rule.confidence)
            existing.evidence.extend(e for e in evidence if e not in existing.evidence)
            if version and not existing.version:
                existing.version = version

    results = [c for c in accumulated.values() if c.confidence >= threshold]
    results.sort(key=lambda c: (-c.confidence, c.name))
    return results


__all__ = [
    "FingerprintRule",
    "ComponentResult",
    "murmurhash3_x86_32",
    "favicon_hash",
    "parse_rule",
    "load_rules",
    "load_rules_from_file",
    "match_fingerprints",
    "DEFAULT_CONFIDENCE_THRESHOLD",
    "CATEGORY_CMS",
    "CATEGORY_FRAMEWORK",
    "CATEGORY_MIDDLEWARE",
    "CATEGORY_LANGUAGE",
    "CATEGORY_JS",
    "CATEGORY_CACHE",
    "CATEGORY_OTHER",
]
