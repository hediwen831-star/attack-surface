"""匹配器与提取器 —— PoC 引擎的判定核心。

## 设计取舍一：为什么要自研 DSL 而不用 eval

一个 PoC 系统里最容易埋雷的地方，就是「让用户写表达式」。
如果用 ``eval()`` 执行 YAML 里写的条件，那么我们加载的就不再是数据，
而是**任意代码** —— 意味着任何一条从社区下载的 PoC 都能在你机器上执行命令。
这是不可接受的攻击面（而且是「一个安全工具自身有 RCE」这种最难看的漏洞）。

所以这里实现一个**白名单语法的小解析器**，只支持四种谓词：

    status == 200
    contains(body, 'root:')
    len(body) > 1024
    regex(header, 'Server: .*nginx')

支持 ``== != > < >= <=`` 六种比较符，以及 ``&&`` / ``||`` 组合。
解析用的是严格正则 + 显式求值，无法表达任意 Python 语义 ——
这正是我们想要的：**表达能力受限是安全特性，不是缺陷。**

## 设计取舍二：为什么匹配结果要带 evidence

判定「存不存在漏洞」只是第一步。安全报告的价值在于**证据**：
- 客户第一反应是「你凭什么说这里有漏洞」
- 误报排查时，必须能看到「是哪个词命中了」
- 多个弱特征叠加判定时，要能说明各自贡献了什么

所以每个匹配器都返回 ``MatchResult``，命中时携带命中的原始片段。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..core.http import Response
from ..exceptions import PluginError

#: 匹配位置
PART_BODY = "body"
PART_HEADER = "header"
PART_ALL = "all"
PART_STATUS = "status"

VALID_PARTS = {PART_BODY, PART_HEADER, PART_ALL}
VALID_MATCHER_TYPES = {"status", "word", "regex", "dsl"}


@dataclass
class MatchResult:
    """单个匹配器的判定结果。"""

    matched: bool
    matcher_type: str = ""
    evidence: str = ""
    """命中证据的原始片段 —— 会写进漏洞记录的 ``evidence`` 字段。"""

    def __bool__(self) -> bool:
        return self.matched

    @classmethod
    def no(cls, matcher_type: str = "") -> MatchResult:
        """构造一个未命中结果。"""
        return cls(matched=False, matcher_type=matcher_type)

    @classmethod
    def yes(cls, matcher_type: str, evidence: str = "") -> MatchResult:
        """构造一个命中结果。"""
        return cls(matched=True, matcher_type=matcher_type, evidence=evidence)


def get_part(response: Response, part: str) -> str:
    """按位置取出用于匹配的文本。

    ``all`` 把响应头和正文拼起来 —— 很多 PoC 并不确定特征出现在哪里，
    用 ``all`` 可以少写一个匹配器，代价是可读性略降。
    """
    if part == PART_BODY:
        return response.text
    if part == PART_HEADER:
        return "\n".join(f"{k}: {v}" for k, v in response.headers.items())
    if part == PART_ALL:
        headers = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        return f"{headers}\n\n{response.text}"
    raise PluginError("未知的匹配位置", part=part, valid=sorted(VALID_PARTS))


# ----------------------------------------------------------------- 各类型匹配器


def match_status(matcher: dict[str, Any], response: Response) -> MatchResult:
    """匹配 HTTP 状态码。

    YAML 里 ``status`` 可以是单个整数或列表，统一归一成列表处理 ——
    让 PoC 作者少纠结格式，是降低插件编写门槛的关键。
    """
    expected = matcher.get("status", [])
    if isinstance(expected, int):
        expected = [expected]
    if not expected:
        raise PluginError("status 匹配器缺少 status 字段")

    expected = [int(code) for code in expected]
    if response.status in expected:
        return MatchResult.yes("status", f"status={response.status}")
    return MatchResult.no("status")


def match_word(matcher: dict[str, Any], response: Response) -> MatchResult:
    """关键字匹配。

    ``condition`` 控制多个词之间的关系：
    - ``or``（默认）：任一命中即算命中 —— 适合「这些特征出现任意一个就够了」
    - ``and``：全部命中才算法命中 —— 适合「单特征太弱，必须多个同时出现」

    支持 ``negative: true`` 做反向匹配（「响应里不包含这个」），
    用于排除误报页，例如「404 页面里也有这个词，所以要排除」。
    """
    part = matcher.get("part", PART_BODY)
    words = matcher.get("words", [])
    condition = str(matcher.get("condition", "or")).lower()
    negative = bool(matcher.get("negative", False))
    case_insensitive = bool(matcher.get("case-insensitive", False))

    if not words:
        raise PluginError("word 匹配器缺少 words 字段")

    haystack = get_part(response, part)
    if case_insensitive:
        haystack = haystack.lower()
        words = [str(w).lower() for w in words]

    hits = [str(w) for w in words if str(w) in haystack]

    matched = len(hits) == len(words) if condition == "and" else len(hits) > 0

    if negative:
        matched = not matched
        return MatchResult.yes("word", "negative-match") if matched else MatchResult.no("word")

    return (
        MatchResult.yes("word", f"hit={hits[0]!r}" if len(hits) == 1 else f"hits={hits}")
        if matched
        else MatchResult.no("word")
    )


def match_regex(matcher: dict[str, Any], response: Response) -> MatchResult:
    """正则匹配。

    预编译 + 捕获组截断的 ``evidence``：
    报告里塞一整页 HTML 没有意义，所以只截取命中位置前后各 80 字符。
    """
    part = matcher.get("part", PART_BODY)
    patterns = matcher.get("regex", [])
    condition = str(matcher.get("condition", "or")).lower()
    negative = bool(matcher.get("negative", False))

    if isinstance(patterns, str):
        patterns = [patterns]
    if not patterns:
        raise PluginError("regex 匹配器缺少 regex 字段")

    haystack = get_part(response, part)
    hits: list[str] = []

    for pattern in patterns:
        try:
            compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        except re.error as exc:
            raise PluginError("正则表达式非法", pattern=pattern, detail=str(exc)) from exc

        found = compiled.search(haystack)
        if found:
            hits.append(found.group(0)[:160])

    matched = len(hits) == len(patterns) if condition == "and" else len(hits) > 0

    if negative:
        matched = not matched
        return MatchResult.yes("regex", "negative-match") if matched else MatchResult.no("regex")

    return (
        MatchResult.yes("regex", hits[0] if len(hits) == 1 else f"{len(hits)}/{len(patterns)} patterns hit")
        if matched
        else MatchResult.no("regex")
    )


# -------------------------------------------------------------------- DSL


#: DSL 谓词白名单。每条都是 (正则, 求值函数) —— 新增语法必须显式加到这里，
#: 不存在「动态构造 Python 表达式」的路径。
_DSL_PREDICATES: list[tuple[re.Pattern[str], Any]] = [
    # status == 200 / status != 404
    (
        re.compile(r"^status\s*(==|!=|>=|<=|>|<)\s*(\d+)$"),
        lambda m, resp: _compare(resp.status, m.group(1), int(m.group(2))),
    ),
    # contains(body, 'xxx')
    (
        re.compile(r"^contains\(\s*(\w+)\s*,\s*['\"](.+?)['\"]\s*\)$", re.DOTALL),
        lambda m, resp: m.group(2) in get_part(resp, m.group(1).lower()),
    ),
    # len(body) > 1024
    (
        re.compile(r"^len\(\s*(\w+)\s*\)\s*(==|!=|>=|<=|>|<)\s*(\d+)$"),
        lambda m, resp: _compare(
            len(get_part(resp, m.group(1).lower())), m.group(2), int(m.group(3))
        ),
    ),
    # regex(header, 'Server: nginx')
    (
        re.compile(r"^regex\(\s*(\w+)\s*,\s*['\"](.+?)['\"]\s*\)$", re.DOTALL),
        lambda m, resp: bool(re.search(m.group(2), get_part(resp, m.group(1).lower()), re.I)),
    ),
]


def _compare(left: Any, operator: str, right: Any) -> bool:
    """比较运算符求值。"""
    return {
        "==": lambda a, b: a == b,
        "!=": lambda a, b: a != b,
        ">": lambda a, b: a > b,
        "<": lambda a, b: a < b,
        ">=": lambda a, b: a >= b,
        "<=": lambda a, b: a <= b,
    }[operator](left, right)


def _split_dsl(expression: str) -> tuple[list[str], list[str]]:
    """把 DSL 表达式拆成谓词列表与连接符列表。

    连接符优先级：``&&`` 高于 ``||``，与主流语言一致。
    当前实现为左到右求值（简单实现），复杂优先级场景建议拆成多个匹配器 ——
    PoC 的可读性比 DSL 的表达能力更重要。
    """
    tokens = re.split(r"(\s*(?:&&|\|\|)\s*)", expression)
    predicates = [t.strip() for t in tokens[::2] if t.strip()]
    connectors = [t.strip() for t in tokens[1::2]]
    return predicates, connectors


def evaluate_dsl_predicate(predicate: str, response: Response) -> bool:
    """求值单个 DSL 谓词。无法识别的语法直接抛错（而不是静默返回 False）。

    为什么选择抛错：静默 False 会让 PoC 作者以为自己写对了但检测不到漏洞，
    调试成本极高。显式报错能在加载阶段就暴露问题。
    """
    for pattern, evaluator in _DSL_PREDICATES:
        if pattern.match(predicate):
            return bool(evaluator(pattern.match(predicate), response))
    raise PluginError(
        "DSL 谓词不在白名单内",
        predicate=predicate,
        supported=[
            "status == 200",
            "contains(body, 'text')",
            "len(body) > 1024",
            "regex(header, 'pattern')",
        ],
    )


def match_dsl(matcher: dict[str, Any], response: Response) -> MatchResult:
    """DSL 匹配器。

    Example:
        matcher: {type: dsl, dsl: ["status == 200", "contains(body, 'uid=')"]}
    """
    expressions = matcher.get("dsl", [])
    condition = str(matcher.get("condition", "and")).lower()

    if isinstance(expressions, str):
        expressions = [expressions]
    if not expressions:
        raise PluginError("dsl 匹配器缺少 dsl 字段")

    results: list[bool] = []
    for expression in expressions:
        predicates, connectors = _split_dsl(str(expression))
        if not predicates:
            raise PluginError("DSL 表达式为空", expression=expression)

        value = evaluate_dsl_predicate(predicates[0], response)
        # connectors 天然比 predicates 少一个（N 个谓词有 N-1 个连接符），
        # 所以显式写 strict=False：截断是设计意图，不是遗漏。
        for connector, predicate in zip(connectors, predicates[1:], strict=False):
            right = evaluate_dsl_predicate(predicate, response)
            value = (value and right) if connector == "&&" else (value or right)
        results.append(value)

    matched = all(results) if condition == "and" else any(results)
    if matched:
        hit = [e for e, ok in zip(expressions, results, strict=False) if ok]
        return MatchResult.yes("dsl", "; ".join(hit)[:160])
    return MatchResult.no("dsl")


# ----------------------------------------------------------------- 统一入口

_MATCHER_DISPATCH = {
    "status": match_status,
    "word": match_word,
    "regex": match_regex,
    "dsl": match_dsl,
}


def evaluate_matcher(matcher: dict[str, Any], response: Response) -> MatchResult:
    """执行单个匹配器。"""
    if not isinstance(matcher, dict):
        raise PluginError("匹配器必须是映射", got=type(matcher).__name__)

    matcher_type = str(matcher.get("type", "")).lower()
    if matcher_type not in VALID_MATCHER_TYPES:
        raise PluginError(
            "未知匹配器类型", type=matcher_type, valid=sorted(VALID_MATCHER_TYPES)
        )
    return _MATCHER_DISPATCH[matcher_type](matcher, response)


@dataclass
class MatcherOutcome:
    """一组匹配器的整体判定结果。"""

    matched: bool
    evidences: list[str] = field(default_factory=list)
    confidence: float = 0.0
    """置信度：命中的强特征越多越高。用于后续按可信度排序与展示。"""

    def __bool__(self) -> bool:
        return self.matched


def evaluate_matchers(
    matchers: list[dict[str, Any]], response: Response, *, condition: str = "and"
) -> MatcherOutcome:
    """执行一组匹配器，按 ``condition`` 组合结果。

    Args:
        matchers: 匹配器列表。
        response: 待判定的响应。
        condition: ``and`` 表示全部命中才判定存在漏洞；``or`` 表示任一命中即可。

    Returns:
        ``MatcherOutcome``。``confidence`` 按命中比例计算 —— 供上层排序与过滤。
    """
    if not matchers:
        raise PluginError("PoC 未定义任何匹配器")

    results: list[MatchResult] = []
    for matcher in matchers:
        results.append(evaluate_matcher(matcher, response))

    hits = [r for r in results if r.matched]
    matched = len(hits) == len(results) if condition == "and" else len(hits) > 0

    if not matched:
        return MatcherOutcome(matched=False, confidence=0.0)

    # 置信度设计：
    # - and 条件下全部命中 → 1.0（多重独立特征同时成立，几乎不可能是巧合）
    # - or 条件下按命中比例给分 → 命中越多越可信
    # - 单个匹配器命中时上限 0.8，因为单一特征（尤其单个关键字）误报率高
    if condition == "and":
        confidence = 1.0
    else:
        ratio = len(hits) / len(results)
        confidence = round(min(0.8, 0.4 + ratio * 0.4), 2)

    return MatcherOutcome(
        matched=True,
        evidences=[r.evidence for r in hits if r.evidence],
        confidence=confidence,
    )


# ----------------------------------------------------------------- 提取器


def run_extractors(
    extractors: list[dict[str, Any]], response: Response
) -> dict[str, str]:
    """执行提取器，返回 ``{变量名: 提取值}``。

    提取器的价值在于把「存在漏洞」升级为「漏洞的具体内容」：
    测到 unauthenticated Redis 只是结论，提取出 ``config get dir`` 的结果才是证据。

    支持 ``internal: true`` 的内部提取器 —— 提取结果不写进报告，
    而是作为后续请求的变量输入（实现多步 PoC 的基础）。
    """
    extracted: dict[str, str] = {}

    for extractor in extractors:
        ext_type = str(extractor.get("type", "regex")).lower()
        part = extractor.get("part", PART_BODY)
        name = str(extractor.get("name", "")).strip()
        if not name:
            raise PluginError("提取器缺少 name 字段")

        haystack = get_part(response, part)

        if ext_type == "regex":
            patterns = extractor.get("regex", [])
            if isinstance(patterns, str):
                patterns = [patterns]
            for pattern in patterns:
                try:
                    compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                except re.error as exc:
                    raise PluginError("提取器正则非法", pattern=pattern, detail=str(exc)) from exc
                found = compiled.search(haystack)
                if found:
                    # 有捕获组就取第一组，否则取整个匹配
                    extracted[name] = (found.group(1) if found.groups() else found.group(0))[:512]
                    break

        elif ext_type == "kv":
            # 从响应头里取指定字段的值
            value = response.header(str(extractor.get("key", "")))
            if value:
                extracted[name] = value[:512]

        else:
            raise PluginError("未知提取器类型", type=ext_type, valid=["regex", "kv"])

    return extracted


__all__ = [
    "MatchResult",
    "MatcherOutcome",
    "evaluate_matcher",
    "evaluate_matchers",
    "run_extractors",
    "get_part",
    "VALID_MATCHER_TYPES",
    "VALID_PARTS",
]
