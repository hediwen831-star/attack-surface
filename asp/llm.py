"""LLM 辅助告警降噪。

## 这个模块解决的具体问题

规则匹配只能判断「特征是否出现」，判断不了「这个特征在这个上下文里意味着什么」。

举两个真实例子：

1. 扫描器在某个页面匹配到 `"paths": {`，判定为 Swagger 文档暴露 ——
   但那其实是一个普通的 JSON API 响应，只是恰好也有个 `paths` 字段。
2. 匹配到 `[core]`，判定为 .git 泄露 —— 但那是一个讲 Git 用法的教程页面，
   正文里就有这些内容。

这两个都是**语义层面的误报**：特征确实出现了，但结论是错的。
正则和关键字解决不了这类问题，因为判断依据是「这段上下文在讲什么」。

这正是 LLM 适合的位置，也是它相对规则引擎**不可替代**的地方 ——
不是"用 AI 让扫描器更高级"，而是「规则做不了的那部分交给它」。

## 三条设计红线

**① LLM 不直接删除发现，只标注研判结果。**

LLM 会犯错。如果它判错一条真漏洞并直接删掉，那条发现就永远找不回来了。
所以它只写 `is_false_positive` + `reason` + `confidence`，
原始记录保持不动，人能复核。

**② 必须能降级运行。**

没有 API key 时用启发式规则兜底（`HeuristicProvider`）。
一个「需要联网 + 需要付费 key 才能跑」的功能，在别人 clone 你的项目时
等于不存在 —— 而这恰恰是最需要被看到的部分。

**③ 必须能验证效果。**

「我用了 LLM 降噪」不是结论，「误报率从 X% 降到 Y%」才是。
所以内置了一份标注样本 + 评估函数（`evaluate`），可以量化准确率与召回率，
也能对比不同 provider 的差异。
"""

from __future__ import annotations

import json
import os
import re
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from .logger import get_logger

logger = get_logger("llm")

#: 研判结论
VERDICT_TRUE_POSITIVE = "true_positive"
VERDICT_FALSE_POSITIVE = "false_positive"
VERDICT_UNCERTAIN = "uncertain"


@dataclass
class TriageVerdict:
    """单条发现的研判结果。"""

    verdict: str = VERDICT_UNCERTAIN
    confidence: float = 0.0
    """研判置信度 0~1。低置信度的结论应该交给人工，而不是自动处理。"""

    reason: str = ""
    provider: str = ""

    @property
    def is_false_positive(self) -> bool:
        return self.verdict == VERDICT_FALSE_POSITIVE

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "is_false_positive": self.is_false_positive,
            "confidence": round(self.confidence, 2),
            "reason": self.reason,
            "provider": self.provider,
        }


@dataclass
class Finding:
    """待研判的发现（从漏洞记录转换而来，保持与数据模型解耦）。"""

    poc_id: str
    name: str
    severity: str
    target: str
    evidence: str = ""
    confidence: float = 1.0
    verified: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def from_vuln(vuln: Any) -> Finding:
        """从数据库的 Vuln 对象构造。"""
        return Finding(
            poc_id=getattr(vuln, "poc_id", ""),
            name=getattr(vuln, "name", ""),
            severity=getattr(vuln, "severity", "info"),
            target=getattr(vuln, "target", ""),
            evidence=(getattr(vuln, "evidence", "") or "")[:2000],
            confidence=getattr(vuln, "confidence", 1.0) or 1.0,
            verified=bool(getattr(vuln, "verified", False)),
        )

    def to_prompt_text(self) -> str:
        """转成给 LLM 看的文本描述。"""
        return (
            f"检测插件: {self.poc_id}\n"
            f"插件名称: {self.name}\n"
            f"严重级别: {self.severity}\n"
            f"命中 URL: {self.target}\n"
            f"引擎置信度: {self.confidence}\n"
            f"是否通过二次对照验证: {'是' if self.verified else '否'}\n"
            f"命中证据:\n{self.evidence or '(无)'}"
        )


# ------------------------------------------------------------------ 抽象


class TriageProvider(ABC):
    """研判提供方基类。"""

    name: str = "base"

    @abstractmethod
    async def judge(self, finding: Finding) -> TriageVerdict:
        """对单条发现给出研判结论。"""

    async def judge_many(self, findings: Sequence[Finding]) -> list[TriageVerdict]:
        """批量研判。默认串行，子类可覆写为并发。"""
        return [await self.judge(f) for f in findings]


# ------------------------------------------------------------------ 启发式


#: 误报信号词。命中证据里出现这些，多半是「错误页/通用页」而不是真漏洞。
_FALSE_POSITIVE_SIGNALS: tuple[tuple[str, str], ...] = (
    (r"404\s*Not\s*Found", "证据里出现 404 页面特征，很可能是错误页被误判"),
    (r"was not found", "证据包含『资源未找到』文案，通常是服务器 404 页"),
    (r"Cannot GET", "Express 的默认 404 响应，说明是路由不存在"),
    (r"Not Found</title>", "页面标题是 Not Found，属于通用错误页"),
    (r"Whitelabel Error Page", "Spring 默认错误页，可能不是目标漏洞"),
    (r"nginx/\d+\.[\d.]+</center>", "nginx 默认错误页特征"),
)

#: 支持真阳性的信号
_TRUE_POSITIVE_SIGNALS: tuple[tuple[str, str], ...] = (
    (r"negative-match", "引擎的负向对照校验通过：同目录随机路径没有命中，说明是路径特有特征"),
    (r"status=200", "命中响应为 200，且非错误页"),
)

#: 结构化内容特征。
#:
#: 误报页几乎都是「一段人类可读的提示文案」；而真实的泄露/暴露类漏洞，
#: 证据通常是被泄露文件本身的**结构化内容**（配置段、JSON 字段）。
#: 这个区别是通用的，不是针对某几个样本 —— 所以它是一条合理的启发式规则。
#:
#: ⚠️ 刻意【没有】收录「key = value 形式的配置项」这条看似通用的规则：
#: SQL 语句、报错信息里到处都是 `id = 1` 这种形式，加上它之后
#: 错误页会被判成真阳性。
#: 规则写太宽松的代价是误判，而误判比不判更糟 —— 它会让人放松警惕。
_STRUCTURED_SIGNALS: tuple[tuple[str, str], ...] = (
    (r"(?m)^\s*\[[a-z][\w.-]*\]\s*$", "证据含 INI 风格的配置段标记（如 [core]）"),
    (r'"[a-z_]+"\s*:\s*[\{\["]', "证据含结构化 JSON 字段"),
    (r"^<\?xml", "证据含 XML 声明"),
)


class HeuristicProvider(TriageProvider):
    """基于规则的启发式研判 —— 无 LLM 时的降级方案。

    **它的定位必须说清楚：它比 LLM 弱得多。**

    它只能识别「证据里出现了错误页特征」这类最明显的误报，
    无法判断语义层面的问题（比如教程页面里提到了 `[core]`）。
    所以它的输出置信度被刻意压低，且在 reason 里标注了这是启发式结论。

    一个诚实的降级方案，比一个假装很强的降级方案有用 ——
    后者会让人误以为已经做过降噪了。
    """

    name = "heuristic"

    #: 启发式的置信度上限。刻意压低，因为它判断依据单薄。
    MAX_CONFIDENCE = 0.65

    async def judge(self, finding: Finding) -> TriageVerdict:
        text = f"{finding.evidence}\n{finding.target}"

        # ① 误报信号优先：错误页特征非常明确
        for pattern, reason in _FALSE_POSITIVE_SIGNALS:
            if re.search(pattern, text, re.I):
                return TriageVerdict(
                    verdict=VERDICT_FALSE_POSITIVE,
                    confidence=0.6,
                    reason=f"[启发式] {reason}",
                    provider=self.name,
                )

        # ② 真阳性信号：负向对照通过是很强的证据
        for pattern, reason in _TRUE_POSITIVE_SIGNALS:
            if re.search(pattern, text, re.I):
                return TriageVerdict(
                    verdict=VERDICT_TRUE_POSITIVE,
                    confidence=self.MAX_CONFIDENCE,
                    reason=f"[启发式] {reason}",
                    provider=self.name,
                )

        # ③ 结构化内容特征：泄露类漏洞的证据通常是文件本身的结构，而非提示文案
        for pattern, reason in _STRUCTURED_SIGNALS:
            if re.search(pattern, text, re.I):
                return TriageVerdict(
                    verdict=VERDICT_TRUE_POSITIVE,
                    confidence=0.55,
                    reason=f"[启发式] {reason}",
                    provider=self.name,
                )

        # ④ 无法判断时明确说无法判断，而不是猜一个
        return TriageVerdict(
            verdict=VERDICT_UNCERTAIN,
            confidence=0.0,
            reason="[启发式] 未匹配任何已知的误报或真阳性信号，需要人工复核或使用 LLM 研判",
            provider=self.name,
        )


# ------------------------------------------------------------------ LLM


SYSTEM_PROMPT = """你是一名安全告警研判分析师。你的任务是判断一条漏洞扫描结果是否属于误报。

判断原则：
1. 只根据给出的证据判断，不要假设未提供的信息
2. 如果证据指向「服务器通用错误页 / 404 页面 / 通用回退页面」，判为误报
3. 如果证据是目标系统特有的、结构化的响应内容，判为真阳性
4. 证据不足以判断时，输出 uncertain —— 不要为了给出结论而猜测

只输出 JSON，不要有其他内容。格式：
{"verdict": "true_positive" | "false_positive" | "uncertain",
 "confidence": 0.0-1.0,
 "reason": "一句话说明判断依据"}"""


class OpenAICompatProvider(TriageProvider):
    """调用 OpenAI 兼容接口的研判实现。

    兼容性：只要实现了 ``/chat/completions`` 的服务都能用 ——
    OpenAI、DeepSeek、通义千问、Moonshot、以及本地的 Ollama / vLLM 等。

    不绑定某一家的 SDK，用 httpx 直接发请求：
    多一个 SDK 依赖就多一份被上游破坏的风险，而这里只需要一个 POST。
    """

    name = "openai"

    def __init__(
        self,
        *,
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4o-mini",
        api_key: str = "",
        timeout: float = 30.0,
        max_concurrency: int = 4,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.max_concurrency = max_concurrency

    async def judge(self, finding: Finding) -> TriageVerdict:
        import httpx

        if not self.api_key:
            return TriageVerdict(
                verdict=VERDICT_UNCERTAIN,
                reason="未配置 API key",
                provider=self.name,
            )

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": finding.to_prompt_text()},
            ],
            "temperature": 0,          # 研判要可复现，不要随机性
            "response_format": {"type": "json_object"},
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                )
        except Exception as exc:  # noqa: BLE001 - 网络问题不该中断整批研判
            logger.warning("llm_request_failed poc=%s error=%s", finding.poc_id, exc)
            return TriageVerdict(
                verdict=VERDICT_UNCERTAIN,
                reason=f"请求失败: {exc}",
                provider=self.name,
            )

        if resp.status_code != 200:
            logger.warning(
                "llm_http_error status=%d body=%s", resp.status_code, resp.text[:200]
            )
            return TriageVerdict(
                verdict=VERDICT_UNCERTAIN,
                reason=f"接口返回 HTTP {resp.status_code}",
                provider=self.name,
            )

        return self._parse_response(resp.json())

    def _parse_response(self, data: dict[str, Any]) -> TriageVerdict:
        """解析模型输出。

        模型可能不按格式来（多包一层 markdown 代码块、字段名写错等），
        所以解析要防御性 —— 解析失败要返回 uncertain 而不是抛异常，
        否则一条格式错误就会让整批研判中断。
        """
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            return TriageVerdict(reason=f"响应结构异常: {exc}", provider=self.name)

        content = content.strip()
        # 去掉可能的 markdown 代码块包裹
        if content.startswith("```"):
            content = re.sub(r"^```\w*\n?", "", content)
            content = re.sub(r"\n?```$", "", content)

        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            # 退一步：从文本里抠出第一个 JSON 对象
            match = re.search(r"\{.*\}", content, re.S)
            if not match:
                return TriageVerdict(
                    reason=f"模型输出不是合法 JSON: {content[:120]}", provider=self.name
                )
            try:
                parsed = json.loads(match.group(0))
            except json.JSONDecodeError:
                return TriageVerdict(
                    reason=f"模型输出无法解析: {content[:120]}", provider=self.name
                )

        verdict = str(parsed.get("verdict", VERDICT_UNCERTAIN)).strip().lower()
        if verdict not in (VERDICT_TRUE_POSITIVE, VERDICT_FALSE_POSITIVE, VERDICT_UNCERTAIN):
            verdict = VERDICT_UNCERTAIN

        try:
            confidence = float(parsed.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))

        return TriageVerdict(
            verdict=verdict,
            confidence=confidence,
            reason=str(parsed.get("reason", ""))[:500],
            provider=self.name,
        )


# ------------------------------------------------------------------ 工厂


#: 默认的 OpenAI 兼容接口与模型
DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"


def build_provider(
    provider: str = "auto",
    *,
    base_url: str = "",
    model: str = "",
    api_key: str = "",
) -> TriageProvider:
    """构造研判提供方。

    **优先级：环境变量 > 函数参数 > 内置默认值。**

    为什么环境变量排在参数前面：API key 和接口地址属于「部署环境相关」的配置，
    而配置文件很容易被一起提交到仓库里。让环境变量能覆盖一切，
    使用者就能在不改任何文件的前提下切换模型或换用本地服务。

    Args:
        provider: ``heuristic`` / ``openai`` / ``auto``。
            ``auto`` 会在有 API key 时用 LLM，否则降级到启发式。
        base_url: OpenAI 兼容接口地址。留空则读 ``ASP_LLM_BASE_URL``。
        model: 模型名。留空则读 ``ASP_LLM_MODEL``。
        api_key: API key。留空则读 ``ASP_LLM_API_KEY``。

    Returns:
        研判提供方实例。任何配置缺失都会降级到启发式，而不是抛异常 ——
        降噪是增强功能，不该成为主流程的失败点。
    """
    env = os.environ.get
    key = env("ASP_LLM_API_KEY", "") or api_key
    base = env("ASP_LLM_BASE_URL", "") or base_url or DEFAULT_BASE_URL
    mdl = env("ASP_LLM_MODEL", "") or model or DEFAULT_MODEL

    choice = (provider or "auto").strip().lower()

    if choice == "heuristic":
        return HeuristicProvider()

    if choice == "openai":
        if not key:
            logger.warning("llm_api_key_missing fallback=heuristic")
            return HeuristicProvider()
        return OpenAICompatProvider(base_url=base, model=mdl, api_key=key)

    # auto
    if key:
        return OpenAICompatProvider(base_url=base, model=mdl, api_key=key)
    logger.info("llm_not_configured fallback=heuristic（设置 ASP_LLM_API_KEY 可启用 LLM 研判）")
    return HeuristicProvider()


# ------------------------------------------------------------------ 评估


@dataclass
class LabeledFinding:
    """带标注的样本，用于评估研判效果。"""

    finding: Finding
    expected_false_positive: bool
    note: str = ""


#: 内置标注样本。
#:
#: 覆盖四类典型场景 —— 这是这个功能能被验证的基础：
#: 没有标注数据，「误报率下降」就只是一句无法证伪的话。
LABELED_SAMPLES: tuple[LabeledFinding, ...] = (
    # ---- 真阳性：结构化、路径特有的证据 ----
    LabeledFinding(
        Finding(
            poc_id="vulnlab-sqli-low-union",
            name="SQL 注入（UNION 回显）",
            severity="high",
            target=(
                "http://127.0.0.1:8080/sqli/low.php"
                "?id=-1 UNION SELECT 1,'VULNLAB_POC_MARKER',3,4"
            ),
            evidence="status=200\nhit='VULNLAB_POC_MARKER'\nnegative-match",
            confidence=1.0,
            verified=True,
        ),
        expected_false_positive=False,
        note="负向对照通过 + 自定义标记串回显，几乎不可能是巧合",
    ),
    LabeledFinding(
        Finding(
            poc_id="git-config-exposure",
            name="Git 配置文件泄露",
            severity="high",
            target="http://target.local/.git/config",
            evidence='[core]\nrepositoryformatversion = 0\nfilemode = true\nbare = false',
            confidence=1.0,
            verified=True,
        ),
        expected_false_positive=False,
        note="Git 配置文件的固定段落标记，且无错误页特征",
    ),
    # ---- 误报：错误页 / 通用页 ----
    LabeledFinding(
        Finding(
            poc_id="swagger-api-docs-exposure",
            name="Swagger 文档暴露",
            severity="medium",
            target="http://target.local/swagger-ui.html",
            evidence="<title>404 Not Found</title><p>The requested resource /swagger-ui.html was not found.</p>",
            confidence=0.6,
            verified=False,
        ),
        expected_false_positive=True,
        note="典型的『路径被回显到 404 页面』误报",
    ),
    LabeledFinding(
        Finding(
            poc_id="backup-file-source-leak",
            name="源码备份文件可下载",
            severity="high",
            target="http://target.local/backup.zip",
            evidence="Cannot GET /backup.zip",
            confidence=0.6,
            verified=False,
        ),
        expected_false_positive=True,
        note="Express 默认 404 响应",
    ),
    LabeledFinding(
        Finding(
            poc_id="spring-actuator-env-exposure",
            name="Actuator 端点暴露",
            severity="high",
            target="http://target.local/actuator/env",
            evidence="Whitelabel Error Page\nThis application has no explicit mapping for /error",
            confidence=0.6,
            verified=False,
        ),
        expected_false_positive=True,
        note="Spring 默认错误页，说明路由不存在",
    ),
    # ---- 边界样本：证据不足以判断 ----
    LabeledFinding(
        Finding(
            poc_id="phpinfo-page-exposure",
            name="phpinfo 页面暴露",
            severity="medium",
            target="http://target.local/info.php",
            evidence="PHP Version 8.1.2",
            confidence=0.5,
            verified=False,
        ),
        expected_false_positive=False,
        note="证据较弱但特征明确；属于需要人工确认的边界情况",
    ),
)


@dataclass
class EvaluationResult:
    """评估结果。"""

    total: int = 0
    correct: int = 0
    uncertain: int = 0
    false_positives_caught: int = 0
    false_positives_total: int = 0
    true_positives_caught: int = 0
    true_positives_total: int = 0
    provider: str = ""
    details: list[tuple[str, str, str]] = field(default_factory=list)
    """(poc_id, 期望, 实际) 三元组，用于人工核对。"""

    @property
    def accuracy(self) -> float:
        """准确率（不确定的计为错误 —— 保守计算）。"""
        return self.correct / self.total if self.total else 0.0

    @property
    def coverage(self) -> float:
        """有效研判比例（1 - 不确定率）。"""
        return (self.total - self.uncertain) / self.total if self.total else 0.0

    @property
    def fp_recall(self) -> float:
        """误报召回率：真正的误报里有多少被识别出来。"""
        return (
            self.false_positives_caught / self.false_positives_total
            if self.false_positives_total
            else 0.0
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "total": self.total,
            "correct": self.correct,
            "uncertain": self.uncertain,
            "accuracy": round(self.accuracy, 3),
            "coverage": round(self.coverage, 3),
            "fp_recall": round(self.fp_recall, 3),
            "false_positives": f"{self.false_positives_caught}/{self.false_positives_total}",
            "true_positives": f"{self.true_positives_caught}/{self.true_positives_total}",
        }


async def evaluate(
    provider: TriageProvider,
    samples: Sequence[LabeledFinding] | None = None,
) -> EvaluationResult:
    """在标注样本上评估研判效果。

    这是「我用了 LLM 降噪」和「误报率从 X% 降到 Y%」之间的桥 ——
    没有它，关于效果的表述就无法证伪。
    """
    items = list(samples if samples is not None else LABELED_SAMPLES)
    result = EvaluationResult(total=len(items), provider=provider.name)

    verdicts = await provider.judge_many([s.finding for s in items])

    for sample, verdict in zip(items, verdicts, strict=False):
        expected = "误报" if sample.expected_false_positive else "真阳性"
        actual = {
            VERDICT_FALSE_POSITIVE: "误报",
            VERDICT_TRUE_POSITIVE: "真阳性",
            VERDICT_UNCERTAIN: "不确定",
        }[verdict.verdict]

        if sample.expected_false_positive:
            result.false_positives_total += 1
            if verdict.is_false_positive:
                result.false_positives_caught += 1
        else:
            result.true_positives_total += 1
            if verdict.verdict == VERDICT_TRUE_POSITIVE:
                result.true_positives_caught += 1

        if verdict.verdict == VERDICT_UNCERTAIN:
            result.uncertain += 1
        elif (verdict.verdict == VERDICT_FALSE_POSITIVE) == sample.expected_false_positive:
            result.correct += 1

        result.details.append((sample.finding.poc_id, expected, actual))

    return result


__all__ = [
    "TriageVerdict",
    "Finding",
    "TriageProvider",
    "HeuristicProvider",
    "OpenAICompatProvider",
    "build_provider",
    "LabeledFinding",
    "LABELED_SAMPLES",
    "EvaluationResult",
    "evaluate",
    "VERDICT_TRUE_POSITIVE",
    "VERDICT_FALSE_POSITIVE",
    "VERDICT_UNCERTAIN",
]
