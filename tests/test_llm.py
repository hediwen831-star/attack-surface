"""LLM 辅助告警降噪测试。

覆盖重点：
- 启发式的三类信号（误报 / 真阳性 / 结构化）与不确定分支
- **模型的防御性解析**（模型不按格式输出是常态，不能因此中断整批研判）
- 评估函数的指标计算
- provider 工厂的降级逻辑
"""

from __future__ import annotations

import pytest

from asp.llm import (
    LABELED_SAMPLES,
    VERDICT_FALSE_POSITIVE,
    VERDICT_TRUE_POSITIVE,
    VERDICT_UNCERTAIN,
    EvaluationResult,
    Finding,
    HeuristicProvider,
    LabeledFinding,
    OpenAICompatProvider,
    TriageVerdict,
    build_provider,
    evaluate,
)


def make_finding(evidence: str = "", target: str = "http://t.local/x", **kw) -> Finding:
    return Finding(
        poc_id=kw.get("poc_id", "test-poc"),
        name=kw.get("name", "测试插件"),
        severity=kw.get("severity", "high"),
        target=target,
        evidence=evidence,
        confidence=kw.get("confidence", 1.0),
        verified=kw.get("verified", False),
    )


# ---------------------------------------------------------- 启发式：误报


@pytest.mark.parametrize(
    "evidence",
    [
        "<title>404 Not Found</title>",
        "The requested resource /x was not found.",
        "Cannot GET /backup.zip",
        "Whitelabel Error Page",
        "<title>Not Found</title>",
    ],
)
async def test_heuristic_detects_error_pages(evidence):
    """错误页特征必须被判为误报 —— 这是最常见的一类假阳性。"""
    verdict = await HeuristicProvider().judge(make_finding(evidence))
    assert verdict.verdict == VERDICT_FALSE_POSITIVE
    assert verdict.confidence > 0
    assert "启发式" in verdict.reason


async def test_heuristic_error_page_signal_has_priority():
    """同时含误报信号与真阳性信号时，误报优先（保守）。

    宁可把一条真漏洞标成待复核，也不要把错误页放过 ——
    因为错误页会污染整份报告的可信度。
    """
    evidence = "status=200\n404 Not Found"
    verdict = await HeuristicProvider().judge(make_finding(evidence))
    assert verdict.verdict == VERDICT_FALSE_POSITIVE


# ---------------------------------------------------------- 启发式：真阳性


async def test_heuristic_recognizes_negative_control():
    """负向对照通过是很强的真阳性证据。"""
    verdict = await HeuristicProvider().judge(
        make_finding("status=200\nhit='MARKER'\nnegative-match")
    )
    assert verdict.verdict == VERDICT_TRUE_POSITIVE
    assert "对照" in verdict.reason


async def test_heuristic_recognizes_ini_structure():
    """INI 配置段标记 —— 这是被泄露的配置文件本身的内容。"""
    verdict = await HeuristicProvider().judge(
        make_finding("[core]\nrepositoryformatversion = 0")
    )
    assert verdict.verdict == VERDICT_TRUE_POSITIVE


async def test_heuristic_recognizes_json_structure():
    verdict = await HeuristicProvider().judge(
        make_finding('{"activeProfiles": [], "propertySources": []}')
    )
    assert verdict.verdict == VERDICT_TRUE_POSITIVE


async def test_heuristic_does_not_treat_sql_as_structured():
    """回归测试：SQL 语句里的 `id = 1` 不该被当成配置项。

    曾经加过一条「key = value 形式」的通用规则，结果 SQL 报错信息
    也被判成真阳性 —— 规则写太宽松的代价是误判，而误判比不判更糟
    （它会让人放松警惕）。
    """
    verdict = await HeuristicProvider().judge(
        make_finding("SQLSTATE[HY000]: near \"id = 1\": syntax error")
    )
    # 既不该判真阳性（没有结构化证据），也不该判误报（没有错误页特征）
    assert verdict.verdict == VERDICT_UNCERTAIN


# ---------------------------------------------------------- 启发式：不确定


async def test_heuristic_returns_uncertain_instead_of_guessing():
    """证据不足时应该说「不知道」，而不是猜一个结论。

    一个会瞎猜的降级方案比没有降级方案更危险 ——
    它会让人误以为已经做过降噪了。
    """
    verdict = await HeuristicProvider().judge(make_finding("PHP Version 8.1.2"))
    assert verdict.verdict == VERDICT_UNCERTAIN
    assert verdict.confidence == 0.0
    assert "人工复核" in verdict.reason


async def test_heuristic_confidence_is_capped():
    """启发式的置信度上限被压低 —— 它的判断依据单薄，不该表现出高确定性。"""
    provider = HeuristicProvider()
    for evidence in ["negative-match", "status=200", "[core]"]:
        verdict = await provider.judge(make_finding(evidence))
        assert verdict.confidence <= provider.MAX_CONFIDENCE


async def test_heuristic_handles_empty_evidence():
    verdict = await HeuristicProvider().judge(make_finding(""))
    assert verdict.verdict == VERDICT_UNCERTAIN


# ---------------------------------------------------------- 批量研判


async def test_judge_many_preserves_order():
    findings = [
        make_finding("404 Not Found", poc_id="a"),
        make_finding("negative-match", poc_id="b"),
        make_finding("nothing here", poc_id="c"),
    ]
    verdicts = await HeuristicProvider().judge_many(findings)
    assert len(verdicts) == 3
    assert verdicts[0].verdict == VERDICT_FALSE_POSITIVE
    assert verdicts[1].verdict == VERDICT_TRUE_POSITIVE
    assert verdicts[2].verdict == VERDICT_UNCERTAIN


# ---------------------------------------------------------- LLM 响应解析


def make_llm() -> OpenAICompatProvider:
    return OpenAICompatProvider(api_key="fake-key-for-parsing-tests")


def llm_response(content: str) -> dict:
    return {"choices": [{"message": {"content": content}}]}


def test_llm_parses_plain_json():
    verdict = make_llm()._parse_response(
        llm_response('{"verdict":"false_positive","confidence":0.9,"reason":"是错误页"}')
    )
    assert verdict.verdict == VERDICT_FALSE_POSITIVE
    assert verdict.confidence == 0.9
    assert verdict.reason == "是错误页"


def test_llm_parses_json_in_markdown_fence():
    """模型很爱把 JSON 包在 ``` 里 —— 必须能处理，否则一半的响应都解析失败。"""
    content = '```json\n{"verdict":"true_positive","confidence":0.8,"reason":"结构化证据"}\n```'
    verdict = make_llm()._parse_response(llm_response(content))
    assert verdict.verdict == VERDICT_TRUE_POSITIVE
    assert verdict.confidence == 0.8


def test_llm_extracts_json_from_chatty_output():
    """模型可能先唠一句再输出 JSON —— 从文本里抠出第一个 JSON 对象。"""
    content = '好的，我的判断如下：\n{"verdict":"uncertain","confidence":0.3,"reason":"证据不足"}\n希望有帮助。'
    verdict = make_llm()._parse_response(llm_response(content))
    assert verdict.verdict == VERDICT_UNCERTAIN


def test_llm_handles_malformed_output():
    """完全无法解析时返回 uncertain，而不是抛异常。

    抛异常会让一条格式错误中断整批研判 —— 那是不可接受的。
    """
    verdict = make_llm()._parse_response(llm_response("这不是 JSON"))
    assert verdict.verdict == VERDICT_UNCERTAIN
    assert "无法解析" in verdict.reason or "不是合法 JSON" in verdict.reason


def test_llm_handles_broken_response_structure():
    for bad in [{}, {"choices": []}, {"choices": [{}]}, {"choices": "x"}]:
        verdict = make_llm()._parse_response(bad)
        assert verdict.verdict == VERDICT_UNCERTAIN
        assert verdict.reason


def test_llm_normalizes_unknown_verdict():
    """模型可能输出没见过的词 —— 归一成 uncertain 而不是原样透传。"""
    verdict = make_llm()._parse_response(
        llm_response('{"verdict":"maybe_a_bug","confidence":0.5,"reason":"x"}')
    )
    assert verdict.verdict == VERDICT_UNCERTAIN


def test_llm_clamps_confidence_range():
    """置信度必须落在 [0,1] —— 模型可能输出 1.5 或 -0.2。"""
    high = make_llm()._parse_response(
        llm_response('{"verdict":"true_positive","confidence":1.5,"reason":"x"}')
    )
    low = make_llm()._parse_response(
        llm_response('{"verdict":"true_positive","confidence":-0.2,"reason":"x"}')
    )
    assert high.confidence == 1.0
    assert low.confidence == 0.0


def test_llm_handles_non_numeric_confidence():
    verdict = make_llm()._parse_response(
        llm_response('{"verdict":"true_positive","confidence":"高","reason":"x"}')
    )
    assert verdict.confidence == 0.0
    assert verdict.verdict == VERDICT_TRUE_POSITIVE


async def test_llm_without_api_key_returns_uncertain():
    """没 key 时不该假装调用，也不该抛异常 —— 直接说无法研判。"""
    provider = OpenAICompatProvider(api_key="")
    verdict = await provider.judge(make_finding("anything"))
    assert verdict.verdict == VERDICT_UNCERTAIN
    assert "未配置" in verdict.reason


# ---------------------------------------------------------- 工厂


def test_build_provider_explicit_heuristic():
    assert isinstance(build_provider("heuristic"), HeuristicProvider)


def test_build_provider_auto_without_key_falls_back(monkeypatch):
    """auto 模式在没 key 时降级到启发式 —— 保证功能始终可跑。"""
    monkeypatch.delenv("ASP_LLM_API_KEY", raising=False)
    assert isinstance(build_provider("auto"), HeuristicProvider)


def test_build_provider_auto_with_key_uses_llm(monkeypatch):
    monkeypatch.setenv("ASP_LLM_API_KEY", "sk-test")
    provider = build_provider("auto")
    assert isinstance(provider, OpenAICompatProvider)
    assert provider.api_key == "sk-test"


def test_build_provider_explicit_openai_without_key_falls_back(monkeypatch):
    """显式指定 openai 但没有 key 时也降级（而不是崩掉）。"""
    monkeypatch.delenv("ASP_LLM_API_KEY", raising=False)
    assert isinstance(build_provider("openai"), HeuristicProvider)


def test_build_provider_reads_base_url_and_model_from_env(monkeypatch):
    monkeypatch.setenv("ASP_LLM_API_KEY", "sk-test")
    monkeypatch.setenv("ASP_LLM_BASE_URL", "https://api.deepseek.com/v1")
    monkeypatch.setenv("ASP_LLM_MODEL", "deepseek-chat")
    provider = build_provider("auto")
    assert provider.base_url == "https://api.deepseek.com/v1"
    assert provider.model == "deepseek-chat"


def test_build_provider_trims_trailing_slash():
    provider = build_provider("openai", base_url="https://x.com/v1/", api_key="k")
    assert provider.base_url == "https://x.com/v1"


# ---------------------------------------------------------- 评估


async def test_evaluate_produces_metrics():
    result = await evaluate(HeuristicProvider())
    assert isinstance(result, EvaluationResult)
    assert result.total == len(LABELED_SAMPLES)
    assert result.correct + result.uncertain <= result.total
    assert 0.0 <= result.accuracy <= 1.0
    assert 0.0 <= result.coverage <= 1.0
    assert 0.0 <= result.fp_recall <= 1.0


async def test_evaluate_catches_all_labeled_false_positives():
    """启发式至少要把标注样本里的误报全抓出来 —— 这是它的核心职责。"""
    result = await evaluate(HeuristicProvider())
    assert result.false_positives_caught == result.false_positives_total


async def test_evaluate_metrics_consistent():
    """指标之间要对得上，不能出现自相矛盾的数字。"""
    result = await evaluate(HeuristicProvider())
    assert result.false_positives_caught <= result.false_positives_total
    assert result.true_positives_caught <= result.true_positives_total
    assert result.false_positives_total + result.true_positives_total == result.total
    assert result.correct + result.uncertain + 0 <= result.total


async def test_evaluate_on_custom_samples():
    samples = [
        type(LABELED_SAMPLES[0])(
            finding=make_finding("404 Not Found", poc_id="x"),
            expected_false_positive=True,
        ),
        type(LABELED_SAMPLES[0])(
            finding=make_finding("negative-match", poc_id="y"),
            expected_false_positive=False,
        ),
    ]
    result = await evaluate(HeuristicProvider(), samples)
    assert result.total == 2
    assert result.correct == 2
    assert result.accuracy == 1.0
    assert result.fp_recall == 1.0


async def test_evaluate_counts_uncertain_as_error():
    """不确定计为错误（保守计算）—— 否则「什么都不判」会得到满分。"""
    samples = [LabeledFinding(make_finding("完全无法判断的内容"), True)]
    result = await evaluate(HeuristicProvider(), samples)
    assert result.uncertain == 1
    assert result.correct == 0
    assert result.accuracy == 0.0


async def test_evaluate_result_is_serializable():
    result = await evaluate(HeuristicProvider())
    data = result.to_dict()
    assert data["provider"] == "heuristic"
    assert isinstance(data["accuracy"], float)
    assert "/" in data["false_positives"]


# ---------------------------------------------------------- 数据结构


def test_verdict_to_dict():
    verdict = TriageVerdict(
        verdict=VERDICT_FALSE_POSITIVE, confidence=0.8765, reason="r", provider="p"
    )
    data = verdict.to_dict()
    assert data["is_false_positive"] is True
    assert data["confidence"] == 0.88      # 保留两位小数
    assert data["verdict"] == VERDICT_FALSE_POSITIVE


def test_finding_from_vuln_like_object():
    """能从任意具有同名属性的对象构造（与数据模型解耦）。"""

    class FakeVuln:
        poc_id = "p"
        name = "n"
        severity = "high"
        target = "http://x"
        evidence = "e"
        confidence = 0.9
        verified = True

    finding = Finding.from_vuln(FakeVuln())
    assert finding.poc_id == "p"
    assert finding.verified is True
    assert finding.confidence == 0.9


def test_finding_prompt_text_contains_key_fields():
    text = make_finding("evidence-here").to_prompt_text()
    for key in ["检测插件", "命中 URL", "命中证据", "evidence-here"]:
        assert key in text


def test_labeled_samples_cover_both_classes():
    """标注样本必须两类都有 —— 只有正例的评估集算不出召回率。"""
    positive = [s for s in LABELED_SAMPLES if not s.expected_false_positive]
    negative = [s for s in LABELED_SAMPLES if s.expected_false_positive]
    assert len(positive) >= 2
    assert len(negative) >= 2
    assert all(s.note for s in LABELED_SAMPLES), "每个样本都应有标注说明"
