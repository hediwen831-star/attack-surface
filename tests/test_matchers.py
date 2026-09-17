"""匹配器单元测试。

覆盖重点：
- 四种匹配器的正常路径与边界
- ``condition: and/or`` 与 ``negative`` 的组合语义
- DSL **必须拒绝白名单外的语法**（这是安全边界，不是功能）
"""

from __future__ import annotations

import pytest

from asp.exceptions import PluginError
from asp.plugins.matchers import (
    evaluate_matcher,
    evaluate_matchers,
    get_part,
    match_dsl,
    match_regex,
    match_status,
    match_word,
    run_extractors,
)

# --------------------------------------------------------------- status


def test_status_single_int(make_response):
    resp = make_response(status=200)
    assert match_status({"type": "status", "status": 200}, resp).matched


def test_status_list(make_response):
    resp = make_response(status=403)
    assert match_status({"type": "status", "status": [200, 403]}, resp).matched


def test_status_miss(make_response):
    resp = make_response(status=404)
    result = match_status({"type": "status", "status": [200]}, resp)
    assert not result.matched


def test_status_missing_field_raises(make_response):
    with pytest.raises(PluginError):
        match_status({"type": "status"}, make_response())


# --------------------------------------------------------------- word


def test_word_or_default(make_response):
    """默认 condition=or：任一命中即算命中。"""
    resp = make_response(body="hello [core] world")
    result = match_word({"type": "word", "words": ["[core]", "nothere"]}, resp)
    assert result.matched
    assert "[core]" in result.evidence


def test_word_and_requires_all(make_response):
    resp = make_response(body="[core] only")
    result = match_word(
        {"type": "word", "words": ["[core]", "repositoryformatversion"], "condition": "and"},
        resp,
    )
    assert not result.matched


def test_word_and_all_present(make_response):
    resp = make_response(body="[core]\nrepositoryformatversion = 0")
    result = match_word(
        {"type": "word", "words": ["[core]", "repositoryformatversion"], "condition": "and"},
        resp,
    )
    assert result.matched


def test_word_case_insensitive(make_response):
    resp = make_response(body="Swagger UI")
    result = match_word(
        {"type": "word", "words": ["swagger"], "case-insensitive": True}, resp
    )
    assert result.matched


def test_word_negative(make_response):
    """negative=true 时，包含该词反而算「不命中」—— 用于排除误报页。"""
    resp = make_response(body="this is a 404 not found page")
    result = match_word(
        {"type": "word", "words": ["404 not found"], "negative": True}, resp
    )
    assert not result.matched

    resp2 = make_response(body="real content here")
    assert match_word(
        {"type": "word", "words": ["404 not found"], "negative": True}, resp2
    ).matched


def test_word_header_part(make_response):
    resp = make_response(headers={"Server": "nginx/1.24.0"})
    result = match_word({"type": "word", "part": "header", "words": ["nginx"]}, resp)
    assert result.matched


def test_word_no_words_raises(make_response):
    with pytest.raises(PluginError):
        match_word({"type": "word"}, make_response())


# --------------------------------------------------------------- regex


def test_regex_match(make_response):
    resp = make_response(body="PHP Version 7.4.33")
    result = match_regex({"type": "regex", "regex": [r"PHP Version\s*([\d.]+)"]}, resp)
    assert result.matched


def test_regex_or_condition(make_response):
    resp = make_response(body='{"openapi": "3.0.1"}')
    result = match_regex(
        {"type": "regex", "regex": [r"swagger\":", r"openapi\"\s*:"], "condition": "or"},
        resp,
    )
    assert result.matched


def test_regex_and_condition_fails_partially(make_response):
    resp = make_response(body="openapi: 3.0.1")
    result = match_regex(
        {"type": "regex", "regex": [r"openapi", r"notpresent"], "condition": "and"}, resp
    )
    assert not result.matched


def test_regex_invalid_pattern_raises(make_response):
    with pytest.raises(PluginError):
        match_regex({"type": "regex", "regex": ["([unclosed"]}, make_response())


# --------------------------------------------------------------- DSL


def test_dsl_status_compare(make_response):
    resp = make_response(status=200)
    assert match_dsl({"dsl": ["status == 200"]}, resp).matched
    assert not match_dsl({"dsl": ["status == 500"]}, resp).matched


def test_dsl_contains(make_response):
    resp = make_response(body="response contains keyword here")
    assert match_dsl({"dsl": ["contains(body, 'keyword')"]}, resp).matched


def test_dsl_contains_header(make_response):
    resp = make_response(headers={"Server": "Apache/2.4.41"})
    # 注意：DSL 里的正则是「正则字符串」，点号要转义成 \. 才是字面点
    assert match_dsl({"dsl": [r"regex(header, 'Apache/2\.4')"]}, resp).matched


def test_dsl_len(make_response):
    resp = make_response(body="x" * 500)
    assert match_dsl({"dsl": ["len(body) > 100"]}, resp).matched
    assert not match_dsl({"dsl": ["len(body) > 1000"]}, resp).matched


def test_dsl_boolean_composition(make_response):
    """&& 与 || 组合。"""
    resp = make_response(status=200, body="admin panel")
    assert match_dsl(
        {"dsl": ["status == 200 && contains(body, 'admin')"]}, resp
    ).matched
    assert match_dsl(
        {"dsl": ["status == 500 || contains(body, 'panel')"]}, resp
    ).matched


def test_dsl_rejects_non_whitelisted_syntax(make_response):
    """安全边界测试：DSL 必须拒绝任意 Python 语义。

    如果这里失败，就意味着一个 YAML PoC 能在用户机器上执行任意代码 ——
    这是整个项目最严重的安全缺陷。
    """
    dangerous = [
        "__import__('os').system('id')",
        "eval('1+1')",
        "open('/etc/passwd').read()",
        "(lambda: 1)()",
        "status == 200 or __import__('os').popen('whoami')",
    ]
    for expression in dangerous:
        with pytest.raises(PluginError):
            match_dsl({"dsl": [expression]}, make_response())


# --------------------------------------------------------------- 组合


def test_evaluate_matchers_and_all_hit(make_response):
    resp = make_response(status=200, body="[core]\nrepositoryformatversion = 0")
    outcome = evaluate_matchers(
        [
            {"type": "status", "status": [200]},
            {"type": "word", "words": ["[core]"]},
        ],
        resp,
        condition="and",
    )
    assert outcome.matched
    assert outcome.confidence == 1.0


def test_evaluate_matchers_and_partial_hit(make_response):
    resp = make_response(status=200, body="nothing interesting")
    outcome = evaluate_matchers(
        [
            {"type": "status", "status": [200]},
            {"type": "word", "words": ["[core]"]},
        ],
        resp,
        condition="and",
    )
    assert not outcome.matched
    assert outcome.confidence == 0.0


def test_evaluate_matchers_or_partial_hit_caps_confidence(make_response):
    """or 条件下单个弱特征命中，置信度必须被压低。"""
    resp = make_response(status=200, body="swagger")
    outcome = evaluate_matchers(
        [
            {"type": "word", "words": ["swagger"], "case-insensitive": True},
            {"type": "regex", "regex": ['"paths"\\s*:\\s*\\{']},
        ],
        resp,
        condition="or",
    )
    assert outcome.matched
    assert outcome.confidence <= 0.8
    assert outcome.confidence > 0.0


def test_evaluate_matchers_empty_raises(make_response):
    with pytest.raises(PluginError):
        evaluate_matchers([], make_response())


def test_unknown_matcher_type_raises(make_response):
    with pytest.raises(PluginError):
        evaluate_matcher({"type": "javascript"}, make_response())


# --------------------------------------------------------------- parts


def test_get_part_all_includes_headers_and_body(make_response):
    resp = make_response(body="BODYTEXT", headers={"X-Test": "HEADERVALUE"})
    combined = get_part(resp, "all")
    assert "BODYTEXT" in combined
    assert "HEADERVALUE" in combined


def test_get_part_invalid_raises(make_response):
    with pytest.raises(PluginError):
        get_part(make_response(), "cookie")


# --------------------------------------------------------------- 提取器


def test_extract_regex_capture_group(make_response):
    resp = make_response(body="version=1.2.3-beta")
    extracted = run_extractors(
        [{"type": "regex", "part": "body", "name": "ver", "regex": [r"version=([\w.\-]+)"]}],
        resp,
    )
    assert extracted["ver"] == "1.2.3-beta"


def test_extract_kv_from_header(make_response):
    resp = make_response(headers={"Server": "nginx/1.24.0"})
    extracted = run_extractors(
        [{"type": "kv", "part": "header", "name": "server", "key": "Server"}], resp
    )
    assert extracted["server"] == "nginx/1.24.0"


def test_extract_missing_name_raises(make_response):
    with pytest.raises(PluginError):
        run_extractors([{"type": "regex", "regex": ["x"]}], make_response())
