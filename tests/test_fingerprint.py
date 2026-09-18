"""Web 指纹识别测试。

覆盖重点：
- **MurmurHash3 实现与官方 mmh3 库交叉验证**（这是自研算法必须有的验证）
- favicon 哈希的编码细节（必须用 encodebytes 而非 b64encode）
- 规则解析与校验
- 置信度累加机制（弱特征单独命中不该判定存在）
"""

from __future__ import annotations

from pathlib import Path

import pytest

from asp.core.http import Response
from asp.discover.fingerprint import (
    CATEGORY_CMS,
    DEFAULT_CONFIDENCE_THRESHOLD,
    ComponentResult,
    FingerprintRule,
    favicon_hash,
    load_rules,
    match_fingerprints,
    murmurhash3_x86_32,
    parse_rule,
)


def make_response(body: str = "", headers: dict | None = None, status: int = 200) -> Response:
    """构造测试用响应。"""
    return Response(
        url="http://example.com/",
        status=status,
        headers=headers or {},
        content=body.encode(),
    )


# ------------------------------------------------- MurmurHash3 正确性


def test_mmh3_empty_input():
    """空输入在 seed=0 时返回 0 —— 这是 MurmurHash3 的定义。"""
    assert murmurhash3_x86_32(b"") == 0


def test_mmh3_returns_signed_int():
    """必须返回有符号 32 位整数，否则与 Shodan 等平台的记录对不上。"""
    for data in [b"a", b"hello", bytes(range(256)), b"x" * 100]:
        value = murmurhash3_x86_32(data)
        assert -(2**31) <= value < 2**31, f"{data[:10]!r} 返回了越界值 {value}"


def test_mmh3_is_deterministic():
    data = b"deterministic input"
    assert murmurhash3_x86_32(data) == murmurhash3_x86_32(data)


def test_mmh3_different_inputs_differ():
    assert murmurhash3_x86_32(b"abc") != murmurhash3_x86_32(b"abd")


def test_mmh3_known_vectors():
    """已知向量回归基线。

    这些值是用官方 mmh3 库算出来的 —— 作为回归基线，
    防止后续重构破坏算法（例如把 mask 写错、轮转方向写反）。
    """
    assert murmurhash3_x86_32(b"hello") == 613153351
    assert murmurhash3_x86_32(b"a") == 1009084850
    assert murmurhash3_x86_32(b"0123456789") == 1891213601


def test_mmh3_matches_reference_library():
    """与官方 mmh3 库逐字节交叉验证。

    这是【自研算法必须有的测试】：自己实现的东西不能自己验证自己。
    官方库缺失时自动跳过（它是 dev 依赖，不进运行时）。
    """
    mmh3 = pytest.importorskip("mmh3", reason="需要 mmh3 库做交叉验证")

    samples = [
        b"",
        b"a",
        b"hello world",
        b"0123456789",
        bytes(range(256)),
        b"x" * 1000,
        bytes(range(255, -1, -1)),
    ]
    for data in samples:
        assert murmurhash3_x86_32(data) == mmh3.hash(data), f"输入 {data[:20]!r} 不一致"


def test_mmh3_tail_handling_all_lengths():
    """长度 0-8 覆盖了「尾部不足 4 字节」的全部余数情况。

    尾部处理是 MurmurHash3 实现最容易写错的地方（tail 分支），
    所以专门把 0~8 每个长度都过一遍。
    """
    mmh3 = pytest.importorskip("mmh3", reason="需要 mmh3 库做交叉验证")
    for length in range(0, 9):
        data = bytes(range(length))
        assert murmurhash3_x86_32(data) == mmh3.hash(data), f"长度 {length} 不一致"


# ------------------------------------------------- favicon 哈希


def test_favicon_hash_empty():
    assert favicon_hash(b"") == 0


def test_favicon_hash_uses_encodebytes_not_b64encode():
    """关键细节：必须用带换行的 encodebytes。

    用 B64encode 会得到完全不同的哈希，导致与所有公开指纹库对不上。
    这个测试用「两种编码结果不同」来锁住这个约定。
    """
    import base64

    content = b"\x00\x01\x02\x03" * 30   # 120 字节，base64 后必然超过 76 字符产生换行

    encoded_with_newlines = base64.encodebytes(content)
    encoded_plain = base64.b64encode(content)
    assert encoded_with_newlines != encoded_plain, "测试素材应能让两种编码产生差异"

    assert favicon_hash(content) == murmurhash3_x86_32(encoded_with_newlines)
    assert favicon_hash(content) != murmurhash3_x86_32(encoded_plain)


def test_favicon_hash_matches_reference():
    import base64

    mmh3 = pytest.importorskip("mmh3", reason="需要 mmh3 库做交叉验证")
    for content in [b"fake-favicon", bytes(range(120)), b"\x89PNG\r\n\x1a\n" + b"\x00" * 200]:
        assert favicon_hash(content) == mmh3.hash(base64.encodebytes(content))


# ------------------------------------------------- 规则解析


def test_parse_rule_minimal():
    rule = parse_rule({"name": "Nginx", "headers": ["Server: nginx"]})
    assert rule.name == "Nginx"
    assert rule.confidence == 0.5
    assert rule.headers == ["Server: nginx"]


def test_parse_rule_string_instead_of_list():
    """YAML 里写单个字符串应该被接受 —— 不该强迫作者写成列表。"""
    rule = parse_rule({"name": "X", "body": "wp-content"})
    assert rule.body == ["wp-content"]


def test_parse_rule_requires_name():
    with pytest.raises(ValueError, match="name"):
        parse_rule({"headers": ["x"]})


def test_parse_rule_rejects_bad_confidence():
    with pytest.raises(ValueError, match="confidence"):
        parse_rule({"name": "X", "confidence": 0})
    with pytest.raises(ValueError, match="confidence"):
        parse_rule({"name": "X", "confidence": 1.5})


def test_load_rules_from_directory(tmp_path: Path):
    (tmp_path / "rules.yaml").write_text(
        "- name: TestCMS\n"
        "  category: cms\n"
        "  confidence: 0.7\n"
        "  body: ['test-marker']\n",
        encoding="utf-8",
    )
    rules = load_rules([tmp_path])
    assert len(rules) == 1
    assert rules[0].name == "TestCMS"


def test_load_rules_skips_underscore_files(tmp_path: Path):
    """``_`` 开头的文件是模板/草稿，不该被加载。"""
    (tmp_path / "_template.yaml").write_text("- name: Draft\n", encoding="utf-8")
    (tmp_path / "real.yaml").write_text(
        "- name: Real\n  headers: ['x']\n", encoding="utf-8"
    )
    names = [r.name for r in load_rules([tmp_path])]
    assert "Real" in names
    assert "Draft" not in names


def test_load_rules_missing_dir_is_not_fatal(tmp_path: Path):
    """目录不存在不该抛异常 —— 只是没有规则而已。"""
    assert load_rules([tmp_path / "nope"]) == []


def test_builtin_rules_load_successfully():
    """仓库自带的规则库必须能被加载（CI 守门人）。

    踩过的坑：内置规则目录曾用相对路径解析，导致从非项目根目录执行时
    规则数为 0，且没有任何报错 —— 扫描照跑，只是什么都识别不出来。
    """
    rules = load_rules(["rules"])
    assert len(rules) >= 30, f"内置规则数量异常偏少：{len(rules)}"

    names = {r.name for r in rules}
    for expected in ["Nginx", "Apache httpd", "WordPress", "PHP", "jQuery"]:
        assert expected in names, f"内置规则缺少 {expected}"


# ------------------------------------------------- 匹配与置信度


def test_match_by_header():
    rules = [FingerprintRule("Nginx", confidence=0.9, headers=[r"Server:\s*nginx"])]
    resp = make_response(headers={"Server": "nginx/1.24.0"})
    results = match_fingerprints(rules, resp)
    assert len(results) == 1
    assert results[0].name == "Nginx"
    assert results[0].confidence == 0.9


def test_match_by_cookie_name():
    rules = [FingerprintRule("PHP", confidence=0.6, cookies=["PHPSESSID"])]
    resp = make_response(headers={"Set-Cookie": "PHPSESSID=abc123; path=/"})
    results = match_fingerprints(rules, resp)
    assert results and results[0].name == "PHP"


def test_match_by_favicon_hash():
    rules = [
        FingerprintRule("KnownApp", confidence=0.9, favicon_hashes=["187403486"])
    ]
    resp = make_response(body="irrelevant")
    assert match_fingerprints(rules, resp, favicon=187403486)
    assert not match_fingerprints(rules, resp, favicon=999)


def test_weak_single_rule_below_threshold_is_dropped():
    """单条弱规则命中不该判定组件存在 —— 这是置信度机制的核心价值。"""
    rules = [FingerprintRule("WordPress", confidence=0.4, body=[r"wp-content/"])]
    resp = make_response(body='<link href="/wp-content/style.css">')
    assert match_fingerprints(rules, resp) == []


def test_multiple_weak_rules_accumulate():
    """多条弱规则同时命中应该累加并越过阈值。"""
    rules = [
        FingerprintRule("WordPress", confidence=0.4, body=[r"wp-content/"]),
        FingerprintRule("WordPress", confidence=0.4, body=[r"wp-includes/"]),
    ]
    resp = make_response(body="wp-content/ and wp-includes/ both here")
    results = match_fingerprints(rules, resp)
    assert len(results) == 1
    assert results[0].confidence == pytest.approx(0.8)
    assert len(results[0].evidence) == 2


def test_confidence_capped_at_one():
    rules = [
        FingerprintRule("X", confidence=0.6, body=["marker"]),
        FingerprintRule("X", confidence=0.6, body=["marker"]),
        FingerprintRule("X", confidence=0.6, body=["marker"]),
    ]
    resp = make_response(body="marker")
    results = match_fingerprints(rules, resp)
    assert results[0].confidence == 1.0


def test_version_extracted_from_rule():
    rules = [
        FingerprintRule(
            "Nginx",
            confidence=0.9,
            headers=[r"Server:\s*nginx"],
            version_regex=r"nginx/([\d.]+)",
        )
    ]
    resp = make_response(headers={"Server": "nginx/1.25.3"})
    results = match_fingerprints(rules, resp)
    assert results[0].version == "1.25.3"


def test_results_sorted_by_confidence():
    rules = [
        FingerprintRule("Weak", confidence=0.6, body=["marker"]),
        FingerprintRule("Strong", confidence=0.95, body=["marker"]),
    ]
    resp = make_response(body="marker")
    results = match_fingerprints(rules, resp)
    assert [r.name for r in results] == ["Strong", "Weak"]


def test_no_match_returns_empty():
    rules = [FingerprintRule("Nginx", confidence=0.9, headers=[r"Server:\s*nginx"])]
    assert match_fingerprints(rules, make_response(headers={"Server": "Apache"})) == []


def test_threshold_is_configurable():
    rules = [FingerprintRule("Weak", confidence=0.4, body=["marker"])]
    resp = make_response(body="marker")
    assert match_fingerprints(rules, resp) == []
    assert match_fingerprints(rules, resp, threshold=0.3)


def test_default_threshold_value():
    assert DEFAULT_CONFIDENCE_THRESHOLD == 0.5


def test_component_to_dict():
    component = ComponentResult(
        name="Nginx", version="1.24", category="middleware", confidence=0.8765,
        evidence=["header:nginx"],
    )
    data = component.to_dict()
    assert data["confidence"] == 0.88       # 保留两位小数
    assert data["name"] == "Nginx"


def test_custom_rule_matches_realistic_page():
    """贴近真实场景：一个 WordPress 站点的完整响应。"""
    rules = [
        FingerprintRule("WordPress", category=CATEGORY_CMS, confidence=0.4,
                        body=[r"wp-content/"]),
        FingerprintRule("WordPress", category=CATEGORY_CMS, confidence=0.4,
                        body=[r"wp-includes/"]),
        FingerprintRule("PHP", confidence=0.5, headers=[r"X-Powered-By:\s*PHP"]),
    ]
    resp = make_response(
        body='<html><head><link rel="stylesheet" href="/wp-content/themes/x/style.css">'
             '<script src="/wp-includes/js/jquery.js"></script></head></html>',
        headers={"X-Powered-By": "PHP/8.1.2", "Server": "nginx/1.24.0"},
    )
    results = match_fingerprints(rules, resp)
    names = {r.name for r in results}
    assert "WordPress" in names
    assert "PHP" in names
