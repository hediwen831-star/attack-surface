"""PoC 加载器测试。

覆盖重点：
- 正常解析
- 各种非法结构必须在**加载阶段**就报错（而不是运行阶段），
  因为一个坏 PoC 跑到一半才失败，排查成本远高于启动时直接告诉作者哪里写错了。
- 内置 PoC 必须全部能通过校验 —— 这条测试相当于「自检」，
  防止自己在写 PoC 时手滑写错字段却没人发现。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from asp.exceptions import PoCParseError
from asp.plugins.loader import (
    SEVERITY_WEIGHTS,
    iter_poc_files,
    load_poc_file,
    load_pocs,
    parse_poc,
)

PACKAGE_POC_DIR = Path(__file__).resolve().parent.parent / "asp" / "pocs"


VALID_POC = {
    "id": "test-poc",
    "info": {"name": "测试 PoC", "severity": "high", "tags": ["test"]},
    "requests": [
        {
            "method": "GET",
            "path": ["{{BaseURL}}/test"],
            "matchers": [{"type": "status", "status": [200]}],
        }
    ],
}


def test_parse_valid_poc():
    poc = parse_poc(VALID_POC)
    assert poc.id == "test-poc"
    assert poc.info.name == "测试 PoC"
    assert poc.info.severity == "high"
    assert poc.info.weight == SEVERITY_WEIGHTS["high"]
    assert len(poc.requests) == 1
    assert poc.requests[0].method == "GET"


def test_parse_normalizes_method_case():
    data = {**VALID_POC, "requests": [{**VALID_POC["requests"][0], "method": "post"}]}
    assert parse_poc(data).requests[0].method == "POST"


def test_parse_path_string_becomes_list():
    data = {**VALID_POC, "requests": [{**VALID_POC["requests"][0], "path": "{{BaseURL}}/x"}]}
    assert parse_poc(data).requests[0].paths == ["{{BaseURL}}/x"]


def test_parse_tags_from_comma_string():
    data = {**VALID_POC, "info": {"name": "x", "severity": "low", "tags": "a, b,c"}}
    assert parse_poc(data).info.tags == ["a", "b", "c"]


@pytest.mark.parametrize(
    "mutate, reason",
    [
        (lambda d: d.pop("id"), "缺少 id"),
        (lambda d: d.update(id="a b!@#"), "id 含非法字符"),
        (lambda d: d.pop("info"), "缺少 info"),
        (lambda d: d.update(info={"severity": "high"}), "info 缺 name"),
        (lambda d: d.update(info={"name": "x", "severity": "super"}), "severity 非法"),
        (lambda d: d.pop("requests"), "缺少 requests"),
        (lambda d: d.update(requests=[]), "requests 为空"),
        (lambda d: d.update(requests=[{"path": ["/x"], "matchers": []}]), "缺 matchers"),
        (lambda d: d.update(requests=[{"matchers": VALID_POC["requests"][0]["matchers"]}]), "缺 path"),
        (
            lambda d: d.update(
                requests=[{**VALID_POC["requests"][0], "method": "TRACE"}]
            ),
            "非法 HTTP 方法",
        ),
        (
            lambda d: d.update(
                requests=[{**VALID_POC["requests"][0], "matchers-condition": "xor"}]
            ),
            "非法 condition",
        ),
    ],
)
def test_parse_rejects_invalid(mutate, reason):
    import copy

    data = copy.deepcopy(VALID_POC)
    mutate(data)
    with pytest.raises(PoCParseError):
        parse_poc(data)


def test_load_poc_file_yaml_error(tmp_path: Path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: x\n  info: [unclosed", encoding="utf-8")
    with pytest.raises(PoCParseError):
        load_poc_file(bad)


def test_load_poc_file_empty(tmp_path: Path):
    empty = tmp_path / "empty.yaml"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(PoCParseError):
        load_poc_file(empty)


def test_iter_poc_files_skips_underscore_and_non_yaml(tmp_path: Path):
    (tmp_path / "a.yaml").write_text("x", encoding="utf-8")
    (tmp_path / "_template.yaml").write_text("x", encoding="utf-8")
    (tmp_path / "readme.txt").write_text("x", encoding="utf-8")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "b.yml").write_text("x", encoding="utf-8")

    names = {p.name for p in iter_poc_files([tmp_path])}
    assert names == {"a.yaml", "b.yml"}


def test_load_pocs_skips_broken_by_default(tmp_path: Path):
    (tmp_path / "good.yaml").write_text(
        "id: good\ninfo:\n  name: ok\n  severity: low\n"
        "requests:\n  - path: [x]\n    matchers: [{type: status, status: [200]}]\n",
        encoding="utf-8",
    )
    (tmp_path / "broken.yaml").write_text("id: broken\n", encoding="utf-8")

    pocs = load_pocs([tmp_path])
    assert [p.id for p in pocs] == ["good"]


def test_load_pocs_strict_raises(tmp_path: Path):
    (tmp_path / "broken.yaml").write_text("id: broken\n", encoding="utf-8")
    with pytest.raises(PoCParseError):
        load_pocs([tmp_path], strict=True)


def test_load_pocs_severity_filter(tmp_path: Path):
    for poc_id, severity in (("a", "high"), ("b", "low"), ("c", "critical")):
        (tmp_path / f"{poc_id}.yaml").write_text(
            f"id: {poc_id}\ninfo:\n  name: {poc_id}\n  severity: {severity}\n"
            "requests:\n  - path: [x]\n    matchers: [{type: status, status: [200]}]\n",
            encoding="utf-8",
        )

    pocs = load_pocs([tmp_path], severities=["high", "critical"])
    assert [p.id for p in pocs] == ["c", "a"]  # 按严重级别降序


def test_load_pocs_tag_filter(tmp_path: Path):
    (tmp_path / "a.yaml").write_text(
        "id: a\ninfo:\n  name: a\n  severity: low\n  tags: [git, exposure]\n"
        "requests:\n  - path: [x]\n    matchers: [{type: status, status: [200]}]\n",
        encoding="utf-8",
    )
    (tmp_path / "b.yaml").write_text(
        "id: b\ninfo:\n  name: b\n  severity: low\n  tags: [spring]\n"
        "requests:\n  - path: [x]\n    matchers: [{type: status, status: [200]}]\n",
        encoding="utf-8",
    )

    assert [p.id for p in load_pocs([tmp_path], tags=["git"])] == ["a"]
    assert [p.id for p in load_pocs([tmp_path], tags=["nope"])] == []


def test_load_pocs_dedupes_duplicate_ids(tmp_path: Path):
    body = (
        "id: same\ninfo:\n  name: n\n  severity: low\n"
        "requests:\n  - path: [x]\n    matchers: [{type: status, status: [200]}]\n"
    )
    (tmp_path / "one.yaml").write_text(body, encoding="utf-8")
    (tmp_path / "two.yaml").write_text(body, encoding="utf-8")
    assert len(load_pocs([tmp_path])) == 1


def test_load_pocs_missing_dir_is_tolerated():
    """目录不存在只告警，不抛异常 —— 用户可能只想用自己指定的目录。"""
    assert load_pocs(["/nonexistent/path/xyz"]) == []


def test_builtin_pocs_are_valid():
    """自检：仓库内置的每个 PoC 都必须能通过加载校验。

    这条测试会在 CI 里跑，等于给所有贡献者一个「格式守门人」。
    """
    pocs = load_pocs([PACKAGE_POC_DIR], strict=True)
    assert len(pocs) >= 5, f"内置 PoC 数量异常: {len(pocs)}"

    for poc in pocs:
        assert poc.id
        assert poc.info.name
        assert poc.info.severity in SEVERITY_WEIGHTS
        assert poc.requests

    ids = [p.id for p in pocs]
    assert len(ids) == len(set(ids)), "内置 PoC 存在重复 id"


def test_template_file_is_not_loaded():
    """``_`` 开头的模板文件不该被加载。"""
    ids = {p.id for p in load_pocs([PACKAGE_POC_DIR], strict=True)}
    assert "template-example" not in ids
