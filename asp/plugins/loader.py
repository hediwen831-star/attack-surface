"""PoC 加载器。

## 格式设计

采用 YAML 而不是 Python 插件，理由是：

| 维度 | YAML PoC | Python 插件 |
|---|---|---|
| 编写门槛 | 会写 HTTP 请求就能写 | 要懂编程接口 |
| 安全风险 | 纯数据，无代码执行 | 加载即执行，等于 RCE |
| 复用性 | 社区生态大（nuclei / xray） | 各自为战 |
| 表达力 | 受限（这是特性） | 无限（这是风险） |

结论：检测逻辑用 YAML 描述，**引擎用代码实现**。
PoC 作者只关心「发什么请求、看什么特征」，不关心怎么调度、怎么限速、怎么去重。

## 一个 PoC 的完整结构

```yaml
id: git-config-exposure          # 唯一标识，必填
info:
  name: Git 配置文件泄露          # 展示名，必填
  severity: high                 # critical/high/medium/low/info，必填
  author: hediwen
  tags: [exposure, git]
  description: 站点暴露 .git 目录，可完整还原源码
  reference:
    - https://owasp.org/...
requests:                        # 至少一条
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words: ["[core]"]
    extractors:
      - type: regex
        part: body
        name: remote_url
        regex: ["url\\s*=\\s*(.+)"]
```
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..exceptions import PoCParseError
from ..logger import get_logger

try:
    import yaml
except ImportError as exc:  # pragma: no cover
    raise PoCParseError("缺少 PyYAML 依赖") from exc

logger = get_logger("plugins.loader")

#: 严重级别白名单与默认排序权重（数字越大越严重）
SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}

VALID_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}


@dataclass
class PoCRequest:
    """PoC 中的一次请求定义。"""

    method: str = "GET"
    paths: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    matchers_condition: str = "and"
    matchers: list[dict[str, Any]] = field(default_factory=list)
    extractors: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.method = self.method.upper()
        if self.method not in VALID_METHODS:
            raise PoCParseError(
                "不支持的 HTTP 方法", method=self.method, valid=sorted(VALID_METHODS)
            )
        if not self.paths:
            raise PoCParseError("请求未定义 path")
        if not self.matchers:
            raise PoCParseError(
                "请求未定义 matchers —— 没有判定条件的 PoC 会命中所有目标"
            )
        if self.matchers_condition not in ("and", "or"):
            raise PoCParseError(
                "matchers-condition 只能是 and 或 or", got=self.matchers_condition
            )


@dataclass
class PoCInfo:
    """PoC 元信息。"""

    name: str
    severity: str = "info"
    author: str = ""
    tags: list[str] = field(default_factory=list)
    description: str = ""
    reference: list[str] = field(default_factory=list)

    @property
    def weight(self) -> int:
        """严重级别权重，用于排序。"""
        return SEVERITY_WEIGHTS.get(self.severity, 0)


@dataclass
class PoC:
    """一个完整的 PoC。"""

    id: str
    info: PoCInfo
    requests: list[PoCRequest] = field(default_factory=list)
    path: str = ""
    """源文件路径 —— 报错时能定位到具体文件，插件一多就靠它排查。"""

    def __repr__(self) -> str:
        return f"<PoC {self.id} [{self.info.severity}]>"


# ------------------------------------------------------------------- 解析


def parse_poc(data: dict[str, Any], *, source_path: str = "") -> PoC:
    """把 YAML 字典解析成 ``PoC`` 对象。

    Raises:
        PoCParseError: 任一必填字段缺失或结构非法。
            注意：这里的所有错误都带 ``source_path``，
            插件目录里几十个文件时，没有路径的报错等于没有报错。
    """
    if not isinstance(data, dict):
        raise PoCParseError("PoC 根节点必须是映射", path=source_path)

    poc_id = str(data.get("id", "")).strip()
    if not poc_id:
        raise PoCParseError("PoC 缺少 id 字段", path=source_path)
    if not poc_id.replace("-", "").replace("_", "").isalnum():
        raise PoCParseError(
            "id 只能包含字母、数字、连字符与下划线", path=source_path, id=poc_id
        )

    info_raw = data.get("info")
    if not isinstance(info_raw, dict):
        raise PoCParseError("PoC 缺少 info 段", path=source_path, id=poc_id)

    name = str(info_raw.get("name", "")).strip()
    if not name:
        raise PoCParseError("info 缺少 name 字段", path=source_path, id=poc_id)

    severity = str(info_raw.get("severity", "info")).lower().strip()
    if severity not in SEVERITY_WEIGHTS:
        raise PoCParseError(
            "severity 取值非法",
            path=source_path,
            id=poc_id,
            got=severity,
            valid=sorted(SEVERITY_WEIGHTS),
        )

    tags = info_raw.get("tags", [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    references = info_raw.get("reference", [])
    if isinstance(references, str):
        references = [references]

    info = PoCInfo(
        name=name,
        severity=severity,
        author=str(info_raw.get("author", "")),
        tags=[str(t) for t in tags],
        description=str(info_raw.get("description", "")),
        reference=[str(r) for r in references],
    )

    requests_raw = data.get("requests", [])
    if not isinstance(requests_raw, list) or not requests_raw:
        raise PoCParseError("PoC 必须定义至少一条 request", path=source_path, id=poc_id)

    requests: list[PoCRequest] = []
    for index, raw in enumerate(requests_raw):
        if not isinstance(raw, dict):
            raise PoCParseError(
                "request 必须是映射", path=source_path, id=poc_id, index=index
            )

        paths = raw.get("path", [])
        if isinstance(paths, str):
            paths = [paths]

        try:
            requests.append(
                PoCRequest(
                    method=str(raw.get("method", "GET")),
                    paths=[str(p) for p in paths],
                    headers={str(k): str(v) for k, v in (raw.get("headers") or {}).items()},
                    body=str(raw.get("body", "") or ""),
                    matchers_condition=str(raw.get("matchers-condition", "and")).lower(),
                    matchers=list(raw.get("matchers") or []),
                    extractors=list(raw.get("extractors") or []),
                )
            )
        except PoCParseError as exc:
            exc.context.setdefault("path", source_path)
            exc.context.setdefault("id", poc_id)
            exc.context.setdefault("index", index)
            raise

    return PoC(id=poc_id, info=info, requests=requests, path=source_path)


def load_poc_file(path: str | Path) -> PoC:
    """从单个 YAML 文件加载 PoC。"""
    poc_path = Path(path)
    try:
        raw = yaml.safe_load(poc_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PoCParseError("YAML 语法错误", path=str(poc_path), detail=str(exc)) from exc
    except OSError as exc:
        raise PoCParseError("PoC 文件读取失败", path=str(poc_path), detail=str(exc)) from exc

    if raw is None:
        raise PoCParseError("PoC 文件为空", path=str(poc_path))
    return parse_poc(raw, source_path=str(poc_path))


def iter_poc_files(dirs: Iterable[str | Path]) -> Iterator[Path]:
    """遍历 PoC 目录下的所有 YAML 文件。

    递归遍历，忽略 ``_`` 开头的文件与模板文件 ——
    允许在 PoC 目录里放 ``_template.yaml`` 作为编写参考而不被引擎加载。
    """
    for directory in dirs:
        base = Path(directory)
        if not base.exists():
            logger.warning("poc_dir_missing dir=%s", base)
            continue
        if base.is_file():
            if base.suffix.lower() in (".yaml", ".yml"):
                yield base
            continue

        for path in sorted(base.rglob("*")):
            if path.suffix.lower() not in (".yaml", ".yml"):
                continue
            if path.name.startswith("_"):
                continue
            yield path


def load_pocs(
    dirs: Sequence[str | Path],
    *,
    severities: Sequence[str] | None = None,
    tags: Sequence[str] | None = None,
    strict: bool = False,
) -> list[PoC]:
    """从多个目录批量加载 PoC。

    Args:
        dirs: PoC 目录列表。
        severities: 只保留指定严重级别。
        tags: 只保留含指定标签的 PoC（任一命中即可）。
        strict: True 时任一 PoC 解析失败就抛异常；False（默认）跳过并告警。
            默认容错 —— 因为社区 PoC 质量参差，一个坏文件不该让整次扫描失败。

    Returns:
        按严重级别降序排列的 PoC 列表。
    """
    loaded: list[PoC] = []
    seen_ids: set[str] = set()
    failed = 0

    for path in iter_poc_files(dirs):
        try:
            poc = load_poc_file(path)
        except PoCParseError as exc:
            failed += 1
            if strict:
                raise
            logger.warning("poc_load_failed path=%s error=%s", path.name, exc)
            continue

        if poc.id in seen_ids:
            logger.warning("poc_duplicate_id id=%s path=%s", poc.id, path.name)
            continue
        seen_ids.add(poc.id)

        if severities and poc.info.severity not in set(severities):
            continue
        if tags and not (set(tags) & set(poc.info.tags)):
            continue

        loaded.append(poc)

    loaded.sort(key=lambda p: (-p.info.weight, p.id))
    logger.info("poc_load_done loaded=%d failed=%d dirs=%s", len(loaded), failed, list(dirs))
    return loaded


def group_by_severity(pocs: Sequence[PoC]) -> dict[str, list[PoC]]:
    """按严重级别分组 —— 报告展示用。"""
    grouped: dict[str, list[PoC]] = {}
    for poc in pocs:
        grouped.setdefault(poc.info.severity, []).append(poc)
    return grouped


__all__ = [
    "PoC",
    "PoCInfo",
    "PoCRequest",
    "load_poc_file",
    "load_pocs",
    "parse_poc",
    "iter_poc_files",
    "group_by_severity",
    "SEVERITY_WEIGHTS",
]
