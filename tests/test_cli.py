"""CLI 测试。

这个文件补的是一块**长期空白**：`asp/cli.py` 有 400 多行，
却是整个项目里唯一覆盖率 0% 的模块。

为什么会漏掉：CLI 看起来"只是把各模块串起来"，逻辑简单。
但实测证明不是 —— CLI 里藏着几类**只有入口层才会出现**的缺陷：

- **退出码语义**：`0` / `1` / `2` 分别代表什么，脚本和 CI 全靠它判断。
  一个搞错的退出码会让流水线把"目标连不上"当成"目标很干净"。
- **目标不可达的输出**：命中数同样是 0，但结论完全相反。
- **输出格式**：JSON 模式必须能直接被 `json.loads()` 消费，
  不能混进日志或彩色控制字符。
- **参数解析**：`--poc` 传了不存在的 ID 时应该警告而不是静默什么都不做。

测试策略：**不真的发网络请求**。
`cmd_poc_run` 内部创建 `AsyncHttpClient`，所以用 monkeypatch 把它换成
`FakeHttpClient` —— 与 `test_engine.py` 用的是同一套假实现，
保证 CLI 层和引擎层看到的目标行为一致。
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from conftest import FakeHttpClient

from asp import cli
from asp.core.http import Response
from asp.plugins.engine import EngineResult, VulnResult

# ------------------------------------------------------------------ 基础设施


@pytest.fixture
def cli_env(tmp_path, monkeypatch):
    """把 CLI 的执行环境隔离到临时目录。

    - 配置指向 tmp_path，避免动到工作区里的 asp.db
    - 不真的初始化日志（否则会往 stdout 打字）
    """
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "setup_logging", lambda *a, **kw: None)
    return tmp_path


def _run(args: list[str]) -> int:
    """执行 CLI 并返回退出码。"""
    return cli.main(args)


class _CapturedRun:
    """记录 `cmd_poc_run` 实际拿到的东西，便于断言。"""

    def __init__(self, result: EngineResult) -> None:
        self.result = result
        self.target: str | None = None
        self.poc_ids: list[str] = []


@pytest.fixture
def stub_scan(monkeypatch):
    """把 scan_target 换成可控的假实现。

    返回一个函数：传入 (vulns, responses_ok, server_error) 就构造出对应结果。
    """

    def _make(
        vulns: list[VulnResult] | None = None,
        *,
        responses_ok: int = 5,
        server_error: int = 0,
        poc_count: int = 1,
        errors: list[str] | None = None,
    ) -> _CapturedRun:
        captured = _CapturedRun(
            EngineResult(
                target="http://target.test",
                vulns=list(vulns or []),
                poc_count=poc_count,
                elapsed=0.01,
                responses_ok=responses_ok,
                responses_server_error=server_error,
                errors=list(errors or []),
            )
        )
        # target_reachable 是 property，靠上面两个计数推导 —— 与真实实现一致

        async def _fake_scan(target, pocs, client, **kwargs):
            captured.target = target
            captured.poc_ids = [p.id for p in pocs]
            result = captured.result
            # 复刻 scan_target 的可达性兜底：不可达时它必然往 errors 里塞一条。
            # 不在夹具里补这一步的话，CLI 层的 errors 传播路径就测不到了。
            if pocs and not result.target_reachable and not result.errors:
                result.errors.append(f"目标 {target} 不可达（测试夹具注入）")
            return result

        monkeypatch.setattr(cli, "scan_target", _fake_scan)

        class _FakeCtx(FakeHttpClient):
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

        # 让 cmd_poc_run 里的 AsyncHttpClient(...) 构造出可用的上下文管理器
        monkeypatch.setattr(cli, "AsyncHttpClient", lambda **kw: _FakeCtx())
        return captured

    return _make


def _vuln(poc_id: str = "t", severity: str = "high") -> VulnResult:
    return VulnResult(
        poc_id=poc_id,
        name=f"测试漏洞 {poc_id}",
        severity=severity,
        target="http://target.test/x",
        confidence=1.0,
        evidence=["status=200"],
    )


# ------------------------------------------------------------ 基础入口行为


def test_no_command_prints_help_and_returns_zero(cli_env, capsys):
    """不带子命令时打印帮助，退出码 0（不是错误）。"""
    assert _run([]) == 0
    out = capsys.readouterr().out
    assert "usage" in out.lower()


def test_version_flag(cli_env, capsys):
    """`--version` 必须能单独跑通 —— 这是 CI 的冒烟检查项之一。"""
    with pytest.raises(SystemExit) as exc:
        _run(["--version"])
    assert exc.value.code == 0
    assert cli.__version__ in capsys.readouterr().out


def test_unknown_command_exits_nonzero(cli_env):
    """未知子命令应当报错退出，而不是静默成功。"""
    with pytest.raises(SystemExit) as exc:
        _run(["definitely-not-a-command"])
    assert exc.value.code != 0


def test_config_error_returns_2(cli_env, monkeypatch, capsys):
    """配置加载失败退出码为 2 —— 与"发现漏洞(1)"区分开。"""
    from asp.exceptions import ConfigError

    def _boom(path):
        raise ConfigError("坏的配置文件")

    monkeypatch.setattr(cli, "load_config", _boom)
    assert _run(["poc", "list"]) == 2
    assert "配置错误" in capsys.readouterr().err


def test_asp_error_returns_2(cli_env, monkeypatch):
    """业务异常统一收敛成退出码 2。

    这条特别重要：CI 里 `asp` 的退出码要区分「扫过了没洞(0)」「发现漏洞(1)」
    和「工具自己出问题了(2)」。把内部异常和"干净结果"混在一起，
    流水线会在工具崩掉时亮绿灯。
    """
    from asp.exceptions import AspError

    def _boom(args, config):
        raise AspError("出事了")

    # 用真实 Config 而不是 object()：main() 会去写 config.log_level，
    # 拿一个裸 object 会因为 AttributeError 直接冒出来，测不到 AspError 分支。
    from asp.config import Config

    monkeypatch.setattr(cli, "load_config", lambda p: Config())
    monkeypatch.setattr(cli, "build_parser", _parser_with(_boom))
    assert _run(["poc", "list"]) == 2


def test_keyboard_interrupt_returns_130(cli_env, monkeypatch):
    """Ctrl-C 退出码 130（128+SIGINT）—— 让上游能区分"用户主动中断"。"""
    from asp.config import Config

    def _interrupt(args, config):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "load_config", lambda p: Config())
    monkeypatch.setattr(cli, "build_parser", _parser_with(_interrupt))
    assert _run(["poc", "list"]) == 130


def _parser_with(func):
    """构造一个最小 parser，让指定函数成为子命令的处理函数。

    必须复刻真实 parser 的两个细节，否则 `main()` 走不到 `args.func`：
      · `dest="command"` —— `main()` 靠它判断"有没有给子命令"
      · `-c/--config`   —— `main()` 紧接着读 `args.config`
    """
    import argparse

    def _build():
        parser = argparse.ArgumentParser(prog="asp")
        parser.add_argument("-c", "--config", help="配置文件路径")
        parser.add_argument("--log-level", default=None)
        parser.add_argument("-q", "--quiet", action="store_true")
        sub = parser.add_subparsers(dest="command")
        p = sub.add_parser("poc")
        psub = p.add_subparsers(dest="poc_command")
        lst = psub.add_parser("list")
        lst.set_defaults(func=func)
        return parser

    return _build


# ------------------------------------------------------- poc run 的退出码


def test_poc_run_exit_0_when_no_vulns_and_reachable(cli_env, stub_scan):
    """有效扫描且无命中 → 0。"""
    stub_scan(vulns=[])
    assert _run(["poc", "run", "http://target.test"]) == 0


def test_poc_run_exit_1_when_vulns_found(cli_env, stub_scan):
    """发现漏洞 → 1。"""
    stub_scan(vulns=[_vuln()])
    assert _run(["poc", "run", "http://target.test"]) == 1


def test_poc_run_exit_2_when_target_unreachable(cli_env, stub_scan):
    """目标不可达 → 2，而**不是** 0。

    这是关键区分：如果这里返回 0，CI 会把"靶场没起来"当成"靶场没漏洞"，
    整条流水线绿灯通过，而实际上什么都没验证到。
    """
    stub_scan(vulns=[], responses_ok=3, server_error=3)  # 全部 5xx
    assert _run(["poc", "run", "http://target.test"]) == 2


def test_poc_run_exit_2_when_no_response_at_all(cli_env, stub_scan):
    """连接层完全失败同样 → 2。"""
    stub_scan(vulns=[], responses_ok=0, server_error=0)
    assert _run(["poc", "run", "http://target.test"]) == 2


def test_unreachable_output_warns_instead_of_saying_no_vulns(cli_env, stub_scan, capsys):
    """不可达时的输出必须明确警告，不能只写「未发现漏洞」。"""
    stub_scan(vulns=[], responses_ok=2, server_error=2)
    _run(["poc", "run", "http://target.test"])
    out = capsys.readouterr().out

    assert "不可达" in out, "必须明确说明目标不可达"
    assert "无效" in out, "必须说明结果无效，而不是让人以为扫过了"


def test_reachable_with_no_vulns_says_no_vulns(cli_env, stub_scan, capsys):
    """反向对照：正常可达且无洞时，不该出现"不可达"警告。

    少了这条，上面那条断言可能因为"永远打印警告"而假通过。
    """
    stub_scan(vulns=[], responses_ok=5, server_error=0)
    code = _run(["poc", "run", "http://target.test"])
    out = capsys.readouterr().out

    assert code == 0
    assert "不可达" not in out
    assert "未发现漏洞" in out


def test_partial_5xx_is_still_reachable(cli_env, stub_scan, capsys):
    """只要有一个非 5xx 响应就判可达 —— 个别路径 500 不该否定整次扫描。"""
    stub_scan(vulns=[], responses_ok=10, server_error=3)
    code = _run(["poc", "run", "http://target.test"])
    assert code == 0
    assert "不可达" not in capsys.readouterr().out


def test_no_pocs_loaded_at_all_returns_nonzero(cli_env, monkeypatch, capsys):
    """PoC 目录为空（比如 `--dir` 指错了）→ 退出码非 0，且提示检查目录。"""
    monkeypatch.setattr(cli, "load_pocs", lambda *a, **kw: [])
    code = _run(["poc", "run", "http://target.test"])
    assert code != 0
    assert "没有可执行的 PoC" in capsys.readouterr().out


# ---------------------------------------------------- 端到端（走真实引擎）


def _unreachable_client_cls():
    """构造一个「所有请求都失败」的客户端类。

    模拟目标不可达最真实的方式是让底层连接失败 ——
    这里直接让 `request` 抛异常，引擎就会把它记进 `Response.error`，
    从而走到可达性兜底分支。比注入 502 更接近"端口没开"的现场。
    """

    class _DeadClient(FakeHttpClient):
        async def request(self, method, url, **kwargs):
            from asp.core.http import Response as _R

            return _R(
                url=url,
                status=0,
                headers={},
                content=b"",
                elapsed=0.0,
                error="Connection refused",
            )

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    return _DeadClient


def test_end_to_end_unreachable_target_is_not_reported_as_clean(
    cli_env, monkeypatch, capsys
):
    """**端到端**：走真实的 scan_target，只在 HTTP 客户端这一层造假。

    这是本文件里最重要的一条断言。前面用 stub_scan 的那些测试是**单元级**的 ——
    它们验证 CLI 拿到不可达结果后怎么表现，但"什么算不可达"这件事
    是由 `scan_target` 决定的。只测 CLI 层，等于假设引擎的判定一定对。

    这里把真实引擎接上，验证整条链路：
        连接失败 → 引擎判定不可达 → 写进 errors → CLI 打印警告 → 退出码 2

    缺了这条，就可能出现"引擎判定逻辑坏了，但 CLI 单测全绿"的情况。
    """
    monkeypatch.setattr(cli, "AsyncHttpClient", lambda **kw: _unreachable_client_cls()())
    # 只留 1 个 PoC，保证测试快且失败信息干净
    monkeypatch.setattr(
        cli,
        "load_pocs",
        lambda dirs, **kw: [_minimal_poc()],
    )

    code = _run(["poc", "run", "http://target.test", "--json"])
    out = capsys.readouterr().out
    data = json.loads(out[out.index("{"):])

    assert data["target_reachable"] is False, "连接全失败必须判为不可达"
    assert data["responses_ok"] == 0
    assert data["errors"], "引擎必须留下可供流水线判断的错误信息"
    assert code == 2, "不可达的退出码必须是 2，不能是 0（那会被 CI 当成干净）"


# ---------------------------------------------------------- --save 落库


def test_save_flag_persists_scan_task(cli_env, stub_scan, capsys):
    """`--save` 必须真的把这次扫描写进数据库，供后续 diff / report 使用。

    这条测试同时是 `services/vuln.py::persist_engine_result` 的端到端覆盖 ——
    那条路径此前完全没被测过（该模块覆盖率 49%），而它是
    `asp poc run --save` → `asp report` 这条数据链的起点。
    """
    stub_scan(vulns=[_vuln("cli-test-poc")])
    code = _run(["poc", "run", "http://target.test", "--save"])

    assert code == 1  # 有命中

    # 打开落库结果，确认任务与漏洞都在
    from asp.core.database import ScanTask, Vuln, create_db_engine, session_scope

    engine = create_db_engine("asp.db")
    with session_scope(engine) as session:
        tasks = session.query(ScanTask).all()
        assert len(tasks) == 1, "应当恰好写入一个扫描任务"
        task = tasks[0]
        assert task.target == "target.test", "target 应归一化成主机名"
        assert task.status == "success"

        vulns = session.query(Vuln).all()
        assert len(vulns) == 1
        assert vulns[0].poc_id == "cli-test-poc"
        assert vulns[0].task_id == task.id, "漏洞必须挂在任务上，否则报告聚合查不到"


def test_save_flag_aggregates_url_and_bare_host(cli_env, stub_scan):
    """`http://target.test` 与 `target.test` 必须聚合成同一个 target。

    这是 normalize_target 存在的理由，也是 `asp report <target>` 能查到
    "同一个域名的多次扫描"的前提。用 CLI 层验证一次，确认它真的接上了。
    """
    from asp.core.database import ScanTask, create_db_engine, session_scope

    stub_scan(vulns=[])
    _run(["poc", "run", "http://target.test", "--save"])
    _run(["poc", "run", "target.test", "--save"])

    engine = create_db_engine("asp.db")
    with session_scope(engine) as session:
        targets = {t.target for t in session.query(ScanTask).all()}
    assert targets == {"target.test"}, f"两种写法应当归一化成一个 target，实际 {targets}"


def _minimal_poc():
    """造一个最小可跑的 PoC，避免依赖内置 PoC 文件的具体内容。
    注意用的是 `asp.plugins.loader.PoC` / `PoCInfo` / `PoCRequest`
    这三个真实 dataclass —— 拿一个鸭子类型的假对象会掩盖字段名变化。
    """
    from asp.plugins.loader import PoC, PoCInfo, PoCRequest

    return PoC(
        id="test-minimal",
        info=PoCInfo(name="最小测试 PoC", severity="info", tags=[]),
        requests=[
            PoCRequest(
                method="GET",
                # 必须写成模板形式 —— 引擎会渲染变量，裸 "/" 会被判为非法 URL
                paths=["{{BaseURL}}/"],
                matchers=[{"type": "status", "status": [200]}],
            )
        ],
        path="<memory>",
    )


def test_end_to_end_reachable_hit_is_reported(cli_env, monkeypatch, capsys):
    """反向对照：客户端能正常应答时，同样的链路必须报出命中且退出码 1。

    没有这条，上面那条断言可能因为"任何情况都判不可达"而假通过。
    """
    monkeypatch.setattr(cli, "AsyncHttpClient", lambda **kw: _AlwaysOkClient())
    monkeypatch.setattr(cli, "load_pocs", lambda dirs, **kw: [_minimal_poc()])

    code = _run(["poc", "run", "http://target.test", "--json", "--no-control"])
    out = capsys.readouterr().out
    data = json.loads(out[out.index("{"):])

    assert data["target_reachable"] is True
    assert data["hit_count"] == 1, "根路径返回 200 应当命中那个最小 PoC"
    assert code == 1


class _AlwaysOkClient(FakeHttpClient):
    """所有请求都返回 200 的客户端。"""

    async def request(self, method, url, **kwargs):
        return Response(url=url, status=200, headers={}, content=b"ok", elapsed=0.0)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False




def test_json_output_is_parseable_and_has_reachability(cli_env, stub_scan, capsys):
    """`--json` 的输出必须能被 json.loads 直接消费，且带可达性字段。

    自动化流水线靠这些字段判断结果有效性 —— 只给 hit_count 是不够的。
    """
    stub_scan(vulns=[_vuln("a"), _vuln("b", "critical")])
    _run(["poc", "run", "http://target.test", "--json"])
    out = capsys.readouterr().out

    # 必须能从第一个 { 起完整解析（前面不能混入日志）
    start = out.index("{")
    data = json.loads(out[start:])

    assert data["hit_count"] == 2
    assert data["by_severity"]["critical"] == 1
    assert data["target_reachable"] is True
    assert "vulns" in data


def test_json_output_marks_unreachable(cli_env, stub_scan, capsys):
    """不可达时 JSON 里的 target_reachable 必须是 false，且 errors 非空。"""
    stub_scan(vulns=[], responses_ok=4, server_error=4)
    _run(["poc", "run", "http://target.test", "--json"])
    out = capsys.readouterr().out
    data = json.loads(out[out.index("{"):])

    assert data["target_reachable"] is False
    assert data["errors"], "不可达必须在 JSON 里留下 errors，供流水线判断"


def test_json_escapes_unicode_not_ascii(cli_env, stub_scan, capsys):
    """中文必须原样输出（ensure_ascii=False），不能变成 \\uXXXX。

    报告是给人看的，转义后的中文在终端里没法读。
    """
    stub_scan(vulns=[_vuln()])
    _run(["poc", "run", "http://target.test", "--json"])
    out = capsys.readouterr().out
    assert "测试漏洞" in out
    assert "\\u" not in out.split("{", 1)[1][:2000]


def test_output_file_written(cli_env, stub_scan):
    """`-o` 指定的文件必须真的落盘且内容与 stdout 一致。"""
    stub_scan(vulns=[_vuln()])
    out_file = cli_env / "result.json"
    _run(["poc", "run", "http://target.test", "--json", "-o", str(out_file)])

    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["hit_count"] == 1


# ------------------------------------------------------- 参数透传正确性


def test_poc_filter_passes_only_matching_ids(cli_env, stub_scan, capsys):
    """`--poc` 过滤必须真的只把匹配的 PoC 传进引擎。

    这条断言是**用 CLI 层的观测点**验证参数过滤：
    `stub_scan` 记录了引擎实际收到哪些 PoC id，比在 cmd_poc_run 内部断言更接近真实调用链。

    用的是内置 PoC 的真实 ID —— 拿一个不存在的 ID 会让"过滤生效"和
    "PoC 压根没加载到"两种失败长得一模一样，测不出东西。
    """
    captured = stub_scan(vulns=[])
    _run(["poc", "run", "http://target.test", "--poc", "git-config-exposure"])

    assert captured.poc_ids == ["git-config-exposure"], (
        f"引擎应当只收到被点名的 PoC，实际收到 {captured.poc_ids}"
    )


def test_poc_filter_accepts_comma_separated_ids(cli_env, stub_scan):
    """`--poc` 支持逗号分隔的多选 —— 文档里写了，就该有断言守着。"""
    captured = stub_scan(vulns=[])
    _run(
        [
            "poc",
            "run",
            "http://target.test",
            "--poc",
            "git-config-exposure,phpinfo-page-exposure",
        ]
    )
    assert set(captured.poc_ids) == {"git-config-exposure", "phpinfo-page-exposure"}


def test_unknown_poc_id_yields_no_pocs(cli_env, monkeypatch, capsys):
    """点名的 PoC 全都不存在 → 引擎不该被调用，并在退出码上体现出来。

    现实意义：脚本里把 PoC ID 拼错了（或改名了），
    如果这里静默跑"剩下的 PoC"，使用者会以为"跑过了没洞"。
    """
    called = {"scan": False}

    async def _never(target, pocs, client, **kwargs):  # pragma: no cover
        called["scan"] = True
        return EngineResult(target=target)

    monkeypatch.setattr(cli, "scan_target", _never)
    code = _run(["poc", "run", "http://target.test", "--poc", "no-such-poc-id"])

    assert code != 0
    assert called["scan"] is False, "没有可用 PoC 时不应该发起扫描"
    assert "没有可执行的 PoC" in capsys.readouterr().out


def test_negative_control_flag_is_forwarded(cli_env, monkeypatch, stub_scan):
    """`--no-control` 必须传成 negative_control=False。"""
    seen: dict[str, Any] = {}

    async def _fake_scan(target, pocs, client, **kwargs):
        seen.update(kwargs)
        return EngineResult(target=target, poc_count=len(pocs), responses_ok=1)

    monkeypatch.setattr(cli, "scan_target", _fake_scan)
    _run(["poc", "run", "http://target.test", "--no-control"])
    assert seen["negative_control"] is False

    # 默认（不加 flag）应当开启对照
    _run(["poc", "run", "http://target.test"])
    assert seen["negative_control"] is True


def test_concurrency_flag_is_forwarded(cli_env, monkeypatch, stub_scan):
    """`--concurrency` 必须生效，否则并发控制形同虚设。"""
    seen: dict[str, Any] = {}

    async def _fake_scan(target, pocs, client, **kwargs):
        seen.update(kwargs)
        return EngineResult(target=target, poc_count=len(pocs), responses_ok=1)

    monkeypatch.setattr(cli, "scan_target", _fake_scan)
    _run(["poc", "run", "http://target.test", "--concurrency", "3"])
    assert seen["concurrency"] == 3


# ---------------------------------------------------------- poc list


def test_poc_list_runs_without_target(cli_env, capsys):
    """`poc list` 不该要求目标参数 —— 它是纯本地查询。"""
    code = _run(["poc", "list"])
    assert code == 0
    out = capsys.readouterr().out
    # 内置 PoC 应当被列出来
    assert "vulnlab" in out.lower() or out.strip(), "至少应输出些内容"


def test_poc_list_json_is_parseable(cli_env, capsys):
    """`poc list --json` 的 JSON 模式同样要可解析。"""
    _run(["poc", "list", "--json"])
    out = capsys.readouterr().out
    start = out.index("[") if "[" in out else out.index("{")
    json.loads(out[start:])  # 不抛异常即可


# ---------------------------------------------------------- init


def test_init_creates_config_file(cli_env):
    """`init` 应当生成一份可用的配置模板。

    注意路径是**位置参数**（`asp init <path>`），不是 `-o` ——
    这一点和 `poc run` / `report` 那些子命令不一样（它们用 `-o` 表示"输出文件"）。
    在 `init` 的语义里路径本身就是唯一的参数，加 `-o` 反而绕。
    """
    target = cli_env / "myconfig.yaml"
    code = _run(["init", str(target)])
    assert code == 0
    assert target.exists()
    content = target.read_text(encoding="utf-8")
    assert "database" in content.lower() or "poc" in content.lower()


def test_init_refuses_to_overwrite_without_force(cli_env, capsys):
    """已存在时默认不覆盖，退出码 1，并提示用 `--force`。

    这一条守的是"不悄悄毁掉用户已有配置"—— 覆盖写会让别人丢掉自己改过的参数。
    """
    target = cli_env / "config.yaml"
    target.write_text("# 我自己改过的配置\n", encoding="utf-8")

    code = _run(["init", str(target)])
    assert code == 1
    assert "--force" in capsys.readouterr().out
    # 原文件必须原封不动
    assert target.read_text(encoding="utf-8") == "# 我自己改过的配置\n"

    # 加了 --force 才允许覆盖
    assert _run(["init", str(target), "--force"]) == 0
    assert "database" in target.read_text(encoding="utf-8").lower()
