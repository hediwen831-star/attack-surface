"""ASP 命令行入口。

设计取舍：为什么用标准库 ``argparse`` 而不是 click / typer？

安全工具被部署到客户环境时，**依赖越少越好**是不会错的判断：
- 少一个依赖 = 少一个供应链攻击面 = 少一次「装不上」的现场事故
- ``argparse`` 支持子命令、类型校验与自动帮助，能力足够
- ``pip install`` 后零附加依赖即可运行，别人 clone 下来能立刻验证

命令行设计原则：**每条命令都能脱离数据库、脱离配置文件单独运行**。
``asp subdomain example.com`` 不需要先 init、不需要写 config，直接出结果 ——
第一印象的体验决定了别人会不会继续读你的代码。
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .config import Config, load_config
from .core.http import AsyncHttpClient
from .exceptions import AspError, ConfigError
from .logger import get_logger, setup_logging
from .plugins.engine import scan_target, to_json
from .plugins.loader import load_pocs
from .services.subdomain import collect_subdomains, diff_tasks, persist_report

logger = get_logger("cli")

#: 严重级别的终端着色（仅终端 TTY 生效）
_SEVERITY_COLORS = {
    "critical": "\033[38;5;199m",
    "high": "\033[38;5;203m",
    "medium": "\033[38;5;214m",
    "low": "\033[38;5;39m",
    "info": "\033[38;5;245m",
}
_RESET = "\033[0m"


def _resolve_poc_dirs(config: Config, extra: Sequence[str] | None = None) -> list[Path]:
    """把配置里的 PoC 目录解析成绝对路径。

    相对路径按「相对于 asp 包目录」解析，保证从任意 cwd 执行都能找到内置 PoC。
    """
    package_dir = Path(__file__).resolve().parent
    resolved: list[Path] = []

    for entry in list(config.engine.poc_dirs) + list(extra or []):
        candidate = Path(entry)
        if candidate.is_absolute():
            resolved.append(candidate)
            continue
        # 先看当前工作目录（方便指定自己的 PoC 目录），再看包目录
        if candidate.exists():
            resolved.append(candidate.resolve())
        else:
            resolved.append(package_dir / entry)

    return resolved


def _use_color() -> bool:
    """是否给终端输出着色。

    Windows 10 之后的终端（Windows Terminal / VSCode 集成终端）都支持 ANSI，
    所以统一按 isatty 判断即可，不需要按平台区分。
    重定向到文件时 isatty 为 False，输出保持纯文本 —— 方便 grep。
    """
    return sys.stdout.isatty()


def _print_table(headers: list[str], rows: list[list[str]], widths: list[int]) -> None:
    """打印简单对齐表格。

    手写而非引入 tabulate：中文字符宽度是 2 而 ASCII 是 1，
    通用库对 CJK 对齐处理经常出错，手写反而可控。
    """
    def _pad(text: str, width: int) -> str:
        # CJK 字符按 2 列宽计算
        display = sum(2 if ord(ch) > 0x2E80 else 1 for ch in text)
        return text + " " * max(0, width - display)

    print("  ".join(_pad(h, w) for h, w in zip(headers, widths, strict=False)))
    print("  ".join("─" * w for w in widths))
    for row in rows:
        print("  ".join(_pad(c, w) for c, w in zip(row, widths, strict=False)))


# ------------------------------------------------------------------ 子命令


def cmd_subdomain(args: argparse.Namespace, config: Config) -> int:
    """``asp subdomain`` —— 子域名收集。"""
    report = asyncio.run(
        collect_subdomains(
            args.domain,
            config,
            sources=args.sources.split(",") if args.sources else None,
            wordlist=args.wordlist,
            verify=not args.no_verify,
        )
    )

    if args.save:
        persist_report(report, config)
        logger.info("saved_to_db target=%s db=%s", report.root, config.database)

    if args.json:
        payload = {
            "root": report.root,
            "count": report.count,
            "sources": report.sources_used,
            "wildcard_ips": sorted(report.wildcard_ips),
            "elapsed": round(report.elapsed, 2),
            "by_source": report.by_source(),
            "assets": [
                {
                    "value": a.value,
                    "resolved_ip": a.resolved_ip,
                    "sources": a.metadata.get("sources", a.source),
                    "all_ips": a.metadata.get("all_ips", ""),
                }
                for a in report.assets
            ],
        }
        text = json.dumps(payload, ensure_ascii=False, indent=2)
    else:
        print()
        print(f"目标: {report.root}")
        print(f"来源: {', '.join(report.sources_used)}")
        if report.wildcard_ips:
            print(f"泛解析基线: {', '.join(sorted(report.wildcard_ips))}  (已过滤)")
        print(f"耗时: {report.elapsed:.2f}s")
        print(f"存活子域名: {report.count}")
        print()

        if report.assets:
            rows = [
                [
                    a.value,
                    a.resolved_ip or "-",
                    a.metadata.get("sources", a.source),
                    "多源" if len(a.metadata.get("sources", "").split(",")) > 1 else "",
                ]
                for a in report.assets
            ]
            _print_table(["子域名", "解析 IP", "来源", "标记"], rows, [38, 16, 16, 6])
        else:
            print("(未发现存活子域名)")

        by_source = report.by_source()
        if by_source:
            print()
            print("按来源统计: " + ", ".join(f"{k}={v}" for k, v in sorted(by_source.items())))

        multi = report.multi_source()
        if multi:
            print(f"多源交叉确认: {len(multi)} 条（优先级最高，建议最先人工复核）")

        text = "\n".join(a.value for a in report.assets)

    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        logger.info("output_written path=%s", args.output)

    return 0


def cmd_diff(args: argparse.Namespace, config: Config) -> int:
    """``asp diff`` —— 资产变更对比。"""
    result = diff_tasks(config, args.domain, limit=args.limit)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    print(f"目标: {args.domain}  (对比最近 {args.limit} 次任务)")
    print(f"新增: {len(result['added'])}")
    for value in result["added"]:
        print(f"  + {value}")
    print(f"消失: {len(result['removed'])}")
    for value in result["removed"]:
        print(f"  - {value}")
    print(f"未变: {len(result['unchanged'])}")
    return 0


def cmd_poc_list(args: argparse.Namespace, config: Config) -> int:
    """``asp poc list`` —— 列出已加载的 PoC。"""
    dirs = _resolve_poc_dirs(config, [args.dir] if args.dir else None)
    pocs = load_pocs(
        dirs,
        severities=args.severity.split(",") if args.severity else None,
        tags=args.tags.split(",") if args.tags else None,
    )

    if args.json:
        print(
            json.dumps(
                [
                    {
                        "id": p.id,
                        "name": p.info.name,
                        "severity": p.info.severity,
                        "tags": p.info.tags,
                        "path": p.path,
                    }
                    for p in pocs
                ],
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if not pocs:
        print("未加载到任何 PoC。请检查目录：")
        for directory in dirs:
            print(f"  {directory}  {'存在' if directory.exists() else '不存在'}")
        return 1

    color = _use_color()
    rows = []
    for poc in pocs:
        severity = poc.info.severity
        label = f"{_SEVERITY_COLORS.get(severity, '')}{severity}{_RESET}" if color else severity
        rows.append([poc.id, poc.info.name, label, ",".join(poc.info.tags)])

    print(f"共 {len(pocs)} 个 PoC（目录：{', '.join(str(d) for d in dirs)}）")
    print()
    _print_table(["ID", "名称", "级别", "标签"], rows, [34, 36, 10, 24])
    return 0


def cmd_poc_run(args: argparse.Namespace, config: Config) -> int:
    """``asp poc run`` —— 对目标执行漏洞验证。"""
    dirs = _resolve_poc_dirs(config, [args.dir] if args.dir else None)
    pocs = load_pocs(
        dirs,
        severities=args.severity.split(",") if args.severity else None,
        tags=args.tags.split(",") if args.tags else None,
    )

    if args.poc:
        wanted = set(args.poc.split(","))
        pocs = [p for p in pocs if p.id in wanted]
        missing = wanted - {p.id for p in pocs}
        if missing:
            logger.warning("poc_not_found ids=%s", ",".join(sorted(missing)))

    if not pocs:
        print("没有可执行的 PoC。")
        return 1

    async def _run():
        async with AsyncHttpClient(
            concurrency=config.discover.concurrency,
            rate_limit=config.discover.rate_limit,
            timeout=config.http.timeout,
            retries=config.http.retries,
            verify_ssl=config.http.verify_ssl,
            user_agent=config.http.user_agent,
        ) as client:
            return await scan_target(
                args.target,
                pocs,
                client,
                concurrency=args.concurrency,
                negative_control=not args.no_control,
            )

    result = asyncio.run(_run())

    if args.json:
        text = to_json(result)
    else:
        color = _use_color()
        print()
        print(f"目标: {result.target}")
        print(f"执行 PoC: {result.poc_count}   耗时: {result.elapsed:.2f}s")
        print(f"命中: {result.hit_count}")
        if result.vulns:
            print()
            rows = []
            for vuln in result.vulns:
                severity = vuln.severity
                label = f"{_SEVERITY_COLORS.get(severity, '')}{severity}{_RESET}" if color else severity
                rows.append(
                    [label, vuln.poc_id, vuln.target, f"{vuln.confidence:.2f}"]
                )
            _print_table(["级别", "PoC", "目标 URL", "置信度"], rows, [10, 34, 46, 8])

            for vuln in result.vulns:
                if vuln.evidence or vuln.extracted:
                    print()
                    print(f"[{vuln.severity}] {vuln.name}")
                    for item in vuln.evidence:
                        print(f"  证据: {item}")
                    for key, value in vuln.extracted.items():
                        print(f"  提取 {key} = {value}")
        else:
            print("\n(未发现漏洞)")
        text = json.dumps(
            {"target": result.target, "hits": result.hit_count,
             "vulns": [v.to_dict() for v in result.vulns]},
            ensure_ascii=False,
            indent=2,
        )

    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        logger.info("output_written path=%s", args.output)

    # 退出码约定：有命中返回 1，便于在 CI / 流水线里用返回码判断
    return 1 if result.vulns else 0


def cmd_init(args: argparse.Namespace, config: Config) -> int:
    """``asp init`` —— 生成一份配置模板。"""
    target = Path(args.path or "config.yaml")
    if target.exists() and not args.force:
        print(f"配置已存在: {target}（用 --force 覆盖）")
        return 1

    template = """# ASP 配置文件
# 环境变量覆盖规则：ASP_<SECTION>_<FIELD>，如 ASP_DISCOVER_CONCURRENCY=300

http:
  timeout: 10.0          # 单次请求超时（秒）
  retries: 2             # 失败重试次数
  verify_ssl: false      # 测绘场景建议 false（自签名证书不代表资产不存在）
  user_agent: "Mozilla/5.0 (compatible; ASP/0.1)"

discover:
  sources: [crtsh, brute]   # 资产来源，顺序即执行顺序
  concurrency: 100          # HTTP 并发上限
  rate_limit: 50.0          # 每秒请求数上限（必须限速！）
  wordlist: null            # 字典路径，null 使用内置字典
  brute_concurrency: 200    # DNS 爆破并发

engine:
  poc_dirs: [pocs]          # 相对路径按 asp 包目录解析
  severity: [critical, high, medium, low, info]
  tags: []

database: asp.db
log_level: INFO
"""
    target.write_text(template, encoding="utf-8")
    print(f"配置模板已写入: {target}")
    return 0


# ------------------------------------------------------------------ 参数


def build_parser() -> argparse.ArgumentParser:
    """构造命令行解析器。"""
    parser = argparse.ArgumentParser(
        prog="asp",
        description="ASP — 外网攻击面自动化测绘与漏洞验证平台",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  asp subdomain example.com                      子域名收集（默认 crtsh + builtin 字典）
  asp subdomain example.com --sources crtsh      仅用证书透明日志
  asp subdomain example.com --json -o out.json   输出 JSON
  asp subdomain example.com --save               结果落库，供 diff 使用
  asp diff example.com                           对比最近两次扫描的资产变化
  asp poc list                                   列出全部 PoC
  asp poc list --severity high,critical          只看高危 PoC
  asp poc run http://target.local                对目标执行全部 PoC
  asp poc run http://target.local --poc git-config-exposure
  asp init                                       生成配置模板

免责声明：本工具仅用于授权范围内的安全测试与自有资产测绘。
""",
    )
    parser.add_argument("--version", action="version", version=f"ASP {__version__}")
    parser.add_argument("-c", "--config", help="配置文件路径")
    parser.add_argument("--log-level", default=None, help="日志级别 DEBUG/INFO/WARNING/ERROR")
    parser.add_argument("-q", "--quiet", action="store_true", help="静默模式")

    subparsers = parser.add_subparsers(dest="command")

    # --- subdomain
    p_sub = subparsers.add_parser("subdomain", help="子域名收集")
    p_sub.add_argument("domain", help="根域名，如 example.com")
    p_sub.add_argument("--sources", help="来源列表，逗号分隔（crtsh,brute）")
    p_sub.add_argument("--wordlist", help="爆破字典路径")
    p_sub.add_argument("--no-verify", action="store_true", help="跳过 DNS 解析验证（更快但结果含死域名）")
    p_sub.add_argument("--save", action="store_true", help="结果写入数据库（diff 需要）")
    p_sub.add_argument("--json", action="store_true", help="以 JSON 输出")
    p_sub.add_argument("-o", "--output", help="结果写入文件")
    p_sub.set_defaults(func=cmd_subdomain)

    # --- diff
    p_diff = subparsers.add_parser("diff", help="资产变更对比")
    p_diff.add_argument("domain", help="根域名")
    p_diff.add_argument("--limit", type=int, default=2, help="对比最近 N 次任务")
    p_diff.add_argument("--json", action="store_true", help="以 JSON 输出")
    p_diff.set_defaults(func=cmd_diff)

    # --- poc
    p_poc = subparsers.add_parser("poc", help="PoC 插件管理")
    poc_sub = p_poc.add_subparsers(dest="poc_command")

    p_poc_list = poc_sub.add_parser("list", help="列出 PoC")
    p_poc_list.add_argument("--severity", help="按级别过滤，逗号分隔")
    p_poc_list.add_argument("--tags", help="按标签过滤，逗号分隔")
    p_poc_list.add_argument("--dir", help="额外 PoC 目录")
    p_poc_list.add_argument("--json", action="store_true", help="以 JSON 输出")
    p_poc_list.set_defaults(func=cmd_poc_list)

    p_poc_run = poc_sub.add_parser("run", help="执行漏洞验证")
    p_poc_run.add_argument("target", help="目标，如 http://192.168.1.10 或 example.com")
    p_poc_run.add_argument("--poc", help="指定 PoC ID，逗号分隔")
    p_poc_run.add_argument("--severity", help="按级别过滤，逗号分隔")
    p_poc_run.add_argument("--tags", help="按标签过滤，逗号分隔")
    p_poc_run.add_argument("--dir", help="额外 PoC 目录")
    p_poc_run.add_argument("--concurrency", type=int, default=20, help="同时执行的 PoC 数")
    p_poc_run.add_argument("--no-control", action="store_true", help="关闭负向对照校验（会增多误报）")
    p_poc_run.add_argument("--json", action="store_true", help="以 JSON 输出")
    p_poc_run.add_argument("-o", "--output", help="结果写入文件")
    p_poc_run.set_defaults(func=cmd_poc_run)

    # --- init
    p_init = subparsers.add_parser("init", help="生成配置模板")
    p_init.add_argument("path", nargs="?", help="输出路径，默认 config.yaml")
    p_init.add_argument("--force", action="store_true", help="覆盖已存在文件")
    p_init.set_defaults(func=cmd_init)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """程序入口。"""
    # Windows 控制台默认 GBK，会让中文输出乱码 —— 强制切 UTF-8
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(AttributeError, ValueError):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return 0

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"配置错误: {exc}", file=sys.stderr)
        return 2

    if args.log_level:
        config.log_level = args.log_level
    setup_logging(config.log_level, quiet=args.quiet)

    try:
        return args.func(args, config)
    except KeyboardInterrupt:
        print("\n已中断", file=sys.stderr)
        return 130
    except AspError as exc:
        logger.error("fatal error=%s", exc)
        return 2
    except BrokenPipeError:  # pragma: no cover - 管道提前关闭
        return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
