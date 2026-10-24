# 测试说明

## 怎么跑

```bash
pip install -e ".[dev]"
pytest                                   # 433 个用例，全部离线
pytest --cov=asp --cov-report=term-missing
ruff check asp tests
```

## 三层测试，职责不同

单测（`tests/`）不依赖网络，也不启动靶场。DNS、HTTP、socket 一律用假实现替换，
所以 CI 不会因为某个第三方站点抖动而变红。这条是硬约束，新加的用例必须遵守。

端到端验证在 vulnlab 仓库，需要起靶场：89 条安全属性断言、16 条基准探针。
它验证的是「扫描器打在真实页面上是什么结果」，不在这个仓库的 CI 里跑。

CI 里还有两个 smoke：CLI 冒烟（`--version` / `poc list` / `--help`）和 JSON 契约
（`--json` 必须输出可解析 JSON、带可达性字段、退出码 2）。它们守的是
「单元测试通过但入口层坏了」这类问题，历史上真发生过。

## 覆盖率

用 `branch = true`，口径是分支覆盖率，不是行覆盖率。基线（2026-10-24，补齐服务层后）：

| 模块 | 起点 | 当前 |
|---|---:|---:|
| `asp/services/subdomain.py` | 28% | 98% |
| `asp/services/host.py` | 39% | 99% |
| `asp/cli.py` | 49% | 91% |
| `asp/discover/portscan.py` | 59% | 95% |
| `asp/report.py` | 67% | 92% |
| 整体 | 72% | 88% |

五个模块均已 ≥85%，整体 88%。CI 用 `--cov-fail-under=85` 兜底，
覆盖率掉到 85 以下会直接判 CI 失败。服务层原来低，原因是外部依赖直接写在
函数体里（DNS 解析、socket、HTTP client）；CLI 层低是因为只测了 `poc run`。
补法都是 monkeypatch 替换依赖，不改产品结构。

补 CLI 覆盖时抓到两个真 bug：`subdomain --json` 和 `portscan --json`
不带 `-o` 时不打印任何东西。和历史上 `poc run --json` 的缺陷同源，
已修并加了用例。

## 写用例的三条规矩

一，每个用例的注释要写清它防的是哪个回归，而不是「测试某某函数」。

二，不允许 `assert True`、不允许只断言「没抛异常」。覆盖率是结果，不是目标。

三，修 bug 必须带一条会失败的用例。先让它在旧代码上红，再改代码让它绿；
顺序反了，用例往往测的是改完之后的实现，不是原来的缺陷。
