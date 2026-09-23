# 更新日志

本文件记录本项目所有值得注意的变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [0.1.1] - 2026-09-23

### 修复

- `asp poc run --json` 在未同时指定 `-o` 时不输出任何内容。JSON 分支把序列化
  后的结果赋给变量后没有打印，只有 `-o` 那条路径会写出内容。通过 `jq` 或
  `$(...)` 消费输出时得到空字符串，与「扫描后没有发现」无法区分。该缺陷自首个
  版本即存在，因为 `asp/cli.py` 此前没有测试覆盖：缺少的 `print` 只在特定参数
  组合下出现，而手工测试几乎总会加上 `-o` 以确认文件已写出。

- 目标不可达被报告为「未发现漏洞」。目标无法连接时所有 PoC 均失败，命中数为 0，
  输出 `(未发现漏洞)`，与成功扫描的输出完全一致。涉及两种情况：连接失败被记录
  在 `Response.error` 中且从未上报；HTTP 代理在端口关闭时返回结构完整的 502 响应，
  在所有既有统计中都计为成功请求。

  现将可达性作为独立维度跟踪：

  - 新增 `EngineResult.responses_ok` 与 `responses_server_error`。
  - `target_reachable` 要求至少有一个非 5xx 响应。5xx 无法证明被测应用处于正常
    工作状态，而 4xx 可以。
  - CLI 显式打印警告，说明本次结果无效。
  - 退出码区分三种结果：`0` 扫描有效且无发现，`1` 有发现，`2` 目标不可达。
    CI 由此可以区分「靶场没启动」与「靶场确实没有漏洞」。
  - JSON 输出携带 `target_reachable`、`responses_ok` 与 `errors`。

- REST 接口每次请求都新建数据库 Engine 且从不释放，造成连接泄漏，并使
  `init_db` 的 DDL 每请求执行一次。现改为按进程缓存 Engine，并在 FastAPI 的
  `lifespan` 关闭钩子中释放。

- `pyproject.toml` 里的项目地址从建项起一直是占位符
  （`https://github.com/yourname/attack-surface-platform`），与实际仓库不符，
  项目页会显示无效链接。现改为真实地址，并补充 `Repository` 与 `Changelog`。

- 构建 wheel 时输出三条 `Package '...' is absent from the packages configuration`
  警告，分别指向 `asp.pocs`、`asp.rules` 与 `asp.api.static`。下载 CI 产物核对后
  确认，这三个目录下的 YAML 与 HTML 实际都已打进 wheel —— `package-data` 中写的
  相对路径起了作用，警告并不代表文件缺失。

  真正的问题是数据目录挂在另一个包的 `package-data` 下，能否随包分发取决于
  setuptools 对未声明子目录的处理方式，不是一条明确的规则。现为三个目录补充
  `__init__.py` 并加入 `packages` 列表，`package-data` 改为按所属包声明，
  警告随之消失。

### 变更

- `asp/cli.py` 不再被排除在覆盖率统计之外。该模块现由 31 条断言覆盖，其中包含
  两条端到端用例：除 HTTP 客户端外全部使用真实实现，以便覆盖引擎自身的可达性判定。
- 测试数 318 → 355。
- 行覆盖率 65% → 74%。`asp/cli.py` 由 0% 提升至 52%，`asp/services/vuln.py`
  由 49% 提升至 98%。
- CI 增加一项 JSON 契约冒烟检查，按使用者的实际调用方式执行 CLI，并断言输出可
  解析、退出码正确。
- 许可证元数据改用 SPDX 表达式（`license = "MIT"`）替代已废弃的
  `license = { text = "MIT" }`，并显式声明 `license-files`。构建后端下限相应由
  `setuptools>=68` 提高到 `>=77` —— 这是该写法要求的最低版本。构建产物中的元数据
  版本为 2.4，许可证字段写作 `License-Expression: MIT`，`LICENSE` 被收进
  `dist-info/licenses/`。

## [0.1.0] - 2026-09-18

首个版本，覆盖从资产发现到报告输出的完整链路。

### 新增

**资产发现**

- 证书透明日志源（crt.sh），多源并发聚合与去重
- DNS 字典爆破源
- 泛解析基线检测：以随机域名探测基线，过滤通配 DNS 产生的大量假资产

**服务探测**

- 端口扫描：asyncio TCP 连接扫描 + 信号量并发控制，三态区分
  `open` / `closed` / `filtered`
- 两阶段 banner 抓取：先静默读取（SSH、FTP、SMTP 会主动发送 banner），
  超时后再按协议主动探测
- 12 类服务指纹规则，支持产品与版本提取
- Web 指纹识别：
  - 纯 Python 实现的 MurmurHash3 x86 32-bit，已与官方 `mmh3` 库交叉验证
    （7 类样本、长度 0~8 及 favicon 场景，逐字节一致）
  - favicon 哈希采用 Shodan 风格（对 `base64.encodebytes` 输出参与哈希，
    而非 `b64encode`）
  - 46 条内置指纹规则，覆盖中间件、CMS、前端库、运维平台、CDN 与 WAF
  - 置信度累加：单条弱规则不触发判定

**漏洞验证**

- 自研 YAML PoC 引擎：4 种匹配器（status / word / regex / dsl）+ 提取器 + 热加载
- 白名单 DSL（不使用 `eval`）：支持条件表达式但不支持任意代码，加载第三方 PoC
  不等于执行任意代码
- 负向对照校验：命中后向同目录随机路径发对照请求，识别「通配 200 页面」类假阳性
- 7 个内置检测插件

**告警降噪**

- 可插拔 LLM provider：兼容 OpenAI 接口，无 API key 时启发式降级
- 内置标注样本与评估函数，输出准确率与召回率（实测：误报召回率 100%，
  准确率 83.3%）
- 三条设计约束：只标注不删除、必须能降级、必须可度量

**数据与输出**

- 六表资产模型（domain / IP / port / service / component / vuln）关联建模
- 每次扫描落库为独立任务，支持资产变更 diff
- 报告导出 JSON、Markdown、HTML 三种格式，跨任务聚合，同一目标的多条扫描链路
  汇总为一份报告
- HTML 报告使用内联样式、无外部资源，可直接作为附件发送
- 所有渲染内容经过 HTML 转义，防止扫描到的资产名反过来向报告注入标记

**Web 看板与 REST 接口**（可选依赖 `[api]`）

- FastAPI 应用：目标列表与详情、报告导出、PoC 列表、三类扫描触发接口
- 单页前端（原生 JS + 内联样式），无构建步骤、无 CDN 依赖
- 安全设计：默认只绑定 `127.0.0.1`；绑定非回环地址时强制要求 token，未设置则
  拒绝启动；token 使用 `hmac.compare_digest` 比较

**工具**

- CLI 命令：`subdomain`、`portscan`、`poc run`、`triage`、`report`、`serve`、
  `diff`、`init`
- 结构化日志，记录每个源的耗时、发现量与过滤量
- 统一异常树，区分可重试与不可重试
- Docker 部署（Dockerfile + docker-compose，以非 root 运行）
- GitHub Actions CI
- 259 个离线单元测试，ruff 零告警

### 变更

- 运行时依赖只保留 3 个（httpx、SQLAlchemy、PyYAML）。FastAPI 作为可选依赖，
  避免为了查看看板而被迫安装整套 Web 框架。
- 内置指纹规则改为按相对包目录解析，而非相对工作目录。按工作目录解析时，从项目根
  目录之外执行会导致规则数静默降为 0，且没有任何报错。

[Unreleased]: https://github.com/hediwen831-star/attack-surface/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/hediwen831-star/attack-surface/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/hediwen831-star/attack-surface/releases/tag/v0.1.0
