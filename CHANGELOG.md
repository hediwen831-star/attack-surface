# 更新日志

本文件记录本项目的所有重要变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 修复

- **`asp poc run --json` 不给 `-o` 时什么都不输出**

  这个 bug 从项目建立起就存在，一直没被发现，原因很简单：
  **它只在"用了 `--json` 但没加 `-o`"这一种组合下才出现**。

  ```python
  if args.json:
      text = to_json(result)
      # ← 这里漏了 print(text)
  else:
      ...终端表格输出...

  if args.output:
      Path(args.output).write_text(text, encoding="utf-8")
  ```

  表现是：终端一片空白。而下游的 `jq` 拿到空输入、
  脚本里 `$(asp poc run ... --json)` 得到空字符串 ——
  看起来像"没扫到东西"，而不是像"工具坏了"。
  只要加上 `-o out.json` 又一切正常，所以手工测试极易漏过。

  **为什么补 `cli.py` 覆盖率才抓出来**：这个文件此前长期是 0% 覆盖
  （400 多行，全项目唯一没测过的模块）。当时觉得"CLI 只是把各模块串起来，
  逻辑简单"—— 事实上入口层藏着一整类只有它才会出现的缺陷：
  退出码语义、输出格式契约、参数透传。**没有任何一层是"简单到不用测"的。**

  修法就是补上 `print(text)`。同时新增 29 条 CLI 测试，
  其中包含**端到端**用例（只在 HTTP 客户端这一层造假，
  让真实的 `scan_target` 跑完整条链路）—— 只测 CLI 层等于假设引擎判定一定对。

- **目标不可达时报告「未发现漏洞」—— 静默失败里危害最大的一种**

  `asp poc run` 在目标连不上时，命中数自然是 0，于是输出
  「命中: 0 / (未发现漏洞)」。这和「扫过了，目标确实没有漏洞」
  **在输出上完全无法区分** —— 使用者拿着一份看起来干净的结论，
  而实际上一个请求都没打出去。

  实测踩到两个层次：

  1. **连接层失败**：靶场进程被回收后，所有 PoC 都连不上，
     `errors` 却是空的（异常被收敛进了 `Response.error`，没人看）。
  2. **更隐蔽的一种**：本机跑着 HTTP 代理时，向已关闭的端口发请求
     **不会**得到"连接被拒"，而是代理返回 **502 Bad Gateway**。
     502 是一个结构完整的 HTTP 响应，所以连"请求失败"都算不上 ——
     它在所有统计里都是一个正常的响应。

  修法是引入**可达性**这个独立维度，而不是只看命中数：

  - 新增 `EngineResult.responses_ok` / `responses_server_error`
  - `target_reachable` 要求至少有一个**非 5xx** 的响应
    （为什么要排除 5xx：502 证明不了"我们扫的是一个正常工作的应用"；
     而 404 反而是好信号 —— 说明应用确实在处理路由）
  - 不可达时 CLI 显式打印 ⚠️ 警告并说明「本次结果无效」
  - **退出码区分三种情况**：`0` 有效且无洞 / `1` 有洞 /
    `2` 目标不可达 —— 让 CI 能把「靶场没起来」和「靶场真没洞」分开处置
  - JSON 输出同步带上 `target_reachable` / `responses_ok` / `errors`，
    自动化流水线同样需要这个区分

  **一个坑**：`Response.status` 字段名和 httpx 的 `status_code` 不同，
  写成 `status_code` 会抛 `AttributeError`，被外层 `except` 兜住后
  表现为"某条 PoC 未捕获异常"—— 又一次印证动手前先确认接口签名。

  新增 6 条测试守住这条线，并做了反向验证
  （把可达性判断改回「拿到响应就算可达」，2 条测试如期失败）。

- **API 连接池每请求新建 Engine 且从不释放**

  改为进程内缓存 Engine + 在 FastAPI `lifespan` 关闭时统一 `dispose()`。
  顺带消掉了测试里的 `ResourceWarning: unclosed database`。

### 变更

- 单元测试 318 → **324 个**（补可达性断言）
- 单元测试 324 → **355 个**（补 `cli.py` 测试，该模块覆盖率 0% → 52%；
  顺带把 `services/vuln.py` 从 49% 带到 98%）
- 全项目行覆盖率 65% → **74%**

### 计划中

- 分布式扫描（多节点协同 + 任务队列）
- 更多内网协议支持（SMB / RDP 探测）

---

## [0.1.0] - 2026-09-18

首个可用版本。完整实现了「资产发现 → 服务探测 → 漏洞验证 → 降噪研判 → 报告/看板」这条链路。

### 新增

**资产发现**

- 证书透明日志源（crt.sh），多源并发聚合去重
- DNS 字典爆破源
- **泛解析基线检测**：随机域名基线探测，过滤通配 DNS 产生的海量假资产

**服务探测**

- 端口扫描：asyncio TCP 连接扫描 + 信号量并发控制，
  三态区分 `open` / `closed` / `filtered`
- **两阶段 banner 抓取**：先静默读（SSH/FTP/SMTP 会主动发 banner），
  超时未果再按端口类型主动探测（HTTP 类发 GET 请求）
- 12 类服务指纹规则，支持产品与版本提取
- Web 指纹识别：
  - **纯 Python 实现的 MurmurHash3 x86 32-bit**，
    已与官方 `mmh3` 库交叉验证（7 类样本 + 长度 0~8 + favicon 场景，逐字节一致）
  - favicon 哈希采用 Shodan 风格（`base64.encodebytes` 参与哈希，而非 `b64encode`）
  - 46 条内置指纹规则（中间件 / CMS / 前端库 / 运维平台 / CDN / WAF）
  - 置信度累加机制：单条弱规则不判定，多条累加过阈值才输出

**漏洞验证**

- 自研 YAML PoC 引擎：4 种匹配器（status / word / regex / dsl）+ 提取器 + 热加载
- **白名单 DSL（无 eval）**：支持条件表达式但不支持任意代码 ——
  加载第三方 PoC ≠ 执行任意代码
- **负向对照校验**：命中后向同目录随机路径发对照请求，
  识别「通配 200 页面」这类假阳性
- 7 个内置检测插件

**告警降噪**

- 可插拔 LLM provider：OpenAI 兼容接口 / 无 API key 时启发式降级
- **内置标注样本 + 评估函数**，可量化准确率与召回率
  （实测：误报召回率 100%，准确率 83.3%）
- 三条设计红线：只标注不删除 / 必须能降级 / 必须能验证

**数据与输出**

- 六表资产模型（domain / IP / port / service / component / vuln）关联建模
- 每次扫描落库为独立任务，支持**资产变更 diff**
- 报告导出：JSON / Markdown / HTML 三种格式，**跨任务聚合**
  （同一目标的多条扫描链路汇总成一份）
- HTML 报告自带内联样式、无外部资源，可直接作为附件发送
- 所有渲染内容经过 HTML 转义 —— 防止扫描到的资产名反过来 XSS 报告本身

**Web 看板与 REST 接口**（可选依赖 `[api]`）

- FastAPI 应用：目标列表/详情、报告导出、PoC 列表、触发三类扫描
- 单页看板前端（原生 JS + 内联样式，无构建步骤、无 CDN 依赖）
- 安全设计：默认只绑 `127.0.0.1`；绑非回环地址时**强制要求 token**
  （没设直接拒绝启动）；token 用 `hmac.compare_digest` 比较避免时序侧信道

**工程化**

- CLI：`subdomain` / `portscan` / `poc run` / `triage` / `report` / `serve` / `diff` / `init`
- 结构化日志，记录每个源的耗时、发现量、过滤量
- 统一异常树（可重试 / 不可重试）
- Docker 部署（Dockerfile + docker-compose，非 root 运行）
- GitHub Actions CI
- **259 个单元测试，全部离线可跑**，ruff 零告警
  （当前已达 **324 个** —— 见 [Unreleased] 段）

### 设计取舍记录

- 运行时依赖刻意只保留 3 个（httpx / SQLAlchemy / PyYAML），
  FastAPI 做成可选依赖 —— 不该因为「想看个界面」就被迫装一整套 Web 框架
- 内置指纹规则目录按**相对包目录**解析，而不是相对工作目录
  （踩过的坑：从非项目根执行时规则数静默变成 0，且没有任何报错）

---

[Unreleased]: https://github.com/hediwen831-star/attack-surface/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hediwen831-star/attack-surface/releases/tag/v0.1.0
