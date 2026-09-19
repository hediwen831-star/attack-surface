# 更新日志

本文件记录本项目的所有重要变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

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

### 设计取舍记录

- 运行时依赖刻意只保留 3 个（httpx / SQLAlchemy / PyYAML），
  FastAPI 做成可选依赖 —— 不该因为「想看个界面」就被迫装一整套 Web 框架
- 内置指纹规则目录按**相对包目录**解析，而不是相对工作目录
  （踩过的坑：从非项目根执行时规则数静默变成 0，且没有任何报错）

---

[Unreleased]: https://github.com/hediwen831-star/attack-surface/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hediwen831-star/attack-surface/releases/tag/v0.1.0
