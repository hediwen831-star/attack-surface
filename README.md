# ASP — 外网攻击面自动化测绘与漏洞验证平台

> 把「资产发现 → 服务识别 → 指纹匹配 → 漏洞验证 → 报告输出」这条真实渗透流水线，
> 做成可插拔、可观测、可复现的异步平台。

```
Python 3.11+ · asyncio · FastAPI 就绪 · SQLite/PostgreSQL · 自研 YAML PoC 引擎
259 个单元测试 · ruff 零告警 · 零网络依赖的单测 · Web 看板 + REST 接口
```

---

## 这是什么

市面上的扫描器解决「怎么扫」，ASP 解决的是**「怎么组织一次扫描」**。

它不是一个「更快的端口扫描器」，而是一个**编排与判定框架**：

- **可插拔** —— 新增资产源或检测插件不需要改引擎代码
- **可观测** —— 结构化日志记录每个源的耗时、发现量、过滤量
- **可复现** —— 每次扫描落库为独立任务，支持资产变更 diff
- **可控误报** —— 内置负向对照校验，把「通配 200 页面」这类假阳性挡在报告之外

---

## 核心特性

| 特性 | 说明 |
|---|---|
| **异步资产发现** | 证书透明日志（crt.sh）+ DNS 字典爆破，多源并发聚合去重 |
| **泛解析基线检测** | 随机域名基线探测，过滤通配 DNS 产生的海量假资产 |
| **统一异步 HTTP 客户端** | 令牌桶限速 + 信号量并发控制 + 指数退避重试 |
| **自研 YAML PoC 引擎** | 4 种匹配器（status/word/regex/dsl）+ 提取器 + 热加载 |
| **白名单 DSL（无 eval）** | 支持条件表达式但**不支持任意代码** —— 加载第三方 PoC 不等于执行任意代码 |
| **负向对照校验** | 命中后向同目录随机路径发对照请求，识别「通配页面」误报 |
| **端口扫描与服务识别** | asyncio TCP 连接扫描 + 两阶段 banner 抓取（先静默读，未果再按端口类型主动探测） |
| **Web 指纹识别** | favicon mmh3 哈希（纯 Python 实现，与官方库逐字节一致）+ 46 条内置规则 + 置信度累加 |
| **报告导出** | JSON / Markdown / HTML 三种格式，**跨任务聚合**（同一目标的多条扫描链路汇总成一份） |
| **Web 看板与 REST 接口** | FastAPI + 单页看板（**可选依赖**）：触发扫描、浏览结果、导出报告，含 token 鉴权与绑定安全检查 |
| **LLM 辅助告警降噪** | 可插拔 provider（OpenAI 兼容接口 / 无 key 时启发式降级），在**标注样本上可量化评估**效果 |
| **六表资产模型** | domain/IP/port/service/component/vuln 关联建模，支持按维度聚合 |
| **资产变更 diff** | 对比两次扫描，输出新增/消失/未变资产 |
| **结构化日志** | `key=value` 格式，可接 ELK / Loki |
| **CLI + JSON 输出** | 可管道、可脚本化，退出码语义化（有命中返回 1） |

---

## 文档

| 文档 | 内容 |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | **技术栈详解、架构分层、核心算法原理、与现有方案的对比** |
| [docs/FAQ.md](docs/FAQ.md) | 面试追问与回答要点（20+ 个高频问题，含"不要说什么"） |
| 本 README | 项目概览、快速开始、PoC 编写指南 |

---

## 快速开始

```bash
pip install -r requirements.txt

# 子域名收集（默认 crtsh + 内置 364 词字典）
python -m asp.cli subdomain example.com

# 指定来源
python -m asp.cli subdomain example.com --sources crtsh,brute

# 结果落库（供 diff 使用）
python -m asp.cli subdomain example.com --save

# 对比最近两次扫描的资产变化
python -m asp.cli diff example.com

# 列出全部 PoC
python -m asp.cli poc list

# 对目标执行漏洞验证
python -m asp.cli poc run http://127.0.0.1:8080

# 端口扫描 + 服务识别（默认扫内置常见端口表）
python -m asp.cli portscan 127.0.0.1

# 指定端口范围并落库
python -m asp.cli portscan 127.0.0.1 --ports 1-1024 --save

# 生成报告（从数据库聚合该目标的全部扫描结果）
python -m asp.cli report 127.0.0.1 -f html -o report.html
python -m asp.cli report example.com -f md

# LLM 辅助告警降噪（无 API key 时自动降级为启发式规则）
python -m asp.cli triage 127.0.0.1
python -m asp.cli triage --self-test          # 在标注样本上评估研判效果

# 启动 Web 看板与 REST 接口（需要先装可选依赖）
pip install -e ".[api]"
python -m asp.cli serve                       # http://127.0.0.1:8000

# 生成配置模板
python -m asp.cli init
```

### 实测输出

`python -m asp.cli subdomain baidu.com --sources crtsh,brute`（25 秒）：

```
目标: baidu.com
来源: crtsh, brute
耗时: 25.11s
存活子域名: 264

子域名                          解析 IP           来源      标记
──────────────────────────────  ────────────────  ────────  ──────
api.push.baidu.com              112.34.111.58     crtsh
c.tieba.baidu.com               183.240.99.140    brute    多源
git.aistudio.baidu.com          111.45.11.59      crtsh
localhost.pan.baidu.com         127.0.0.1         crtsh
…

按来源统计: brute=104, crtsh=160
多源交叉确认: 9 条（优先级最高，建议最先人工复核）
```

`localhost.pan.baidu.com → 127.0.0.1` 这类记录是真实存在的攻击面盲区 ——
**多源交叉确认**标记让 9 条最可信的资产被排在最前面复核。

---

## 架构

```
                        ┌──────────────────────────────────────┐
                        │              CLI (argparse)          │
                        │  subdomain │ poc run │ poc list │ diff │
                        └───────────────────┬──────────────────┘
                                            │
        ┌───────────────────────────────────┼───────────────────────────────────┐
        │                                   │                                   │
        ▼                                   ▼                                   ▼
┌───────────────┐                 ┌──────────────────┐                ┌────────────────┐
│   discover/   │                 │    plugins/      │                │   services/    │
│               │                 │                  │                │                │
│ CrtshSource   │                 │ loader.py        │                │ subdomain.py   │
│ BruteForce    │                 │  YAML → PoC      │                │  collect()     │
│  ├ 泛解析检测 │                 │ matchers.py      │                │  persist()     │
│  └ 字典爆破   │                 │  status/word/    │                │  diff_tasks()  │
│               │                 │  regex/dsl       │                │                │
│  Source(ABC)  │                 │ engine.py        │                │  编排 + 去重   │
│   ↑ 新增源只需│                 │  执行 + 负向对照 │                │  + 验证 + 落库 │
│     实现 fetch│                 │                  │                │                │
└───────┬───────┘                 └────────┬─────────┘                └───────┬────────┘
        │                                  │                                  │
        └──────────────────┬───────────────┴──────────────────────────────────┘
                           ▼
              ┌──────────────────────────────┐      ┌─────────────────────────┐
              │           core/              │      │   core/database.py      │
              │  http.py                     │      │   六表资产模型 (ORM)    │
              │   令牌桶限速 + 信号量并发     │      │                         │
              │   + 指数退避重试             │      │   ScanTask ─< Asset     │
              │  config.py  配置加载与校验   │      │            ─< Port      │
              │  logger.py  结构化日志       │      │            ─< Service   │
              └──────────────────────────────┘      │            ─< Component
                                                    │            ─< Vuln      │
                                                    └─────────────────────────┘
```

---

## PoC 编写

在 `asp/pocs/` 下新建 YAML 即可，**无需改引擎代码**（热加载）：

```yaml
id: my-first-poc

info:
  name: 我的第一个检测插件
  severity: high              # critical/high/medium/low/info
  author: your-name
  tags: [exposure, custom]

requests:
  - method: GET
    path:
      - "{{BaseURL}}/vulnerable/endpoint"

    matchers-condition: and   # 强烈建议用 and —— 单条件命中误报率极高

    matchers:
      - type: status
        status: [200]

      - type: word
        part: body            # body / header / all
        words: ["特征字符串"]
        condition: and

      - type: regex
        part: body
        regex: ["version[=:]\\s*([\\d.]+)"]

      - type: dsl
        dsl:
          - "len(body) > 1024"
          - "contains(body, 'uid=')"
        condition: and

    extractors:
      - type: regex
        part: body
        name: version
        regex: ["version[=:]\\s*([\\d.]+)"]
```

参考 `asp/pocs/_template.yaml`（带注释的完整模板）。

**可用变量**：`{{BaseURL}}` `{{RootURL}}` `{{Hostname}}` `{{Port}}` `{{Scheme}}`

---

## 设计取舍

这一节是这个项目最有价值的部分 —— 面试时会被追问的都在这里。

### 1. 为什么用 asyncio 而不是多线程？

测绘是**极端 IO 密集**的任务：一次子域名收集要发几百次 DNS 查询，
每次耗时几十毫秒且几乎全在等待。多线程模型下：
- 每个线程有独立的栈开销（MB 级），几百个线程就吃掉大量内存
- GIL 让线程切换有额外成本，而我们真正想要的只是「并发等待」
- 线程的取消/超时控制比协程笨拙得多

asyncio 下单个事件循环可以轻松挂住上千个等待中的 socket，
内存开销是每个协程几 KB。实测 200 并发 DNS 查询稳定运行。

**但也要说清楚代价**：asyncio 的调试成本更高（栈回溯可读性差），
且任何同步阻塞调用都会拖垮整个事件循环。这也是为什么
DNS 解析这里用的是 `loop.getaddrinfo`（内部走线程池）
而不是自己写 socket —— 标准库已经处理好了这个坑。

### 2. 为什么自研 DSL 而不用 `eval`？

一个检测引擎里最容易埋雷的地方就是「让用户写表达式」。

如果用 `eval()` 执行 YAML 里写的条件，那我们加载的就不再是数据，而是**任意代码**——
意味着任何一条从社区下载的 PoC 都能在你机器上执行命令。
「一个安全工具自身有 RCE」是最难看的漏洞。

所以这里实现了一个**白名单语法的小解析器**，只支持四种谓词：

```
status == 200
contains(body, 'root:')
len(body) > 1024
regex(header, 'Server: .*nginx')
```

测试用例 `test_dsl_rejects_non_whitelisted_syntax` 专门守这条边界，
里面用 `__import__('os').system('id')` 之类的内容做断言。

**表达能力受限是安全特性，不是缺陷。**

### 3. 泛解析过滤：为什么是「子集」而非「交集」判断

配置了 `*.example.com IN A 1.2.3.4` 的域名，任意随机子域名都能解析成功。
不做处理的话，364 个词的字典会产出 364 条假资产。

算法：
1. 随机生成 3 个一定不存在的子域名做基线探测
2. 若有 ≥2 个解析到**同一 IP**，判定为泛解析，记录该 IP 集合
3. 爆破时，若某域名的解析结果**全部落在**泛解析 IP 集合内 → 丢弃

**为什么是 `issubset` 而不是 `isdisjoint`？**

假设 `mail.example.com` 同时解析到 `1.2.3.4`（泛解析 IP）和 `5.6.7.8`（真实记录）。
- 用 `isdisjoint`：因为它和泛解析集合有交集，会被误杀 → **漏掉真实资产**
- 用 `issubset`：只有全部 IP 都在泛解析集合里才丢弃 → 真实资产被保留

宁可多留一条假资产让人工复核，也不漏掉一条真实资产 ——
这是安全工具的基本态度。误报可以筛掉，漏报没法补救。

**为什么基线探测要 ≥2 次命中而不是 1 次？**
单次命中可能是运营商 DNS 劫持（国内校园网/运营商把不存在的域名劫持到广告页）。
要求两个独立随机域名命中同一 IP，才能排除这种偶发噪声。

**已知局限**（诚实写出来）：只检测顶层泛解析；CDN 场景下泛解析与真实记录可能指向同一 CDN IP，会误杀。
业界解法是叠加 HTTP 响应内容差异比对，本项目尚未实现。

### 4. 负向对照校验：把「通配 200 页面」挡在报告外

很多站点对所有路径都返回 200 + 同一个页面（SPA 的 index.html 回退、自定义 404、
WAF 拦截页）。此时一个只写了 `status: [200]` 的 PoC 会命中**所有** URL。

解法是命中后再发一个**对照请求**到同目录下的随机路径：

```
命中的是: GET /admin/config.php      → 200 + "[core]"
对照请求: GET /admin/asp-ctl-a1b2c3  → 200 + "[core]"   ← 也命中了
```

对照也命中 → 说明这个特征是**页面的通用特征**而非**该路径的特殊特征** → 判为误报。

这一步把结论从「这个特征出现了」升级为「这个特征**只在这个路径**出现」。
测试 `test_negative_control_filters_universal_200_page` 专门守这个行为。

### 5. 为什么阈值化「置信度」而不是简单真假

`and` 条件全部命中 → 置信度 1.0（多重独立特征同时成立，几乎不可能是巧合）
`or` 条件按命中比例给分，且**单个匹配器命中时上限 0.8**。

理由：单一特征（尤其单个关键词）的误报率显著高于多特征组合。
报告里按置信度排序，让人工复核从最可信的开始 ——
**给结论附上「我有多确定」，比给一个武断的布尔值有用得多。**

### 6. 为什么任务要落库而不是覆盖

每次收集创建一个新的 `ScanTask`。只有保留历史快照，才能算出
「相比上次扫描新增/消失了哪些资产」——而这正是攻击面管理区别于
「扫一遍就忘」的核心价值。

### 7. 依赖精简到极致

运行时只有三个依赖：`httpx`、`SQLAlchemy`、`PyYAML`。
CLI 用标准库 `argparse`（不用 click/typer），表格输出手写（不用 tabulate），
DNS 用标准库（不用 aiodns）。

这不是「造轮子癖」，而是安全工具的现实约束：
**被部署到客户环境时，少一个依赖就少一次「装不上」的现场事故。**

---

## 项目结构

```
attack-surface/
├── asp/
│   ├── cli.py                  # 命令行入口（subdomain / portscan / poc / report / diff / init）
│   ├── config.py               # 配置加载、校验、环境变量覆盖
│   ├── exceptions.py           # 统一异常树（可重试 / 不可重试）
│   ├── logger.py               # 结构化日志
│   ├── report.py               # 报告生成（JSON / Markdown / HTML，跨任务聚合）
│   ├── llm.py                  # LLM 辅助告警降噪（可插拔 provider + 启发式降级）
│   ├── api/                    # Web 看板与 REST 接口（可选依赖）
│   │   ├── app.py              # FastAPI 应用（含绑定安全检查与 token 鉴权）
│   │   └── static/index.html   # 单页看板前端
│   ├── core/
│   │   ├── http.py             # 异步 HTTP 客户端（限速/并发/重试）
│   │   └── database.py         # 六表资产模型
│   ├── discover/
│   │   ├── base.py             # Source 抽象 + DiscoveredAsset
│   │   ├── crtsh.py            # 证书透明日志源
│   │   ├── bruteforce.py       # DNS 爆破 + 泛解析检测
│   │   ├── portscan.py         # 端口扫描 + 服务指纹识别
│   │   └── fingerprint.py      # Web 指纹（含纯 Python MurmurHash3 实现）
│   ├── plugins/
│   │   ├── loader.py           # YAML PoC 加载与校验
│   │   ├── matchers.py         # 匹配器 + 提取器 + 白名单 DSL
│   │   └── engine.py           # 执行引擎 + 负向对照校验
│   ├── services/
│   │   ├── subdomain.py        # 子域名编排、聚合、验证、落库、diff
│   │   ├── host.py             # 主机测绘编排（端口 + 指纹 + 落库）
│   │   └── vuln.py             # 漏洞结果持久化 + target 归一化
│   ├── rules/
│   │   └── fingerprints.yaml   # 46 条 Web 指纹规则
│   └── pocs/                   # 内置检测插件
├── conf/config.example.yaml
├── tests/                      # 259 个单元测试（全部离线）
├── .github/workflows/ci.yml
├── pyproject.toml
└── requirements.txt
```

---

## 测试

```bash
pip install -r requirements-dev.txt

pytest -v            # 259 个用例
ruff check asp tests # 静态检查
```

**所有单测都不依赖网络。** 测绘工具天生依赖外部服务，
但测试绝不能依赖 —— 否则 CI 会因为某个第三方站点抖动而红，久了就没人信测试了。
所以 DNS 与 HTTP 全部通过 monkeypatch 替换成可控的假实现。

几个值得一看的测试：

| 测试 | 守住什么 |
|---|---|
| `test_dsl_rejects_non_whitelisted_syntax` | PoC 不能执行任意代码（安全边界） |
| `test_negative_control_filters_universal_200_page` | 通配页面误报必须被过滤 |
| `test_bruteforce_filters_wildcard_fake_assets` | 泛解析假资产必须被丢弃，真实资产必须保留 |
| `test_detect_wildcard_single_hit_is_noise` | 单次命中不算泛解析（排除 DNS 劫持噪声） |
| `test_builtin_pocs_are_valid` | 仓库内置 PoC 的自检（CI 守门人） |
| `test_scan_target_survives_broken_poc` | 单个坏 PoC 不能中断整次扫描 |

---

## 与 VulnLab 靶场联动

配套的 [VulnLab](../vulnlab) 靶场为每个漏洞提供了确定的 URL 与已知结论，
可作为本引擎的**效果评测基准**：

```bash
python -m asp.cli poc run http://127.0.0.1:8080 --dir ../vulnlab/pocs
```

```
执行 PoC: 7   耗时: 0.17s
命中: 3

high    vulnlab-sqli-low-union      .../sqli/low.php?id=-1%20UNION%20SELECT%20...   1.00
high    sql-injection-error-based   .../sqli/low.php?id=1%27                        0.80
high    sql-injection-error-based   .../sqli/medium.php?id=1%27                     0.80
```

靶场的 `high` 档（已修复）是天然的**误报诱饵** ——
引擎若在这里报漏洞，说明判定逻辑有问题。

---

## 路线图

- [x] 配置加载与校验、结构化日志、统一异常体系
- [x] 异步 HTTP 客户端（令牌桶限速 + 指数退避）
- [x] 证书透明日志源 + DNS 爆破源 + 泛解析检测
- [x] 六表资产模型 + 资产变更 diff
- [x] YAML PoC 引擎（4 种匹配器 + 提取器 + 白名单 DSL）
- [x] 负向对照校验
- [x] 259 个离线单元测试 + GitHub Actions CI
- [x] 端口扫描与服务识别（asyncio 连接扫描 + 两阶段 banner 抓取）
- [x] Web 指纹识别（纯 Python MurmurHash3 + 46 条规则 + 置信度累加）
- [x] 报告导出（HTML / Markdown / JSON，跨任务聚合）
- [x] FastAPI REST 接口 + 单页 Web 看板（可选依赖，含鉴权与绑定安全检查）
- [x] LLM 辅助告警降噪（可插拔 provider + 标注样本量化评估）
- [ ] 分布式扫描（多节点协同 + 任务队列）
- [ ] 更多协议支持（SMB / RDP 等内网协议探测）

---

## ⚠️ 免责声明

**本工具仅用于授权范围内的安全测试与自有资产测绘。**

使用者需自行确保对目标拥有合法授权。未经授权对他人系统进行扫描、
探测或漏洞验证在多数司法管辖区属于违法行为。

工具内置了限速机制（默认 50 QPS）与可识别的前缀标记
（探测域名 `asp-probe-*`、对照路径 `asp-ctl-*`），
目的是让目标管理员能识别并联系，而不是掩饰行为。

---

## 许可

MIT
