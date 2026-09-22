# 贡献指南

## 开发环境

```bash
git clone https://github.com/hediwen831-star/attack-surface.git
cd attack-surface

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -r requirements.txt
pip install -r requirements-dev.txt    # 测试与 lint
```

## 提交前必须跑的两件事

```bash
ruff check asp tests     # 必须零告警
pytest -q                # 必须全绿
```

CI 会跑同样的检查。**本地不跑等于让 CI 替你发现低级错误** ——
既浪费 CI 时间，也让提交历史里多一堆「修复 lint」的无意义 commit。

Windows 上如果 pytest 报临时目录权限错误，加 `--basetemp=.pytest_tmp`。

---

## 硬性约定

这些不是风格偏好，每条都有具体原因。

### 1. 单元测试必须离线可跑

测绘工具依赖网络，但**测试绝不能依赖**。需要外部请求的地方用 `monkeypatch` 替换。

**原因**：测试一旦依赖网络，就会因为「目标挂了」「被墙了」「被限速了」
而随机失败。**随机失败的测试比没有测试更糟** —— 它会让所有人开始忽略红色。

### 2. 字典型数据用多行文本维护

```python
TOP_PORTS = tuple("""
    80 443 8080 8443
    22 3389 5900
""".split())
```

不要写几百个元素的 list 字面量 —— 没人能在一屏里看完，也没法有效 diff。

### 3. PoC 引擎坚持不用 eval

`asp/plugins/matchers.py` 的 DSL 是白名单实现，
`test_dsl_rejects_non_whitelisted_syntax` 守着这条线。

**「加载第三方 YAML」和「执行任意代码」必须是两件事** ——
这是这个引擎能被安全使用的前提。

### 4. 新增匹配器 / 提取器要配测试

并且在 docstring 里说明「它解决什么场景下的什么问题」，
而不只是「它做了什么」。

### 5. 结论要可追溯

新增任何「判断」逻辑（组件是否存在、漏洞是否命中）时，
都要保留**判定依据**（证据片段、置信度、理由）。

这是整个项目的设计主线 —— 扫描结果最容易被质疑的就是
「你报的这个是真的吗」，可追溯性是对这个问题的正面回答。

---

## 提交规范

用 [Conventional Commits](https://www.conventionalcommits.org/)：

| 前缀 | 用途 |
|---|---|
| `feat:` | 新功能 |
| `fix:` | 修复 |
| `docs:` | 文档 |
| `test:` | 测试 |
| `refactor:` | 重构 |
| `chore:` | 构建 / 工具 |
| `perf:` | 性能 |

**第一行要能独立读懂**，正文说明「为什么这么改」而不只是「改了什么」。

好的例子：

```
fix: MySQL 握手包被误判为 telnet

mysql_native_password 这个字符串里含 "password"，
被过宽的 telnet 兜底规则命中了。

教训：兜底规则越宽松，误报越难排查 —— 因为看起来确实匹配到了内容。
```

差的例子：

```
fix: 修了一个 bug
```

---

## 新增资产源

1. 在 `asp/discover/` 下实现 `Source` 接口
2. 在 `asp/discover/base.py` 的注册表里注册
3. 补单测（用 monkeypatch 替换 DNS / HTTP）
4. 更新 README 的「核心特性」表格

## 新增 PoC 插件

1. 在 `asp/pocs/` 下加 YAML
2. 本地对 [VulnLab 靶场](https://github.com/hediwen831-star/vulnlab) 跑一遍确认能命中
3. 说明该 PoC 的误报风险（是否需要负向对照）

---

## Pull Request

- **一个 PR 只做一件事** —— 混在一起的改动没法有效评审
- 描述里写清楚：做了什么、为什么、**怎么验证的**
- CI 必须全绿
- 涉及行为变更的改动要同步更新文档

模板见 [.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md)。

---

## 报告问题

- **Bug / 功能建议** → [开 issue](.github/ISSUE_TEMPLATE/)
- **安全漏洞** → 见 [SECURITY.md](SECURITY.md)，**不要开公开 issue**
