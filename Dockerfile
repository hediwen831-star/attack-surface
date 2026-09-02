# ASP — 攻击面测绘平台
#
# 这个镜像解决的是「clone 下来就能跑」：
# 使用者不需要装 Python、不需要建 venv、不需要 pip install ——
# 一条 docker compose run 就能对一个目标跑完整条链路。
#
# ══════════════════════════════════════════════════════════════════
# 用法示例
# ══════════════════════════════════════════════════════════════════
#
#   docker build -t asp:latest .
#
#   # 子域名收集
#   docker run --rm -v "$PWD/data:/app/data" asp:latest subdomain example.com --save
#
#   # 端口扫描 + 指纹识别
#   docker run --rm -v "$PWD/data:/app/data" asp:latest portscan 127.0.0.1 --save
#
#   # 生成报告
#   docker run --rm -v "$PWD/data:/app/data" -v "$PWD/out:/out" \
#       asp:latest report example.com -f html -o /out/report.html
#
#   # Web 看板（需要挂端口 + 设 token，见 docker-compose.yml）
#   docker run --rm -p 127.0.0.1:8000:8000 -v "$PWD/data:/app/data" \
#       -e ASP_API_TOKEN=xxx asp:latest serve --host 0.0.0.0 --port 8000

FROM python:3.11-slim

# 为什么是 3.11 而不是更新的 3.13：
# 项目声明 3.11+，3.11 是当前生态验证最充分的版本
# （SQLAlchemy / httpx 的异步栈都已长期稳定），没必要追最新。
# slim 而不是 alpine：alpine 用 musl libc，
# 某些依赖的 wheel 需要现场编译，构建时间会明显变长。

WORKDIR /app

# ── 先拷依赖清单，单独成层 ──
#
# 这样改代码不会触发重新装依赖 —— 构建缓存能命中这一层，
# 反复构建时能省掉大部分时间。
COPY pyproject.toml requirements.txt README.md ./

# ── 再拷源码 ──
COPY asp/ ./asp/
COPY conf/ ./conf/

# 以可编辑模式安装，顺带把 [api] extra 装上（Web 看板需要）
#
# 用阿里云镜像：这是给国内网络环境用的。
# 如果你的构建环境直连 PyPI 很快，可以把 -i 参数去掉。
RUN pip install --no-cache-dir \
        -i https://mirrors.aliyun.com/pypi/simple/ \
        -e ".[api]"

# ── 运行时准备 ──
#
# 用非 root 用户运行。
#
# 这不是形式主义：这个工具会处理来自外部的数据（扫描结果、第三方 PoC 文件），
# 还会发起网络请求。以 root 跑一个"会解析外部输入"的程序，
# 是把容器逃逸的门槛降到最低。
RUN useradd -m -u 1000 -s /bin/bash asp \
    && mkdir -p /app/data /app/out \
    && chown -R asp:asp /app
USER asp

# 数据库落在 /app/data —— 由 compose 挂载出来，保证容器重启后数据还在。
# 环境变量格式见 asp/config.py 的 _apply_env_overrides：
# 顶层字段用 ASP_<FIELD>，嵌套字段用 ASP_<SECTION>_<FIELD>。
ENV ASP_DATABASE=/app/data/asp.db

# 结果文件默认写这里，方便挂载
WORKDIR /app

ENTRYPOINT ["python", "-m", "asp.cli"]
CMD ["--help"]
