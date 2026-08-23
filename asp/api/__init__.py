"""Web API 与可视化看板。

这一层是**可选依赖**：核心能力不需要 FastAPI。
安装方式：``pip install -e ".[api]"``，启动方式：``asp serve``。

安全提醒：``/api/scan/*`` 端点会发起主动扫描，
所以绑定非回环地址时强制要求 ``ASP_API_TOKEN``（详见 app.py 的说明）。
"""

from .app import check_bind_safety, create_app, serve

__all__ = ["create_app", "serve", "check_bind_safety"]
