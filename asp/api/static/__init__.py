"""Web 看板的静态资源目录。

只有 HTML，不含 Python 代码；``asp/api/app.py`` 通过文件系统路径读取
（``STATIC_DIR = Path(__file__).parent / "static"``）。

声明为包是为了让 setuptools 能把 ``index.html`` 打进 wheel。
"""
