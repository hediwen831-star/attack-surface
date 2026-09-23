"""内置 PoC 目录。

目录里是 YAML 格式的 PoC 定义，由 ``asp.plugins.loader`` 加载，
不会被当作 Python 代码导入。

声明为包是为了让 setuptools 能把 YAML 打进 wheel ——
否则 ``pip install`` 之后引擎会找不到任何 PoC。
"""
