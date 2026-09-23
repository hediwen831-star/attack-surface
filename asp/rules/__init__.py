"""内置指纹规则目录。

目录里是 YAML 格式的指纹规则，由 ``asp.discover.fingerprint`` 加载，
不会被当作 Python 代码导入。

声明为包是为了让 setuptools 能把 YAML 打进 wheel。
"""
