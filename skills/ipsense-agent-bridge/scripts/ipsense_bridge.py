#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""1.1.22 遗留只读别名 —— 已弃用，请改用 `mh`。

1.1.25 起「CLI 是 agent 唯一的手和眼」，实现只保留在 scripts/mh.py 一份。
本文件仅把旧的 `ipsense_bridge.py <命令>` 转发给 mh，避免旧脚本 / 旧文档里
`ipsense_bridge.py orders` 这类调用直接失效；不再单独维护任何读写逻辑。

新流程：
    python scripts/mh.py init / check / read / show / prompt / prepare / commit
"""
import os
import runpy
import sys

sys.stderr.write("[deprecated] ipsense_bridge.py 已弃用，请改用 mh（scripts/mh.py）。\n")
runpy.run_path(os.path.join(os.path.dirname(os.path.abspath(__file__)), "mh.py"),
               run_name="__main__")
