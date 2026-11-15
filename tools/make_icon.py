# -*- coding: utf-8 -*-
"""生成应用图标（纯标准库写 PNG，无需 Pillow）。"""
import os
import math
import zlib
import struct

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")


def blend(dst, src, a):
    return tuple(int(dst[i] * (1 - a) + src[i] * a) for i in range(3))


def make(size):
    rows = []
    cx = cy = size * 0.5
    scale = size / 256.0
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            t = y / float(size)
            r, g, b = (int(11 + 12 * t), int(18 + 19 * t), int(32 + 28 * t))
            # 外圈：雷达
            d = math.hypot(x - cx, y - cy) / scale
            for rad, col, w in ((96, (59, 130, 246), 4.5), (70, (34, 211, 238), 3.0),
                                (44, (96, 165, 250), 2.5)):
                if abs(d - rad * scale) < w * scale:
                    r, g, b = blend((r, g, b), col, 0.55)
            # 中心点
            if d < 15 * scale:
                r, g, b = blend((r, g, b), (59, 130, 246), 0.95)
            # 攻击射线：中心 -> 右上
            x1, y1, x2, y2 = cx, cy, cx + 92 * scale, cy - 78 * scale
            den = (x2 - x1) ** 2 + (y2 - y1) ** 2
            tt = max(0.0, min(1.0, ((x - x1) * (x2 - x1) + (y - y1) * (y2 - y1)) / den))
            px, py = x1 + tt * (x2 - x1), y1 + tt * (y2 - y1)
            if math.hypot(x - px, y - py) < 4.2 * scale:
                r, g, b = blend((r, g, b), (255, 77, 109), 0.92)
            if math.hypot(x - x2, y - y2) < 11 * scale:
                r, g, b = blend((r, g, b), (255, 77, 109), 0.95)
            # 左下青点
            if math.hypot(x - (cx - 74 * scale), y - (cy + 58 * scale)) < 9 * scale:
                r, g, b = blend((r, g, b), (52, 211, 153), 0.95)
            row += bytes((max(0, min(255, r)), max(0, min(255, g)),
                          max(0, min(255, b)), 255))
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + \
            struct.pack(">I", zlib.crc32(tag + data) & 0xffffffff)

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 9))
    png += chunk(b"IEND", b"")
    return png


def write(path, size):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(make(size))


if __name__ == "__main__":
    for p in ("ICON.PNG", "ICON_256.PNG"):
        write(os.path.join(SRC, p), 256)
    write(os.path.join(SRC, "app", "ui", "images", "icon_256.png"), 256)
    write(os.path.join(SRC, "app", "ui", "images", "icon_64.png"), 64)
    print("icons written")
