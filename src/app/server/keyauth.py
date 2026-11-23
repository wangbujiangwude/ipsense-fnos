# -*- coding: utf-8 -*-
"""1.1.27 · 密钥授权状态：用户可知、随时可撤销。

只管理 /vol1/@appdata/ipsense/keyauth.json 里带 ipsense-agent-bridge 标记的授权，
以及该授权自己的 authorized_keys 行与 keys/ 目录下的密钥副本。

边界（红线）：不改提交单 orders.json、不改防火墙、不动用户其它密钥、不执行系统命令。
本模块只做文件级增删，处置与提交单分别由 fw / mh 负责。
"""
import datetime
import io
import json
import os

MARK = "ipsense-agent-bridge"
KEYDIR = "/vol1/@appdata/ipsense/keys"


class KeyAuth(object):
    def __init__(self, var_dir, log=None):
        self.path = os.path.join(var_dir, "keyauth.json")
        self._log = log or (lambda m: None)

    def _read(self):
        try:
            with io.open(self.path, "r", encoding="utf-8") as f:
                d = json.load(f)
            if isinstance(d, dict) and isinstance(d.get("grants"), list):
                return d
        except Exception:
            pass
        return {"version": 1, "grants": []}

    def _write(self, d):
        tmp = self.path + ".tmp"
        with io.open(tmp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(d, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)
        os.chmod(self.path, 0o644)

    def state(self):
        """返回给 UI 的授权列表：只给指纹 / 公钥 / 时间 / 设备 / 状态，不给私钥内容。"""
        d = self._read()
        out = []
        for g in d["grants"]:
            if not isinstance(g, dict):
                continue
            out.append({
                "id": g.get("id", ""),
                "fingerprint": g.get("fingerprint", ""),
                "pubkey": g.get("pubkey", ""),
                "device": g.get("device", ""),
                "created_at": g.get("created_at", ""),
                "status": g.get("status", "active"),
                "revoked_at": g.get("revoked_at", ""),
                "authorized_keys": g.get("authorized_keys", ""),
                "key_on_device": bool(g.get("private_key")),
            })
        return {
            "version": d.get("version", 1),
            "grants": out,
            "note": "撤销只删除本应用带 ipsense-agent-bridge 标记的授权行与密钥副本，不动其它密钥",
        }

    def revoke(self, grant_id):
        grant_id = (grant_id or "").strip()
        if not grant_id.startswith("mh1-"):
            raise ValueError("非法授权 ID")
        d = self._read()
        hit = None
        for g in d["grants"]:
            if isinstance(g, dict) and g.get("id") == grant_id:
                hit = g
                break
        if not hit:
            raise ValueError("找不到授权：%s" % grant_id)
        if hit.get("status") == "revoked":
            return self.state()

        # 1) 从 authorized_keys 删掉本授权那一行（按标记精确匹配，保留用户其它密钥）
        ak = hit.get("authorized_keys") or ""
        if ak and os.path.isfile(ak):
            tag = "%s:%s" % (MARK, grant_id)
            try:
                st = os.stat(ak)
                with io.open(ak, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                keep = [ln for ln in lines if tag not in ln]
                tmp = ak + ".ipsense.tmp"
                with io.open(tmp, "w", encoding="utf-8", newline="\n") as f:
                    f.writelines(keep)
                try:
                    os.chown(tmp, st.st_uid, st.st_gid)   # 保留原属主，避免 sshd StrictModes 拒绝
                except (AttributeError, OSError):
                    pass   # 非 POSIX / 无 chown 权限时忽略，不阻断撤销
                os.chmod(tmp, 0o600)
                os.replace(tmp, ak)
            except Exception as e:
                raise ValueError("更新 authorized_keys 失败：%s" % e)

        # 2) 删除设备上的密钥副本（严格白名单：只在本应用 keys/ 目录下）
        for k in ("private_key", "public_key"):
            p = hit.get(k) or ""
            if p and os.path.abspath(p).startswith(KEYDIR + os.sep):
                try:
                    if os.path.isfile(p):
                        os.remove(p)
                except Exception as e:
                    self._log("keyauth: remove %s failed: %s" % (p, e))

        # 3) 状态改为 revoked，清空密钥路径
        hit["status"] = "revoked"
        hit["revoked_at"] = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
        hit["private_key"] = ""
        hit["public_key"] = ""
        self._write(d)
        self._log("keyauth: revoked %s" % grant_id)
        return self.state()
