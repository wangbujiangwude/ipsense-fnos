# -*- coding: utf-8 -*-
"""1.1.25 · 提交单四区状态机 / AI 标记工单 / mh 接口 / 短读取提示词。

边界写死，不因需求变化放宽：
  * 只读写 $TRIM_PKGVAR/orders.json 这一个文件；
  * 不引入任何子进程模块，不调用系统命令接口，不执行外部程序；
  * 不触碰任何防火墙设施，不读写任何规则文件；
  * 软件永远不改防火墙设置，处置完全交给外部 agent；
    本模块只维护「提交单」这份结构化状态与一句读取提示词。

设计要点（1.1.25 方案 B 演进）：
  * skill 文档是「规矩/大脑」（边界、完整证据在哪读、建议流程都在那儿）；
  * mh CLI 是外部 agent 唯一的「手和眼」：对工程状态的一切感知与修改都走
    /api/mh/* 接口，读命令与写命令严格分层，写命令只改提交单、不碰用户页面；
  * 每次 mh 调用都是短命进程，状态全部落在这个文件里，不依赖长驻会话；
  * 乐观锁：每个条目带 rev（每次变更自增），读时签发 receipt（回执），
    提交时校验「回执里的 rev == 当前 rev」，旧回执一律拒绝，防止把过时指令
    误标成已完成（防串台）。
  * 提交单四区：pending 待处理 / done 已完成 / revert 待撤回 / restored 已复原；
    「全部」显示全部条目 + 完整操作流水 log。
"""
import hashlib
import json
import os
import re
import threading
import time

IP_CHARS = re.compile(r"^[0-9A-Fa-f:.]{3,45}$")
MAX_NOTE = 500
MAX_SUMMARY = 600
MAX_ITEMS = 200
MAX_FIELD = 300
MAX_LOG = 300
STAGE_TTL = 600                       # prepare 出来的两阶段预备 10 分钟内有效
SOCKET_HINT = "/vol1/@appcenter/ipsense/app.sock"

# 短提示词：一句话模式 + 单独给 AI 的读取路径。规矩/证据/流程全部挪进 skill，
# 不再在每次提交的提示词里反复塞边界、白名单、TTL、建议流程等关键词（省 token）。
ONE_LINER = "请读取工程中的 AI 标记，按标注逐项修改"
ONE_LINER_REVERT = "请读取工程中的 AI 标记，按标注逐项复原"
SKILL_HINT = "ipsense-agent-bridge skill"

# 四区状态与 tab 映射。restored（已复原）归入「已完成」展示，但带独立徽标；
# 「全部」不受过滤，显示所有状态 + 完整 log。
STATUSES = ("pending", "done", "revert", "restored")
TAB_FILTER = {
    "pending": ("pending",),
    "done": ("done", "restored"),
    "revert": ("revert",),
    "all": None,
}
STATUS_LABEL = {"pending": "待处理", "done": "已完成",
                "revert": "待撤回", "restored": "已复原"}

# 合法状态转移（防呆）。UI 侧动作与 mh 侧动作分开，写命令只能落在这张表里。
#   user save/reopen -> pending ；UI「待撤回」 done -> revert ；
#   agent prepare/commit：pending -> done（mark-done）、revert -> restored（restore）
TRANSITIONS = {
    "mark-done": ("pending", "done"),
    "restore": ("revert", "restored"),
}


def _clean(v, limit=MAX_FIELD):
    """所有来自日志 / 用户输入 / agent 回写的文本进入状态文件前统一清洗：
    去掉控制字符与换行（防止伪造结构 / 注入）、替换尖括号与代码围栏、截断长度。
    这些文本一律是「数据」，绝不当指令拼接。"""
    s = re.sub(r"[\r\n\t\x00-\x1f]+", " ", str(v if v is not None else ""))
    s = s.replace("```", "'''").replace("<", "‹").replace(">", "›")
    return s.strip()[:limit]


def _valid_ip(ip):
    """IP 白名单：只允许 IPv4 / IPv6 的合法字符，挡掉空格、引号、$()、分号等。"""
    ip = str(ip or "").strip()
    if not IP_CHARS.match(ip):
        return None
    if ip.count(".") > 3 and ":" not in ip:
        return None
    return ip


def _receipt(it):
    """回执 = f(ip, rev, status) 的短摘要。rev 一变，旧回执立即失效（乐观锁）。"""
    raw = "%s|%d|%s" % (it.get("ip", ""), int(it.get("rev", 0) or 0),
                        it.get("status", "pending"))
    return "mh1-" + hashlib.md5(raw.encode("utf-8")).hexdigest()[:10]


def _bump(it):
    it["rev"] = int(it.get("rev", 0) or 0) + 1
    it["updated"] = int(time.time())
    return it["rev"]


def _public(it):
    """对外条目：附带当前有效回执，保留 history 供「全部」展示。"""
    d = dict(it)
    d["receipt"] = _receipt(it)
    d["status_label"] = STATUS_LABEL.get(it.get("status"), "—")
    return d


class OrderBook(object):
    def __init__(self, var_dir, log=None):
        self.path = os.path.join(var_dir, "orders.json")
        self._log = log or (lambda m: None)
        self._lock = threading.Lock()
        self._data = {"version": 2, "updated": 0, "items": [],
                      "log": [], "_staged": {}}
        self._load()

    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                d = json.load(f)
            if isinstance(d, dict) and isinstance(d.get("items"), list):
                items = []
                for x in d["items"]:
                    if not isinstance(x, dict):
                        continue
                    items.append(self._normalize(x))
                self._data = {
                    "version": 2,
                    "updated": d.get("updated", 0),
                    "items": items[:MAX_ITEMS],
                    "log": [e for e in (d.get("log") or []) if isinstance(e, dict)][-MAX_LOG:],
                    "_staged": d.get("_staged") if isinstance(d.get("_staged"), dict) else {},
                }
        except Exception:
            pass

    @staticmethod
    def _normalize(x):
        """把 1.1.22~1.1.24 的旧条目 / 缺字段条目补齐成 v2，绝不丢历史数据。"""
        y = dict(x)
        y["ip"] = str(y.get("ip") or "")
        y["note"] = str(y.get("note") or "")
        y["status"] = y.get("status") if y.get("status") in STATUSES else "pending"
        y["rev"] = int(y.get("rev", 0) or 0) or 1
        y["created"] = int(y.get("created", 0) or 0) or int(time.time())
        y["updated"] = int(y.get("updated", 0) or 0) or y["created"]
        y["evidence"] = y.get("evidence") if isinstance(y.get("evidence"), dict) else {}
        y["summary"] = str(y.get("summary") or "")
        y["in_order"] = y.get("in_order") is not False
        y["history"] = [h for h in (y.get("history") or []) if isinstance(h, dict)][-40:]
        for k in ("done_at", "revert_at", "restored_at"):
            y[k] = int(y.get(k, 0) or 0)
        return y

    def _save(self):
        self._data["updated"] = int(time.time())
        tmp = self.path + ".tmp"
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)

    def _append_log(self, ip, action, frm, to, by, summary=""):
        e = {"at": int(time.time()), "ip": ip, "action": action,
             "from": frm, "to": to, "by": by, "summary": _clean(summary, 160)}
        self._data["log"] = (self._data.get("log") or [])[-MAX_LOG:]
        self._data["log"].append(e)
        return e

    def _touch(self, it, action, frm, to, by, summary=""):
        _bump(it)
        e = self._append_log(it["ip"], action, frm, to, by, summary)
        it["history"] = (it.get("history") or [])[-40:] + [dict(e)]
        return e

    def snapshot(self):
        with self._lock:
            items = [_public(x) for x in self._data["items"]]
            counts = self._counts_locked()
            log = [dict(e) for e in (self._data.get("log") or [])]
            path, updated = self.path, self._data.get("updated", 0)
        return {
            "items": items,
            "count": len(items),
            "in_order": sum(1 for x in items if x.get("in_order") is not False),
            "counts": counts,
            "tabs": {k: (v or STATUSES) for k, v in TAB_FILTER.items()},
            "log": log,
            "path": path,
            "updated": updated,
            "read_path": path,
            "read_cmd": "mh read pending",
            "version": 2,
        }

    def _counts_locked(self):
        c = {s: 0 for s in STATUSES}
        for x in self._data["items"]:
            s = x.get("status")
            if s in c:
                c[s] += 1
        c["done_view"] = c["done"] + c["restored"]
        c["all"] = len(self._data["items"])
        return c

    def _find(self, ip):
        for x in self._data["items"]:
            if x.get("ip") == ip:
                return x
        return None

    def _find_by_receipt(self, receipt):
        r = str(receipt or "").strip()
        if not r.startswith("mh1-"):
            return None
        for x in self._data["items"]:
            if _receipt(x) == r:
                return x
        return None

    @staticmethod
    def _evidence(raw):
        """证据只保留白名单字段，且逐项清洗；不接受任何可执行片段。"""
        raw = raw if isinstance(raw, dict) else {}
        scalar = ("geo", "scope", "n", "first", "last", "verdict",
                  "proto", "port", "source")
        lists = ("paths", "recent")
        out = {}
        for k in scalar:
            out[k] = _clean(raw.get(k), 160)
        for k in lists:
            v = raw.get(k)
            out[k] = [_clean(t, 120) for t in v[:10]] if isinstance(v, list) else []
        return out

    # ---------------- 用户侧（UI）：写标注 / 移出 / 清空 / 待撤回 ----------------
    def save(self, ip, note, evidence, in_order=True):
        ip = _valid_ip(ip)
        if not ip:
            raise ValueError("IP 格式不合法")
        note = _clean(note, MAX_NOTE)
        with self._lock:
            it = self._find(ip)
            if it is None:
                if len(self._data["items"]) >= MAX_ITEMS:
                    raise ValueError("提交单已满（上限 %d 条）" % MAX_ITEMS)
                it = self._normalize({"ip": ip, "created": int(time.time()),
                                      "status": "pending", "rev": 0})
                self._data["items"].append(it)
                frm = ""
            else:
                frm = it.get("status", "pending")
            it["note"] = note
            it["in_order"] = bool(in_order)
            it["evidence"] = self._evidence(evidence)
            # 重新标注一律回到「待处理」：旧回执随 rev 自增失效，防止用旧证据提交。
            it["status"] = "pending"
            it["summary"] = ""
            self._touch(it, "save", frm, "pending", "user", note)
            self._save()
        self._log("orders.save %s -> pending" % ip)
        return self.snapshot()

    def toggle(self, ip, in_order):
        ip = _valid_ip(ip)
        if not ip:
            raise ValueError("IP 格式不合法")
        with self._lock:
            it = self._find(ip)
            if it:
                it["in_order"] = bool(in_order)
                _bump(it)
                self._save()
        return self.snapshot()

    def remove(self, ip):
        ip = _valid_ip(ip)
        if not ip:
            raise ValueError("IP 格式不合法")
        with self._lock:
            it = self._find(ip)
            if it:
                self._append_log(ip, "remove", it.get("status", ""), "", "user", "")
            self._data["items"] = [x for x in self._data["items"] if x.get("ip") != ip]
            self._save()
        return self.snapshot()

    def clear(self):
        with self._lock:
            self._data["items"] = []
            self._data["_staged"] = {}
            self._data["log"] = []
            self._save()
        return self.snapshot()

    def request_revert(self, ip):
        """用户在「已完成」区点「待撤回」：done/restored -> revert。只允许这个方向。"""
        ip = _valid_ip(ip)
        if not ip:
            raise ValueError("IP 格式不合法")
        with self._lock:
            it = self._find(ip)
            if not it:
                raise ValueError("提交单里没有这个 IP")
            if it.get("status") not in ("done", "restored"):
                raise ValueError("只有「已完成」的条目才能标记为待撤回")
            frm = it["status"]
            it["status"] = "revert"
            it["revert_at"] = int(time.time())
            self._touch(it, "request-revert", frm, "revert", "user", it.get("summary", ""))
            self._save()
        return self.snapshot()

    # ---------------- agent 侧（mh）：只读查询接口 ----------------
    def mh_state(self, tab="pending"):
        """只读。返回某一区的条目（带 receipt）、各区计数、操作流水、读取路径。"""
        tab = tab if tab in TAB_FILTER else "pending"
        filt = TAB_FILTER[tab]
        with self._lock:
            items = [_public(x) for x in self._data["items"]
                     if x.get("in_order") is not False and
                     (filt is None or x.get("status") in filt)]
            items.sort(key=lambda x: -(x.get("updated") or 0))
            counts = self._counts_locked()
            log = [dict(e) for e in (self._data.get("log") or [])]
            path, updated = self.path, self._data.get("updated", 0)
        return {
            "tab": tab,
            "tab_label": {"pending": "待处理", "done": "已完成",
                          "revert": "待撤回", "all": "全部"}[tab],
            "counts": counts,
            "items": items,
            "log": log,
            "path": path,
            "read_path": path,
            "read_cmd": "mh read " + tab,
            "updated": updated,
            "version": 2,
            "transitions": {k: list(v) for k, v in TRANSITIONS.items()},
        }

    def mh_show(self, ip):
        """只读。单个 IP 的完整证据 + 总结 + 操作历史 + 当前回执。"""
        ip = _valid_ip(ip)
        if not ip:
            raise ValueError("IP 格式不合法")
        with self._lock:
            it = self._find(ip)
            if not it:
                raise ValueError("提交单里没有这个 IP")
            d = _public(it)
        d["evidence_full"] = self._evidence(it.get("evidence"))
        return d

    def mh_path(self):
        """只读。给 AI 的读取路径与接口清单（skill 里也有一份，避免提示词重复）。"""
        return {
            "file": self.path,
            "socket": SOCKET_HINT,
            "skill": SKILL_HINT,
            "read_cmds": ["mh read pending", "mh read done",
                          "mh read revert", "mh read all"],
            "api": {
                "state": "GET /api/mh/state?tab=<tab>",
                "show": "GET /api/mh/show?ip=<IP>",
                "prompt": "GET /api/mh/prompt?tab=<tab>",
                "path": "GET /api/mh/path",
                "write": "POST /api/mh/write（action=prepare / commit / discard）",
            },
        }

    # ---------------- 给外部 agent 的「一句话」读取提示词 ----------------
    def prompt(self, tab="pending"):
        """短提示词：一句话模式 + 单独给 AI 的读取路径。
        边界 / 完整证据在哪读 / 建议流程等规矩全部搬进 skill，不再重复塞进提示词。"""
        tab = tab if tab in TAB_FILTER else "pending"
        line = ONE_LINER_REVERT if tab == "revert" else ONE_LINER
        L = [
            line,
            "",
            "读取路径：" + self.path,
            "读取命令：mh read " + tab,
            "规矩与流程：见 " + SKILL_HINT + "（mh 是唯一读写接口）",
        ]
        return "\n".join(L)

    # ---------------- agent 侧（mh）：两阶段写入 + 乐观锁 ----------------
    def _prune_staged(self):
        now = int(time.time())
        st = self._data.get("_staged") or {}
        self._data["_staged"] = {k: v for k, v in st.items()
                                 if int(v.get("expire", 0) or 0) > now}

    def _action_for(self, it):
        st = it.get("status")
        for act, (frm, to) in TRANSITIONS.items():
            if frm == st:
                return act, frm, to
        return None, st, None

    def mh_prepare(self, receipt, by="agent"):
        """写命令①：校验回执，生成一份「可确认」的变更预备（不落库、不真正改状态）。
        短命 CLI 进程不持有状态，预备放在 orders.json 的 _staged 里。"""
        with self._lock:
            self._prune_staged()
            it = self._find_by_receipt(receipt)
            if not it:
                raise ValueError("旧回执被拒：找不到匹配的当前条目，请重新 mh read")
            act, frm, to = self._action_for(it)
            if not act:
                raise ValueError("当前状态（%s）不允许提交，只有待处理 / 待撤回可提交" %
                                 STATUS_LABEL.get(frm, frm))
            token = "tk-" + hashlib.md5(
                ("%s|%d|%d" % (it["ip"], it["rev"], int(time.time() * 1000))
                 ).encode("utf-8")).hexdigest()[:12]
            plan = {"token": token, "ip": it["ip"], "receipt": _receipt(it),
                    "rev": it["rev"], "action": act, "from": frm, "to": to,
                    "expire": int(time.time()) + STAGE_TTL}
            self._data.setdefault("_staged", {})[token] = plan
            self._save()
        return {"plan": plan,
                "confirm": "%s：%s %s → %s，确认请 mh commit --token %s" %
                           (act, it["ip"], STATUS_LABEL.get(frm, frm),
                            STATUS_LABEL.get(to, to), token)}

    def mh_commit(self, token, summary="", by="agent"):
        """写命令②：确认预备。提交时再次校验 rev —— 读取后若条目被改过
        （用户重新标注 / 又点了待撤回 / 别的 agent 抢先提交），旧回执一律拒绝，
        不会把过时指令误标成已完成（乐观锁防串台）。"""
        with self._lock:
            self._prune_staged()
            plan = (self._data.get("_staged") or {}).get(str(token or ""))
            if not plan:
                raise ValueError("预备不存在或已过期，请重新 mh prepare")
            it = self._find(plan["ip"])
            if not it:
                raise ValueError("条目已不存在，提交取消")
            if it.get("rev") != plan["rev"] or it.get("status") != plan["from"]:
                raise ValueError("旧回执被拒：条目在读取后被改动，请重新 mh read 再提交（防串台）")
            act, to = plan["action"], plan["to"]
            frm = plan["from"]
            it["status"] = to
            clean_sum = _clean(summary, MAX_SUMMARY)
            it["summary"] = clean_sum
            if to == "done":
                it["done_at"] = int(time.time())
            elif to == "restored":
                it["restored_at"] = int(time.time())
            self._touch(it, act, frm, to, by, clean_sum)
            self._data["_staged"].pop(str(token), None)
            self._save()
            out = _public(it)
        return {"ok": True, "item": out, "receipt": out["receipt"],
                "action": act, "from": frm, "to": to,
                "confirm": "已确认：%s %s → %s（rev %d）" %
                           (out["ip"], STATUS_LABEL.get(frm, frm),
                            STATUS_LABEL.get(to, to), out["rev"])}

    def mh_discard(self, token):
        """写命令③：丢弃一份预备，不改条目状态。"""
        with self._lock:
            self._prune_staged()
            ex = (self._data.get("_staged") or {}).pop(str(token or ""), None)
            self._save()
        return {"ok": True, "discarded": bool(ex)}

    def mh_write(self, payload):
        """mh 写命令统一入口：action 白名单，只改提交单，不碰用户页面 / 任何其它文件。"""
        if not isinstance(payload, dict):
            raise ValueError("请求体必须是 JSON 对象")
        act = str(payload.get("action") or "").strip()
        if act == "prepare":
            return self.mh_prepare(payload.get("receipt"), payload.get("by") or "agent")
        if act == "commit":
            return self.mh_commit(payload.get("token"), payload.get("summary", ""),
                                  payload.get("by") or "agent")
        if act == "discard":
            return self.mh_discard(payload.get("token"))
        raise ValueError("未知 mh 写操作：%s（只允许 prepare / commit / discard）" % act)
