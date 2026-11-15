#!/bin/bash
# 端口敲门数据源 · 只读诊断（默认不修改任何防火墙规则）
#
# 设计原则：这是「预留数据源」。安装应用不会动系统 nftables / iptables，
# 避免影响飞牛自身的网络策略。启用需使用者明确决定，步骤如下：
#   1) 在路由器把敲门端口序列（例如 7000,8000,9000）转发到本机；
#   2) 在宿主以 root 添加一条只记录日志的 nft 规则，日志前缀必须是 IPSENSE-KNOCK：
#        nft add table inet ipsense
#        nft add chain inet ipsense knocks { type filter hook prerouting priority -150 \; }
#        nft add rule inet ipsense knocks tcp dport { 7000, 8000, 9000 } \
#            log prefix "IPSENSE-KNOCK " flags tcp sequence
#      （该规则只 log，不 drop、不 accept，不改变转发行为）
#   3) touch /etc/ipsense/knock.enabled，并在应用「设置」里打开「端口敲门 · 内核日志」；
#   4) 应用会 tail /var/log/kern.log，把带 IPSENSE-KNOCK 且含 SRC= / DPT= 的行记为敲门事件。
#   回滚：nft delete table inet ipsense

set -u
echo "=== IP 动态感知 · 端口敲门状态 ==="
echo -n "内核日志: "; [ -r /var/log/kern.log ] && echo "可读" || echo "不可读（需 root）"
echo -n "标记文件: "; [ -f /etc/ipsense/knock.enabled ] && echo "已启用" || echo "未安装 / 未启用"
echo -n "nft 表:   "
if command -v nft >/dev/null 2>&1; then
    if nft list tables 2>/dev/null | grep -q 'inet ipsense'; then echo "inet ipsense 存在"; else echo "未创建"; fi
else
    echo "nft 不可用"
fi
echo -n "最近敲门记录: "
grep -ac "IPSENSE-KNOCK" /var/log/kern.log 2>/dev/null || echo 0
echo "本脚本只读，不会修改防火墙。完整启用步骤见上方注释或应用文档。"
exit 0
