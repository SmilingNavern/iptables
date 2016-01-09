# iptables
Iptables management script. 
Replaces iptables-save/iptables-restore.

Script is intended to use with configuration management systems(ansible and etc.).

It uses base file /etc/iptables to base confguration distrubition.
You can save persistent custom rules for one server in /etc/iptables.d directory(with extension ".ipt")
and have temporary rules(for example docker rules).
You can reapply iptables rules without losing custom temporary rules.

Powered by LTD BeGet.
