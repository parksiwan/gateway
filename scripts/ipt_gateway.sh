#!/bin/sh
IPT="/sbin/iptables"
MOD="/sbin/modprobe"
INT_NET="10.0.0.0/24"
OUT_NET="192.168.1.0/24"

$IPT -F
$IPT -F -t nat
$IPT -X
$IPT -P INPUT ACCEPT
$IPT -P OUTPUT ACCEPT
$IPT -P FORWARD ACCEPT
#$IPT -P PREROUTING ACCEPT
#$IPT -P POSTROUTING ACCEPT

$MOD ip_conntrack
$MOD iptable_nat
$MOD ip_conntrack_ftp
$MOD ip_nat_ftp

$IPT -A INPUT -i lo -j ACCEPT
$IPT -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
$IPT -A INPUT -i eth0 -j ACCEPT
$IPT -A INPUT -i eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
$IPT -A INPUT -d 255.255.255.255/32 -i eth1 -j ACCEPT
$IPT -A INPUT -i eth1 -p tcp -m tcp --dport 20 -j ACCEPT
$IPT -A INPUT -i eth1 -p tcp -m tcp --dport 21 -j ACCEPT
$IPT -A INPUT -i eth1 -p tcp -m tcp --dport 22 -j ACCEPT
$IPT -A INPUT -i eth1 -p tcp -m tcp --dport 80 -j ACCEPT
$IPT -A INPUT -i eth1 -p tcp -m tcp --sport 80 -j ACCEPT
$IPT -A INPUT -i eth1 -p tcp -m tcp --sport 3129 -j ACCEPT

$IPT -A FORWARD -p udp -m udp --dport 53 -j ACCEPT
$IPT -A FORWARD -p udp -m udp --dport 123 -j ACCEPT
$IPT -A FORWARD -p udp -m udp --dport 123 -j ACCEPT
$IPT -A FORWARD -p udp -m udp --dport 443 -j ACCEPT
$IPT -A FORWARD -p udp -m udp --sport 443 -j ACCEPT
$IPT -A FORWARD -s $INT_NET -j ACCEPT
$IPT -A FORWARD -i lo -j ACCEPT
$IPT -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
#$IPT -A FORWARD -j firewalled
#$IPT -A firewalled -j DROP

$IPT -A OUTPUT -p tcp -m tcp --dport 3129 -j ACCEPT
$IPT -A OUTPUT -p tcp -m tcp --dport 8081 -j ACCEPT

$IPT -t nat -A PREROUTING -d 10.0.0.1/255.255.255.255 -p tcp -m tcp --dport 80 -j ACCEPT
$IPT -t nat -A PREROUTING -s $INT_NET -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 3129
#$IPT -t nat -A PREROUTING -s $INT_NET -p tcp -m tcp --dport 443 -j REDIRECT --to-ports 3130
#$IPT -t nat -A PREROUTING -s $INT_NET -p tcp -m tcp --dport 8080 -j REDIRECT --to-ports 3128
#$IPT -t nat -A PREROUTING -s $INT_NET -p tcp -m tcp --dport 3128 -j REDIRECT --to-ports 3128

$IPT -t nat -A POSTROUTING -s $INT_NET -o eth1 -j SNAT --to-source 192.168.1.16
#$IPT -t nat -A POSTROUTING -s $INT_NET -o eth1 -j SNAT --to-source 172.16.7.41



