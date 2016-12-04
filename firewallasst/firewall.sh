#!/bin/bash -

MY_NETWORK="a.b.c.0/24"

# Replace the ip address here with the ip address for your computer. You can use the programs "/sbin/ifconfig", or "/sbin/ip addr show". 
MY_HOST="a.b.c.XX" 

# Network interfaces
IN=em1
OUT=em1

# Path to iptables, "/sbin/iptables"
IPTABLES="sudo /sbin/iptables"



########################
### DON'T TOUCH THIS ###
########################
# Explanation: Changing these rules may freeze your machine, because the nfs connection to your home directory will be lost.

# Flushing all chains and setting default policy
$IPTABLES -P INPUT ACCEPT
$IPTABLES -P FORWARD ACCEPT
$IPTABLES -P OUTPUT ACCEPT
$IPTABLES -F

# delete chain CTH if it exists
$IPTABLES -L CTH &>/dev/null
if [ $? -eq 0 ]; then
    $IPTABLES -X CTH
fi

# Make sure NFS works (allow traffic to ), or your machine may hang until restarted
$IPTABLES -N CTH
$IPTABLES -A CTH -s 129.16.226.60 -m state --state ESTABLISHED,RELATED -m comment --comment "NFS server" -j ACCEPT
$IPTABLES -A CTH -s 129.16.20.0/22 -m comment --comment "Ignore CSE networks (including rooms 4220/4225)" -j RETURN
$IPTABLES -A CTH -m state --state ESTABLISHED,RELATED -m comment --comment "Allow the rest to Chalmers" -j ACCEPT

$IPTABLES -A INPUT -i $IN -s 129.16.0.0/16 -m comment --comment "Allow NFS traffic" -j CTH
$IPTABLES -A OUTPUT -o $OUT -d 129.16.0.0/16 -j ACCEPT

# reset counters to zero
$IPTABLES -Z

##################
### START HERE ###
##################

# Kill malformed packets (example rules)
$IPTABLES -A INPUT -p tcp --tcp-flags FIN,PSH,URG FIN,PSH,URG -m comment --comment "Block XMAS packets" -j DROP
$IPTABLES -A INPUT -p tcp --tcp-flags ALL NONE -m comment --comment "Block NULL packets" -j DROP

#prevent spoofing packets from outside network.
$IPTABLES -A INPUT -i em1 -s 10.0.0.0/8 -j DROP
$IPTABLES -A INPUT -i em1 -s 172.16.0.0/12 -j DROP
$IPTABLES -A INPUT -i em1 -s 192.168.0.0/16 -j DROP
$IPTABLES -A INPUT -i em1 -s 169.254.0.0/16 -j DROP

#prevent spoofing packets from inside network.
$IPTABLES -A OUTPUT -o em1 -s 10.0.0.0/8 -j DROP
$IPTABLES -A OUTPUT -o em1 -s 172.16.0.0/12 -j DROP
$IPTABLES -A OUTPUT -o em1 -s 192.168.0.0/16 -j DROP
$IPTABLES -A OUTPUT -o em1 -s 169.254.0.0/16 -j DROP

#Activating ping and adding some protection from ping-flooding
$IPTABLES -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
$IPTABLES -A INPUT -p icmp --icmp-type echo-request -j DROP

#Allow all traffic from the loopback 
$IPTABLES -A INPUT -i lo -j ACCEPT
$IPTABLES -A OUTPUT -o lo -j ACCEPT

#Allow traffic from my host
$IPTABLES -A OUTPUT -o em1 -j ACCEPT

#stateful inspection
$IPTABLES -A INPUT -i em1 -m state --state ESTABLISHED -j ACCEPT
$IPTABLES -A INPUT -i em1 -m state --state RELATED -j ACCEPT


#Accepted services
$IPTABLES -A INPUT -i em1 -m state --state NEW -p tcp --dport 22 --syn -j ACCEPT
$IPTABLES -A INPUT -i em1 -m state --state NEW -p tcp --dport 8080 --syn  -j ACCEPT
$IPTABLES -A INPUT -i em1 -m state --state NEW -p tcp --dport 111 --syn -j ACCEPT
$IPTABLES -A INPUT -i em1 -m state --state NEW -p udp --dport 111 -j ACCEPT

#Logging all other packets
$IPTABLES -A INPUT -i em1  -p tcp -j LOG
$IPTABLES -A INPUT -i em1  -p udp -j LOG
$IPTABLES -A INPUT -i em1  -p icmp -j LOG

#Default Policy
$IPTABLES -P INPUT DROP
$IPTABLES -P OUTPUT DROP
$IPTABLES -P FORWARD DROP


echo "Done!"
