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

echo "Done!"
