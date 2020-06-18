#!/bin/bash
#
# Delte current default route entries and insert a new one given from
# command line.

if [ $# != 2 ]; then
    echo gw ip dev
    exit 1
fi

gw_ip=$1
dev=$2

ip route show | grep default |
    while IFS= read -r line; do
        ip route del $line
    done

ip route add default via $gw_ip dev $dev
