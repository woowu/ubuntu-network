#!/bin/bash
#
# Delete current default route entries and insert a new one given from
# command line.

if [ $# -eq 1 ]; then
    case $1 in
        --list)
            echo honlan
            echo iphone
            echo jike
            exit 0
            ;;
        honlan)
            gw_ip=159.99.248.1
            ;;
        iphone)
            gw_ip=172.20.10.1
            ;;
        jike)
            gw_ip=192.168.1.1
            ;;
        *)
            echo unknown alias
            exit 1
            ;;
    esac
else
    echo gw gw-alias
    exit 1
fi

ip route show | grep default |
    while IFS= read -r line; do
        ip route del $line
    done

ip route add default via $gw_ip
