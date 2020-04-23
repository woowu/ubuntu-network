#!/bin/bash

if [ $# != 1 ]; then
    echo No interface name
    exit 1
fi

nif=$1

rt=`ip route show | grep "default via .* dev $nif"`

if [ ! -n "$rt" ]; then
    echo "default route for $nif not found"
    exit 1
fi

add_script=$nif.add.default
del_script=$nif.del.default

echo "#!/bin/bash" > ${add_script}
echo "ip route add ${rt}" >> ${add_script}
chmod a+x ${add_script}

echo "#!/bin/bash" > ${del_script}
echo "ip route del ${rt}" >> ${del_script}
chmod a+x ${del_script}

ip route del ${rt}
echo saved scripts in ${add_script} ${del_script}
