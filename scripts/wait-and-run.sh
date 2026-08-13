#!/bin/sh
while [ ! -e /sys/class/net/eth1 ]; do
  sleep 1
done
exec /docker-entrypoint.sh -i eth1 -vv
