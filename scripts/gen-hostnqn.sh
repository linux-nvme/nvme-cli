#!/bin/bash

LC_ALL=C

if [ -e "/proc/device-tree/ibm,partition-uuid" ] ; then
	UUID=$(tr -d '\0' < /proc/device-tree/ibm,partition-uuid)
else
	UUID=$(dmidecode -s system-uuid | tr -d '[:space:]')
fi

if [ -z "$UUID" ] ; then
	>&2 echo "No UUID found, can't determine hostnqn."
	exit 1
fi

# convert UUID to lower-case only:
UUID=$(echo $UUID | tr '[:upper:]' '[:lower:]')

# check UUID format, e.g.: 4c4c4544-0156-4a10-8134-b7d04f383232, so: 8-4-4-4-12
if ! [[ $UUID =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] ; then
	>&2 echo "UUID has invalid format."
	>&2 echo "Invalid UUID: ${UUID}"
	exit 2
fi

HOSTNQN="nqn.2014-08.org.nvmexpress:uuid:${UUID}"

echo $HOSTNQN
