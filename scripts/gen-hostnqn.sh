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

# HEURISTIC:
# (1) if any one given character occurs more than 50% of the time, it is likely
# that the UUID is fake.
# (2) if the first or the last group consists of mostly the same character, it
# is likely that the UUID is fake.
FIRST_GROUP="$(echo $UUID | cut -d'-' -f1)"
LAST_GROUP="$(echo $UUID | cut -d'-' -f5)"
for i in {{0..9},{a..f}} ; do
	COUNT_TOTAL="${UUID//[^$i]}"
	COUNT_FIRST="${FIRST_GROUP//[^$i]}"
	COUNT_LAST="${LAST_GROUP//[^$i]}"
	if [ ${#COUNT_TOTAL} -ge 16 ] || [ ${#COUNT_FIRST} -ge 7 ] || [ ${#COUNT_LAST} -ge 11 ] ; then
		>&2 echo "UUID is too repetitive. This may be a false alert."
		>&2 echo "Repetitive UUID: ${UUID}"
		exit 3
	fi
done

HOSTNQN="nqn.2014-08.org.nvmexpress:uuid:${UUID}"

echo $HOSTNQN
