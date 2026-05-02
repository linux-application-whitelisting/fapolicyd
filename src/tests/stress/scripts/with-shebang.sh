#!/bin/sh

data=${1:?missing data path}
i=0

while [ "$i" -lt 4 ]; do
	cat "$data" >/dev/null || exit 1
	i=$((i + 1))
done

exit 0
