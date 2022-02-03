#!/bin/bash

file=$1

for func in $(sed -n 's/ \* \([a-z_]*\)() -.*/\1/p' $file); do
	echo ${func}
done

for struct in $(sed -n 's/ \* struct \([a-z_]*\) -.*/\1/p' $file); do
	echo ${struct}
done

for enum in $(sed -n 's/ \* enum \([a-z_]*\) -.*/\1/p' $file); do
	echo ${enum}
done
