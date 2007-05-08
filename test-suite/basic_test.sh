#!/bin/sh
while read user password; do
case $password in
UNKNOWN)
	echo "ERR Unknown User"
	;;
OK*)	echo "OK"
	;;
*)	echo "ERR Incorrect Login"
	;;
esac
done
