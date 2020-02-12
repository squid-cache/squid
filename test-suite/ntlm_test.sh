#!/bin/sh
#
## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

while read request; do
case $request in
*SLEEP=*)
	sleep `echo $request | sed -e 's/.*SLEEP=\([^;]*\).*/\1/'`
	request=`echo $request | sed -e 's/SLEEP=[^;]*;*//'`
	;;
esac
data="`echo $request | cut -c4-`"
blob="$$.$data-$challenge.`date +%s`"
case $request in

??" USER="*)
	echo "AF `echo $request|cut -d= -f2-`"
	;;

??" BAD"*)
	echo "BH `echo $request|cut -c7-`"
	;;

??" ERR"*)
	echo "NA `echo $request|cut -c7-`"
	;;

"YR"*)
	challenge="$data.`date +%s`"
	echo "TT Challenge-$$.$challenge"
	;;

"KK"*)
	echo "TT Negotiate-$$.$data-$challenge.`date +%s`"
	;;
*)
	echo "BH Invalid request"
	;;
esac
done
