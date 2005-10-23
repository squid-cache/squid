#!/bin/sh
while read request; do
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
