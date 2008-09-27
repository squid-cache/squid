#!/bin/bash
# A checker


for FILENAME in $*; do

    if test -e $FILENAME -a -e "$FILENAME.astylebak"; then
	md51=`cat  $FILENAME| tr -d "\n \t\r" | md5sum|sed 's/  -//'`;
	md52=`cat  $FILENAME.astylebak| tr -d "\n \t\r" | md5sum|sed 's/  -//'`;
	
	if test $md51 != $md52; then
	    echo "File $FILENAME not converted well";
	fi
    else
	echo "can not check file: $FILENAME";
    fi

done





