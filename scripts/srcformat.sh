#!/usr/local/bin/bash
#
# A checker to recursively reformat all source files: .h .c .cc .cci
# using a custom astyle formatter and to use MD5 to validate that
# the formatter has not altered the code syntax.
#
# If code alteration takes place the process is halted for manual intervention.
#

# On squid-cache.org we have to use the python scripted md5sum
HOST=`hostname`
if test "$HOST" = "squid-cache.org" ; then
	MD5="python /usr/local/share/python2.4/Tools/scripts/md5sum.py -"
else
	MD5="md5sum"
fi

ROOT="$1"
PWD=`pwd`
for FILENAME in `ls -1`; do

    if    test "${FILENAME: -2:2}" = ".h" \
       || test "${FILENAME: -2:2}" = ".c" \
       || test "${FILENAME: -3:3}" = ".cc" \
       || test "${FILENAME: -4:4}" = ".cci" \
    ; then
	${ROOT}/scripts/formater.pl ${FILENAME}

	if test -e $FILENAME -a -e "$FILENAME.astylebak"; then
		md51=`cat  $FILENAME| tr -d "\n \t\r" | $MD5 | sed 's/  -//'`;
		md52=`cat  $FILENAME.astylebak| tr -d "\n \t\r" | $MD5 | sed 's/  -//'`;

		if test "$md51" != "$md52" ; then
			echo "File $PWD/$FILENAME not converted well";
			exit 1;
		fi
		rm $FILENAME.astylebak
		continue;
        fi
    fi

    if test -d $FILENAME ; then
	cd $FILENAME
	$ROOT/scripts/srcformat.sh "$ROOT"  || exit 1
	cd ..
    fi

done
