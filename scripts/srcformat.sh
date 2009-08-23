#!/bin/sh
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

ROOT=`bzr root`
PWD=`pwd`
for FILENAME in `ls -1`; do

    case ${FILENAME} in

    *.h|*.c|*.cc|*.cci)

	${ROOT}/scripts/formater.pl ${FILENAME}

	if test -e $FILENAME -a -e "$FILENAME.astylebak"; then
		md51=`cat  $FILENAME| tr -d "\n \t\r" | $MD5`;
		md52=`cat  $FILENAME.astylebak| tr -d "\n \t\r" | $MD5`;

		if test "$md51" != "$md52" ; then
			echo "ERROR: File $PWD/$FILENAME not formating well";
			mv $FILENAME $FILENAME.astylebad
			mv $FILENAME.astylebak $FILENAME
		else
			rm $FILENAME.astylebak
		fi
		continue;
        fi
    esac

    if test -d $FILENAME ; then
	cd $FILENAME
	$ROOT/scripts/srcformat.sh || exit 1
	cd ..
    fi

done
