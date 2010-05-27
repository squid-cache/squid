#!/bin/sh
#
# This script contains the code run to perform automatic source maintenance
#

## Source Code Format Enforcement
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

srcformat ()
{
PWD=`pwd`
echo "FORMAT: ${PWD}..."

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
			rm -f $FILENAME.astylebak
		fi
		continue
        fi
	;;

    Makefile.am)

    	perl -i -p -e 's/@([A-Z0-9_]+)@/\$($1)/g' <${FILENAME} >${FILENAME}.styled
	mv ${FILENAME}.styled ${FILENAME}
	;;

    esac

    if test -d $FILENAME ; then
	cd $FILENAME
	srcformat || exit 1
	cd ..
    fi

done
}

srcformat || exit 1

#
#  DEBUG Section listing maintenance
#
cat ${ROOT}/{compat,src,lib,include}/*{.,/*.,/*/*.,/*/*/*.}{h,c,cc,cci} 2>/dev/null \
	| grep " DEBUG:" \
	| sed -e 's/ \* DEBUG: //' \
	| sort -u \
	| sort -n >${ROOT}/doc/debug-sections.txt
