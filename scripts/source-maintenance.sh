#!/bin/sh
#
## Copyright (C) 1996-2014 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

#
# This script contains the code run to perform automatic source maintenance
# on Squid
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
	MD5="md5"
else
	MD5="md5sum"
fi

ROOT=`bzr root`

ASVER=`astyle --version 2>&1 | grep -o -E "[0-9.]+"`
if test "${ASVER}" != "2.04" ; then
	echo "Astyle version problem. You have ${ASVER} instead of 2.04"
	ASVER=""
else
	echo "Found astyle ${ASVER}. Formatting..."
fi

COPYRIGHT_YEARS=`date +"1996-%Y"`
echo "s/1996-2[0-9]+ The Squid Software Foundation and contributors/${COPYRIGHT_YEARS} The Squid Software Foundation and contributors/g" >>${ROOT}/boilerplate_fix.sed

srcformat ()
{
PWD=`pwd`
#echo "FORMAT: ${PWD}..."

#
# Scan for incorrect use of #ifdef/#ifndef
#
bzr grep --no-recursive "ifn?def .*_SQUID_" |
    grep -v -E "_H$" |
    while read f; do echo "PROBLEM?: ${PWD} ${f}"; done

#
# Scan for file-specific actions
#
for FILENAME in `bzr ls --versioned`; do
    skip_copyright_check=""

    case ${FILENAME} in

    *.h|*.c|*.cc|*.cci)

	#
	# Code Style formatting maintenance
	#
        if test "${ASVER}"; then
		${ROOT}/scripts/formater.pl ${FILENAME}
		if test -e $FILENAME -a -e "$FILENAME.astylebak"; then
			md51=`cat  $FILENAME| tr -d "\n \t\r" | $MD5`;
			md52=`cat  $FILENAME.astylebak| tr -d "\n \t\r" | $MD5`;

			if test "$md51" != "$md52"; then
				echo "ERROR: File $PWD/$FILENAME not formating well";
				mv $FILENAME $FILENAME.astylebad
				mv $FILENAME.astylebak $FILENAME
				bzr revert ${FILENAME}
			else
				rm -f $FILENAME.astylebak
			fi
        	fi
	fi

	${ROOT}/scripts/sort-includes.pl ${FILENAME} >${FILENAME}.sorted
	if test -e ${FILENAME} -a -e "${FILENAME}.sorted"; then
		md51=`cat  ${FILENAME}| tr -d "\n \t\r" | $MD5`;
		md52=`cat  ${FILENAME}.sorted| tr -d "\n \t\r" | $MD5`;

		if test "$md51" != "$md52" ; then
			echo "NOTICE: File $PWD/${FILENAME} changed #include order"
		fi
		mv ${FILENAME}.sorted ${FILENAME}
	fi

	#
	# REQUIRE squid.h first #include
	#
	case ${FILENAME} in
	*.c|*.cc)
		FI=`grep "#include" ${FILENAME} | head -1`;
		if test "${FI}" != "#include \"squid.h\"" -a "${FILENAME}" != "cf_gen.cc"; then
			echo "ERROR: ${PWD}/${FILENAME} does not include squid.h first!"
		fi
		;;
	*.h|*.cci)
		FI=`grep "#include \"squid.h\"" ${FILENAME}`;
		if test "x${FI}" != "x" ; then
			echo "ERROR: ${PWD}/${FILENAME} duplicate include of squid.h"
		fi
		;;
	esac

	#
	# forward.h means different things to Squid code depending on the path
	# require the full path is explicit for every include
	#
	FI=`grep "#include \"forward.h\"" ${FILENAME}`;
	if test "x${FI}" != "x" ; then
		echo "ERROR: ${PWD}/${FILENAME} contains reference to forward.h without path"
	fi

	#
	# detect functions unsafe for use within Squid.
	# strdup() - only allowed in compat/xstring.h which defines a safe replacement.
	# sprintf() - not allowed anywhere.
	#
	STRDUP=`grep -e "[^x]strdup(" ${FILENAME}`;
	if test "x${STRDUP}" != "x" -a "${FILENAME}" != "xstring.h"; then
		echo "ERROR: ${PWD}/${FILENAME} contains unprotected use of strdup()"
	fi
	SPRINTF=`grep -e "[^v]sprintf(" ${FILENAME}`;
	if test "x${SPRINTF}" != "x" ; then
		echo "ERROR: ${PWD}/${FILENAME} contains unsafe use of sprintf()"
	fi

	#
	# DEBUG Section list maintenance
	#
	grep " DEBUG: section" <${FILENAME} | sed -e 's/ \* DEBUG: //' -e 's%/\* DEBUG: %%' -e 's% \*/%%' | sort -u >>${ROOT}/doc/debug-sections.tmp

	#
	# File permissions maintenance.
	#
	chmod 644 ${FILENAME}
	;;

    *.pl|*.sh)
	#
	# File permissions maintenance.
	#
	chmod 755 ${FILENAME}
	;;

    Makefile.am)

    	perl -p -e 's/@([A-Z0-9_]+)@/\$($1)/g' <${FILENAME} >${FILENAME}.styled
	mv ${FILENAME}.styled ${FILENAME}
	;;

    */ChangeLog|*.list|*.png|*.po|*.pot|*.txt|*test-suite/squidconf/empty)
        # we do not enforce copyright blurbs in:
        #
        #  images,
        #  translation PO/POT
        #  auto-generated .list files,
        #  (imported) plain-text documentation files and ChangeLogs
        #
        skip_copyright_check=1
        ;;
    esac

    # check for Foundation copyright blurb
    if test -f ${PWD}/${FILENAME} -a "x$skip_copyright_check" = "x"; then
        BLURB=`grep -o "${COPYRIGHT_YEARS} The Squid Software Foundation and contributors" ${FILENAME}`;
        if test "x${BLURB}" = "x"; then
            BOILER=`grep -o -E "1996-2[0-9]+ The Squid Software Foundation and contributors" ${FILENAME}`;
            if test "x${BOILER}" != "x"; then
                echo "UPDATE COPYRIGHT for ${PWD}/${FILENAME}"
                sed --in-place -r -f ${ROOT}/boilerplate_fix.sed ${FILENAME}
            else
                echo "CHECK COPYRIGHT for ${PWD}/${FILENAME}"
            fi
        fi
    fi

    if test "$FILENAME" = "libltdl/" ; then
        :
    elif test -d $FILENAME ; then
	cd $FILENAME
	srcformat ${ROOT} || exit 1
	cd ..
    fi

done
}

# Build XPROF types file from current sources
(
cat scripts/boilerplate.h
echo "#ifndef _PROFILER_XPROF_TYPE_H_"
echo "#define _PROFILER_XPROF_TYPE_H_"
echo "/* AUTO-GENERATED FILE */"
echo "#if USE_XPROF_STATS"
echo "typedef enum {"
echo "  XPROF_PROF_UNACCOUNTED,"
grep -R -h "PROF_start.*" ./* | grep -v probename | sed -e 's/ //g; s/PROF_start(/XPROF_/; s/);/,/' | sort -u
echo "  XPROF_LAST } xprof_type;"
echo "#endif"
echo "#endif"
) >${ROOT}/lib/profiler/list
mv ${ROOT}/lib/profiler/list ${ROOT}/lib/profiler/xprof_type.h

# Build icons install include from current icons available
(
sed -e 's%\ \*%##%' -e 's%/\*%##%' -e 's%##/%##%' <scripts/boilerplate.h
echo -n "ICONS="
for f in `ls -1 ${ROOT}/icons/silk/* | sort -u`
do
	echo " \\"
	echo -n "    ${f}"
done
echo " "
)| sed s%${ROOT}/icons/%%g >${ROOT}/icons/icon.list

# Build templates install include from current templates available
(
sed -e 's%\ \*%##%' -e 's%/\*%##%' -e 's%##/%##%' <scripts/boilerplate.h
echo -n "ERROR_TEMPLATES="
for f in `ls -1 ${ROOT}/errors/templates/ERR_* | sort -u`
do
	echo " \\"
	echo -n "    ${f}"
done
echo " "
)| sed s%${ROOT}/errors/%%g >${ROOT}/errors/template.list

# Build errors translation install include from current .PO available
(
sed -e 's%\ \*%##%' -e 's%/\*%##%' -e 's%##/%##%' <scripts/boilerplate.h
echo -n "TRANSLATE_LANGUAGES="
for f in `ls -1 ${ROOT}/errors/*.po | sort -u`
do
	echo " \\"
	echo -n "    ${f}"
done
echo " "
)| sed s%${ROOT}/errors/%%g | sed s%\.po%\.lang%g >${ROOT}/errors/language.list

# Build manuals translation install include from current .PO available
(
sed -e 's%\ \*%##%' -e 's%/\*%##%' -e 's%##/%##%' <scripts/boilerplate.h
echo -n "TRANSLATE_LANGUAGES="
for f in `ls -1 ${ROOT}/doc/manuals/*.po | sort -u`
do
	echo " \\"
	echo -n "    ${f}"
done
echo " "
)| sed s%${ROOT}/doc/manuals/%%g | sed s%\.po%\.lang%g >${ROOT}/doc/manuals/language.list

# Build STUB framework include from current stub_* available
(
sed -e 's%\ \*%##%' -e 's%/\*%##%' -e 's%##/%##%' <scripts/boilerplate.h
echo -n "STUB_SOURCE= tests/STUB.h"
for f in `ls -1 ${ROOT}/src/tests/stub_*.cc | sort -u`
do
	echo " \\"
	echo -n "	${f}"
done
echo " "
)| sed s%${ROOT}/src/%%g >${ROOT}/src/tests/Stub.list

# Run formating
echo "" >${ROOT}/doc/debug-sections.tmp
srcformat || exit 1
sort -u <${ROOT}/doc/debug-sections.tmp | sort -n >${ROOT}/doc/debug-sections.tmp2
cat scripts/boilerplate.h ${ROOT}/doc/debug-sections.tmp2 >${ROOT}/doc/debug-sections.txt
rm ${ROOT}/doc/debug-sections.tmp ${ROOT}/doc/debug-sections.tmp2
rm ${ROOT}/boilerplate_fix.sed
