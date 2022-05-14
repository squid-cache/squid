#!/bin/sh
#
## Copyright (C) 1996-2021 The Squid Software Foundation and contributors
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
# using a custom astyle formatter and to use md5sum (or similar) to validate
# that the formatter has not altered the code syntax.
#
# If code alteration takes place the process is halted for manual intervention.
#

# TODO: Expand the subset of failures covered by this feature; see run_().
KeepGoing="no"
# the actual name of the directive that enabled keep-going mode
KeepGoingDirective=""

# the version of astyle tool required by Squid coding style
TargetAstyleVersion="3.1"

# whether to check and, if necessary, update boilerplate copyright years
CheckAndUpdateCopyright=yes

printUsage () {
cat <<_EOF
Usage: $0 [option...]
options:
    --keep-going|-k                            (default: stop on error)
    --check-and-update-copyright <yes|no>      (default: no)
    --with-astyle </path/to/astyle/executable> (default: astyle)
    --only-changed-since <fork|commit-id>      (default: apply to all files)

This script applies Squid mandatory code style guidelines.

It requires astyle version $TargetAstyleVersion, or it will skip formatting
program files. The path to the astyle binary can be specified using the
--with-astyle option or with the ASTYLE environment variable.

It will try to auto-detect a checksum program (e.g. md5sum).

If the --only-changed-since argument is supplied, it expects a git commit-id,
branch name or the special keyword 'fork'. The script will try identifying
changed files since the specified commit and, if successful, only examine
files that have changed. The keyword 'fork' will look for files changed
since the current branch was forked off 'upstream/master'. Sensible values
for this argument may include HEAD^, master, origin/master, or the branch
the current one was forked off
_EOF
}

# command-line options
OnlyChangedSince=""
while [ $# -ge 1 ]; do
    case "$1" in
    --keep-going|-k)
        KeepGoing=yes
        KeepGoingDirective=$1
        shift
        ;;
    --check-and-update-copyright)
        if test "x$2" != xyes -a "x$2" != xno
        then
            printUsage
            echo "Error: Option $1 expects a yes or no argument but got $2"
            exit 1;
        fi
        CheckAndUpdateCopyright=$2
        shift 2
        ;;
    --help|-h)
        printUsage
        exit 0;
        ;;
    --with-astyle)
        ASTYLE=$2
        shift 2
        ;;
    --only-changed-since)
        OnlyChangedSince="$2"
        shift 2
        ;;
    *)
        printUsage
        echo "Unsupported command-line option: $1"
        exit 1;
        ;;
    esac
done

# an error code seen by a KeepGoing-aware command (or zero)
SeenErrors=0

if ! git diff --quiet; then
	echo "There are unstaged changes. This script may modify sources."
	echo "Stage changes to avoid permanent losses when things go bad."
	exit 1
fi

for Checksum in md5sum md5 shasum sha1sum
do
    if "$Checksum" </dev/null >/dev/null 2>/dev/null ; then
        break
    fi
done
echo "detected checksum program $Checksum"

if [ "x$ASTYLE" != "x" ] ; then
    if ${ASTYLE} --version >/dev/null 2>/dev/null ; then
        :
    else
        echo "ERROR: cannot run user-supplied astyle ${ASTYLE}"
    fi
else
    for AttemptedBinary in astyle-${TargetAstyleVersion} astyle
    do
        if $AttemptedBinary --version >/dev/null 2>/dev/null ; then
            ASTYLE=$AttemptedBinary
            echo "detected astyle program ${ASTYLE}"
            break
        fi
    done
fi

ASVER=`${ASTYLE} --version 2>&1 | grep -o -E "[0-9.]+"`
if test "${ASVER}" != "${TargetAstyleVersion}" ; then
	if test "${ASTYLE}" = "astyle" ; then
		echo "Astyle version problem. You have ${ASVER} instead of ${TargetAstyleVersion}"
		echo "Formatting step skipped due to version mismatch"
		ASVER=""
	else
		echo "WARNING: ${ASTYLE} is version ${ASVER} instead of ${TargetAstyleVersion}"
		echo "Formatting anyway, please double check output before submitting"
	fi
else
	echo "Found astyle ${ASVER}"
fi

if test $CheckAndUpdateCopyright = yes
then
    COPYRIGHT_YEARS=`date +"1996-%Y"`
    echo "s/1996-2[0-9]+ The Squid Software Foundation and contributors/${COPYRIGHT_YEARS} The Squid Software Foundation and contributors/g" >> boilerplate_fix.sed
fi

# executes the specified command
# in KeepGoing mode, remembers errors and hides them from callers
run_ ()
{
        "$@" && return; # return on success
        error=$?

        if test $KeepGoing = no; then
                return $error
        fi

        echo "ERROR: Continuing after a failure ($error) due to $KeepGoingDirective"
        SeenErrors=$error # TODO: Remember the _first_ error instead
        return 0 # hide error from the caller
}

updateIfChanged ()
{
	original="$1"
	updated="$2"
	message="$3"

	if ! cmp -s "${original}" "${updated}"; then
		echo "NOTICE: File ${original} changed: ${message}"
		run_ mv "${updated}" "${original}" || return
	else
		run_ rm -f "${updated}" || exit $?
	fi
}

# uses the given script to update the given source file
applyPlugin ()
{
        script="$1"
        source="$2"

        new="$source.new"
        $script "$source" > "$new" &&
                updateIfChanged "$source" "$new" "by $script"
}

# updates the given source file using the given script(s)
applyPluginsTo ()
{
        source="$1"
        shift

        for script in `git ls-files "$@"`; do
                run_ applyPlugin $script $source || return
        done
}

# succeeds if all MakeNamedErrorDetail() names are unique
checkMakeNamedErrorDetails ()
{
    problems=1 # assume there are problems until proven otherwise

    options='-h --only-matching --extended-regexp'
    git grep $options 'MakeNamedErrorDetail[(]".*?"[)]' src |
        sort |
        uniq --count > \
        MakeNamedErrorDetail.tmp

    if grep --quiet --word-regexp 1 MakeNamedErrorDetail.tmp; then
        if grep --invert-match --word-regexp 1 MakeNamedErrorDetail.tmp; then
            echo "ERROR: Duplicated MakeNamedErrorDetail names (see above)."
        else
            problems=0
        fi
    else
        echo "ERROR: Cannot find or process MakeNamedErrorDetail calls."
    fi

    rm MakeNamedErrorDetail.tmp # ignore (unexpected) cleanup failures
    return $problems
}

# extract IDs and gists of cache_log_message debugs() in the given source file
collectDebugMessagesFrom ()
{
    source="$1"
    destination="doc/debug-messages.tmp"

    # Merge multi-line debugs() into one-liners and remove '//...' comments.
    awk 'BEGIN { found=0; dbgLine=""; } {
        if ($0 ~ /[ \t]debugs[ \t]*\(/)
            found = 1;
        if (found) {
            commented = match($0, /\);[ \t]*\/\//);
            if (commented)
                $0 = substr($0, 1, RSTART+1);
            dbgLine = dbgLine $0;
        }
        if ($0 ~ /\);/) {
            if (found) {
                found = 0;
                print dbgLine;
                dbgLine = "";
            }
        }
    }' $source > doc/debug-messages.tmp2

    # sed expressions:
    # - replace debugs() prefix with the message ID contained in it
    # - remove simple parenthesized non-"string" items like (a ? b : c)
    # - replace any remaining non-"string" items with ...
    # - remove quotes around "strings"
    # - remove excessive whitespace
    # - remove debugs() statement termination sugar
    grep -o -E '\bdebugs[^,]*,\s*(Critical|Important)[(][0-9]+.*' doc/debug-messages.tmp2 | \
        sed -r \
            -e 's/.*?(Critical|Important)[(]([0-9]+)[)],\s*/\2 /' \
            -e 's/<<\s*[(].*[)]\s*(<<|[)];)/<< ... \1/g' \
            -e 's/<<\s*[^"]*/.../g' \
            -e 's@([^\\])"@\1@g' \
            -e 's/\s\s*/ /g' \
            -e 's/[)];$//g' \
        >> $destination

    rm -f doc/debug-messages.tmp2
}

# make doc/debug-messages.dox from aggregate collectDebugMessagesFrom results
processDebugMessages ()
{
    source="doc/debug-messages.tmp"
    destination="doc/debug-messages.dox"

    if test '!' -s "$source"; then
        echo "ERROR: Failed to find debugs() message IDs"
        return 1;
    fi

    repeatedIds=`awk '{print $1}' $source | sort -n | uniq -d`
    if test "x$repeatedIds" != "x"; then
        echo "ERROR: Repeated debugs() message IDs:"
        echo "$repeatedIds"
        echo ""
        return 1;
    fi

    repeatedGists=`awk '{$1=""; print substr($0,2)}' $source | sort | uniq -d`
    if test "x$repeatedGists" != "x"; then
        echo "ERROR: Repeated debugs() message gists:"
        echo "$repeatedGists"
        echo ""
        return 1;
    fi

    cat scripts/boilerplate.h > $destination
    printf '/**\n' >> $destination
    printf '\\page ControlledCacheLogMessages Message IDs and gists for cache_log_message\n' >> $destination
    printf '\\verbatim\n' >> $destination
    printf 'ID Message gist\n' >> $destination
    printf '== ============\n' >> $destination
    sort -n < $source >> $destination
    printf '\\endverbatim\n' >> $destination
    printf '*/\n' >> $destination

    rm -f $source
}

# make doc/debug-sections.txt from aggregated by srcFormat extracts
processDebugSections ()
{
    destination="doc/debug-sections.txt"

    sort -u < doc/debug-sections.tmp | sort -n > doc/debug-sections.tmp2
    cat scripts/boilerplate.h > $destination
    echo "" >> $destination
    cat doc/debug-sections.tmp2 >> $destination

    rm -f doc/debug-sections.tmp*
}

srcFormat ()
{
    # remove stale temporary files that accumulate info extracted below
    rm -f doc/debug-messages.tmp*
    rm -f doc/debug-sections.tmp*

#
# Scan for incorrect use of #ifdef/#ifndef
#
git grep "ifn?def .*_SQUID_" |
    grep -v -E "_H$" |
    grep -v "scripts/source-maintenance.sh" |
    while read f; do echo "PROBLEM?: ${f}"; done

#
# Scan for file-specific actions
#
ForkPoint=""
FilesToOperateOn=""
if test "x$OnlyChangedSince" = "x" ; then
    FilesToOperateOn=`git ls-files`
elif test "x$OnlyChangedSince" = "xfork" ; then
    ForkPoint=`git merge-base --fork-point upstream/master`
    if test "x$ForkPoint" = "x" ; then
        echo "Could not identify fork point - sometimes it happens"
        echo "Please specify commit-id explicitly"
        exit 1
    fi
    OnlyChangedSince="$ForkPoint"
fi
if test "x$FilesToOperateOn" = "x" && test "x$OnlyChangedSince" != "x" ; then
    FilesToOperateOn=`git diff --name-only $OnlyChangedSince`
fi

for FILENAME in $FilesToOperateOn; do
    skip_copyright_check=""

    # skip subdirectories, git ls-files is recursive
    test -d $FILENAME && continue

    case ${FILENAME} in

    *.h|*.c|*.cc|*.cci)

	#
	# Code Style formatting maintenance
	#
	applyPluginsTo ${FILENAME} scripts/maintenance/ || return
	if test "${ASVER}"; then
		./scripts/formater.pl --with-astyle ${ASTYLE} ${FILENAME}
		if test -e $FILENAME -a -e "$FILENAME.astylebak"; then
			md51=`cat  $FILENAME| tr -d "\n \t\r" | $Checksum`;
			md52=`cat  $FILENAME.astylebak| tr -d "\n \t\r" | $Checksum`;

			if test "$md51" != "$md52"; then
				echo "ERROR: File $FILENAME not formatting well";
				mv $FILENAME $FILENAME.astylebad
				mv $FILENAME.astylebak $FILENAME
				git checkout -- ${FILENAME}
			else
				rm -f $FILENAME.astylebak
			fi
        	fi
	fi

	#
	# REQUIRE squid.h first #include
	#
	case ${FILENAME} in
	src/cf_gen.cc)
		# ignore, this is a build tool.
		;;
	*.c|*.cc)
		FI=`grep "#include" ${FILENAME} | head -1`;
		if test "${FI}" != "#include \"squid.h\"" -a "${FILENAME}" != "cf_gen.cc"; then
			echo "ERROR: ${FILENAME} does not include squid.h first!"
		fi
		;;
	*.h|*.cci)
		FI=`grep "#include \"squid.h\"" ${FILENAME}`;
		if test "x${FI}" != "x" ; then
			echo "ERROR: ${FILENAME} duplicate include of squid.h"
		fi
		;;
	esac

	#
	# If a file includes openssl headers, then it must include compat/openssl.h
	#
	if test "${FILENAME}" != "compat/openssl.h"; then
		FA=`grep "#include.*openssl/" "${FILENAME}" 2>/dev/null | head -1`;
		FB=`grep '#include.*compat/openssl[.]h' "${FILENAME}" 2>/dev/null | head -1`;
		if test "x${FA}" != "x" -a "x${FB}" = "x"; then
			echo "ERROR: ${FILENAME} includes openssl headers without including \"compat/openssl.h\""
		fi
	fi

	#
	# forward.h means different things to Squid code depending on the path
	# require the full path is explicit for every include
	#
	FI=`grep "#include \"forward.h\"" ${FILENAME}`;
	if test "x${FI}" != "x" ; then
		echo "ERROR: ${FILENAME} contains reference to forward.h without path"
	fi

	#
	# detect functions unsafe for use within Squid.
	# strdup() - only allowed in compat/xstring.h which defines a safe replacement.
	# sprintf() - not allowed anywhere.
	#
	STRDUP=`grep -e "[^x]strdup(" ${FILENAME}`;
	if test "x${STRDUP}" != "x" -a "${FILENAME}" != "compat/xstring.h"; then
		echo "ERROR: ${FILENAME} contains unprotected use of strdup()"
	fi
	SPRINTF=`grep -e "[^v]sprintf(" ${FILENAME}`;
	if test "x${SPRINTF}" != "x" ; then
		echo "ERROR: ${FILENAME} contains unsafe use of sprintf()"
	fi

	collectDebugMessagesFrom ${FILENAME}

	#
	# DEBUG Section list maintenance
	#
	grep " DEBUG: section" <${FILENAME} | sed -e 's/ \* DEBUG: //' -e 's%/\* DEBUG: %%' -e 's% \*/%%' | sort -u >>doc/debug-sections.tmp

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

    *.am)
		applyPluginsTo ${FILENAME} scripts/format-makefile-am.pl || return
	;;

    ChangeLog|CREDITS|CONTRIBUTORS|COPYING|*.png|*.po|*.pot|rfcs/|*.txt|test-suite/squidconf/empty|.bzrignore)
        # we do not enforce copyright blurbs in:
        #
        #  Squid Project contributor attribution file
        #  third-party copyright attribution file
        #  images,
        #  translation PO/POT
        #  license documentation files
        #  (imported) plain-text documentation files and ChangeLogs
        #  VCS internal files
        #
        skip_copyright_check=1
        ;;
    esac

    # check for Foundation copyright blurb
    if test $CheckAndUpdateCopyright = yes -a -f ${FILENAME} -a "x$skip_copyright_check" = "x"; then
        BLURB=`grep -o "${COPYRIGHT_YEARS} The Squid Software Foundation and contributors" ${FILENAME}`;
        if test "x${BLURB}" = "x"; then
            BOILER=`grep -o -E "1996-2[0-9]+ The Squid Software Foundation and contributors" ${FILENAME}`;
            if test "x${BOILER}" != "x"; then
                echo "UPDATE COPYRIGHT for ${FILENAME}"
                sed --in-place -r -f boilerplate_fix.sed ${FILENAME}
            else
                echo "CHECK COPYRIGHT for ${FILENAME}"
            fi
        fi
    fi

done

    run_ processDebugSections || return
    run_ processDebugMessages || return
}

# Build XPROF types file from current sources
(
cat scripts/boilerplate.h
echo "#ifndef _PROFILER_XPROF_TYPE_H_"
echo "#define _PROFILER_XPROF_TYPE_H_"
echo "/* AUTO-GENERATED FILE */"
echo "#if USE_XPROF_STATS"
echo "typedef enum {"
echo "    XPROF_PROF_UNACCOUNTED,"
grep -R -h "PROF_start.*" ./* | grep -v probename | sed -e 's/ //g; s/PROF_start(/    XPROF_/; s/);/,/;' | sort -u
echo "    XPROF_LAST"
echo "} xprof_type;"
echo "#endif"
echo "#endif"
echo ""
) >lib/profiler/list
mv lib/profiler/list lib/profiler/xprof_type.h

printAmFile ()
{
    sed -e 's%\ \*%##%; s%/\*%##%; s%##/%##%' < scripts/boilerplate.h
    echo -n "$1 ="
    git ls-files $2$3 | sed -e s%$2%%g | sort -u | while read f; do
        echo " \\"
        echo -n "    ${f}"
    done
    echo ""
}

# Build icons install include from current icons available
printAmFile ICONS "icons/" "silk/*" > icons/icon.am

# Build templates install include from current templates available
printAmFile ERROR_TEMPLATES "errors/" "templates/ERR_*" > errors/template.am

# Build errors translation install include from current .PO available
printAmFile TRANSLATE_LANGUAGES "errors/" "*.po" | sed 's%\.po%\.lang%g' > errors/language.am

# Build manuals translation install include from current .PO available
printAmFile TRANSLATE_LANGUAGES "doc/manuals/" "*.po" | sed 's%\.po%\.lang%g' > doc/manuals/language.am

# Build STUB framework include from current stub_* available
printAmFile STUB_SOURCE "src/" "tests/stub_*.cc" > src/tests/Stub.am

# Build the GPERF generated content
if [ -f src/http/Makefile ]; then
    make -C src/http gperf-files
else
    echo "source tree not configured; skipping regeneration of xperf sources"
    echo "to run it manually use:  make -C src/http gperf-files"
fi

run_ checkMakeNamedErrorDetails || exit 1

# Run formatting
srcFormat || exit 1

if [ -z "$OnlyChangedSince" ]; then
    sort -u <doc/debug-sections.tmp | sort -n >doc/debug-sections.tmp2
    cat scripts/boilerplate.h doc/debug-sections.tmp2 >doc/debug-sections.txt
    rm doc/debug-sections.tmp2
else
    echo "--only-changed-since specified, Skipping update of doc/debug-sections.txt"
fi
rm -f doc/debug-sections.tmp
rm -f boilerplate_fix.sed

exit $SeenErrors
