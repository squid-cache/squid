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
# using a custom astyle formatter and to use CHECKSUM to validate that
# the formatter has not altered the code syntax.
#
# If code alteration takes place the process is halted for manual intervention.
#

# TODO: Expand the subset of failures covered by this feature; see run_().
KeepGoing="no"
# the actual name of the directive that enabled keep-going mode
KeepGoingDirective=""


TargetAstyleVersion="2.04"
ASTYLE="${ASTYLE:-astyle}"

# whether to check and, if necessary, update boilerplate copyright years
CheckAndUpdateCopyright=yes

printUsage () {
cat <<_EOF
Usage: $0 [option...]
options:
    --keep-going|-k                            (default: stop on error)
    --check-and-update-copyright <yes|no>      (default no)
    --with-astyle </path/to/astyle/executable> (default: "astyle")
    --only-changed-since <fork|commit-id>      (default: apply to all files)

This script applies Squid mandatory code style guidelines.

It requires astyle version ${TargetAstyleVersion}, or it will skip formatting
program files.
The path to the astyle binary can be specified using the
--with-astyle option or with the ASTYLE environment variable.
It will try to auto-detect a checksum program (e.g. md5sum), the path to it
can be specified with the CHECKSUM environment variable.
If the --only-changed-since argument is supplied, it expects a git commit-id,
branch name or the special keyword 'fork'. The script will try identifying
changed files since the specified commit and, if successful, only examine
files that have changed. The keyword 'fork' will look for files changed
since the current branch was forked off 'upstream/master'. Sensible values
for this argument may include HEAD^, master, orgin/master, or the branch
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
        export ASTYLE
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

if test "x${CHECKSUM}" != "x"
then
    if ! "${CHECKSUM}" </dev/null >/dev/null
    then
        echo "user-supplied checksum utility ${CHECKSUM} cannot run"
        exit 1
    fi
fi

for CHECKSUM in "${CHECKSUM:-md5}" md5sum shasum sha1sum
do
    if "${CHECKSUM}" </dev/null >/dev/null 2>/dev/null ; then
        break
    fi
done
echo "detected checksum program ${CHECKSUM}"

${ASTYLE} --version >/dev/null 2>/dev/null
result=$?
if test $result -gt 0 ; then
	echo "ERROR: cannot run ${ASTYLE}"
	exit 1
fi
AstyleVersion=`${ASTYLE} --version 2>&1 | grep -o -E "[0-9.]+"`
if test "${AstyleVersion}" != "${TargetAstyleVersion}" ; then
	if test "${ASTYLE}" = "astyle" ; then
		echo "Astyle version problem. You have ${AstyleVersion} instead of ${TargetAstyleVersion}"
		echo "Formatting step skipped due to version mismatch"
		AstyleVersion=""
	else
		echo "WARNING: ${ASTYLE} is version ${AstyleVersion} instead of ${TargetAstyleVersion}"
		echo "Formatting anyway, please double check output before submitting"
	fi
else
	echo "Found astyle ${AstyleVersion}"
fi

if [ ! -f src/http/Makefile ]; then
    echo "please run ./bootstrap.sh && ./configure to prepare xperf sources"
    exit 1
fi

if test $CheckAndUpdateCopyright = yes
then
    CopyRightYears=`date +"1996-%Y"`
    echo "s/1996-2[0-9]+ The Squid Software Foundation and contributors/${CopyRightYears} The Squid Software Foundation and contributors/g" >> boilerplate_fix.sed
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

srcFormat ()
{
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
if test "x${OnlyChangedSince}" = "x" ; then
    FilesToOperateOn=`git ls-files`
fi
if test "x${FilesToOperateOn}" = "x" && test "x${OnlyChangedSince}" = "xfork" ; then
    ForkPoint=`git merge-base --fork-point upstream/master`
    if test "x${ForkPoint}" = "x" ; then
        echo "Could not identify fork point - sometimes it happens"
        echo "Please specify commit-id explicitly"
        exit 1
    fi
    OnlyChangedSince="${ForkPoint}"
fi
if test "x${FilesToOperateOn}" = "x" && test "x${OnlyChangedSince}" != "x" ; then
    FilesToOperateOn=`git diff --name-only ${OnlyChangedSince}`
fi

for FileName in ${FilesToOperateOn}; do
    skip_copyright_check=""

    # skip subdirectories, git ls-files is recursive
    test -d ${FileName} && continue

    case ${FileName} in

    *.h|*.c|*.cc|*.cci)

	#
	# Code Style formatting maintenance
	#
	applyPluginsTo ${FileName} scripts/maintenance/ || return
	if test "${AstyleVersion}"; then
		./scripts/formater.pl ${FileName}
		if test -e ${FileName} -a -e "${FileName}.astylebak"; then
			md51=`cat  ${FileName}| tr -d "\n \t\r" | ${CHECKSUM}`;
			md52=`cat  ${FileName}.astylebak| tr -d "\n \t\r" | ${CHECKSUM}`;

			if test "$md51" != "$md52"; then
				echo "ERROR: File ${FileName} not formatting well";
				mv ${FileName} ${FileName}.astylebad
				mv ${FileName}.astylebak ${FileName}
				git checkout -- ${FileName}
			else
				rm -f ${FileName}.astylebak
			fi
        	fi
	fi

	#
	# REQUIRE squid.h first #include
	#
	case ${FileName} in
	src/cf_gen.cc)
		# ignore, this is a build tool.
		;;
	*.c|*.cc)
		IncludedFilesFirstLine=`grep "#include" ${FileName} | head -1`;
		if test "${IncludedFilesFirstLine}" != "#include \"squid.h\"" -a "${FileName}" != "cf_gen.cc"; then
			echo "ERROR: ${FileName} does not include squid.h first!"
		fi
		;;
	*.h|*.cci)
		IncludedFilesOnlySquidH=`grep "#include \"squid.h\"" ${FileName}`;
		if test "x${IncludedFilesOnlySquidH}" != "x" ; then
			echo "ERROR: ${FileName} duplicate include of squid.h"
		fi
		;;
	esac

	#
	# If a file includes openssl headers, then it must include compat/openssl.h
	#
	if test "${FileName}" != "compat/openssl.h"; then
		IncludedFilesOnlyOpenSsl=`grep "#include.*openssl/" "${FileName}" 2>/dev/null | head -1`;
		IncludedFilesOnlyCompatOpenSsl=`grep '#include.*compat/openssl[.]h' "${FileName}" 2>/dev/null | head -1`;
		if test "x${IncludedFilesOnlyOpenSsl}" != "x" -a "x${IncludedFilesOnlyCompatOpenSsl}" = "x"; then
			echo "ERROR: ${FileName} includes openssl headers without including \"compat/openssl.h\""
		fi
	fi

	#
	# forward.h means different things to Squid code depending on the path
	# require the full path is explicit for every include
	#
	IncludedFilesOnlyForwardH=`grep "#include \"forward.h\"" ${FileName}`;
	if test "x${IncludedFilesOnlyForwardH}" != "x" ; then
		echo "ERROR: ${FileName} contains reference to forward.h without path"
	fi

	#
	# detect functions unsafe for use within Squid.
	# strdup() - only allowed in compat/xstring.h which defines a safe replacement.
	# sprintf() - not allowed anywhere.
	#
	IsStrdupUsedInFile=`grep -e "[^x]strdup(" ${FileName}`;
	if test "x${IsStrdupUsedInFile}" != "x" -a "${FileName}" != "compat/xstring.h"; then
		echo "ERROR: ${FileName} contains unprotected use of strdup()"
	fi
	IsSprintfUsedInFile=`grep -e "[^v]sprintf(" ${FileName}`;
	if test "x${IsSprintfUsedInFile}" != "x" ; then
		echo "ERROR: ${FileName} contains unsafe use of sprintf()"
	fi

	#
	# DEBUG Section list maintenance
	#
	grep " DEBUG: section" <${FileName} | sed -e 's/ \* DEBUG: //' -e 's%/\* DEBUG: %%' -e 's% \*/%%' | sort -u >>doc/debug-sections.tmp

	#
	# File permissions maintenance.
	#
	chmod 644 ${FileName}
	;;

    *.pl|*.sh)
	#
	# File permissions maintenance.
	#
	chmod 755 ${FileName}
	;;

    *.am)
		applyPluginsTo ${FileName} scripts/format-makefile-am.pl || return
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
    if test ${CheckAndUpdateCopyright} = yes -a -f ${FileName} -a "x$skip_copyright_check" = "x"; then
        Blurb=`grep -o "${CopyRightYears} The Squid Software Foundation and contributors" ${FileName}`;
        if test "x${Blurb}" = "x"; then
            BoilerPlate=`grep -o -E "1996-2[0-9]+ The Squid Software Foundation and contributors" ${FileName}`;
            if test "x${BoilerPlate}" != "x"; then
                echo "UPDATE COPYRIGHT for ${FileName}"
                sed --in-place -r -f boilerplate_fix.sed ${FileName}
            else
                echo "CHECK COPYRIGHT for ${FileName}"
            fi
        fi
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
make -C src/http gperf-files

run_ checkMakeNamedErrorDetails || exit 1

# Run formatting
echo "" >doc/debug-sections.tmp
srcFormat || exit 1

if [ -z "${OnlyChangedSince}" ]; then
    sort -u <doc/debug-sections.tmp | sort -n >doc/debug-sections.tmp2
    cat scripts/boilerplate.h doc/debug-sections.tmp2 >doc/debug-sections.txt
else
    echo "--only-changed-since specified, Skipping updating doc/debug-sections.txt"
fi

rm doc/debug-sections.tmp doc/debug-sections.tmp2
rm -f boilerplate_fix.sed

exit $SeenErrors
