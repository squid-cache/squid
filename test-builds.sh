#!/bin/sh
#
#  Run specific build tests for a given OS environment.
#
top=`dirname $0`

cleanup="no"
verbose="no"
while [ $# -ge 1 ]; do
    case "$1" in
    --cleanup)
	cleanup="yes"
	shift
	;;
    --verbose)
	verbose="yes"
	shift
	;;
    *)
    	break
	;;
    esac
done

# Things to catch
errors="^ERROR|\ error:|\ Error\ |No\ such|assertion\ failed|FAIL:"

logtee() {
    if [ $verbose = yes ]; then
	tee $1
    else
	cat >$1
    fi
}

buildtest() {
    opts=$1
    layer=`basename $opts .opts`
    btlayer="bt$layer"
    log=${btlayer}.log
    echo "TESTING: ${layer}"
    rm -f -r ${btlayer} && mkdir ${btlayer}
    {
	cd ${btlayer}
	if test -e $top/test-suite/buildtest.sh ; then
		$top/test-suite/buildtest.sh $opts
	elif test -e ../$top/test-suite/buildtest.sh ; then
		../$top/test-suite/buildtest.sh ../$opts
	fi
    } 2>&1 | logtee $log
    grep -E "BUILD" ${log}
    grep -E "${errors}" $log && exit 1
    if test "${cleanup}" = "yes" ; then
	echo "REMOVE DATA: ${btlayer}"
	rm -f -r ${btlayer}
    fi
    result=`tail -2 $log | head -1`
    if test "${result}" = "Build Successful." ; then
        echo "${result}"
    else
        echo "Build Failed:"
        tail -5 $log
        exit 1
    fi
    if test "${cleanup}" = "yes" ; then
	echo "REMOVE LOG: ${log}"
	rm -f -r $log
    fi
}

# Run a single test build by name or opts file
if [ -e "$1" ]; then 

	buildtest $1
	exit 0
fi
tmp=`basename "${1}" .opts`
if test -e $top/test-suite/buildtests/${tmp}.opts ; then
	buildtest $top/test-suite/buildtests/${tmp}.opts
	exit 0
fi

#
#  Run specific tests for each combination of configure-time
#  Options.
#
#  These layers are constructed from detailed knowledge of
#  component dependencies.
#
for f in `ls -1 $top/test-suite/buildtests/layer*.opts` ; do
	buildtest $f
done
