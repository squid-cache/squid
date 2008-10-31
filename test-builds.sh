#!/bin/sh
#
#  Run specific build tests for a given OS environment.
#

cleanup="no"
if test "${1}" = "--cleanup" ; then
	cleanup="yes"
	shift
fi

# Run a single test build by name
tmp="${1}"
if test -e ./test-suite/buildtests/${tmp}.opts ; then
	echo "TESTING: ${tmp}"
	rm -f -r bt${tmp} && mkdir bt${tmp} && cd bt${tmp}
	../test-suite/buildtest.sh ../test-suite/buildtests/${tmp}
	( grep -E "^ERROR|\ error:\ |No\ such" buildtest_*.log && exit 1 )
	cd ..
	exit 0
fi

#
#  Run specific tests for each combination of configure-time
#  Options.
#
#  These layers are constructed from detailed knowledge of
#  component dependencies.
#
for f in `ls -1 ./test-suite/buildtests/layer*.opts` ; do
	layer=`echo "${f}" | grep -o -E "layer-[0-9]*-[^\.]*"`
	rm -f -r bt${layer} && mkdir bt${layer} && cd bt${layer}
	arg=`echo "${f}" | sed s/\\.opts//`
	echo "TESTING: ${arg}"
	../test-suite/buildtest.sh ".${arg}" ||
	( grep -E "^ERROR|\ error:\ |No\ such" buildtest_*.log && exit 1 )
	cd ..
	if test "${cleanup}" = "yes" ; then
		echo "REMOVE: bt${layer}"
		rm -f -r bt${layer}
	fi
done
