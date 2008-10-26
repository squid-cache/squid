#!/bin/sh
#
#  Run specific build tests for a given OS environment.
#

tmp="${1}"
if test -e ./test-suite/buildtests/os-${tmp}.opts ; then
	echo "TESTING: ${tmp}"
	rm -f -r btos${tmp} && mkdir btos${tmp} && cd btos${tmp}
	../test-suite/buildtest.sh ../test-suite/buildtests/os-${tmp}
	cd ..
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
	rm -f -r btl${layer} && mkdir btl${layer} && cd btl${layer}
	arg=`echo "${f}" | sed s/\\.opts//`
	echo "TESTING: ${arg}"
	../test-suite/buildtest.sh ".${arg}" ||
	( grep -E "^ERROR|\ error:\ |No\ such" buildtest_*.log && exit 1 )
	cd ..
done
