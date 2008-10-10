#!/bin/sh
#
#  Run specific build tests for a given OS environment.
#

tmp="${1}"
if test -e ./test-suite/buildtests/os-${tmp}.opts ; then
	echo "TESTING: ${tmp}"
	./test-suite/buildtest.sh ./test-suite/buildtests/os-${tmp}
fi

#
#  Run specific tests for each combination of configure-time
#  Options.
#
#  These layers are constructed from detailed knowledge of
#  component dependencies.
#

for f in `ls -1 ./test-suite/buildtests/layer*.opts` ; do
	arg=`echo "${f}" | sed s/\\.opts//`
	echo "TESTING: ${arg}"
	./test-suite/buildtest.sh "${arg}" ||
	( grep -E "^ERROR|\ error:\ " buildtest_*.log && exit 1 )
done
