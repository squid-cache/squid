# #!/bin/bash
#
#  Run specific build tests for a given OS environment.
#

if test -f "./test-suite/buildtests/os-${1}.opts" ; then
	echo "TESTING: ${1}"
	./test-suite/buildtest.sh ./test-suite/buildtests/os-${1}
fi

#
#  Run specific tests for each combination of configure-time
#  Options.
#
#  These layers are constructed from detailed knowledge of
#  component dependencies.
#

for f in `ls -1 ./test-suite/buildtests/layer*.opts` ; do
	echo "TESTING: ${f/.opts}"
	./test-suite/buildtest.sh ${f/.opts}
done
