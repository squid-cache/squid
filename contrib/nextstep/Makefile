VERSION=`pwd | sed 's"/contrib/nextstep""' | sed 's/.*-//'`
ARCHS=`grep 's%@host_cpu@%' ../../config.status | sed "s/s%@host_cpu@%\([nihs]*\)%g/\1/g" | tr a-z A-Z`

pkg:
	${MAKE} -f Makefile.real ARCHS=${ARCHS} VERSION=${VERSION} pkg

tar:
	${MAKE} -f Makefile.real ARCHS=${ARCHS} VERSION=${VERSION} tar

clean:
	${MAKE} -f Makefile.real ARCHS=${ARCHS} VERSION=${VERSION} clean

echo:
	${MAKE} -f Makefile.real ARCHS=${ARCHS} VERSION=${VERSION} echo
