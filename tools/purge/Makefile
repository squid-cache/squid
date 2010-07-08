#
# Makefile
#
# The Makefile is divided into three sections, the "generic section", the
# "host section" and the "rules section". The generics section defines
# defaults which you should not change. Changes should solely be made to
# the rules section.
#
# You will need to select several parameters befitting your compiler/system:
#
# -DHAS_BOOL	- set, if your C++ compiler knows about the 'bool' type.
# -DHAS_PSIGNAL - set, if your libc supports psignal(int,const char*).
# -fno-exceptions - may not be recognized by all variants of g++
# -ffor-scope	- the new ANSI C++ scoping of for() variables is used...
#
# === [1] ==================================================== generics section
#
CXX	= g++ -ffor-scope -DHAS_BOOL -DHAS_PSIGNAL
CC	= gcc
LD	= $(CC)		# yes, I do mean gcc and not g++
CXXFLAGS = # -pg -g # -fprofile-arcs -ftest-coverage
SYSTEM  = $(shell uname -s | tr '[a-z]' '[A-Z]' | tr -d '_ -/')
CPU	= $(shell uname -p)
VERSION = $(shell uname -r)
HOST	= $(shell uname -n)
MAJOR   = $(firstword $(subst ., ,$(VERSION)))
MINOR   = $(strip $(word 2,$(subst ., ,$(VERSION))))
LOADLIBES =
SOCKLEN	= int # default except for glibc2?

# optimization levels - Do *not* use levels above -O1 with g++,
# if -fprofile-arcs or -ftest-coverage is selected! Set to different
# values in the host specific section below.
#
# - OPT_NORM for normal level optimization, O2 is a good choice.
#
OPT_NORM = -O2

# electric fence library, for test purposes only (helps w/ memory leaks)
# (developers only)
EFENCE	= -L/usr/local/lib -lefence

#
# === [2] ======================================================= hosts section
#

ifeq (SUNOS,${SYSTEM})
ifeq (5,${MAJOR})
# use these for the SUN CC compiler (for STL, see below or above)
# You must define this for Solaris 2.x: CXXFLAGS = -DSOLARIS 
CC	= cc
#CXX	= CC -DHAS_BOOL -DHAS_PSIGNAL -DHAS_MUTABLE
#CXXFLAGS = -DSOLARIS  '-library=%none,Cstd,Crun' 
#CXXFLAGS += -dalign -ftrap=%none -fsimple -xlibmil
#OPT_NORM = -xtarget=ultra2 -xO4
#EXTRALIB += -lnsl -lsocket
#LD	= CC
#
## g++ settings for Solaris on Ultra Sparcs (comment out all of above):
CXXFLAGS += -DSOLARIS # -ggdb
OPT_NORM = -O2 # -mcpu=supersparc
LD	= $(CC)
##
#EXTRALIB += -lnsl -lsocket -Wl,-Bstatic -lstdc++ -Wl,-Bdynamic
else
# old SunOS 4.1.x, not supported!
CXXFLAGS += -DSUN
endif
endif

ifeq (IRIX64,${SYSTEM})
# The regular 64bit Irix stuff is just too slow, use n32!
SYSTEM        := IRIX
endif

ifeq (FREEBSD,${SYSTEM})
SOCKLEN	= socklen_t
endif

ifeq (IRIX,${SYSTEM})
CXX     = CC -n32 -mips3 -r4000 -DEFAULT:abi=n32:isa=mips3:proc=r4k
CXX	+= -LANG:ansi-for-init-scope=on -LANG:bool=on
CXX	+= -LANG:exceptions=off -LANG:explicit=off -LANG:wchar_t=off
CXX	+= -LANG:mutable=on -LANG:namespaces=on -LANG:std
CC	= cc -n32 -mips3 -r4000
CXXFLAGS = -woff 1174 -LANG:exceptions=off -DHAS_BOOL -DHAS_PSIGNAL
LD	= $(CXX)
OPT_NORM = -O3 -IPA -LNO:opt=1
# for g++
#CXXFLAGS += -mips3 -mcpu=r4000 
endif

ifeq (AIX,${SYSTEM})
ifeq (,${MINOR})
MINOR	:= ${MAJOR}
MAJOR	= 4
endif
CXX	= xlC -UHAS_BOOL -UHAS_PSIGNAL
CC	= xlc
CXXFLAGS = -qtune=pwr # -qdbxextra -g
#CXX	= g++ -ffor-scope -DHAS_BOOL -UHAS_PSIGNAL
SOCKLEN	= size_t
LD	= $(CXX)
endif

ifeq (LINUX,${SYSTEM})
# determine highest version of all installed libc's.
LIBCVER = $(shell /bin/ls /lib/libc.so.? | \
	awk -F'.' '{ if (m<$$3) m=$$3;} END { print m} ')
ifeq (6,${LIBCVER})
SOCKLEN	= size_t
endif
CXXFLAGS += -DHAS_PSIGNAL -DLIBCVERSION=$(LIBCVER) -pipe # -Wall -pedantic
OPT_NORM = -march=pentium -O2
# if your g++ balks (e.g. SuSE still uses 2.7.2.3)
#CXXFLAGS += -DHAS_PSIGNAL -DLIBCVERSION=$(LIBCVER) -m486
LD	= $(CC)
EXTRALIB = -Wl,-Bstatic -lstdc++ -Wl,-Bdynamic
endif

#
# === [3] ======================================================= rules section
# There is no need to change things below this line.
CXXFLAGS += -D${SYSTEM} -DMAJOR=${MAJOR} -DMINOR=${MINOR} -DSOCKLEN=${SOCKLEN}
CFLAGS	= $(CXXFLAGS)
LDFLAGS += $(OPT_NORM)

%.o:%.cc
	$(CXX) $(CXXFLAGS) $(OPT_NORM) -c $< -o $@

OBJS	= convert.o socket.o signal.o squid-tlv.o copyout.o conffile.o
SRCS	= $(OBJS:.o=.cc)
HDRS	= $(OBJS:.o=.hh)
FILES	= $(SRCS) $(HDRS) Makefile purge.cc hexd.c
DIST	= $(addprefix purge/,$(FILES) README)

all: purge

purge: $(OBJS) purge.o 
	$(LD) $(OPT_NORM) $(LDFLAGS) $^ -o $@ $(LOADLIBES) $(EXTRALIB)
hexd: hexd.o
	$(CC) $(OPT_NORM) $(LDFLAGS) $^ -o $@ $(LOADLIBES)
#
# object file rules, generated with "g++ -MM -E *.cc"
#
purge.o: purge.cc $(HDRS)
	$(CXX) $(CXXFLAGS) $(OPT_NORM) -c $< -o $@
convert.o: convert.cc convert.hh
conffile.o: conffile.cc conffile.hh
signal.o: signal.cc signal.hh
socket.o: socket.cc socket.hh convert.hh
squid-tlv.o: squid-tlv.cc squid-tlv.hh
copyout.o: copyout.cc copyout.hh
hexd.o: hexd.c

clean:
	$(RM) *.o
	if [ "${SYSTEM}" = "IRIX"  ]; then rm -rf ii_files; fi
	if [ "${SYSTEM}" = "SUNOS" ]; then rm -rf Templates.DB; fi
	if [ "${SYSTEM}" = "SUNOS" ]; then rm -rf SunWS_cache; fi

distclean: clean
	$(RM) purge hexd

realclean: distclean
clobber: distclean

co-all:	$(FILES)
	echo all checked out
co-all-lock:
	co -l $(FILES)
ci-all:
	for i in $(FILES); do \
		test -w $$i && ci $$i; \
		rm -f $$i; \
	done

dist: distclean co-all
	( cd .. ; gtar cvzf purge-`date +"%Y%m%d"`-src.tar.gz $(DIST) )
tar: distclean ci-all
	( cd .. ; gtar cvzf purge-`date +"%Y%m%d"`-all.tar.gz purge )
