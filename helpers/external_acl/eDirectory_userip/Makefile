# squid_edir_iplookup - Copyright (C) 2009, 2010 Chad E. Naugle
#
#*******************************************************************************
#
# Makefile --
#
# Builds squid_edir_lookup when run.  PORTING NEEDED.
#

CC = gcc
LD = gcc
CFLAGS = -O2 -Wall -Wextra
PROGNAME = squid_edir_iplookup
UID = squid
GID = nogroup
OBJECTS = main.o iplookup.o util.o
LIBS = -lldap -llber
HEADERS = config.h main.h util.h iplookup.h

all: ${PROGNAME}

${PROGNAME}: ${OBJECTS}
	${LD} ${CFLAGS} -o ${PROGNAME} ${OBJECTS} ${LIBS}
	chmod 0550 ${PROGNAME}
	chown ${UID} ${PROGNAME}
	chgrp ${GID} ${PROGNAME}

clean:
	rm -f *.o ${PROGNAME}

install: ${PROGNAME}
	cp ${PROGNAME} /usr/sbin

main.o: ${HEADERS} main.c
	${CC} ${CFLAGS} -c main.c

iplookup.o: ${HEADERS} iplookup.c
	${CC} ${CFLAGS} -c iplookup.c

util.o: ${HEADERS} util.c
	${CC} ${CFLAGS} -c util.c
