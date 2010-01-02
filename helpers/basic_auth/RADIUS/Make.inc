#
# Makefile	RADIUS authentifications for squid
#
#

PREFIX  = /usr/local/squid
BINDIR	= $(PREFIX)/libexec/
MANDIR  = $(PREFIX)/man/man8
MANEXT	= .8
CONFDIR  = $(PREFIX)/etc

INCLUDES       = radius.h md5.h

ALL:	squid_radius_auth


attrprint.o: attrprint.c $(INCLUDES)
	$(CC) $(CFLAGS) -c attrprint.c

dict.o: dict.c $(INCLUDES)
	$(CC) $(CFLAGS) -c dict.c

util.o: util.c $(INCLUDES)
	$(CC) $(CFLAGS) -c util.c

squid_radius_auth: squid_rad_auth.o md5.o util.o
	$(CC) $(LDFLAGS) -o squid_radius_auth squid_rad_auth.o md5.o util.o $(LIBS)

squid_radius_auth.o: squid_rad_auth.c $(INCLUDES)
	$(CC) $(CFLAGS) -c squid_rad_auth.c

md5.o: md5.c md5.h
	$(CC) $(CFLAGS) -c md5.c

clean:
	rm -f *.o squid_radius_auth

install: squid_radius_auth
	mkdir -p $(DESTDIR)$(BINDIR)
	install -m 755 -s squid_radius_auth $(DESTDIR)$(BINDIR)/squid_radius_auth
	mkdir -p $(DESTDIR)$(MANDIR)
	install -m 755 squid_radius_auth.8 $(DESTDIR)$(MANDIR)/squid_radius_auth$(MANEXT)
	mkdir -p $(DESTDIR)$(CONFDIR)
	install -m 644 etc/squid_radius_auth.conf $(DESTDIR)$(CONFDIR)/squid_radius_auth.conf.default
	if ! test -f $(DESTDIR)$(CONFDIR)/squid_radius_auth.conf; then \
	    cp -p $(DESTDIR)$(CONFDIR)/squid_radius_auth.conf.default $(DESTDIR)$(CONFDIR)/squid_radius_auth.conf; \
	fi


