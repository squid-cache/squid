#
# Linux:
# -D__LITTLE_ENDIAN__ 
# Solaris:
# -D__BIG_ENDIAN__
#

CFLAGS = -fpic

LIB = libspnegohelp.a
SLIB = libspnegohelp.so

OBJS = derparse.o  spnego.o  spnegohelp.o  spnegoparse.o

all: 
	make `uname`

debug:
	make CFLAGS="$(CFLAGS) -DDEBUG" `uname`

SunOS:
	make CFLAGS="$(CFLAGS) -D__BIG_ENDIAN__" libs

AIX:
	make CFLAGS="$(CFLAGS) -D__BIG_ENDIAN__" libs

Linux:
	make CFLAGS="$(CFLAGS) -D__LITTLE_ENDIAN__" libs

libs: $(LIB) $(SLIB)

$(LIB): $(OBJS)
	ar -r $(LIB) $(OBJS)

$(SLIB): $(OBJS)
	gcc --shared -o $(SLIB) $(OBJS)

derparse.o: derparse.c derparse.h spnego.h Makefile
	gcc -c $(CFLAGS) derparse.c -o $@

spnego.o: spnego.c derparse.h spnego.h spnegoparse.h Makefile
	gcc -c $(CFLAGS) spnego.c -o $@

spnegoparse.o: spnegoparse.c derparse.h spnego.h spnegoparse.h Makefile
	gcc -c $(CFLAGS) spnegoparse.c -o $@

spnegohelp.o: spnegohelp.c spnego.h spnegohelp.h Makefile
	gcc -c $(CFLAGS) spnegohelp.c -o $@

clean:
	rm $(OBJS) $(LIB) $(SLIB)
