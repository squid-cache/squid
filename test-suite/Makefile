CC	= gcc
CFLAGS	= -g -Wall -I../include -I../src
OBJS	= membanger.o hash.o SizeToPool.o
LIB	= -L. -lMem
TARGLIB = libMem.a
LIBOBJS = Mem.o \
          Stack.o
AR_R      = /usr/bin/ar r
RM      = rm
XTRA_LIBS = -lm  -lmalloc

all:  membanger

membanger: $(OBJS) $(TARGLIB)
	$(CC) -o membanger $(OBJS) $(LIB)

tcp-banger2: tcp-banger2.o
	$(CC) -g -o $@ tcp-banger2.o

tcp-banger2.o: tcp-banger2.c
	$(CC) -c $(CFLAGS) tcp-banger2.c

$(OBJS): Makefile

$(TARGLIB): $(LIBOBJS)
	$(AR_R) $(TARGLIB) $(LIBOBJS)

clean: 
	rm $(OBJS) $(TARGLIB) $(LIBOBJS)
