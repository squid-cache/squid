CC	= gcc
CFLAGS	= -g -DWITH_LIB
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
	gcc -o membanger $(OBJS) $(LIB)

$(OBJS): Makefile

$(TARGLIB): $(LIBOBJS)
	$(AR_R) $(TARGLIB) $(LIBOBJS)

clean: 
	rm $(OBJS) $(TARGLIB) $(LIBOBJS)
