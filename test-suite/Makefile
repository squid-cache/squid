CC	= gcc
CFLAGS	= -O2
OBJS	= membanger.o hash.o
LIB	= -lmylib

all: membanger


membanger: $(OBJS)
	gcc -o membanger $(OBJS)

$(OBJS): Makefile

clean: membanger
	rm $(OBJS) 
