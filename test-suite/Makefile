CC	= gcc
CFLAGS	= -g
OBJS	= membanger.o hash.o
LIB	= -lmylib

all: membanger


membanger: $(OBJS)
	gcc -o membanger $(OBJS)

$(OBJS): Makefile

clean: membanger
	rm $(OBJS) 
