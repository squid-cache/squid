# makefile for smblib

INCLUDES      = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
		-I$(top_srcdir)/src/

noinst_LIBRARIES = libsmbvalid.a
libsmbvalid_a_SOURCES = valid.c session.c rfcnb-util.c rfcnb-io.c \
	smblib-util.c smblib.c smbencrypt.c smbdes.c md4.c byteorder.h \
	rfcnb-error.h  rfcnb-util.h  smbencrypt.h     smblib.h        valid.h \
	md4.h           rfcnb-io.h     rfcnb.h       smblib-common.h  std-defines.h \
	rfcnb-common.h  rfcnb-priv.h   smbdes.h      smblib-priv.h    std-includes.h 

##OBJS = smblib.o smblib-util.o file.o smb-errors.o exper.o smblib-api.o smbencrypt.o smbdes.o md4.o
