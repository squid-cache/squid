#!/bin/sh
#
# Linux:
# -D__LITTLE_ENDIAN__
# Solaris:
# -D__BIG_ENDIAN__
#
CC=gcc
#CFLAGS="-Wall -Wextra -Werror -Wcomment -Wpointer-arith -Wcast-align -Wwrite-strings -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wdeclaration-after-statement -Wshadow -O2"
CFLAGS="-Wall -Werror -Wcomment -Wpointer-arith -Wcast-align -Wwrite-strings -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wshadow -O2"
if [ "$1" = "HEIMDAL" ]; then
  DEFINE="-DHEIMDAL -D__LITTLE_ENDIAN__"
  INCLUDE="-I/usr/include/heimdal -Ispnegohelp"
  LIBS="-lgssapi -lkrb5 -lcom_err -lasn1 -lroken"
else
if [ "$1" = "SOLARIS" ]; then
#MIT
  CC=cc
  CFLAGS=""
  DEFINE="-D__BIG_ENDIAN__ -DSOLARIS_11"
  INCLUDE="-Ispnegohelp -Iinclude -Iinclude/kerberosv5"
  LIBS="-R/usr/lib/gss -L/usr/lib/gss -lgss /usr/lib/gss/mech_krb5.so -lsocket"
else
#MIT
  DEFINE="-D__LITTLE_ENDIAN__"
  INCLUDE=-Ispnegohelp
  LIBS="-lgssapi_krb5 -lkrb5 -lcom_err"
fi
fi
SPNEGO="spnegohelp/derparse.c  spnegohelp/spnego.c  spnegohelp/spnegohelp.c  spnegohelp/spnegoparse.c"
SOURCE="squid_kerb_auth.c base64.c"
$CC -g $CFLAGS -o squid_kerb_auth $DEFINE $INCLUDE $SOURCE $SPNEGO $LIBS
