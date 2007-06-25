--------------------------------------------------------------------------------
readme.txt is the squid_kerb_auth read-me file.

Author: Markus Moeller (markus_moeller at compuserve.com)

Copyright (C) 2007 Markus Moeller. All rights reserved.
--------------------------------------------------------------------------------

squid_kerb_auth Read Me

Markus Moeller
May 12, 2007

1 Introduction

squid_kerb_auth is a reference implementation that supports authentication via 
the Negotiate RFC 4559 for proxies. It decodes RFC 2478 SPNEGO GSS-API tokens 
from IE7 either through helper functions or via SPNEGO supporting Kerberos libraries
and RFC 1964 Kerberos tokens from Firefox on Linux. Currently, squid_kerb_auth
 supports Squid 2.6 on Linux. 

squid_auth_kerb requires either MIT or Heimdal Kerberos libraries and header files.

2 Building and Installation

# Linux:
# -D__LITTLE_ENDIAN__
# Solaris:
# -D__BIG_ENDIAN__
#
#DEFINE_SPNEGO=-DHAVE_SPNEGO
#HEIMDAL
# DEFINE="-DHEIMDAL $DEFINE_SPNEGO -D__LITTLE_ENDIAN__"
# INCLUDE=-I/usr/include/heimdal -Ispnegohelp
# LIBS="-lgssapi -lkrb5 -lcom_err -lasn1 -lroken"
#MIT
  DEFINE="$DEFINE_SPNEGO -D__LITTLE_ENDIAN__"
  INCLUDE=-Ispnegohelp
  LIBS="-lgssapi_krb5 -lkrb5 -lcom_err"
#
SPNEGO="spnegohelp/derparse.c  spnegohelp/spnego.c  spnegohelp/spnegohelp.c  spnegohelp/spnegoparse.c"
SOURCE="squid_kerb_auth.c base64.c"
gcc -o squid_kerb_auth $DEFINE $INCLUDE $SOURCE $SPNEGO $LIBS

Copy the helper squid_kerb_auth to an apropriate directory.

3 Configuration

a) Configure IE or Firefox to point to the squid proxy by using the fqdn. IE and Firefox will use the
fqdn to query for a HTTP/fqdn Kerberos service principal. 

b) Create a keytab which contains the HTTP/fqdn Kerberos service principal and place it into a directory
where the squid run user can read the keytab. 

c) Add the following line to squid.conf

auth_param negotiate program /usr/sbin/squid_kerb_auth 
auth_param negotiate children 10
auth_param negotiate keep_alive on

d) Modify squid startup file

Add the following lines to the squid startup script to point squid to a keytab file which
contains the HTTP/fqdn service principal for the default Kerberos domain. The fqdn must be 
the proxy name set in IE or firefox. You can not use an IP address.

KRB5_KTNAME=/etc/squid/HTTP.keytab
export KRB5_KTNAME

If you use a different Kerberos domain than the machine itself is in you can point squid to 
the seperate Kerberos config file by setting the following environmnet variable in the startup 
script.

KRB5_CONFIG=/etc/krb-squid5.conf
export KRB5_CONFIG

4 Miscellaneous

The -i options creates informational messages whereas -d creates full debug output

If squid_kerb_auth doesn't determine for some reason the right service principal you can provide 
it with -s HTTP/fqdn.

If you serve multiple Kerberos realms add a HTTP/fqdn@REALM service principal per realm to the 
HTTP.keytab file and use the -s GSS_C_NO_NAME option with squid_kerb_auth.





