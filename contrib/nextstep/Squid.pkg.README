This installer package contains the Squid internet cache for OPENSTEP. It has
been compiled for m68k and i486.

The following has not been checked for Squid 2:

Currently, the Run* scripts in /usr/local/squid/bin do not work because they
assume a non-standard date program. If you want them to work, compile and
install the following program as /usr/local/squid/bin/epoch:

#include <stdio.h>

main()
{
    long t = time();
    printf( "%ul\n", t);
}

And change the "date '+%d%H%M%S'" invocations in the Run* scripts to
/usr/local/squid/bin/epoch

Gerben Wierda
