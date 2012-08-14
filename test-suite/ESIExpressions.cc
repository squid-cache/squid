
/*
 * $Id$
 *
 * DEBUG: section 86    ESI Expressions
 * AUTHOR:  Robert Collins
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "esi/Expression.h"

int
main ()
{
    char const *expressions[] = {
        "!(1==1)", "!(1!=1)", "1!=1", "!1==1", "1==1",
        "1 <=1","2<=1", "1 < 1", "1 < 2", "-1 < 1","!-1<1",
        "1>2","2>1","2>=2", "2>3", "1==1&1==1","1==1&1==0",
        "!('a'<='c')",
        "(1==1)|('abc'=='def')",
        "(4!=5)&(4==5)",
        "(1==1)|(2==3)&(3==4)",	/* should be true because of precedence */
        "(1 & 4)",
        "(\"abc\" | \"edf\")", "1==1==1",
        "!('')",
        /* End of array */""
    };

    int results[] = {0, 1, 0, 0, 1,
                     1, 0, 0, 1, 1,
                     0, 0, 1, 1, 0,
                     1, 0, 0, 1, 0,
                     1, 0, 0, 0, 0,
                     1, 0
                    };

    int i = 0;

    while (strlen (expressions[i])) {
        int result = ESIExpression::Evaluate (expressions[i]);
#if VERBOSEDEBUG

        printf("Expr '%s' = '%s' (expected %s)\n", expressions[i],
               result ? "true" : "false",
               results[i] ? "true" : "false");
#endif

        if (result != results[i])
            return 1;

        ++i;
    }

    return 0;
}
