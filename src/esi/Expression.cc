
/*
 * $Id$
 *
 * DEBUG: section 86    ESI processing
 * AUTHOR: Robert Collins
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
 ;  but WITHOUT ANY WARRANTY; without even the implied warranty of
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

/* stack precedence rules:
 * before pushing an operator onto the stack, the
 * top 2 elements are checked. if either has a higher
 * or equal precedence than the current operator, they
 * are evaluated.
 * Start of expression has 5 precedence,
 * end of expression has 0 precedence
 * literal has 1 as does expression results
 * | has 2
 * & has 3
 * ! has 4
 * == != < > <= >= has 5
 * ( has 5
 * ) has 0
 */

typedef struct _stackmember stackmember;

typedef int evaluate (stackmember * stack, int *depth, int whereAmI,
                      stackmember * candidate);

typedef enum {
    ESI_EXPR_INVALID,
    ESI_EXPR_LITERAL,
    ESI_EXPR_OR,
    ESI_EXPR_AND,
    ESI_EXPR_NOT,
    ESI_EXPR_START,
    ESI_EXPR_END,
    ESI_EXPR_EQ,
    ESI_EXPR_NOTEQ,
    ESI_EXPR_LESS,
    ESI_EXPR_LESSEQ,
    ESI_EXPR_MORE,
    ESI_EXPR_MOREEQ,
    ESI_EXPR_EXPR			/* the result of an expr PRI 1 */
} evaltype;

typedef enum {
    ESI_LITERAL_STRING,
    ESI_LITERAL_FLOAT,
    ESI_LITERAL_INT,
    ESI_LITERAL_BOOL,
    ESI_LITERAL_INVALID
} literalhint;

struct _stackmember {
    evaluate *eval;
    union {
        char *string;
        double floating;
        int integral;
    } value;
    literalhint valuestored;
    evaltype valuetype;
    int precedence;
};

static void cleanmember (stackmember *);
static void stackpop (stackmember * s, int *depth);

void
cleanmember (stackmember * s)
{
    if (s->valuetype == ESI_EXPR_LITERAL
            && s->valuestored == ESI_LITERAL_STRING) {
        safe_free (s->value.string);
        s->value.string = NULL;
    }

}

void
stackpop (stackmember * s, int *depth)
{
    if (!(*depth)--)
        return;

    cleanmember (&s[*depth]);
}

static evaluate evalnegate;
static evaluate evalliteral;
static evaluate evalor;
static evaluate evaland;
static evaluate evallesseq;
static evaluate evallessthan;
static evaluate evalmoreeq;
static evaluate evalmorethan;
static evaluate evalequals;
static evaluate evalnotequals;
static evaluate evalstartexpr;
static evaluate evalendexpr;
static evaluate evalexpr;
static void dumpstack (stackmember * stack, int depth);
static int addmember (stackmember * stack, int *stackdepth,
                      stackmember * candidate);
static int membercompare (stackmember a, stackmember b);
static char const *trim (char const *s);
static stackmember getsymbol (const char *s, char const **endptr);
static void printliteral (stackmember s);
static void printmember (stackmember s);

/* -2 = failed to compate
 * -1 = a less than b
 * 0 = a equal b
 * 2 - a more than b
 */
int
membercompare (stackmember a, stackmember b)
{
    /* we can compare: sub expressions to sub expressions ,
     * literals to literals
     */

    if (!((a.valuetype == ESI_EXPR_LITERAL && b.valuetype == ESI_EXPR_LITERAL &&
            a.valuestored != ESI_LITERAL_INVALID && b.valuestored != ESI_LITERAL_INVALID) ||
            (a.valuetype == ESI_EXPR_EXPR && b.valuetype == ESI_EXPR_EXPR)))
        return -2;

    if (a.valuetype == ESI_EXPR_EXPR) {
        if (a.value.integral == b.value.integral)
            return 0;
        else
            return 1;
    } else if (a.valuestored == ESI_LITERAL_STRING) {
        if (b.valuestored == ESI_LITERAL_STRING) {
            int i =strcmp (a.value.string, b.value.string);

            if (i < 0)
                return -1;

            if (i > 0)
                return 1;

            return 0;
        } else {
            /* TODO: numeric to string conversion ? */
            debugs(86, 1, "strcmp with non-string");
            return -2;
        }
    } else if (a.valuestored == ESI_LITERAL_FLOAT) {
        if (b.valuestored == ESI_LITERAL_INT) {
            if (fabs(a.value.floating - b.value.integral) < 0.00001)
                return 0;
            else if (a.value.floating < b.value.integral)
                return -1;
            else
                return 1;
        } else if (b.valuestored == ESI_LITERAL_FLOAT) {
            if (a.value.floating == b.value.floating)
                return 0;
            else if (a.value.floating < b.value.floating)
                return -1;
            else
                return 1;
        } else {
            /* TODO: attempt numeric converson again? */
            debugs(86, 1, "floatcomp with non float or int");
            return -2;
        }
    } else if (a.valuestored == ESI_LITERAL_INT) {
        if (b.valuestored == ESI_LITERAL_INT) {
            if (a.value.integral == b.value.integral)
                return 0;
            else if (a.value.integral < b.value.integral)
                return -1;
            else
                return 1;
        } else if (b.valuestored == ESI_LITERAL_FLOAT) {
            if (fabs(a.value.integral - b.value.floating) < 0.00001)
                return 0;
            else if (a.value.integral < b.value.floating)
                return -1;
            else
                return 1;
        } else {
            /* TODO: attempt numeric converson again? */
            debugs(86, 1, "intcomp vs non float non int");
            return -2;
        }
    }

    return -2;
}

/* return 0 on success, 1 on failure */
int evalnegate
(stackmember * stack, int *depth, int whereAmI, stackmember * candidate)
{
    if (whereAmI != *depth - 2)
        /* invalid stack */
        return 1;

    if (stack[whereAmI + 1].valuetype != ESI_EXPR_EXPR)
        /* invalid operand */
        return 1;

    /* copy down */
    --(*depth);

    stack[whereAmI] = stack[(*depth)];

    cleanmember (candidate);

    if (stack[whereAmI].value.integral == 1)
        stack[whereAmI].value.integral = 0;
    else
        stack[whereAmI].value.integral = 1;

    return 0;
}

int evalliteral
(stackmember * stack, int *depth, int whereAmI, stackmember * candidate)
{
    debugs(86, 1, "attempt to evaluate a literal");
    /* literals can't be evaluated */
    return 1;
}

int evalexpr
(stackmember * stack, int *depth, int whereAmI, stackmember * candidate)
{
    debugs(86, 1, "attempt to evaluate a sub-expression result");
    /* sub-scpr's can't be evaluated */
    return 1;
}


int evalor
(stackmember * stack, int *depth, int whereAmI, stackmember * candidate)
{
    int rv;
    stackmember srv;

    if (*depth < 3)
        /* Not enough operands */
        return 1;

    if (whereAmI != *depth - 2)
        /* invalid stack */
        return 1;

    if (stack[whereAmI + 1].valuetype != ESI_EXPR_EXPR ||
            stack[whereAmI - 1].valuetype != ESI_EXPR_EXPR)
        /* invalid operand */
        return 1;

    rv = stack[whereAmI - 1].value.integral || stack[whereAmI + 1].value.integral;

    if (rv == -2)
        /* invalid comparison */
        return 1;

    stackpop (stack, depth);      /* arg rhs */

    stackpop (stack, depth);      /* me */

    stackpop (stack, depth);      /* arg lhs */

    srv.valuetype = ESI_EXPR_EXPR;

    srv.eval = evalliteral;

    srv.valuestored = ESI_LITERAL_BOOL;

    srv.value.integral = rv ? 1 : 0;

    srv.precedence = 1;

    stack[(*depth)++] = srv;

    /* we're out of way, try adding now */
    if (!addmember (stack, depth, candidate))
        /* Something wrong upstream */
        return 1;

    return 0;
}

int evaland
(stackmember * stack, int *depth, int whereAmI, stackmember * candidate)
{
    int rv;
    stackmember srv;

    if (*depth < 3)
        /* Not enough operands */
        return 1;

    if (whereAmI != *depth - 2)
        /* invalid stack */
        return 1;

    if (stack[whereAmI + 1].valuetype != ESI_EXPR_EXPR ||
            stack[whereAmI - 1].valuetype != ESI_EXPR_EXPR)
        /* invalid operand */
        return 1;

    rv = stack[whereAmI - 1].value.integral && stack[whereAmI + 1].value.integral;

    if (rv == -2)
        /* invalid comparison */
        return 1;

    stackpop (stack, depth);      /* arg rhs */

    stackpop (stack, depth);      /* me */

    stackpop (stack, depth);      /* arg lhs */

    srv.valuetype = ESI_EXPR_EXPR;

    srv.eval = evalexpr;

    srv.valuestored = ESI_LITERAL_BOOL;

    srv.value.integral = rv ? 1 : 0;

    srv.precedence = 1;

    stack[(*depth)++] = srv;

    /* we're out of way, try adding now */
    if (!addmember (stack, depth, candidate))
        /* Something wrong upstream */
        return 1;

    return 0;
}

int evallesseq
(stackmember * stack, int *depth, int whereAmI, stackmember * candidate)
{
    int rv;
    stackmember srv;

    if (*depth < 3)
        /* Not enough operands */
        return 1;

    if (whereAmI != *depth - 2)
        /* invalid stack */
        return 1;

    rv = membercompare (stack[whereAmI - 1], stack[whereAmI + 1]);

    if (rv == -2)
        /* invalid comparison */
        return 1;

    stackpop (stack, depth);      /* arg rhs */

    stackpop (stack, depth);      /* me */

    stackpop (stack, depth);      /* arg lhs */

    srv.valuetype = ESI_EXPR_EXPR;

    srv.eval = evalexpr;

    srv.valuestored = ESI_LITERAL_BOOL;

    srv.value.integral = rv <= 0 ? 1 : 0;

    srv.precedence = 1;

    stack[(*depth)++] = srv;

    /* we're out of way, try adding now */
    if (!addmember (stack, depth, candidate))
        /* Something wrong upstream */
        return 1;

    /*  debugs(86, 1, "?= " << srv.value.integral << " "); */
    return 0;


}

int evallessthan
(stackmember * stack, int *depth, int whereAmI, stackmember * candidate)
{
    int rv;
    stackmember srv;

    if (*depth < 3)
        /* Not enough operands */
        return 1;

    if (whereAmI != *depth - 2)
        /* invalid stack */
        return 1;

    rv = membercompare (stack[whereAmI - 1], stack[whereAmI + 1]);

    if (rv == -2)
        /* invalid comparison */
        return 1;

    stackpop (stack, depth);      /* arg rhs */

    stackpop (stack, depth);      /* me */

    stackpop (stack, depth);      /* arg lhs */

    srv.valuetype = ESI_EXPR_EXPR;

    srv.eval = evalexpr;

    srv.valuestored = ESI_LITERAL_BOOL;

    srv.value.integral = rv < 0 ? 1 : 0;

    srv.precedence = 1;

    stack[(*depth)++] = srv;

    /* we're out of way, try adding now */
    if (!addmember (stack, depth, candidate))
        /* Something wrong upstream */
        return 1;

    /* debugs(86, 1, "?= " << srv.value.integral << " "); */
    return 0;


}

int evalmoreeq
(stackmember * stack, int *depth, int whereAmI, stackmember * candidate)
{
    int rv;
    stackmember srv;

    if (*depth < 3)
        /* Not enough operands */
        return 1;

    if (whereAmI != *depth - 2)
        /* invalid stack */
        return 1;

    rv = membercompare (stack[whereAmI - 1], stack[whereAmI + 1]);

    if (rv == -2)
        /* invalid comparison */
        return 1;

    stackpop (stack, depth);      /* arg rhs */

    stackpop (stack, depth);      /* me */

    stackpop (stack, depth);      /* arg lhs */

    srv.valuetype = ESI_EXPR_EXPR;

    srv.eval = evalexpr;

    srv.valuestored = ESI_LITERAL_BOOL;

    srv.value.integral = rv >= 0 ? 1 : 0;

    srv.precedence = 1;

    stack[(*depth)++] = srv;

    /* we're out of way, try adding now */
    if (!addmember (stack, depth, candidate))
        /* Something wrong upstream */
        return 1;

    /* debugs(86, 1, "?= " << srv.value.integral << " "); */
    return 0;


}

int evalmorethan
(stackmember * stack, int *depth, int whereAmI, stackmember * candidate)
{
    int rv;
    stackmember srv;

    if (*depth < 3)
        /* Not enough operands */
        return 1;

    if (whereAmI != *depth - 2)
        /* invalid stack */
        return 1;

    rv = membercompare (stack[whereAmI - 1], stack[whereAmI + 1]);

    if (rv == -2)
        /* invalid comparison */
        return 1;

    stackpop (stack, depth);	/* arg rhs */

    stackpop (stack, depth);	/* me */

    stackpop (stack, depth);	/* arg lhs */

    srv.valuetype = ESI_EXPR_EXPR;

    srv.eval = evalexpr;

    srv.valuestored = ESI_LITERAL_BOOL;

    srv.value.integral = rv > 0 ? 1 : 0;

    srv.precedence = 1;

    stack[(*depth)++] = srv;

    /* we're out of way, try adding now */
    if (!addmember (stack, depth, candidate))
        /* Something wrong upstream */
        return 1;

    /* debugs(86, 1, "?= " << srv.value.integral << " "); */
    return 0;

}

int
evalequals (stackmember * stack, int *depth, int whereAmI,
            stackmember * candidate)
{
    int rv;
    stackmember srv;

    if (*depth < 3)
        /* Not enough operands */
        return 1;

    if (whereAmI != *depth - 2)
        /* invalid stack */
        return 1;

    rv = membercompare (stack[whereAmI - 1], stack[whereAmI + 1]);

    if (rv == -2)
        /* invalid comparison */
        return 1;

    stackpop (stack, depth);	/* arg rhs */

    stackpop (stack, depth);	/* me */

    stackpop (stack, depth);	/* arg lhs */

    srv.valuetype = ESI_EXPR_EXPR;

    srv.eval = evalexpr;

    srv.valuestored = ESI_LITERAL_BOOL;

    srv.value.integral = rv ? 0 : 1;

    srv.precedence = 1;

    stack[(*depth)++] = srv;

    /* we're out of way, try adding now */
    if (!addmember (stack, depth, candidate))
        /* Something wrong upstream */
        return 1;

    /* debugs(86, 1, "?= " << srv.value.integral << " "); */
    return 0;
}

int evalnotequals
(stackmember * stack, int *depth, int whereAmI, stackmember * candidate)
{
    int rv;
    stackmember srv;

    if (*depth < 3)
        /* Not enough operands */
        return 1;

    if (whereAmI != *depth - 2)
        /* invalid stack */
        return 1;

    rv = membercompare (stack[whereAmI - 1], stack[whereAmI + 1]);

    if (rv == -2)
        /* invalid comparison */
        return 1;

    stackpop (stack, depth);	/* arg rhs */

    stackpop (stack, depth);	/* me */

    stackpop (stack, depth);	/* arg lhs */

    srv.valuetype = ESI_EXPR_EXPR;

    srv.eval = evalexpr;

    srv.valuestored = ESI_LITERAL_BOOL;

    srv.value.integral = rv ? 1 : 0;

    srv.precedence = 1;

    stack[(*depth)++] = srv;

    /* we're out of way, try adding now */
    if (!addmember (stack, depth, candidate))
        /* Something wrong upstream */
        return 1;

    /* debugs(86, 1, "?= " << srv.value.integral << " "); */
    return 0;
}

int evalstartexpr
(stackmember * stack, int *depth, int whereAmI, stackmember * candidate)
{
    /* debugs(86, 1, "?("); */

    if (whereAmI != *depth - 2)
        /* invalid stack */
        return 1;

    /* Only valid when RHS is an end bracket */
    if (candidate->valuetype != ESI_EXPR_END)
        return 1;

    --(*depth);

    stack[whereAmI] = stack[(*depth)];

    cleanmember (candidate);

    return 0;
}

int evalendexpr
(stackmember * stack, int *depth, int whereAmI, stackmember * candidate)
{
    /* Can't evaluate ) brackets */
    return 1;
}

char const *
trim (char const *s)
{
    while (*s == ' ')
        ++s;

    return s;
}

stackmember
getsymbol (const char *s, char const **endptr)
{
    stackmember rv;
    char *end;
    char const *origs = s;
    /* trim whitespace */
    s = trim (s);
    rv.eval = NULL;		/* A literal */
    rv.valuetype = ESI_EXPR_INVALID;
    rv.valuestored = ESI_LITERAL_INVALID;

    if (('0' <= *s && *s <= '9') || *s == '-') {
        size_t length = strspn (s, "0123456789.");
        char const *point;

        if ((point = strchr (s, '.')) && point - s < (ssize_t)length) {
            /* floating point */
            errno=0; /* reset errno */
            rv.value.floating = strtod (s, &end);

            if (s == end || errno) {
                /* Couldn't convert to float */
                debugs(86, 1, "failed to convert '" << s << "' to float ");
                *endptr = origs;
            } else {
                debugs (86,6, "found " << rv.value.floating << " of length " << end - s);
                *endptr = end;
                rv.eval = evalliteral;
                rv.valuestored = ESI_LITERAL_FLOAT;
                rv.valuetype = ESI_EXPR_LITERAL;
                rv.precedence = 1;
            }
        } else {
            /* INT */
            errno=0; /* reset errno */
            rv.value.integral = strtol (s, &end, 0);

            if (s == end || errno) {
                /* Couldn't convert to int */
                debugs(86, 1, "failed to convert '" << s << "' to int ");
                *endptr = origs;
            } else {
                debugs (86,6, "found " << rv.value.integral << " of length " << end - s);
                *endptr = end;
                rv.eval = evalliteral;
                rv.valuestored = ESI_LITERAL_INT;
                rv.valuetype = ESI_EXPR_LITERAL;
                rv.precedence = 1;
            }
        }
    } else if ('!' == *s) {
        if ('=' == *(s + 1)) {
            debugs(86, 6, "found !=");
            *endptr = s + 2;
            rv.eval = evalnotequals;
            rv.valuetype = ESI_EXPR_NOTEQ;
            rv.precedence = 5;
        } else {
            debugs(86, 6, "found !");
            *endptr = s + 1;
            rv.valuetype = ESI_EXPR_NOT;
            rv.precedence = 4;
            rv.eval = evalnegate;
        }
    } else if ('\'' == *s) {
        char const *t = s + 1;
        debugs(86, 6, "found \'");

        while (*t != '\'' && *t)
            ++t;

        if (!*t) {
            debugs(86, 1, "missing end \' in '" << s << "'");
            *endptr = origs;
        } else {
            *endptr = t + 1;
            /* Special case for zero length strings */

            if (t - s - 1)
                rv.value.string = xstrndup (s + 1, t - s - 1);
            else
                rv.value.string = static_cast<char *>(xcalloc (1,1));

            rv.eval = evalliteral;

            rv.valuestored = ESI_LITERAL_STRING;

            rv.valuetype = ESI_EXPR_LITERAL;

            rv.precedence = 1;

            debugs(86, 6, "found  string '" << rv.value.string << "'");
        }
    } else if ('(' == *s) {
        debugs(86, 6, "found subexpr start");
        *endptr = s + 1;
        rv.valuetype = ESI_EXPR_START;
        rv.precedence = 5;
        rv.eval = evalstartexpr;
    } else if (')' == *s) {
        debugs(86, 6, "found subexpr end");
        *endptr = s + 1;
        rv.valuetype = ESI_EXPR_END;
        rv.precedence = 0;
        rv.eval = evalendexpr;
    } else if ('&' == *s) {
        debugs(86, 6, "found AND");
        *endptr = s + 1;
        rv.valuetype = ESI_EXPR_AND;
        rv.precedence = 3;
        rv.eval = evaland;
    } else if ('|' == *s) {
        debugs(86, 6, "found OR");
        *endptr = s + 1;
        rv.valuetype = ESI_EXPR_OR;
        rv.precedence = 2;
        rv.eval = evalor;
    } else if ('=' == *s) {
        if ('=' == *(s + 1)) {
            debugs(86, 6, "found equals");
            *endptr = s + 2;
            rv.valuetype = ESI_EXPR_EQ;
            rv.precedence = 5;
            rv.eval = evalequals;
        } else {
            debugs(86, 1, "invalid expr '" << s << "'");
            *endptr = origs;
        }
    } else if ('<' == *s) {
        if ('=' == *(s + 1)) {
            debugs(86, 6, "found less-equals");
            *endptr = s + 2;
            rv.valuetype = ESI_EXPR_LESSEQ;
            rv.precedence = 5;
            rv.eval = evallesseq;
        } else {
            debugs(86, 6, "found less than");
            *endptr = s + 1;
            rv.valuetype = ESI_EXPR_LESS;
            rv.precedence = 5;
            rv.eval = evallessthan;
        }
    } else if ('>' == *s) {
        if ('=' == *(s + 1)) {
            debugs(86, 6, "found more-equals");
            *endptr = s + 2;
            rv.valuetype = ESI_EXPR_MOREEQ;
            rv.precedence = 5;
            rv.eval = evalmoreeq;
        } else {
            debugs(86, 6, "found more than");
            *endptr = s + 1;
            rv.valuetype = ESI_EXPR_MORE;
            rv.precedence = 5;
            rv.eval = evalmorethan;
        }
    } else if (!strncmp (s, "false", 5)) {
        debugs(86, 5, "getsymbol: found variable result 'false'");
        *endptr = s + 5;
        rv.valuetype = ESI_EXPR_EXPR;
        rv.valuestored = ESI_LITERAL_BOOL;
        rv.value.integral = 0;
        rv.precedence = 1;
        rv.eval = evalexpr;
    } else if (!strncmp (s, "true", 4)) {
        debugs(86, 5, "getsymbol: found variable result 'true'");
        *endptr = s + 4;
        rv.valuetype = ESI_EXPR_EXPR;
        rv.valuestored = ESI_LITERAL_BOOL;
        rv.value.integral = 1;
        rv.precedence = 1;
        rv.eval = evalexpr;
    } else {
        debugs(86, 1, "invalid expr '" << s << "'");
        *endptr = origs;
    }

    return rv;
}

void
printliteral (stackmember s)
{
    switch (s.valuestored) {

    case ESI_LITERAL_INVALID:
        debug(86, 1) ( " Invalid " );
        break;

    case ESI_LITERAL_FLOAT:
        debug (86,1) ("%f", s.value.floating);
        break;

    case ESI_LITERAL_STRING:
        debug (86,1) ("'%s'", s.value.string);
        break;

    case ESI_LITERAL_INT:
        debug (86,1) ("%d", s.value.integral);
        break;

    case ESI_LITERAL_BOOL:
        debug (86,1)("%s",s.value.integral ? "true" : "false");
    }
}

void
printmember (stackmember s)
{
    switch (s.valuetype) {

    case ESI_EXPR_INVALID:
        debug (86,1) (" Invalid ");
        break;

    case ESI_EXPR_LITERAL:
        printliteral (s);
        break;

    case ESI_EXPR_EXPR:
        debug (86,1) ("%s", s.value.integral ? "true" : "false");
        break;

    case ESI_EXPR_OR:
        debug (86,1) ("|");
        break;

    case ESI_EXPR_AND:
        debug (86,1) ("&");
        break;

    case ESI_EXPR_NOT:
        debug (86,1) ("!");
        break;

    case ESI_EXPR_START:
        debug (86,1) ("(");
        break;

    case ESI_EXPR_END:
        debug (86,1) (")");
        break;

    case ESI_EXPR_EQ:
        debug (86,1) ("==");
        break;

    case ESI_EXPR_NOTEQ:
        debug (86,1) ("!=");
        break;

    case ESI_EXPR_LESS:
        debug (86,1) ("<");
        break;

    case ESI_EXPR_LESSEQ:
        debug (86,1) ("<=");
        break;

    case ESI_EXPR_MORE:
        debug (86,1) (">");
        break;

    case ESI_EXPR_MOREEQ:
        debug (86,1) (">=");
        break;
    }
}

void
dumpstack (stackmember * stack, int depth)
{
    int i;

    for (i = 0; i < depth; ++i)
        printmember (stack[i]);

    if (depth)
        debug (86,1) ("\n");
}

int
addmember (stackmember * stack, int *stackdepth, stackmember * candidate)
{
    if (candidate->valuetype != ESI_EXPR_LITERAL && *stackdepth > 1) {
        /* !(!(a==b))) is why thats safe */
        /* strictly less than until we unwind */

        if (candidate->precedence < stack[*stackdepth - 1].precedence ||
                candidate->precedence < stack[*stackdepth - 2].precedence) {
            /* must be an operator */

            if (stack[*stackdepth - 2].valuetype == ESI_EXPR_LITERAL ||
                    stack[*stackdepth - 2].valuetype == ESI_EXPR_INVALID ||
                    stack[*stackdepth - 2].eval (stack, stackdepth,
                                                 *stackdepth - 2, candidate)) {
                /* cleanup candidate and stack */
                dumpstack (stack, *stackdepth);
                cleanmember (candidate);
                debugs(86, 1, "invalid expression");
                return 0;
            }
        } else {
            stack[(*stackdepth)++] = *candidate;
        }
    } else if (candidate->valuetype != ESI_EXPR_INVALID)
        stack[(*stackdepth)++] = *candidate;

    return 1;
}

int
ESIExpression::Evaluate (char const *s)
{
    stackmember stack[20];
    int stackdepth = 0;
    char const *end;
    PROF_start(esiExpressionEval);

    while (*s) {
        stackmember candidate = getsymbol (s, &end);

        if (candidate.valuetype != ESI_EXPR_INVALID) {
            assert (s != end);

            if (!addmember (stack, &stackdepth, &candidate)) {
                PROF_stop(esiExpressionEval);
                return 0;
            }

            s = end;
        } else {
            assert (s == end);
            debugs(86, 1, "failed parsing expression");
            PROF_stop(esiExpressionEval);
            return 0;
        }
    }

    if (stackdepth > 1) {
        stackmember rv;
        rv.valuetype = ESI_EXPR_INVALID;
        rv.precedence = 0;

        if (stack[stackdepth - 2].
                eval (stack, &stackdepth, stackdepth - 2, &rv)) {
            /* special case - leading operator failed */
            debugs(86, 1, "invalid expression");
            PROF_stop(esiExpressionEval);
            return 0;
        }
    }

    if (stackdepth == 0) {
        /* Empty expression - evaluate to false */
        PROF_stop(esiExpressionEval);
        return 0;
    }

    /* if we hit here, we think we have a valid result */
    assert (stackdepth == 1);

    assert (stack[0].valuetype == ESI_EXPR_EXPR);

    PROF_stop(esiExpressionEval);

    return stack[0].value.integral ? 1 : 0;
}
