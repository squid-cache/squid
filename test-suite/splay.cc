/*
 * $Id: splay.cc,v 1.1 2003/02/05 10:37:14 robertc Exp $
 *
 * based on ftp://ftp.cs.cmu.edu/user/sleator/splaying/top-down-splay.c
 * http://bobo.link.cs.cmu.edu/cgi-bin/splay/splay-cgi.pl
 */

#include "config.h"

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "splay.h"
#include "util.h"

typedef struct {
    int i;
} intnode;

int
compareint(void const *a, void const *n)
{
    intnode *A = (intnode *)a;
    intnode *B = (intnode *)n;
    //((splayNode *)n)->data;
    return A->i - B->i;
}

void
printint(void *a, void *state)
{
    intnode *A = (intnode *)a;
    printf("%d\n", A->i);
}

int
main(int argc, char *argv[])
{
    int i;
    intnode *I;
    splayNode *top = NULL;
    srandom(time(NULL));
    for (i = 0; i < 100; i++) {
	I = (intnode *)xcalloc(sizeof(intnode), 1);
	I->i = random();
	top = splay_insert(I, top, compareint);
    }
    splay_walk(top, printint, NULL);
    return 0;
}
