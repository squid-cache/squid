/*
 * $Id: splay.cc,v 1.2 2003/02/08 01:45:51 robertc Exp $
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
compareintvoid(void * const &a, void * const &n)
{
    intnode *A = (intnode *)a;
    intnode *B = (intnode *)n;
    return A->i - B->i;
}

int
compareint(intnode * const &a, intnode * const &b)
{
    return a->i - b->i;
}

void
printintvoid(void * const &a, void *state)
{
    intnode *A = (intnode *)a;
    printf("%d\n", A->i);
}

void
printint (intnode * const &a, void *state)
{
    printf("%d\n",a->i);
}

void
destintvoid(void * &data)
{
    intnode *i = (intnode *)data;
    xfree (i);
}

void
destint(intnode * &data)
{
    delete data;
}

int
compareintref(intnode const &a, intnode const &b)
{
    return a.i - b.i;
}

void
printintref (intnode const &a, void *unused)
{
    printf("%d\n",a.i);
}

void
destintref (intnode &)
{
}

int
main(int argc, char *argv[])
{
    int i;
    intnode *I;
    /* test void * splay containers */
    splayNode *top = NULL;
    srandom(time(NULL));
    for (i = 0; i < 100; i++) {
	I = (intnode *)xcalloc(sizeof(intnode), 1);
	I->i = random();
	top = splay_insert(I, top, compareintvoid);
    }
    splay_walk(top, printintvoid, NULL);
    
    top->walk(printintvoid, NULL);
    top->destroy(destintvoid);
    /* check we don't segfault on NULL splay calls */
    top = NULL;
    top->splay(NULL, compareintvoid);

    /* test typesafe splay containers */
      {
    /* intnode* */
    SplayNode<intnode *> *safeTop = NULL;
    for (i = 0; i < 100; i++) {
	I = new intnode;
	I->i = random();
	safeTop = safeTop->insert(I, compareint);
    }
    safeTop->walk(printint, NULL);
    
    safeTop->destroy(destint);
    /* check we don't segfault on NULL splay calls */
    safeTop = NULL;
    safeTop->splay(NULL, compareint);
      }
      {
    /* intnode */
    SplayNode<intnode> *safeTop = NULL;
    for (i = 0; i < 100; i++) {
	intnode I;
	I.i = random();
	safeTop = safeTop->insert(I, compareintref);
    }
    safeTop->walk(printintref, NULL);
    
    safeTop->destroy(destintref);
    /* check we don't segfault on NULL splay calls */
    safeTop = NULL;
    safeTop->splay(intnode(), compareintref);
    safeTop->walk(printintref, NULL);
}
    return 0;
}
