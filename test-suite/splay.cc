/*
 * $Id: splay.cc,v 1.3 2003/04/22 01:37:44 robertc Exp $
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

class SplayCheck
{
  public:
    static void BeginWalk();
    static int LastValue;
    static bool ExpectedFail;
    static void WalkVoid(void *const &, void *);
    static void WalkNode(intnode *const &, void *);
    static void WalkNodeRef(intnode const &, void *);
    static void CheckNode(intnode const &);
};

int SplayCheck::LastValue (0);
bool SplayCheck::ExpectedFail (false);

void
SplayCheck::BeginWalk()
{
    LastValue = 0;
}

void
SplayCheck::WalkVoid(void *const &node, void *state)
{
    intnode *A = (intnode *)node;
    CheckNode(*A);
}

void
SplayCheck::CheckNode(intnode const &A)
{
    if (LastValue > A.i) {
	/* failure */
	if (!ExpectedFail)
	    exit (1);
    } else
	/* success */
	if (ExpectedFail)
	    exit (1);
    LastValue = A.i;
}

void
SplayCheck::WalkNode (intnode *const &a, void *state)
{
    CheckNode (*a);
}

void
SplayCheck::WalkNodeRef (intnode const &a, void *state)
{
    CheckNode (a);
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
destintref (intnode &)
{
}

int
main(int argc, char *argv[])
{
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
    SplayCheck::BeginWalk();
    splay_walk(top, SplayCheck::WalkVoid, NULL);
    
    SplayCheck::BeginWalk();
    top->walk(SplayCheck::WalkVoid, NULL);
    top->destroy(destintvoid);
    /* check we don't segfault on NULL splay calls */
    top = NULL;
    top->splay(NULL, compareintvoid);
      }
    /* test typesafe splay containers */
      {
    /* intnode* */
    SplayNode<intnode *> *safeTop = NULL;
    for ( int i = 0; i < 100; i++) {
	intnode *I;
	I = new intnode;
	I->i = random();
	safeTop = safeTop->insert(I, compareint);
    }
    SplayCheck::BeginWalk();
    safeTop->walk(SplayCheck::WalkNode, NULL);
    
    safeTop->destroy(destint);
    /* check we don't segfault on NULL splay calls */
    safeTop = NULL;
    safeTop->splay(NULL, compareint);
      }
      {
    /* intnode */
    SplayNode<intnode> *safeTop = NULL;
    for (int i = 0; i < 100; i++) {
	intnode I;
	I.i = random();
	safeTop = safeTop->insert(I, compareintref);
    }
    SplayCheck::BeginWalk();
    safeTop->walk(SplayCheck::WalkNodeRef, NULL);
    
    safeTop->destroy(destintref);
    /* check we don't segfault on NULL splay calls */
    safeTop = NULL;
    safeTop->splay(intnode(), compareintref);
    SplayCheck::BeginWalk();
    safeTop->walk(SplayCheck::WalkNodeRef, NULL);
}
    /* check the check routine */
    SplayCheck::BeginWalk();
    intnode I;
    I.i = 1;
    SplayCheck::WalkNodeRef(I, NULL);
    I.i = 0;
    SplayCheck::ExpectedFail = true;
    SplayCheck::WalkNodeRef(I, NULL);
    return 0;
}
