/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * based on ftp://ftp.cs.cmu.edu/user/sleator/splaying/top-down-splay.c
 * http://bobo.link.cs.cmu.edu/cgi-bin/splay/splay-cgi.pl
 */

#include "squid.h"
#include "splay.h"
#include "util.h"

#include <cstdlib>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <random>

class intnode
{

public:
    intnode() : i(0) {}

    intnode (int anInt) : i (anInt) {}

    int i;
};

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
{}

int
main(int argc, char *argv[])
{
    std::mt19937 generator;
    xuniform_int_distribution<int> distribution;
    auto nextRandom = std::bind (distribution, generator);

    {
        /* test void * splay containers */
        splayNode *top = NULL;

        for (int i = 0; i < 100; ++i) {
            intnode *I = (intnode *)xcalloc(sizeof(intnode), 1);
            I->i = nextRandom();
            if (top)
                top = top->insert(I, compareintvoid);
            else
                top = new splayNode(static_cast<void*>(new intnode(101)));
        }

        SplayCheck::BeginWalk();
        top->walk(SplayCheck::WalkVoid, NULL);

        SplayCheck::BeginWalk();
        top->walk(SplayCheck::WalkVoid, NULL);
        top->destroy(destintvoid);
    }

    /* test typesafe splay containers */
    {
        /* intnode* */
        SplayNode<intnode *> *safeTop = new SplayNode<intnode *>(new intnode(101));

        for ( int i = 0; i < 100; ++i) {
            intnode *I;
            I = new intnode;
            I->i = nextRandom();
            safeTop = safeTop->insert(I, compareint);
        }

        SplayCheck::BeginWalk();
        safeTop->walk(SplayCheck::WalkNode, NULL);

        safeTop->destroy(destint);
    }
    {
        /* intnode */
        SplayNode<intnode> *safeTop = new SplayNode<intnode>(101);

        for (int i = 0; i < 100; ++i) {
            intnode I;
            I.i = nextRandom();
            safeTop = safeTop->insert(I, compareintref);
        }

        SplayCheck::BeginWalk();
        safeTop->walk(SplayCheck::WalkNodeRef, NULL);

        safeTop->destroy(destintref);
    }

    /* check the check routine */
    {
        SplayCheck::BeginWalk();
        intnode I;
        I.i = 1;
        /* check we don't segfault on NULL splay calls */
        SplayCheck::WalkNodeRef(I, NULL);
        I.i = 0;
        SplayCheck::ExpectedFail = true;
        SplayCheck::WalkNodeRef(I, NULL);
    }

    {
        /* check for begin() */
        Splay<intnode> *safeTop = new Splay<intnode>();

        if (safeTop->start() != NULL)
            exit (1);

        if (safeTop->finish() != NULL)
            exit (1);

        for (int i = 0; i < 100; ++i) {
            intnode I;
            I.i = nextRandom();

            if (I.i > 50 && I.i < 10000000)
                safeTop->insert(I, compareintref);
        }

        {
            intnode I;
            I.i = 50;
            safeTop->insert (I, compareintref);
            I.i = 10000000;
            safeTop->insert (I, compareintref);
        }

        if (!safeTop->start())
            exit (1);

        if (safeTop->start()->data.i != 50)
            exit (1);

        if (!safeTop->finish())
            exit (1);

        if (safeTop->finish()->data.i != 10000000)
            exit (1);

        safeTop->destroy(destintref);
    }

    {
        Splay<intnode *> aSplay;

        if (aSplay.start() != NULL)
            exit (1);

        if (aSplay.size() != 0)
            exit (1);

        aSplay.insert (new intnode(5), compareint);

        if (aSplay.start() == NULL)
            exit (1);

        if (aSplay.size() != 1)
            exit (1);

        aSplay.destroy(destint);

        if (aSplay.start() != NULL)
            exit (1);

        if (aSplay.size() != 0)
            exit (1);
    }

    /* TODO: also test the other Splay API */

    return 0;
}

