/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
#include <functional>
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

static int
compareintvoid(void *const &a, void *const &n)
{
    intnode *A = (intnode *)a;
    intnode *B = (intnode *)n;
    return A->i - B->i;
}

static int
compareint(intnode *const &a, intnode *const &b)
{
    return a->i - b->i;
}

class SplayCheck
{

public:
    static void BeginWalk();
    static int LastValue;
    static bool ExpectedFail;
    static void VisitVoid(void *const &);
    static void VisitNode(intnode *const &);
    static void VisitNodeRef(intnode const &);
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
SplayCheck::VisitVoid(void *const &node)
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
            exit(EXIT_FAILURE);
    } else
        /* success */
        if (ExpectedFail)
            exit(EXIT_FAILURE);

    LastValue = A.i;
}

void
SplayCheck::VisitNode(intnode *const &a)
{
    CheckNode (*a);
}

void
SplayCheck::VisitNodeRef(intnode const &a)
{
    CheckNode (a);
}

static void
destintvoid(void *&data)
{
    intnode *i = (intnode *)data;
    xfree (i);
}

static void
destint(intnode *&data)
{
    delete data;
}

static int
compareintref(intnode const &a, intnode const &b)
{
    return a.i - b.i;
}

static void
destintref(intnode &)
{}

int
main(int, char *[])
{
    std::mt19937 generator;
    std::uniform_int_distribution<int> distribution;
    auto nextRandom = std::bind (distribution, generator);

    {
        /* test void * splay containers */
        const auto top = new Splay<void *>();

        for (int i = 0; i < 100; ++i) {
            intnode *I = (intnode *)xcalloc(sizeof(intnode), 1);
            I->i = nextRandom();
            top->insert(I, compareintvoid);
        }

        SplayCheck::BeginWalk();
        top->visit(SplayCheck::VisitVoid);

        SplayCheck::BeginWalk();
        top->visit(SplayCheck::VisitVoid);
        top->destroy(destintvoid);
    }

    /* test typesafe splay containers */
    {
        /* intnode* */
        const auto safeTop = new Splay<intnode *>();

        for ( int i = 0; i < 100; ++i) {
            intnode *I;
            I = new intnode;
            I->i = nextRandom();
            safeTop->insert(I, compareint);
        }

        SplayCheck::BeginWalk();
        safeTop->visit(SplayCheck::VisitNode);

        safeTop->destroy(destint);
    }
    {
        /* intnode */
        const auto safeTop = new Splay<intnode>();

        for (int i = 0; i < 100; ++i) {
            intnode I;
            I.i = nextRandom();
            safeTop->insert(I, compareintref);
        }

        SplayCheck::BeginWalk();
        safeTop->visit(SplayCheck::VisitNodeRef);

        safeTop->destroy(destintref);
    }

    /* check the check routine */
    {
        SplayCheck::BeginWalk();
        intnode I;
        I.i = 1;
        /* check we don't segfault on NULL splay calls */
        SplayCheck::VisitNodeRef(I);
        I.i = 0;
        SplayCheck::ExpectedFail = true;
        SplayCheck::VisitNodeRef(I);
    }

    {
        /* check for begin() */
        Splay<intnode> *safeTop = new Splay<intnode>();

        if (safeTop->start() != nullptr)
            exit(EXIT_FAILURE);

        if (safeTop->finish() != nullptr)
            exit(EXIT_FAILURE);

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
            exit(EXIT_FAILURE);

        if (safeTop->start()->data.i != 50)
            exit(EXIT_FAILURE);

        if (!safeTop->finish())
            exit(EXIT_FAILURE);

        if (safeTop->finish()->data.i != 10000000)
            exit(EXIT_FAILURE);

        safeTop->destroy(destintref);
    }

    {
        Splay<intnode *> aSplay;

        if (aSplay.start() != nullptr)
            exit(EXIT_FAILURE);

        if (aSplay.size() != 0)
            exit(EXIT_FAILURE);

        aSplay.insert (new intnode(5), compareint);

        if (aSplay.start() == nullptr)
            exit(EXIT_FAILURE);

        if (aSplay.size() != 1)
            exit(EXIT_FAILURE);

        aSplay.destroy(destint);

        if (aSplay.start() != nullptr)
            exit(EXIT_FAILURE);

        if (aSplay.size() != 0)
            exit(EXIT_FAILURE);
    }

    /* TODO: also test the other Splay API */

    return EXIT_SUCCESS;
}

