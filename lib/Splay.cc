/*
 * $Id: Splay.cc,v 1.2 2003/02/08 01:45:47 robertc Exp $
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

int splayLastResult = 0;

splayNode *
splay_insert(void *data, splayNode * top, splayNode::SPLAYCMP * compare)
{
    return top->insert (data, compare);
}

splayNode *
splay_splay(const void **data, splayNode * top, splayNode::SPLAYCMP * compare)
{
    return top->splay((void * const)*data, compare);
}

splayNode *
splay_delete(const void *data, splayNode * top, splayNode::SPLAYCMP * compare)
{
    return top->remove ((void * const)data, compare);
}

void
splay_destroy(splayNode * top, splayNode::SPLAYFREE * free_func)
{
    top->destroy(free_func);
}

void
splay_walk(splayNode * top, splayNode::SPLAYWALKEE * walkee, void *state)
{
    top->walk(walkee,state);
}

#ifdef DEBUG
void
splay_dump_entry(void *data, int depth)
{
    printf("%*s%s\n", depth, "", (char *) data);
}

static void
splay_do_dump(splayNode * top, void printfunc(void *data, int depth), int depth)
{
    if (!top)
	return;
    splay_do_dump(top->left, printfunc, depth + 1);
    printfunc(top->data, depth);
    splay_do_dump(top->right, printfunc, depth + 1);
}

void
splay_dump(splayNode * top, void printfunc(void *data, int depth))
{
    splay_do_dump(top, printfunc, 0);
}


#endif
