/*
 * $Id: Splay.cc,v 1.1 2003/02/05 10:36:40 robertc Exp $
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
splay_insert(void *data, splayNode * top, SPLAYCMP * compare)
{
    splayNode *newNode = new splayNode;
    newNode->data = data;
    if (top == NULL) {
	newNode->left = newNode->right = NULL;
	return newNode;
    }
    top = splay_splay(data, top, compare);
    if (splayLastResult < 0) {
	newNode->left = top->left;
	newNode->right = top;
	top->left = NULL;
	return newNode;
    } else if (splayLastResult > 0) {
	newNode->right = top->right;
	newNode->left = top;
	top->right = NULL;
	return newNode;
    } else {
	/* duplicate entry */
	xfree(newNode);
	return top;
    }
}

splayNode *
splay_splay(const void *data, splayNode * top, SPLAYCMP * compare)
{
    splayNode N;
    splayNode *l;
    splayNode *r;
    splayNode *y;
    if (top == NULL)
	return top;
    N.left = N.right = NULL;
    l = r = &N;

    for (;;) {
	splayLastResult = compare(data, top->data);
	if (splayLastResult < 0) {
	    if (top->left == NULL)
		break;
	    if ((splayLastResult = compare(data, top->left->data)) < 0) {
		y = top->left;	/* rotate right */
		top->left = y->right;
		y->right = top;
		top = y;
		if (top->left == NULL)
		    break;
	    }
	    r->left = top;	/* link right */
	    r = top;
	    top = top->left;
	} else if (splayLastResult > 0) {
	    if (top->right == NULL)
		break;
	    if ((splayLastResult = compare(data, top->right->data)) > 0) {
		y = top->right;	/* rotate left */
		top->right = y->left;
		y->left = top;
		top = y;
		if (top->right == NULL)
		    break;
	    }
	    l->right = top;	/* link left */
	    l = top;
	    top = top->right;
	} else {
	    break;
	}
    }
    l->right = top->left;	/* assemble */
    r->left = top->right;
    top->left = N.right;
    top->right = N.left;
    return top;
}

splayNode *
splay_delete(const void *data, splayNode * top, SPLAYCMP * compare)
{
    splayNode *x;
    if (top == NULL)
	return NULL;
    top = splay_splay(data, top, compare);
    if (splayLastResult == 0) {	/* found it */
	if (top->left == NULL) {
	    x = top->right;
	} else {
	    x = splay_splay(data, top->left, compare);
	    x->right = top->right;
	}
	xfree(top);
	return x;
    }
    return top;			/* It wasn't there */
}

void
splay_destroy(splayNode * top, SPLAYFREE * free_func)
{
    if (top->left)
	splay_destroy(top->left, free_func);
    if (top->right)
	splay_destroy(top->right, free_func);
    free_func(top->data);
    xfree(top);
}

void
splay_walk(splayNode * top, SPLAYWALKEE * walkee, void *state)
{
    if (top->left)
	splay_walk(top->left, walkee, state);
    walkee(top->data, state);
    if (top->right)
	splay_walk(top->right, walkee, state);
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
