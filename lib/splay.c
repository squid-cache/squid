
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
splay_insert(void *data, splayNode * top, SPCMP compare)
{
    splayNode *new = xcalloc(sizeof(splayNode), 1);
    new->data = data;
    if (top == NULL) {
	new->left = new->right = NULL;
	return new;
    }
    top = splay_splay(data, top, compare);
    if (splayLastResult < 0) {
	new->left = top->left;
	new->right = top;
	top->left = NULL;
	return new;
    } else if (splayLastResult > 0) {
	new->right = top->right;
	new->left = top;
	top->right = NULL;
	return new;
    } else {
	/* duplicate entry */
	free(new);
	return top;
    }
}

splayNode *
splay_splay(const void *data, splayNode * top, SPCMP compare)
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
	splayLastResult = compare(data, top);
	if (splayLastResult < 0) {
	    if (top->left == NULL)
		break;
	    if ((splayLastResult = compare(data, top->left)) < 0) {
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
	    if ((splayLastResult = compare(data, top->right)) > 0) {
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

void
splay_destroy(splayNode * top, void (*free_func) (void *))
{
    if (top->left)
	splay_destroy(top->left, free_func);
    if (top->right)
	splay_destroy(top->right, free_func);
    free_func(top->data);
    xfree(top);
}


#ifdef DRIVER

void
splay_print(splayNode * top, void (*printfunc) ())
{
    if (top == NULL)
	return;
    splay_print(top->left, printfunc);
    printfunc(top->data);
    splay_print(top->right, printfunc);
}

typedef struct {
    int i;
} intnode;

int
compareint(void *a, splayNode * n)
{
    intnode *A = a;
    intnode *B = n->data;
    return A->i - B->i;
}

void
printint(void *a)
{
    intnode *A = a;
    printf("%d\n", A->i);
}

main(int argc, char *argv[])
{
    int i;
    intnode *I;
    splayNode *top = NULL;
    srandom(time(NULL));
    for (i = 0; i < 100; i++) {
	I = xcalloc(sizeof(intnode), 1);
	I->i = random();
	top = splay_insert(I, top, compareint);
    }
    splay_print(top, printint);
    return 0;
}
#endif
