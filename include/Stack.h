/*
 * $Id: Stack.h,v 1.5 1998/03/11 22:18:42 rousskov Exp $
 *
 * AUTHOR: Alex Rousskov
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

#ifndef _STACK_H_
#define _STACK_H_

/* see Stack.c for more documentation */

struct _Stack {
    /* public, read only */
    size_t capacity;

    /* protected, do not use these, use interface functions instead */
    int count;
    void **items;
};

typedef struct _Stack Stack;

extern Stack *stackCreate();
extern void stackInit(Stack * s);
extern void stackClean(Stack * s);
extern void stackDestroy(Stack *s);
extern void *stackPop(Stack *s);
extern void stackPush(Stack *s, void *obj);
extern void stackPrePush(Stack * s, int push_count);


#endif /* ndef _STACK_H_ */
