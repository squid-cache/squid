/*
 * $Id: Stack.h,v 1.2 1998/02/21 00:56:35 rousskov Exp $
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
	int is_full;         /* true if the stack is full */

	u_num32 push_count;  /* always grows, might overflow, use for stats only */
	u_num32 pop_count;   /* always grows, might overflow, use for stats only */

	/* protected, do not use these, use interface functions instead */
	size_t count;
	void **buf;
};

typedef struct _Stack Stack;

extern Stack *stackCreate(size_t capacity);
extern void stackDestroy(Stack *s);
extern void *stackPop(Stack *s);
extern void stackPush(Stack *s, void *obj);


#endif /* ndef _STACK_H_ */
