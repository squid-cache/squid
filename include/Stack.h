/*
 * $Id: Stack.h,v 1.8 1998/07/20 17:18:48 wessels Exp $
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *  
 */

#ifndef _STACK_H_
#define _STACK_H_

#include "Array.h"

typedef Array Stack;

#define stackCreate arrayCreate
#define stackInit arrayInit
#define stackClean arrayClean
#define stackDestroy arrayDestroy
extern void *stackPop(Stack *s);
#define stackPush arrayAppend
#define stackPrePush arrayPreAppend
extern void *stackTop(Stack *s);

#endif /* ndef _STACK_H_ */
