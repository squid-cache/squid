/*
 * $Id: Array.h,v 1.2 1998/07/20 17:18:46 wessels Exp $
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

#ifndef _ARRAY_H_
#define _ARRAY_H_

/* see Array.c for more documentation */

typedef struct {
    int capacity;
    int count;
    void **items;
} Array;


extern Array *arrayCreate();
extern void arrayInit(Array * s);
extern void arrayClean(Array * s);
extern void arrayDestroy(Array *s);
extern void arrayAppend(Array *s, void *obj);
extern void arrayPreAppend(Array * s, int app_count);


#endif /* ndef _ARRAY_H_ */
