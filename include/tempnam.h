/*
 * $Id: tempnam.h,v 1.10 1998/09/23 17:20:06 wessels Exp $
 */


/* Copyright (C) 1991, 1992, 1993 Free Software Foundation, Inc.
 * This file is part of the GNU C Library.
 * The GNU C Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 * 
 * The GNU C Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 * 
 * You should have received a copy of the GNU Library General Public
 * License along with the GNU C Library; see the file COPYING.LIB.  If
 * not, write to the Free Software Foundation, Inc., 675 Mass Ave,
 * Cambridge, MA 02139, USA.  */

#ifndef _TEMPNAM_H
#define _TEMPNAM_H
extern char *tempnam(const char *, const char *);
#endif /* _TEMPNAM_H */
