/*
 * Unix SMB/Netbios implementation.
 * Version 1.9.
 * SMB Byte handling
 * Copyright (C) Andrew Tridgell 1992-1995
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * This file implements macros for machine independent short and
 * int manipulation
 */

#undef CAREFUL_ALIGNMENT

/* we know that the 386 can handle misalignment and has the "right"
 * byteorder */
#ifdef __i386__
#define CAREFUL_ALIGNMENT 0
#endif

#ifndef CAREFUL_ALIGNMENT
#define CAREFUL_ALIGNMENT 1
#endif

#define CVAL(buf,pos) (((unsigned char *)(buf))[pos])
#define PVAL(buf,pos) ((unsigned)CVAL(buf,pos))
#define SCVAL(buf,pos,val) (CVAL(buf,pos) = (val))


#if CAREFUL_ALIGNMENT
#define SVAL(buf,pos) (PVAL(buf,pos)|PVAL(buf,(pos)+1)<<8)
#define IVAL(buf,pos) (SVAL(buf,pos)|SVAL(buf,(pos)+2)<<16)
#define SSVALX(buf,pos,val) (CVAL(buf,pos)=(val)&0xFF,CVAL(buf,pos+1)=(val)>>8)
#define SIVALX(buf,pos,val) (SSVALX(buf,pos,val&0xFFFF),SSVALX(buf,pos+2,val>>16))
#define SVALS(buf,pos) ((int16)SVAL(buf,pos))
#define IVALS(buf,pos) ((int32)IVAL(buf,pos))
#define SSVAL(buf,pos,val) SSVALX((buf),(pos),((uint16)(val)))
#define SIVAL(buf,pos,val) SIVALX((buf),(pos),((uint32)(val)))
#define SSVALS(buf,pos,val) SSVALX((buf),(pos),((int16)(val)))
#define SIVALS(buf,pos,val) SIVALX((buf),(pos),((int32)(val)))
#else
/* this handles things for architectures like the 386 that can handle
 * alignment errors */
/*
 * WARNING: This section is dependent on the length of int16 and int32
 * being correct
 */
#define SVAL(buf,pos) (*(uint16 *)((char *)(buf) + (pos)))
#define IVAL(buf,pos) (*(uint32 *)((char *)(buf) + (pos)))
#define SVALS(buf,pos) (*(int16 *)((char *)(buf) + (pos)))
#define IVALS(buf,pos) (*(int32 *)((char *)(buf) + (pos)))
#define SSVAL(buf,pos,val) SVAL(buf,pos)=((uint16)(val))
#define SIVAL(buf,pos,val) IVAL(buf,pos)=((uint32)(val))
#define SSVALS(buf,pos,val) SVALS(buf,pos)=((int16)(val))
#define SIVALS(buf,pos,val) IVALS(buf,pos)=((int32)(val))
#endif


/* now the reverse routines - these are used in nmb packets (mostly) */
#define SREV(x) ((((x)&0xFF)<<8) | (((x)>>8)&0xFF))
#define IREV(x) ((SREV(x)<<16) | (SREV((x)>>16)))

#define RSVAL(buf,pos) SREV(SVAL(buf,pos))
#define RIVAL(buf,pos) IREV(IVAL(buf,pos))
#define RSSVAL(buf,pos,val) SSVAL(buf,pos,SREV(val))
#define RSIVAL(buf,pos,val) SIVAL(buf,pos,IREV(val))
