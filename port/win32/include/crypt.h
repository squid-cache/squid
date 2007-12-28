/* encrypt.h - API to 56 bit DES encryption via  calls
               encrypt(3), setkey(3) and crypt(3)
   Copyright (C) 1991 Jochen Obalek

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

#ifndef _ENCRYPT_H_
#define _ENCRYPT_H_

#ifdef __cplusplus
extern "C"
{
#endif


#ifdef WIN32
void encrypt(char *block, int edflag);
void setkey(char *key);
char * crypt(const char *key, const char *salt);

#else
#include <_ansi.h>

void _EXFUN(encrypt, (char *block, int edflag));
void _EXFUN(setkey, (char *key));
char * _EXFUN(crypt, (const char *key, const char *salt));
#endif

#ifdef __cplusplus
}
#endif

#endif /* _ENCRYPT_H_ */
