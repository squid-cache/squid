/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SMBLIB_SMBENCRYPT_H
#define _SMBLIB_SMBENCRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

void SMBencrypt(unsigned char *passwd, unsigned char *c8, unsigned char *p24);
void SMBNTencrypt(unsigned char *passwd, unsigned char *c8, unsigned char *p24);
void nt_lm_owf_gen(char *pwd, char *nt_p16, char *p16);

#ifdef __cplusplus
}
#endif
#endif /* _SMBLIB_SMBENCRYPT_H */

