/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_LIB_SMBLIB_SMBDES_H
#define SQUID_LIB_SMBLIB_SMBDES_H

void E_P16(unsigned char *p14, unsigned char *p16);
void E_P24(unsigned char *p21, unsigned char *c8, unsigned char *p24);
void cred_hash1(unsigned char *out, unsigned char *in, unsigned char *key);
void cred_hash2(unsigned char *out, unsigned char *in, unsigned char *key);

#endif /* SQUID_LIB_SMBLIB_SMBDES_H */

