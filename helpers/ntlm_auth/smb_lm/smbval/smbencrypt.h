#ifndef __SMB_LM_SMBVAL_SMBENCRYPT_H
#define __SMB_LM_SMBVAL_SMBENCRYPT_H


extern void SMBencrypt(uchar * passwd, uchar * c8, uchar * p24);
extern void SMBNTencrypt(uchar * passwd, uchar * c8, uchar * p24);

#endif /* __SMB_LM_SMBVAL_SMBENCRYPT_H */

