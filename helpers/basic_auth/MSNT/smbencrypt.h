/* smbencrypt.c */
void SMBencrypt(unsigned char *passwd, unsigned char *c8, unsigned char *p24);
void SMBNTencrypt(unsigned char *passwd, unsigned char *c8, unsigned char *p24);
void nt_lm_owf_gen(char *pwd, char *nt_p16, char *p16);
