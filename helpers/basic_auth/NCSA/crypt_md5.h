/*
 * Creates a MD5 based hash of a password
 *
 * To validate a entered password, use the previously calculated
 * password hash as salt, and then compare the result. If identical
 * then the password matches.
 *
 * While encoding a password the salt should be 8 randomly selected
 * characters from the base64 alphabet, for example generated as follows:
 *    char salt[9];
 *    to64(salt, rand(), 4);
 *    to64(salt+4, rand(), 4);
 *    salt[0] = '\0';
 */
char *crypt_md5(const char *pw, const char *salt);
