#ifndef _SQUID_COMPAT_XSTRERROR_H
#define _SQUID_COMPAT_XSTRERROR_H

/** strerror() wrapper replacement.
 *
 * Provides the guarantee that a string is always returned.
 * Where strerror() would have provided NULL this will report the error as unknown.
 */
#define xstrerror() xstrerr(errno)

/** Provide the textual display of a system error number.
 * A string is always returned.
 */
extern const char * xstrerr(int error);

#endif /* _SQUID_COMPAT_XSTRERROR_H */
