#ifndef SQUID_OS_DRAGONFLY_H
#define SQUID_OS_DRAGONFLY_H

#if _SQUID_DRAGONFLY_

/****************************************************************************
 *--------------------------------------------------------------------------*
 * DO *NOT* MAKE ANY CHANGES below here unless you know what you're doing...*
 *--------------------------------------------------------------------------*
 ****************************************************************************/

/*
 * Don't allow inclusion of malloc.h
 */
#if defined(HAVE_MALLOC_H)
#undef HAVE_MALLOC_H
#endif

#endif /* _SQUID_DRAGONFLY_ */
#endif /* SQUID_OS_DRAGONFLY_H */
