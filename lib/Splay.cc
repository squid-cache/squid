/*
 * $Id: Splay.cc,v 1.3 2004/08/30 05:12:30 robertc Exp $
 *
 * based on ftp://ftp.cs.cmu.edu/user/sleator/splaying/top-down-splay.c
 * http://bobo.link.cs.cmu.edu/cgi-bin/splay/splay-cgi.pl
 */

#include "config.h"

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "splay.h"
#include "util.h"

int splayLastResult = 0;
