/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 86    ESI processing */

#ifndef SQUID_SRC_ESI_EXPRESSION_H
#define SQUID_SRC_ESI_EXPRESSION_H

#if HAVE_LIBEXPAT || HAVE_LIBXML2

class ESIExpression
{

public:
    static int Evaluate (char const *);
};

#endif /* HAVE_LIBEXPAT || HAVE_LIBXML2 */
#endif /* SQUID_SRC_ESI_EXPRESSION_H */

