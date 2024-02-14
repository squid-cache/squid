/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ADAPTATION_ELEMENTS_H
#define SQUID_SRC_ADAPTATION_ELEMENTS_H

// widely used adaptation primitives

namespace Adaptation
{

typedef enum { methodNone, methodReqmod, methodRespmod, methodOptions } Method;
typedef enum { pointNone, pointPreCache, pointPostCache } VectPoint;
typedef enum { srvBlock, srvBypass, srvWait, srvForce} SrvBehaviour;

extern const char *crlf;
const char *methodStr(Method); // TODO: make into a stream operator?
const char *vectPointStr(VectPoint); // TODO: make into a stream op?

} // namespace Adaptation

#endif /* SQUID_SRC_ADAPTATION_ELEMENTS_H */

