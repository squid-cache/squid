#ifndef SQUID_ADAPTATION__ELEMENTS_H
#define SQUID_ADAPTATION__ELEMENTS_H

// widely used adaptation primitives

namespace Adaptation
{

typedef enum { methodNone, methodReqmod, methodRespmod, methodOptions } Method;
typedef enum { pointNone, pointPreCache, pointPostCache } VectPoint;

extern const char *crlf;
extern const char *methodStr(Method); // TODO: make into a stream operator?
extern const char *vectPointStr(VectPoint); // TODO: make into a stream op?

} // namespace Adaptation

#endif /* SQUID_ADAPTATION_ELEMENTS_H */
