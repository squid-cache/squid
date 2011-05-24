#ifndef STUB
#include "fatal.h"

#define STUB { fatal(STUB_API " required"); }
#define STUB_RETVAL(x) { fatal(STUB_API " required"); return x; }
//#define STUB_RETREF(x) { fatal(STUB_API " required"); x* o = new (x); return *o; }
// NP: no () around the x here
#define STUB_RETREF(x) { fatal(STUB_API " required"); return new x; }
#define STUB_RETSTATREF(x) { fatal(STUB_API " required"); static x v; return v; }

#endif /* STUB */
