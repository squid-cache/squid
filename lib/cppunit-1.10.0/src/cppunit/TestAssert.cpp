#if HAVE_CMATH
#   include <cmath>
#else
#   include <math.h>
#endif

#include <cppunit/TestAssert.h>


CPPUNIT_NS_BEGIN


void 
assertDoubleEquals( double expected,
                    double actual,
                    double delta,
                    SourceLine sourceLine )
{
  Asserter::failNotEqualIf( fabs( expected - actual ) > delta,
                            assertion_traits<double>::toString(expected),
                            assertion_traits<double>::toString(actual),
                            sourceLine );
}


CPPUNIT_NS_END
