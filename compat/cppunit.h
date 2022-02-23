/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_CPPUNIT_H
#define SQUID_COMPAT_CPPUNIT_H

// CPPUNIT test suite uses auto_ptr which is deprecated in C++0x

#if HAVE_CPPUNIT_EXTENSIONS_HELPERMACROS_H
#if defined(__cplusplus)
#include <cppunit/extensions/HelperMacros.h>

#undef CPPUNIT_TEST_SUITE_END

// Clone from cppunit 1.12.1
#define CPPUNIT_TEST_SUITE_END()                                               \
    }                                                                          \
                                                                               \
    static CPPUNIT_NS::TestSuite *suite()                                      \
    {                                                                          \
      const CPPUNIT_NS::TestNamer &namer = getTestNamer__();                   \
      std::unique_ptr<CPPUNIT_NS::TestSuite> suite(                            \
             new CPPUNIT_NS::TestSuite( namer.getFixtureName() ));             \
      CPPUNIT_NS::ConcretTestFixtureFactory<TestFixtureType> factory;          \
      CPPUNIT_NS::TestSuiteBuilderContextBase context( *suite.get(),           \
                                                       namer,                  \
                                                       factory );              \
      TestFixtureType::addTestsToSuite( context );                             \
      return suite.release();                                                  \
    }                                                                          \
  private: /* dummy typedef so that the macro can still end with ';'*/         \
    typedef int CppUnitDummyTypedefForSemiColonEnding__

#endif /* __cplusplus */
#endif /* HAVE_CPPUNIT_EXTENSIONS_HELPERMACROS_H */
#endif /* SQUID_COMPAT_CPPUNIT_H */

