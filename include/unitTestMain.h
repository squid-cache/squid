/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_INCLUDE_UNITTESTMAIN_H
#define SQUID_INCLUDE_UNITTESTMAIN_H

#if ENABLE_DEBUG_SECTION
#include "debug/Stream.h"
#endif /* ENABLE_DEBUG_SECTION */

#include <cppunit/BriefTestProgressListener.h>
#include <cppunit/TextTestProgressListener.h>
#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/TestResult.h>
#include <cppunit/TestResultCollector.h>
#include <cppunit/TestRunner.h>

#include <memory>
#include <stdexcept>

/// implements test program's main() function while enabling customization
class TestProgram
{
public:
    virtual ~TestProgram() = default;

    /// Runs before all tests.
    /// Does nothing by default.
    virtual void startup() {std::cerr << "XXX1: Default Before\n";}

    /// Runs after all tests, regardless of their outcome.
    /// Does nothing by default.
    virtual void shutdown() {std::cerr << "XXX9: Default After\n";}

    /// Implements main(), combining all the steps.
    /// Must be called from main().
    /// \returns desired main() result.
    int run();

private:
    bool runTests();
};

int
TestProgram::run()
{
#if ENABLE_DEBUG_SECTION
    Debug::Levels[ENABLE_DEBUG_SECTION] = 99;
#endif

    startup();
    const auto result = runTests();
    shutdown();

    return result ? 0 : 1;
}

/// runs all tests registered with CPPUNIT_TEST_SUITE_REGISTRATION() calls
/// \returns whether all tests were successful
bool
TestProgram::runTests()
{
    // Create the event manager and test controller
    CPPUNIT_NS::TestResult controller;

    // Add a listener that colllects test result
    CPPUNIT_NS::TestResultCollector result;
    controller.addListener( &result );

    // Add a listener that print dots as test run.
    // use BriefTestProgressListener to get names of each test
    // even when they pass.
//    CPPUNIT_NS::BriefTestProgressListener progress;
    CPPUNIT_NS::TextTestProgressListener progress;
    controller.addListener( &progress );

    // Add the top suite to the test runner
    CPPUNIT_NS::TestRunner runner;
    runner.addTest( CPPUNIT_NS::TestFactoryRegistry::getRegistry().makeTest() );
    runner.run( controller );

    // Print test in a compiler compatible format.
    CPPUNIT_NS::CompilerOutputter outputter( &result, std::cerr );
    outputter.write();

    return result.wasSuccessful();
}

/// TestProgram object registered by RegisterTestProgram() (or nil).
static std::unique_ptr<TestProgram> TestProgram_;

/// Creates and registers a CustomTestProgram object. Optionally "uses" the
/// static defined by RegisterTestProgram (by taking that variable address).
/// Use RegisterTestProgram_() instead.
template <class CustomTestProgram>
static bool
RegisterTestProgram_(void * = nullptr)
{
    // Avoid assert(): Some tests do not link with libcompatsquid.la (XXX?).
    // assert(!TestProgram_);
    if (TestProgram_)
        throw std::runtime_error("attempt to register more than one TestProgram");

    TestProgram_.reset(new CustomTestProgram());
    return true;
}

/// A helper macro to create and register a CustomTestProgram object.
#define RegisterTestProgram(CustomTestProgram) \
    static bool CustomTestProgramRegistration_ = RegisterTestProgram_<CustomTestProgram>(&CustomTestProgramRegistration_)

int
main(int, char *[])
{
    if (!TestProgram_)
        RegisterTestProgram(TestProgram);
    return TestProgram_->run();
}

#endif /* SQUID_INCLUDE_UNITTESTMAIN_H */

