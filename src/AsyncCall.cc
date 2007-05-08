#include "squid.h"
#include "AsyncCall.h"

void scheduleAsyncCall(int debugSection, int debugLevel,
    const char *fileName, int fileLine, void *objectPtr, const char *callName,
    EVH *wrapper, bool cbdataProtected)
{
    debugs(debugSection, debugLevel, fileName << "(" << fileLine <<
        ") will call " << callName << '(' << objectPtr << ')');
    eventAdd(callName, wrapper, objectPtr, 0.0, 0, cbdataProtected);
}

bool enterAsyncCallWrapper(int debugSection, int debugLevel,
    void *objectPtr, const char *className, const char *methodName)
{
    assert(objectPtr);
    debugs(debugSection, debugLevel, "entering " << className << "::" <<
        methodName << '(' << objectPtr << ')');
    return true;
}

void exitAsyncCallWrapper(int debugSection, int debugLevel,
    void *objectPtr, const char *className, const char *methodName)
{
    debugs(debugSection, debugLevel, "exiting " << className << "::" <<
        methodName << '(' << objectPtr << ')');
}


#if USAGE_SKETCH

class TestClass {
    public:
        virtual ~TestClass();

        virtual void testMethod(); // does not have to be virtual
        AsyncCallWrapper(0,0, TestClass, testMethod) // define a wrapper

    private:
        CBDATA_CLASS2(TestClass);
};

void testCase(TestClass *c) {
    AsyncCall(0,0, &c, TestClass::testMethod); // make an async call to c
}

#endif
