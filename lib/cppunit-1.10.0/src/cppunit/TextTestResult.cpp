#include <cppunit/Exception.h>
#include <cppunit/Test.h>
#include <cppunit/TestFailure.h>
#include <cppunit/TextTestResult.h>
#include <cppunit/TextOutputter.h>
#include <iostream>


CPPUNIT_NS_BEGIN


TextTestResult::TextTestResult()
{
  addListener( this );
}


void 
TextTestResult::addFailure( const TestFailure &failure )
{
  TestResultCollector::addFailure( failure );
  std::cerr << ( failure.isError() ? "E" : "F" );
}


void 
TextTestResult::startTest( Test *test )
{
  TestResultCollector::startTest (test);
  std::cerr << ".";
}


void 
TextTestResult::print( std::ostream& stream ) 
{
  TextOutputter outputter( this, stream );
  outputter.write();
}


std::ostream &
operator <<( std::ostream &stream, 
             TextTestResult &result )
{ 
  result.print (stream); return stream; 
}


CPPUNIT_NS_END
