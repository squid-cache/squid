#ifndef CPPUNIT_TEXTOUTPUTTER_H
#define CPPUNIT_TEXTOUTPUTTER_H

#include <cppunit/Portability.h>
#include <cppunit/Outputter.h>
#include <iostream>

CPPUNIT_NS_BEGIN


class Exception;
class SourceLine;
class TestResultCollector;
class TestFailure;


/*! \brief Prints a TestResultCollector to a text stream.
 * \ingroup WritingTestResult
 */
class CPPUNIT_API TextOutputter : public Outputter
{
public:
  TextOutputter( TestResultCollector *result,
                 std::ostream &stream );

  /// Destructor.
  virtual ~TextOutputter();

  void write();
  virtual void printFailures();
  virtual void printHeader();

  virtual void printFailure( TestFailure *failure,
                             int failureNumber );
  virtual void printFailureListMark( int failureNumber );
  virtual void printFailureTestName( TestFailure *failure );
  virtual void printFailureType( TestFailure *failure );
  virtual void printFailureLocation( SourceLine sourceLine );
  virtual void printFailureDetail( Exception *thrownException );
  virtual void printFailureWarning();
  virtual void printStatistics();

protected:
  TestResultCollector *m_result;
  std::ostream &m_stream;

private:
  /// Prevents the use of the copy constructor.
  TextOutputter( const TextOutputter &copy );

  /// Prevents the use of the copy operator.
  void operator =( const TextOutputter &copy );
};



CPPUNIT_NS_END

#endif  // CPPUNIT_TEXTOUTPUTTER_H
