// //////////////////////////////////////////////////////////////////////////
// Implementation file ClockerListener.cpp for class ClockerListener
// (c)Copyright 2000, Baptiste Lepilleur.
// Created: 2002/04/19
// //////////////////////////////////////////////////////////////////////////
#include <cppunit/Test.h>
#include <iostream>
#include "ClockerListener.h"
#include "ClockerModel.h"
#include <stdio.h>


ClockerListener::ClockerListener( ClockerModel *model,
                                  bool text )
    : m_model( model )
    , m_text( text )
{
}


ClockerListener::~ClockerListener()
{
}


void 
ClockerListener::startTestRun( CPPUNIT_NS::Test *test, 
                               CPPUNIT_NS::TestResult *eventManager )
{
  m_model->setExpectedTestCount( test->countTestCases() *2 );
}


void 
ClockerListener::endTestRun( CPPUNIT_NS::Test *test, 
                             CPPUNIT_NS::TestResult *eventManager )
{
  if ( m_text )
    printStatistics();
}


void 
ClockerListener::startTest( CPPUNIT_NS::Test *test )
{
  m_model->enterTest( test, false );
}


void 
ClockerListener::endTest( CPPUNIT_NS::Test *test )
{
  m_model->exitTest( test, false );
}


void 
ClockerListener::startSuite( CPPUNIT_NS::Test *suite )
{
  m_model->enterTest( suite, true );
}


void 
ClockerListener::endSuite( CPPUNIT_NS::Test *suite )
{
  m_model->exitTest( suite, true );
}


void 
ClockerListener::printStatistics() const
{
  printTest( 0, "" );
  std::cout  <<  std::endl;
  std::cout  <<  "Total elapsed time: ";
  printTime( m_model->totalElapsedTime() );
  std::cout  <<  ", average test case time: ";
  printTime( m_model->averageTestCaseTime() );
}


void 
ClockerListener::printTest( int testIndex,
                            const std::string &indentString ) const
{
  std::string indent = indentString;
  const int indentLength = 3;

  printTestIndent( indentString, indentLength );
  printTime( m_model->testTimeFor( testIndex ) );

  std::cout  <<  m_model->testPathFor( testIndex ).getChildTest()->getName();
  std::cout  <<  std::endl;

  if ( m_model->childCountFor( testIndex ) == 0 )
    indent+= std::string( indentLength, ' ' );
  else
    indent+= "|" + std::string( indentLength -1, ' ' );

  for ( int index =0; index < m_model->childCountFor( testIndex ); ++index )
    printTest( m_model->childAtFor( testIndex, index ), indent );
}


void 
ClockerListener::printTestIndent( const std::string &indent,
                                  const int indentLength ) const
{
  if ( indent.empty() )
    return;

  std::cout << "   ";
  std::cout << indent.substr( 0, indent.length() - indentLength ) ;
  std::cout << "+"  <<  std::string( indentLength -1, '-' );
}


void 
ClockerListener::printTime( double time ) const
{
  std::cout <<  '('  <<  ClockerModel::timeStringFor( time )  <<  "s) ";
}
