// //////////////////////////////////////////////////////////////////////////
// Implementation file TestPlugInRunnerModel.cpp for class TestPlugInRunnerModel
// (c)Copyright 2000, Baptiste Lepilleur.
// Created: 2001/06/24
// //////////////////////////////////////////////////////////////////////////

#include "StdAfx.h"
#include "TestPlugInRunnerModel.h"
#include <cppunit/TestSuite.h>
#include "TestPlugIn.h"


TestPlugInRunnerModel::TestPlugInRunnerModel() : 
    TestRunnerModel( new CPPUNIT_NS::TestSuite( "Default" ) ),
    m_plugIn( new TestPlugIn( "default plug-in" ) )
{
}


TestPlugInRunnerModel::~TestPlugInRunnerModel()
{
  delete m_plugIn;
}


void 
TestPlugInRunnerModel::setPlugIn( TestPlugIn *plugIn )
{
  delete m_plugIn;
  m_plugIn = plugIn;
  reloadPlugIn();
}


void 
TestPlugInRunnerModel::reloadPlugIn()
{
  try 
  {
    CWaitCursor waitCursor;
    m_history.clear();
    setRootTest( m_plugIn->makeTest() );

    loadHistory();
  }
  catch (...)
  {
    setRootTest( new CPPUNIT_NS::TestSuite( "Default" ) );  
    loadHistory();
    throw;
  }
}
