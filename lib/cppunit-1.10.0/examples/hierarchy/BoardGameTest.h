#ifndef __BOARDGAMETEST_H__
#define __BOARDGAMETEST_H__

#include <cppunit/extensions/HelperMacros.h>
#include <iostream>

template<class GAMECLASS> 
class BoardGameTest : public CPPUNIT_NS::TestFixture 
{
  CPPUNIT_TEST_SUITE( BoardGameTest );
  CPPUNIT_TEST( testReset );
  CPPUNIT_TEST( testResetShouldFail );
  CPPUNIT_TEST_SUITE_END();
protected:
  GAMECLASS	*m_game;
  
public:
  BoardGameTest()
  {
  }

  int countTestCases () const
  { 
    return 1; 
  }
  
  void setUp() 
  { 
    m_game = new GAMECLASS; 
  }
  
  void tearDown()
  { 
    delete m_game; 
  }
  
  void testReset() 
  { 
    CPPUNIT_ASSERT( m_game->reset() );
  }

  void testResetShouldFail() 
  { 
    std::cout << "The following test fails, this is intended:" << std::endl;
    CPPUNIT_ASSERT( !m_game->reset() );
  }
};

#endif
