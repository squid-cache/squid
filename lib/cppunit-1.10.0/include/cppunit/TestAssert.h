#ifndef CPPUNIT_TESTASSERT_H
#define CPPUNIT_TESTASSERT_H

#include <cppunit/Portability.h>
#include <cppunit/Exception.h>
#include <cppunit/Asserter.h>


CPPUNIT_NS_BEGIN


/*! \brief Traits used by CPPUNIT_ASSERT_EQUAL().
 *
 * Here is an example of specialization of that traits:
 *
 * \code
 * template<>
 * struct assertion_traits<std::string>   // specialization for the std::string type
 * {
 *   static bool equal( const std::string& x, const std::string& y )
 *   {
 *     return x == y;
 *   }
 * 
 *   static std::string toString( const std::string& x )
 *   {
 *     std::string text = '"' + x + '"';    // adds quote around the string to see whitespace
 *     OStringStream ost;
 *     ost << text;
 *     return ost.str();
 *   }
 * };
 * \endcode
 */
template <class T>
struct assertion_traits 
{  
    static bool equal( const T& x, const T& y )
    {
        return x == y;
    }

    static std::string toString( const T& x )
    {
        OStringStream ost;
        ost << x;
        return ost.str();
    }
};


/*! \brief (Implementation) Asserts that two objects of the same type are equals.
 * Use CPPUNIT_ASSERT_EQUAL instead of this function.
 * \sa assertion_traits, Asserter::failNotEqual().
 */
template <class T>
void assertEquals( const T& expected,
                   const T& actual,
                   SourceLine sourceLine,
                   const std::string &message )
{
  if ( !assertion_traits<T>::equal(expected,actual) ) // lazy toString conversion...
  {
    Asserter::failNotEqual( assertion_traits<T>::toString(expected),
                            assertion_traits<T>::toString(actual),
                            sourceLine,
                            message );
  }
}

/*! \brief (Implementation) Asserts that two double are equals given a tolerance.
 * Use CPPUNIT_ASSERT_DOUBLES_EQUAL instead of this function.
 * \sa Asserter::failNotEqual().
 */
void CPPUNIT_API assertDoubleEquals( double expected,
                                     double actual,
                                     double delta,
                                     SourceLine sourceLine );


/* A set of macros which allow us to get the line number
 * and file name at the point of an error.
 * Just goes to show that preprocessors do have some
 * redeeming qualities.
 */
#if CPPUNIT_HAVE_CPP_SOURCE_ANNOTATION
/** Assertions that a condition is \c true.
 * \ingroup Assertions
 */
#define CPPUNIT_ASSERT(condition)                                                 \
  ( CPPUNIT_NS::Asserter::failIf( !(condition),                                   \
                                 CPPUNIT_NS::Message( "assertion failed",         \
                                                      "Expression: " #condition), \
                                 CPPUNIT_SOURCELINE() ) )
#else
#define CPPUNIT_ASSERT(condition)                                            \
  ( CPPUNIT_NS::Asserter::failIf( !(condition),                              \
                                  CPPUNIT_NS::Message( "assertion failed" ), \
                                  CPPUNIT_SOURCELINE() ) )
#endif

/** Assertion with a user specified message.
 * \ingroup Assertions
 * \param message Message reported in diagnostic if \a condition evaluates
 *                to \c false.
 * \param condition If this condition evaluates to \c false then the
 *                  test failed.
 */
#define CPPUNIT_ASSERT_MESSAGE(message,condition)          \
  ( CPPUNIT_NS::Asserter::failIf( !(condition),            \
                                  (message),               \
                                  CPPUNIT_SOURCELINE() ) )

/** Fails with the specified message.
 * \ingroup Assertions
 * \param message Message reported in diagnostic.
 */
#define CPPUNIT_FAIL( message )                                         \
  ( CPPUNIT_NS::Asserter::fail( CPPUNIT_NS::Message( "forced failure",  \
                                                     message ),         \
                                CPPUNIT_SOURCELINE() ) )

#ifdef CPPUNIT_ENABLE_SOURCELINE_DEPRECATED
/// Generalized macro for primitive value comparisons
#define CPPUNIT_ASSERT_EQUAL(expected,actual)                     \
  ( CPPUNIT_NS::assertEquals( (expected),             \
                              (actual),               \
                              __LINE__, __FILE__ ) )
#else
/** Asserts that two values are equals.
 * \ingroup Assertions
 *
 * Equality and string representation can be defined with
 * an appropriate CppUnit::assertion_traits class.
 *
 * A diagnostic is printed if actual and expected values disagree.
 *
 * Requirement for \a expected and \a actual parameters:
 * - They are exactly of the same type
 * - They are serializable into a std::strstream using operator <<.
 * - They can be compared using operator ==. 
 *
 * The last two requirements (serialization and comparison) can be
 * removed by specializing the CppUnit::assertion_traits.
 */
#define CPPUNIT_ASSERT_EQUAL(expected,actual)          \
  ( CPPUNIT_NS::assertEquals( (expected),              \
                              (actual),                \
                              CPPUNIT_SOURCELINE(),    \
                              "" ) )

/** Asserts that two values are equals, provides additional messafe on failure.
 * \ingroup Assertions
 *
 * Equality and string representation can be defined with
 * an appropriate assertion_traits class.
 *
 * A diagnostic is printed if actual and expected values disagree.
 * The message is printed in addition to the expected and actual value
 * to provide additional information.
 *
 * Requirement for \a expected and \a actual parameters:
 * - They are exactly of the same type
 * - They are serializable into a std::strstream using operator <<.
 * - They can be compared using operator ==. 
 *
 * The last two requirements (serialization and comparison) can be
 * removed by specializing the CppUnit::assertion_traits.
 */
#define CPPUNIT_ASSERT_EQUAL_MESSAGE(message,expected,actual)      \
  ( CPPUNIT_NS::assertEquals( (expected),              \
                              (actual),                \
                              CPPUNIT_SOURCELINE(),    \
                              (message) ) )
#endif

/*! \brief Macro for primitive value comparisons
 * \ingroup Assertions
 */
#define CPPUNIT_ASSERT_DOUBLES_EQUAL(expected,actual,delta)        \
  ( CPPUNIT_NS::assertDoubleEquals( (expected),        \
                                    (actual),          \
                                    (delta),           \
                                    CPPUNIT_SOURCELINE() ) )


/** Asserts that the given expression throws an exception of the specified type.
 * \ingroup Assertions
 * Example of usage:
 * \code
 *   std::vector<int> v;
 *  CPPUNIT_ASSERT_THROW( v.at( 50 ), std::out_of_range );
 * \endcode
 */
# define CPPUNIT_ASSERT_THROW( expression, ExceptionType )          \
   do {                                                             \
      bool cpputExceptionThrown_ = false;                           \
      try {                                                         \
         expression;                                                \
      } catch ( const ExceptionType & ) {                           \
         cpputExceptionThrown_ = true;                              \
      }                                                             \
                                                                    \
      if ( cpputExceptionThrown_ )                                  \
         break;                                                     \
                                                                    \
      CPPUNIT_NS::Asserter::fail(                                   \
                     "Expected exception: " #ExceptionType          \
                     " not thrown.",                                \
                     CPPUNIT_SOURCELINE() );                        \
   } while ( false )


// implementation detail
#if CPPUNIT_USE_TYPEINFO_NAME
#define CPPUNIT_EXTRACT_EXCEPTION_TYPE_( exception, no_rtti_message ) \
   CPPUNIT_NS::TypeInfoHelper::getClassName( typeid(exception) )
#else
#define CPPUNIT_EXTRACT_EXCEPTION_TYPE_( exception, no_rtti_message ) \
   std::string( no_rtti_message )
#endif // CPPUNIT_USE_TYPEINFO_NAME

/** Asserts that the given expression does not throw any exceptions.
 * \ingroup Assertions
 * Example of usage:
 * \code
 *   std::vector<int> v;
 *   v.push_back( 10 );
 *  CPPUNIT_ASSERT_NO_THROW( v.at( 0 ) );
 * \endcode
 */
# define CPPUNIT_ASSERT_NO_THROW( expression )                             \
   try {                                                                   \
      expression;                                                          \
   } catch ( const std::exception &e ) {                                   \
      CPPUNIT_NS::Message message( "Unexpected exception caught" );        \
      message.addDetail( "Type: " +                                        \
                   CPPUNIT_EXTRACT_EXCEPTION_TYPE_( e,                     \
                                       "std::exception or derived" ) );    \
      message.addDetail( std::string("What: ") + e.what() );               \
      CPPUNIT_NS::Asserter::fail( message,                                 \
                                  CPPUNIT_SOURCELINE() );                  \
   } catch ( ... ) {                                                       \
      CPPUNIT_NS::Asserter::fail( "Unexpected exception caught",           \
                                  CPPUNIT_SOURCELINE() );                  \
   }

/** Asserts that an assertion fail.
 * \ingroup Assertions
 * Use to test assertions.
 * Example of usage:
 * \code
 *   CPPUNIT_ASSERT_ASSERTION_FAIL( CPPUNIT_ASSERT( 1 == 2 ) );
 * \endcode
 */
# define CPPUNIT_ASSERT_ASSERTION_FAIL( assertion )                 \
   CPPUNIT_ASSERT_THROW( assertion, CPPUNIT_NS::Exception )


/** Asserts that an assertion pass.
 * \ingroup Assertions
 * Use to test assertions.
 * Example of usage:
 * \code
 *   CPPUNIT_ASSERT_ASSERTION_PASS( CPPUNIT_ASSERT( 1 == 1 ) );
 * \endcode
 */
# define CPPUNIT_ASSERT_ASSERTION_PASS( assertion )                 \
   CPPUNIT_ASSERT_NO_THROW( assertion )




// Backwards compatibility

#if CPPUNIT_ENABLE_NAKED_ASSERT

#undef assert
#define assert(c)                 CPPUNIT_ASSERT(c)
#define assertEqual(e,a)          CPPUNIT_ASSERT_EQUAL(e,a)
#define assertDoublesEqual(e,a,d) CPPUNIT_ASSERT_DOUBLES_EQUAL(e,a,d)
#define assertLongsEqual(e,a)     CPPUNIT_ASSERT_EQUAL(e,a)

#endif


CPPUNIT_NS_END

#endif  // CPPUNIT_TESTASSERT_H
