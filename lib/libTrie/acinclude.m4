dnl
dnl thanks to autogen, for the template..
dnl
dnl @synopsis  AC_TEST_CHECKFORHUGEOBJECTS
dnl
dnl Test whether -fhuge-objects is available with this c++ compiler. gcc-29.5 series compilers need this on some platform with large objects.
dnl
HUGE_OBJECT_FLAG=""
AC_DEFUN([AC_TEST_CHECKFORHUGEOBJECTS],[
 if test "$GCC" = "yes"; then
  AC_MSG_CHECKING([whether compiler accepts -fhuge-objects])
  AC_CACHE_VAL([ac_cv_test_checkforhugeobjects],[
    ac_cv_test_checkforhugeobjects=`echo "int main(int argc, char **argv) { int foo; }" > conftest.cc
${CXX} -Werror -fhuge-objects -o conftest.bin conftest.cc 2>/dev/null
res=$?
rm -f conftest.*
echo yes
exit $res`
    if [[ $? -ne 0 ]]
    then ac_cv_test_checkforhugeobjects=no
    else if [[ -z "$ac_cv_test_checkforhugeobjects" ]]
         then ac_cv_test_checkforhugeobjects=yes
    fi ; fi
  ]) # end of CACHE_VAL
  AC_MSG_RESULT([${ac_cv_test_checkforhugeobjects}])

  if test "X${ac_cv_test_checkforhugeobjects}" != Xno
  then
    HUGE_OBJECT_FLAG="-fhuge-objects"
  fi
 fi #gcc
]) # end of AC_DEFUN of AC_TEST_CHECKFORHUGEOBJECTS

