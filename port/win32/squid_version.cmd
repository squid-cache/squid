@echo off
FOR /F "usebackq skip=2 tokens=2 delims=,(" %%i in (`find "AC_INIT" ../../configure.in`) do set PACKAGE_NAME=%%i
FOR /F "usebackq skip=2 tokens=4 delims=, " %%i in (`find "AC_INIT" ../../configure.in`) do set PACKAGE_VERSION=%%i
FOR /F "usebackq skip=2 tokens=5 delims=, " %%i in (`find "AC_INIT" ../../configure.in`) do set PACKAGE_BUGREPORT=%%i
FOR /F "usebackq skip=2 tokens=6 delims=), " %%i in (`find "AC_INIT" ../../configure.in`) do set PACKAGE_TARNAME=%%i
echo PACKAGE_NAME = %PACKAGE_NAME%
echo PACKAGE_TARNAME = %PACKAGE_TARNAME%
echo PACKAGE_VERSION = %PACKAGE_VERSION%
echo PACKAGE_STRING = %PACKAGE_NAME% %PACKAGE_VERSION%
echo PACKAGE_BUGREPORT = %PACKAGE_BUGREPORT%
echo PACKAGE = %PACKAGE_TARNAME%
echo VERSION = %PACKAGE_VERSION%
