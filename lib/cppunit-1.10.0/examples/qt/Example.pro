TEMPLATE	= app
CONFIG		= qt warn_on release thread
win32-msvc:INCLUDEPATH		= ../../include
win32-msvc:LIBS			= ../../lib/cppunit.lib ../../lib/qttestrunner.lib
win32-msvc:TMAKE_CXXFLAGS	= /GX /GR
win32-msvc:DEFINES		= QT_DLL QTTESTRUNNER_DLL
HEADERS		= ExampleTestCase.h
SOURCES		= ExampleTestCase.cpp \
		  Main.cpp
INTERFACES	= 
TARGET		= example