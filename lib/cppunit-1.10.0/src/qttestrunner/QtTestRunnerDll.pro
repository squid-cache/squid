TEMPLATE	= lib
CONFIG		= qt warn_on release thread dll
TARGET		= qttestrunner
DESTDIR		= ../../lib
win32-msvc:INCLUDEPATH		= ../../include
win32-msvc:LIBS			= ../../lib/cppunit.lib
win32-msvc:TMAKE_CXXFLAGS	= /GX /GR
win32-msvc:DEFINES		= QT_DLL QTTESTRUNNER_DLL_BUILD

HEADERS		= MostRecentTests.h \
		  TestBrowserDlgImpl.h \
		  TestFailureInfo.h \
		  TestFailureListViewItem.h \
		  TestListViewItem.h \
		  TestRunnerDlgImpl.h \
		  TestRunnerFailureEvent.h \
		  TestRunnerModel.h \
		  TestRunnerModelThreadInterface.h \
		  TestRunnerTestCaseRunEvent.h \
		  TestRunnerThread.h \
		  TestRunnerThreadEvent.h \
		  TestRunnerThreadFinishedEvent.h \
		  ../../include/cppunitui/qt/TestRunner.h
SOURCES		= MostRecentTests.cpp \
		  TestBrowserDlgImpl.cpp \
		  TestFailureInfo.cpp \
		  TestFailureListViewItem.cpp \
		  TestListViewItem.cpp \
		  QtTestRunner.cpp \
		  TestRunnerDlgImpl.cpp \
		  TestRunnerFailureEvent.cpp \
		  TestRunnerModel.cpp \
		  TestRunnerModelThreadInterface.cpp \
		  TestRunnerTestCaseRunEvent.cpp \
		  TestRunnerThread.cpp \
		  TestRunnerThreadEvent.cpp \
		  TestRunnerThreadFinishedEvent.cpp
INTERFACES	= testbrowserdlg.ui \
		  testrunnerdlg.ui