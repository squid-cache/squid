TEMPLATE	= lib
CONFIG		+= qt warn_on thread

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
		  ../../include/cppunit/ui/qt/TestRunner.h

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

INTERFACE_DECL_PATH = .
DESTDIR         = ../../lib
TARGET          = qttestrunner
INCLUDEPATH     = ../../include
DEPENDPATH      = .
OBJECTS_DIR     = objs
MOC_DIR         = mocs
#!REQUIRES        = full-config
