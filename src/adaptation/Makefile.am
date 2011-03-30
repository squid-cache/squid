include $(top_srcdir)/src/Common.am
include $(top_srcdir)/src/TestHeaders.am

## make a list of directories for configured adaptation schemes
SUBDIRS =

if USE_ICAP_CLIENT
SUBDIRS += icap
endif

if USE_ECAP
SUBDIRS += ecap
endif

noinst_LTLIBRARIES = libadaptation.la

## start with the code shared among all adaptation schemes
libadaptation_la_SOURCES = \
	AccessCheck.cc \
	AccessCheck.h \
	AccessRule.cc \
	AccessRule.h \
	Answer.cc \
	Answer.h \
	Config.cc \
	Config.h \
	DynamicGroupCfg.cc \
	DynamicGroupCfg.h \
	Elements.cc \
	Elements.h \
	forward.h \
	Initiate.cc \
	Initiate.h \
	Initiator.cc \
	Initiator.h \
	Iterator.cc \
	Iterator.h \
	Message.cc \
	Message.h \
	Service.cc \
	Service.h \
	ServiceConfig.cc \
	ServiceConfig.h \
	ServiceGroups.cc \
	ServiceGroups.h \
	ServiceFilter.cc \
	ServiceFilter.h \
	History.cc \
	History.h 

# add libraries for specific adaptation schemes
libadaptation_la_LIBADD = $(ECAP_LIBS) $(ICAP_LIBS)

libadaptation_la_DEPENDENCIES = $(ECAP_LIBS) $(ICAP_LIBS)
