# Microsoft Developer Studio Generated NMAKE File, Based on squid.dsp
!IF "$(CFG)" == ""
CFG=squid - Win32 Debug
!MESSAGE No configuration specified. Defaulting to squid - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "squid - Win32 Release" && "$(CFG)" != "squid - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "squid.mak" CFG="squid - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "squid - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "squid - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "squid - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\squid.exe"

!ELSE 

ALL : "libdigest - Win32 Release" "libnull - Win32 Release" "libawin32 - Win32 Release" "libheap - Win32 Release" "libufs - Win32 Release" "libntlm - Win32 Release" "liblru - Win32 Release" "libbasic - Win32 Release" "squid_conf_default - Win32 Release" "modules - Win32 Release" "libsnmp - Win32 Release" "libntlmauth - Win32 Release" "PerlPreprocessing - Win32 Release" "libmiscutil - Win32 Release" "libgnuregex - Win32 Release" "$(OUTDIR)\squid.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libgnuregex - Win32 ReleaseCLEAN" "libmiscutil - Win32 ReleaseCLEAN" "PerlPreprocessing - Win32 ReleaseCLEAN" "libntlmauth - Win32 ReleaseCLEAN" "libsnmp - Win32 ReleaseCLEAN" "modules - Win32 ReleaseCLEAN" "squid_conf_default - Win32 ReleaseCLEAN" "libbasic - Win32 ReleaseCLEAN" "liblru - Win32 ReleaseCLEAN" "libntlm - Win32 ReleaseCLEAN" "libufs - Win32 ReleaseCLEAN" "libheap - Win32 ReleaseCLEAN" "libawin32 - Win32 ReleaseCLEAN" "libnull - Win32 ReleaseCLEAN" "libdigest - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\access_log.obj"
	-@erase "$(INTDIR)\acl.obj"
	-@erase "$(INTDIR)\asn.obj"
	-@erase "$(INTDIR)\auth_modules.obj"
	-@erase "$(INTDIR)\authenticate.obj"
	-@erase "$(INTDIR)\cache_cf.obj"
	-@erase "$(INTDIR)\cache_manager.obj"
	-@erase "$(INTDIR)\CacheDigest.obj"
	-@erase "$(INTDIR)\carp.obj"
	-@erase "$(INTDIR)\cbdata.obj"
	-@erase "$(INTDIR)\client_db.obj"
	-@erase "$(INTDIR)\client_side.obj"
	-@erase "$(INTDIR)\comm.obj"
	-@erase "$(INTDIR)\comm_select.obj"
	-@erase "$(INTDIR)\comm_win32.obj"
	-@erase "$(INTDIR)\debug.obj"
	-@erase "$(INTDIR)\delay_pools.obj"
	-@erase "$(INTDIR)\disk.obj"
	-@erase "$(INTDIR)\dns_internal.obj"
	-@erase "$(INTDIR)\errorpage.obj"
	-@erase "$(INTDIR)\ETag.obj"
	-@erase "$(INTDIR)\event.obj"
	-@erase "$(INTDIR)\fd.obj"
	-@erase "$(INTDIR)\filemap.obj"
	-@erase "$(INTDIR)\forward.obj"
	-@erase "$(INTDIR)\fqdncache.obj"
	-@erase "$(INTDIR)\ftp.obj"
	-@erase "$(INTDIR)\globals.obj"
	-@erase "$(INTDIR)\gopher.obj"
	-@erase "$(INTDIR)\helper.obj"
	-@erase "$(INTDIR)\htcp.obj"
	-@erase "$(INTDIR)\http.obj"
	-@erase "$(INTDIR)\HttpBody.obj"
	-@erase "$(INTDIR)\HttpHdrCc.obj"
	-@erase "$(INTDIR)\HttpHdrContRange.obj"
	-@erase "$(INTDIR)\HttpHdrRange.obj"
	-@erase "$(INTDIR)\HttpHeader.obj"
	-@erase "$(INTDIR)\HttpHeaderTools.obj"
	-@erase "$(INTDIR)\HttpMsg.obj"
	-@erase "$(INTDIR)\HttpReply.obj"
	-@erase "$(INTDIR)\HttpRequest.obj"
	-@erase "$(INTDIR)\HttpStatusLine.obj"
	-@erase "$(INTDIR)\icmp.obj"
	-@erase "$(INTDIR)\icp_v2.obj"
	-@erase "$(INTDIR)\icp_v3.obj"
	-@erase "$(INTDIR)\ident.obj"
	-@erase "$(INTDIR)\internal.obj"
	-@erase "$(INTDIR)\ipc.obj"
	-@erase "$(INTDIR)\ipcache.obj"
	-@erase "$(INTDIR)\leakfinder.obj"
	-@erase "$(INTDIR)\logfile.obj"
	-@erase "$(INTDIR)\main.obj"
	-@erase "$(INTDIR)\mem.obj"
	-@erase "$(INTDIR)\MemBuf.obj"
	-@erase "$(INTDIR)\mime.obj"
	-@erase "$(INTDIR)\multicast.obj"
	-@erase "$(INTDIR)\neighbors.obj"
	-@erase "$(INTDIR)\net_db.obj"
	-@erase "$(INTDIR)\Packer.obj"
	-@erase "$(INTDIR)\pconn.obj"
	-@erase "$(INTDIR)\peer_digest.obj"
	-@erase "$(INTDIR)\peer_select.obj"
	-@erase "$(INTDIR)\redirect.obj"
	-@erase "$(INTDIR)\referer.obj"
	-@erase "$(INTDIR)\refresh.obj"
	-@erase "$(INTDIR)\repl_modules.obj"
	-@erase "$(INTDIR)\send-announce.obj"
	-@erase "$(INTDIR)\snmp_agent.obj"
	-@erase "$(INTDIR)\snmp_core.obj"
	-@erase "$(INTDIR)\ssl.obj"
	-@erase "$(INTDIR)\stat.obj"
	-@erase "$(INTDIR)\StatHist.obj"
	-@erase "$(INTDIR)\stmem.obj"
	-@erase "$(INTDIR)\store.obj"
	-@erase "$(INTDIR)\store_client.obj"
	-@erase "$(INTDIR)\store_digest.obj"
	-@erase "$(INTDIR)\store_dir.obj"
	-@erase "$(INTDIR)\store_io.obj"
	-@erase "$(INTDIR)\store_key_md5.obj"
	-@erase "$(INTDIR)\store_log.obj"
	-@erase "$(INTDIR)\store_modules.obj"
	-@erase "$(INTDIR)\store_rebuild.obj"
	-@erase "$(INTDIR)\store_swapin.obj"
	-@erase "$(INTDIR)\store_swapmeta.obj"
	-@erase "$(INTDIR)\store_swapout.obj"
	-@erase "$(INTDIR)\String.obj"
	-@erase "$(INTDIR)\string_arrays.obj"
	-@erase "$(INTDIR)\tools.obj"
	-@erase "$(INTDIR)\unlinkd.obj"
	-@erase "$(INTDIR)\url.obj"
	-@erase "$(INTDIR)\urn.obj"
	-@erase "$(INTDIR)\useragent.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\wais.obj"
	-@erase "$(INTDIR)\wccp.obj"
	-@erase "$(INTDIR)\whois.obj"
	-@erase "$(INTDIR)\win32.obj"
	-@erase "$(OUTDIR)\squid.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /G6 /MT /W3 /GX /O2 /I "../../" /I "../include" /I "../../../include" /I "../../../src" /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D "HAVE_CONFIG_H" /Fp"$(INTDIR)\squid.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\squid.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=ws2_32.lib advapi32.lib psapi.lib pthreadVC.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\squid.pdb" /machine:I386 /out:"$(OUTDIR)\squid.exe" 
LINK32_OBJS= \
	"$(INTDIR)\access_log.obj" \
	"$(INTDIR)\acl.obj" \
	"$(INTDIR)\asn.obj" \
	"$(INTDIR)\auth_modules.obj" \
	"$(INTDIR)\authenticate.obj" \
	"$(INTDIR)\cache_cf.obj" \
	"$(INTDIR)\cache_manager.obj" \
	"$(INTDIR)\CacheDigest.obj" \
	"$(INTDIR)\carp.obj" \
	"$(INTDIR)\cbdata.obj" \
	"$(INTDIR)\client_db.obj" \
	"$(INTDIR)\client_side.obj" \
	"$(INTDIR)\comm.obj" \
	"$(INTDIR)\comm_select.obj" \
	"$(INTDIR)\comm_win32.obj" \
	"$(INTDIR)\debug.obj" \
	"$(INTDIR)\delay_pools.obj" \
	"$(INTDIR)\disk.obj" \
	"$(INTDIR)\dns_internal.obj" \
	"$(INTDIR)\errorpage.obj" \
	"$(INTDIR)\ETag.obj" \
	"$(INTDIR)\event.obj" \
	"$(INTDIR)\fd.obj" \
	"$(INTDIR)\filemap.obj" \
	"$(INTDIR)\forward.obj" \
	"$(INTDIR)\fqdncache.obj" \
	"$(INTDIR)\ftp.obj" \
	"$(INTDIR)\globals.obj" \
	"$(INTDIR)\gopher.obj" \
	"$(INTDIR)\helper.obj" \
	"$(INTDIR)\htcp.obj" \
	"$(INTDIR)\http.obj" \
	"$(INTDIR)\HttpBody.obj" \
	"$(INTDIR)\HttpHdrCc.obj" \
	"$(INTDIR)\HttpHdrContRange.obj" \
	"$(INTDIR)\HttpHdrRange.obj" \
	"$(INTDIR)\HttpHeader.obj" \
	"$(INTDIR)\HttpHeaderTools.obj" \
	"$(INTDIR)\HttpMsg.obj" \
	"$(INTDIR)\HttpReply.obj" \
	"$(INTDIR)\HttpRequest.obj" \
	"$(INTDIR)\HttpStatusLine.obj" \
	"$(INTDIR)\icmp.obj" \
	"$(INTDIR)\icp_v2.obj" \
	"$(INTDIR)\icp_v3.obj" \
	"$(INTDIR)\ident.obj" \
	"$(INTDIR)\internal.obj" \
	"$(INTDIR)\ipc.obj" \
	"$(INTDIR)\ipcache.obj" \
	"$(INTDIR)\leakfinder.obj" \
	"$(INTDIR)\logfile.obj" \
	"$(INTDIR)\main.obj" \
	"$(INTDIR)\mem.obj" \
	"$(INTDIR)\MemBuf.obj" \
	"$(INTDIR)\mime.obj" \
	"$(INTDIR)\multicast.obj" \
	"$(INTDIR)\neighbors.obj" \
	"$(INTDIR)\net_db.obj" \
	"$(INTDIR)\Packer.obj" \
	"$(INTDIR)\pconn.obj" \
	"$(INTDIR)\peer_digest.obj" \
	"$(INTDIR)\peer_select.obj" \
	"$(INTDIR)\redirect.obj" \
	"$(INTDIR)\referer.obj" \
	"$(INTDIR)\refresh.obj" \
	"$(INTDIR)\repl_modules.obj" \
	"$(INTDIR)\send-announce.obj" \
	"$(INTDIR)\snmp_agent.obj" \
	"$(INTDIR)\snmp_core.obj" \
	"$(INTDIR)\ssl.obj" \
	"$(INTDIR)\stat.obj" \
	"$(INTDIR)\StatHist.obj" \
	"$(INTDIR)\stmem.obj" \
	"$(INTDIR)\store.obj" \
	"$(INTDIR)\store_client.obj" \
	"$(INTDIR)\store_digest.obj" \
	"$(INTDIR)\store_dir.obj" \
	"$(INTDIR)\store_io.obj" \
	"$(INTDIR)\store_key_md5.obj" \
	"$(INTDIR)\store_log.obj" \
	"$(INTDIR)\store_modules.obj" \
	"$(INTDIR)\store_rebuild.obj" \
	"$(INTDIR)\store_swapin.obj" \
	"$(INTDIR)\store_swapmeta.obj" \
	"$(INTDIR)\store_swapout.obj" \
	"$(INTDIR)\String.obj" \
	"$(INTDIR)\string_arrays.obj" \
	"$(INTDIR)\tools.obj" \
	"$(INTDIR)\unlinkd.obj" \
	"$(INTDIR)\url.obj" \
	"$(INTDIR)\urn.obj" \
	"$(INTDIR)\useragent.obj" \
	"$(INTDIR)\wais.obj" \
	"$(INTDIR)\wccp.obj" \
	"$(INTDIR)\whois.obj" \
	"$(INTDIR)\win32.obj" \
	"..\libgnuregex\Release\libgnuregex.lib" \
	"..\libmiscutil\Release\libmiscutil.lib" \
	"..\libntlmauth\Release\libntlmauth.lib" \
	"..\libsnmp\Release\libsnmp.lib" \
	"..\libbasic\Release\libbasic.lib" \
	"..\liblru\Release\liblru.lib" \
	"..\libntlm\Release\libntlm.lib" \
	"..\libufs\Release\libufs.lib" \
	"..\libheap\Release\libheap.lib" \
	"..\libawin32\Release\libawin32.lib" \
	"..\libnull\Release\libnull.lib" \
	"..\libdigest\Release\libdigest.lib"

"$(OUTDIR)\squid.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "squid - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\squid.exe"

!ELSE 

ALL : "libdigest - Win32 Debug" "libnull - Win32 Debug" "libawin32 - Win32 Debug" "libheap - Win32 Debug" "libufs - Win32 Debug" "libntlm - Win32 Debug" "liblru - Win32 Debug" "libbasic - Win32 Debug" "squid_conf_default - Win32 Debug" "modules - Win32 Debug" "libsnmp - Win32 Debug" "libntlmauth - Win32 Debug" "PerlPreprocessing - Win32 Debug" "libmiscutil - Win32 Debug" "libgnuregex - Win32 Debug" "$(OUTDIR)\squid.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libgnuregex - Win32 DebugCLEAN" "libmiscutil - Win32 DebugCLEAN" "PerlPreprocessing - Win32 DebugCLEAN" "libntlmauth - Win32 DebugCLEAN" "libsnmp - Win32 DebugCLEAN" "modules - Win32 DebugCLEAN" "squid_conf_default - Win32 DebugCLEAN" "libbasic - Win32 DebugCLEAN" "liblru - Win32 DebugCLEAN" "libntlm - Win32 DebugCLEAN" "libufs - Win32 DebugCLEAN" "libheap - Win32 DebugCLEAN" "libawin32 - Win32 DebugCLEAN" "libnull - Win32 DebugCLEAN" "libdigest - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\access_log.obj"
	-@erase "$(INTDIR)\acl.obj"
	-@erase "$(INTDIR)\asn.obj"
	-@erase "$(INTDIR)\auth_modules.obj"
	-@erase "$(INTDIR)\authenticate.obj"
	-@erase "$(INTDIR)\cache_cf.obj"
	-@erase "$(INTDIR)\cache_manager.obj"
	-@erase "$(INTDIR)\CacheDigest.obj"
	-@erase "$(INTDIR)\carp.obj"
	-@erase "$(INTDIR)\cbdata.obj"
	-@erase "$(INTDIR)\client_db.obj"
	-@erase "$(INTDIR)\client_side.obj"
	-@erase "$(INTDIR)\comm.obj"
	-@erase "$(INTDIR)\comm_select.obj"
	-@erase "$(INTDIR)\comm_win32.obj"
	-@erase "$(INTDIR)\debug.obj"
	-@erase "$(INTDIR)\delay_pools.obj"
	-@erase "$(INTDIR)\disk.obj"
	-@erase "$(INTDIR)\dns_internal.obj"
	-@erase "$(INTDIR)\errorpage.obj"
	-@erase "$(INTDIR)\ETag.obj"
	-@erase "$(INTDIR)\event.obj"
	-@erase "$(INTDIR)\fd.obj"
	-@erase "$(INTDIR)\filemap.obj"
	-@erase "$(INTDIR)\forward.obj"
	-@erase "$(INTDIR)\fqdncache.obj"
	-@erase "$(INTDIR)\ftp.obj"
	-@erase "$(INTDIR)\globals.obj"
	-@erase "$(INTDIR)\gopher.obj"
	-@erase "$(INTDIR)\helper.obj"
	-@erase "$(INTDIR)\htcp.obj"
	-@erase "$(INTDIR)\http.obj"
	-@erase "$(INTDIR)\HttpBody.obj"
	-@erase "$(INTDIR)\HttpHdrCc.obj"
	-@erase "$(INTDIR)\HttpHdrContRange.obj"
	-@erase "$(INTDIR)\HttpHdrRange.obj"
	-@erase "$(INTDIR)\HttpHeader.obj"
	-@erase "$(INTDIR)\HttpHeaderTools.obj"
	-@erase "$(INTDIR)\HttpMsg.obj"
	-@erase "$(INTDIR)\HttpReply.obj"
	-@erase "$(INTDIR)\HttpRequest.obj"
	-@erase "$(INTDIR)\HttpStatusLine.obj"
	-@erase "$(INTDIR)\icmp.obj"
	-@erase "$(INTDIR)\icp_v2.obj"
	-@erase "$(INTDIR)\icp_v3.obj"
	-@erase "$(INTDIR)\ident.obj"
	-@erase "$(INTDIR)\internal.obj"
	-@erase "$(INTDIR)\ipc.obj"
	-@erase "$(INTDIR)\ipcache.obj"
	-@erase "$(INTDIR)\leakfinder.obj"
	-@erase "$(INTDIR)\logfile.obj"
	-@erase "$(INTDIR)\main.obj"
	-@erase "$(INTDIR)\mem.obj"
	-@erase "$(INTDIR)\MemBuf.obj"
	-@erase "$(INTDIR)\mime.obj"
	-@erase "$(INTDIR)\multicast.obj"
	-@erase "$(INTDIR)\neighbors.obj"
	-@erase "$(INTDIR)\net_db.obj"
	-@erase "$(INTDIR)\Packer.obj"
	-@erase "$(INTDIR)\pconn.obj"
	-@erase "$(INTDIR)\peer_digest.obj"
	-@erase "$(INTDIR)\peer_select.obj"
	-@erase "$(INTDIR)\redirect.obj"
	-@erase "$(INTDIR)\referer.obj"
	-@erase "$(INTDIR)\refresh.obj"
	-@erase "$(INTDIR)\repl_modules.obj"
	-@erase "$(INTDIR)\send-announce.obj"
	-@erase "$(INTDIR)\snmp_agent.obj"
	-@erase "$(INTDIR)\snmp_core.obj"
	-@erase "$(INTDIR)\ssl.obj"
	-@erase "$(INTDIR)\stat.obj"
	-@erase "$(INTDIR)\StatHist.obj"
	-@erase "$(INTDIR)\stmem.obj"
	-@erase "$(INTDIR)\store.obj"
	-@erase "$(INTDIR)\store_client.obj"
	-@erase "$(INTDIR)\store_digest.obj"
	-@erase "$(INTDIR)\store_dir.obj"
	-@erase "$(INTDIR)\store_io.obj"
	-@erase "$(INTDIR)\store_key_md5.obj"
	-@erase "$(INTDIR)\store_log.obj"
	-@erase "$(INTDIR)\store_modules.obj"
	-@erase "$(INTDIR)\store_rebuild.obj"
	-@erase "$(INTDIR)\store_swapin.obj"
	-@erase "$(INTDIR)\store_swapmeta.obj"
	-@erase "$(INTDIR)\store_swapout.obj"
	-@erase "$(INTDIR)\String.obj"
	-@erase "$(INTDIR)\string_arrays.obj"
	-@erase "$(INTDIR)\tools.obj"
	-@erase "$(INTDIR)\unlinkd.obj"
	-@erase "$(INTDIR)\url.obj"
	-@erase "$(INTDIR)\urn.obj"
	-@erase "$(INTDIR)\useragent.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\vc60.pdb"
	-@erase "$(INTDIR)\wais.obj"
	-@erase "$(INTDIR)\wccp.obj"
	-@erase "$(INTDIR)\whois.obj"
	-@erase "$(INTDIR)\win32.obj"
	-@erase "$(OUTDIR)\squid.exe"
	-@erase "$(OUTDIR)\squid.ilk"
	-@erase "$(OUTDIR)\squid.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /G6 /MTd /W3 /Gm /GX /ZI /Od /I "../include" /I "../../../include" /I "../../../src" /D "_DEBUG" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D "HAVE_CONFIG_H" /Fp"$(INTDIR)\squid.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\squid.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=ws2_32.lib advapi32.lib psapi.lib iphlpapi.lib pthreadVC.lib /nologo /subsystem:console /incremental:yes /pdb:"$(OUTDIR)\squid.pdb" /debug /machine:I386 /out:"$(OUTDIR)\squid.exe" /pdbtype:sept 
LINK32_OBJS= \
	"$(INTDIR)\access_log.obj" \
	"$(INTDIR)\acl.obj" \
	"$(INTDIR)\asn.obj" \
	"$(INTDIR)\auth_modules.obj" \
	"$(INTDIR)\authenticate.obj" \
	"$(INTDIR)\cache_cf.obj" \
	"$(INTDIR)\cache_manager.obj" \
	"$(INTDIR)\CacheDigest.obj" \
	"$(INTDIR)\carp.obj" \
	"$(INTDIR)\cbdata.obj" \
	"$(INTDIR)\client_db.obj" \
	"$(INTDIR)\client_side.obj" \
	"$(INTDIR)\comm.obj" \
	"$(INTDIR)\comm_select.obj" \
	"$(INTDIR)\comm_win32.obj" \
	"$(INTDIR)\debug.obj" \
	"$(INTDIR)\delay_pools.obj" \
	"$(INTDIR)\disk.obj" \
	"$(INTDIR)\dns_internal.obj" \
	"$(INTDIR)\errorpage.obj" \
	"$(INTDIR)\ETag.obj" \
	"$(INTDIR)\event.obj" \
	"$(INTDIR)\fd.obj" \
	"$(INTDIR)\filemap.obj" \
	"$(INTDIR)\forward.obj" \
	"$(INTDIR)\fqdncache.obj" \
	"$(INTDIR)\ftp.obj" \
	"$(INTDIR)\globals.obj" \
	"$(INTDIR)\gopher.obj" \
	"$(INTDIR)\helper.obj" \
	"$(INTDIR)\htcp.obj" \
	"$(INTDIR)\http.obj" \
	"$(INTDIR)\HttpBody.obj" \
	"$(INTDIR)\HttpHdrCc.obj" \
	"$(INTDIR)\HttpHdrContRange.obj" \
	"$(INTDIR)\HttpHdrRange.obj" \
	"$(INTDIR)\HttpHeader.obj" \
	"$(INTDIR)\HttpHeaderTools.obj" \
	"$(INTDIR)\HttpMsg.obj" \
	"$(INTDIR)\HttpReply.obj" \
	"$(INTDIR)\HttpRequest.obj" \
	"$(INTDIR)\HttpStatusLine.obj" \
	"$(INTDIR)\icmp.obj" \
	"$(INTDIR)\icp_v2.obj" \
	"$(INTDIR)\icp_v3.obj" \
	"$(INTDIR)\ident.obj" \
	"$(INTDIR)\internal.obj" \
	"$(INTDIR)\ipc.obj" \
	"$(INTDIR)\ipcache.obj" \
	"$(INTDIR)\leakfinder.obj" \
	"$(INTDIR)\logfile.obj" \
	"$(INTDIR)\main.obj" \
	"$(INTDIR)\mem.obj" \
	"$(INTDIR)\MemBuf.obj" \
	"$(INTDIR)\mime.obj" \
	"$(INTDIR)\multicast.obj" \
	"$(INTDIR)\neighbors.obj" \
	"$(INTDIR)\net_db.obj" \
	"$(INTDIR)\Packer.obj" \
	"$(INTDIR)\pconn.obj" \
	"$(INTDIR)\peer_digest.obj" \
	"$(INTDIR)\peer_select.obj" \
	"$(INTDIR)\redirect.obj" \
	"$(INTDIR)\referer.obj" \
	"$(INTDIR)\refresh.obj" \
	"$(INTDIR)\repl_modules.obj" \
	"$(INTDIR)\send-announce.obj" \
	"$(INTDIR)\snmp_agent.obj" \
	"$(INTDIR)\snmp_core.obj" \
	"$(INTDIR)\ssl.obj" \
	"$(INTDIR)\stat.obj" \
	"$(INTDIR)\StatHist.obj" \
	"$(INTDIR)\stmem.obj" \
	"$(INTDIR)\store.obj" \
	"$(INTDIR)\store_client.obj" \
	"$(INTDIR)\store_digest.obj" \
	"$(INTDIR)\store_dir.obj" \
	"$(INTDIR)\store_io.obj" \
	"$(INTDIR)\store_key_md5.obj" \
	"$(INTDIR)\store_log.obj" \
	"$(INTDIR)\store_modules.obj" \
	"$(INTDIR)\store_rebuild.obj" \
	"$(INTDIR)\store_swapin.obj" \
	"$(INTDIR)\store_swapmeta.obj" \
	"$(INTDIR)\store_swapout.obj" \
	"$(INTDIR)\String.obj" \
	"$(INTDIR)\string_arrays.obj" \
	"$(INTDIR)\tools.obj" \
	"$(INTDIR)\unlinkd.obj" \
	"$(INTDIR)\url.obj" \
	"$(INTDIR)\urn.obj" \
	"$(INTDIR)\useragent.obj" \
	"$(INTDIR)\wais.obj" \
	"$(INTDIR)\wccp.obj" \
	"$(INTDIR)\whois.obj" \
	"$(INTDIR)\win32.obj" \
	"..\libgnuregex\Debug\libgnuregex.lib" \
	"..\libmiscutil\Debug\libmiscutil.lib" \
	"..\libntlmauth\Debug\libntlmauth.lib" \
	"..\libsnmp\Debug\libsnmp.lib" \
	"..\libbasic\Debug\libbasic.lib" \
	"..\liblru\Debug\liblru.lib" \
	"..\libntlm\Debug\libntlm.lib" \
	"..\libufs\Debug\libufs.lib" \
	"..\libheap\Debug\libheap.lib" \
	"..\libawin32\Debug\libawin32.lib" \
	"..\libnull\Debug\libnull.lib" \
	"..\libdigest\Debug\libdigest.lib"

"$(OUTDIR)\squid.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("squid.dep")
!INCLUDE "squid.dep"
!ELSE 
!MESSAGE Warning: cannot find "squid.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "squid - Win32 Release" || "$(CFG)" == "squid - Win32 Debug"
SOURCE=..\..\..\src\access_log.c

"$(INTDIR)\access_log.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\acl.c

"$(INTDIR)\acl.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\asn.c

"$(INTDIR)\asn.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\auth_modules.c

"$(INTDIR)\auth_modules.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\authenticate.c

"$(INTDIR)\authenticate.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\cache_cf.c

"$(INTDIR)\cache_cf.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\cache_manager.c

"$(INTDIR)\cache_manager.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\CacheDigest.c

"$(INTDIR)\CacheDigest.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\carp.c

"$(INTDIR)\carp.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\cbdata.c

"$(INTDIR)\cbdata.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\client_db.c

"$(INTDIR)\client_db.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\client_side.c

"$(INTDIR)\client_side.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\comm.c

"$(INTDIR)\comm.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\comm_select.c

"$(INTDIR)\comm_select.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\src\comm_win32.c

"$(INTDIR)\comm_win32.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\debug.c

"$(INTDIR)\debug.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\delay_pools.c

"$(INTDIR)\delay_pools.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\disk.c

"$(INTDIR)\disk.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\dns_internal.c

"$(INTDIR)\dns_internal.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\errorpage.c

"$(INTDIR)\errorpage.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\ETag.c

"$(INTDIR)\ETag.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\event.c

"$(INTDIR)\event.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\fd.c

"$(INTDIR)\fd.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\filemap.c

"$(INTDIR)\filemap.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\forward.c

"$(INTDIR)\forward.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\fqdncache.c

"$(INTDIR)\fqdncache.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\ftp.c

"$(INTDIR)\ftp.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\globals.c

"$(INTDIR)\globals.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\gopher.c

"$(INTDIR)\gopher.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\helper.c

"$(INTDIR)\helper.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\htcp.c

"$(INTDIR)\htcp.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\http.c

"$(INTDIR)\http.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\HttpBody.c

"$(INTDIR)\HttpBody.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\HttpHdrCc.c

"$(INTDIR)\HttpHdrCc.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\HttpHdrContRange.c

"$(INTDIR)\HttpHdrContRange.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\HttpHdrRange.c

"$(INTDIR)\HttpHdrRange.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\HttpHeader.c

"$(INTDIR)\HttpHeader.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\HttpHeaderTools.c

"$(INTDIR)\HttpHeaderTools.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\HttpMsg.c

"$(INTDIR)\HttpMsg.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\HttpReply.c

"$(INTDIR)\HttpReply.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\HttpRequest.c

"$(INTDIR)\HttpRequest.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\HttpStatusLine.c

"$(INTDIR)\HttpStatusLine.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\icmp.c

"$(INTDIR)\icmp.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\icp_v2.c

"$(INTDIR)\icp_v2.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\icp_v3.c

"$(INTDIR)\icp_v3.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\ident.c

"$(INTDIR)\ident.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\internal.c

"$(INTDIR)\internal.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\ipc.c

"$(INTDIR)\ipc.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\ipcache.c

"$(INTDIR)\ipcache.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\leakfinder.c

"$(INTDIR)\leakfinder.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\logfile.c

"$(INTDIR)\logfile.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\main.c

"$(INTDIR)\main.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\mem.c

"$(INTDIR)\mem.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\MemBuf.c

"$(INTDIR)\MemBuf.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\mime.c

"$(INTDIR)\mime.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\multicast.c

"$(INTDIR)\multicast.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\neighbors.c

"$(INTDIR)\neighbors.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\net_db.c

"$(INTDIR)\net_db.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\Packer.c

"$(INTDIR)\Packer.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\pconn.c

"$(INTDIR)\pconn.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\peer_digest.c

"$(INTDIR)\peer_digest.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\peer_select.c

"$(INTDIR)\peer_select.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\redirect.c

"$(INTDIR)\redirect.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\referer.c

"$(INTDIR)\referer.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\refresh.c

"$(INTDIR)\refresh.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\repl_modules.c

"$(INTDIR)\repl_modules.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE="..\..\..\src\send-announce.c"

"$(INTDIR)\send-announce.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\snmp_agent.c

"$(INTDIR)\snmp_agent.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\snmp_core.c

"$(INTDIR)\snmp_core.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\ssl.c

"$(INTDIR)\ssl.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\stat.c

"$(INTDIR)\stat.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\StatHist.c

"$(INTDIR)\StatHist.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\stmem.c

"$(INTDIR)\stmem.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\store.c

"$(INTDIR)\store.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\store_client.c

"$(INTDIR)\store_client.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\store_digest.c

"$(INTDIR)\store_digest.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\store_dir.c

"$(INTDIR)\store_dir.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\store_io.c

"$(INTDIR)\store_io.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\store_key_md5.c

"$(INTDIR)\store_key_md5.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\store_log.c

"$(INTDIR)\store_log.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\store_modules.c

"$(INTDIR)\store_modules.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\store_rebuild.c

"$(INTDIR)\store_rebuild.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\store_swapin.c

"$(INTDIR)\store_swapin.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\store_swapmeta.c

"$(INTDIR)\store_swapmeta.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\store_swapout.c

"$(INTDIR)\store_swapout.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\String.c

"$(INTDIR)\String.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\string_arrays.c

"$(INTDIR)\string_arrays.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\tools.c

"$(INTDIR)\tools.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\unlinkd.c

"$(INTDIR)\unlinkd.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\url.c

"$(INTDIR)\url.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\urn.c

"$(INTDIR)\urn.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\useragent.c

"$(INTDIR)\useragent.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\wais.c

"$(INTDIR)\wais.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\wccp.c

"$(INTDIR)\wccp.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\whois.c

"$(INTDIR)\whois.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\..\src\win32.c

"$(INTDIR)\win32.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!IF  "$(CFG)" == "squid - Win32 Release"

"libgnuregex - Win32 Release" : 
   cd "\work\nt\port\win32\libgnuregex"
   $(MAKE) /$(MAKEFLAGS) /F .\libgnuregex.mak CFG="libgnuregex - Win32 Release" 
   cd "..\squid"

"libgnuregex - Win32 ReleaseCLEAN" : 
   cd "\work\nt\port\win32\libgnuregex"
   $(MAKE) /$(MAKEFLAGS) /F .\libgnuregex.mak CFG="libgnuregex - Win32 Release" RECURSE=1 CLEAN 
   cd "..\squid"

!ELSEIF  "$(CFG)" == "squid - Win32 Debug"

"libgnuregex - Win32 Debug" : 
   cd "\work\nt\port\win32\libgnuregex"
   $(MAKE) /$(MAKEFLAGS) /F .\libgnuregex.mak CFG="libgnuregex - Win32 Debug" 
   cd "..\squid"

"libgnuregex - Win32 DebugCLEAN" : 
   cd "\work\nt\port\win32\libgnuregex"
   $(MAKE) /$(MAKEFLAGS) /F .\libgnuregex.mak CFG="libgnuregex - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\squid"

!ENDIF 

!IF  "$(CFG)" == "squid - Win32 Release"

"libmiscutil - Win32 Release" : 
   cd "\work\nt\port\win32\libmiscutil"
   $(MAKE) /$(MAKEFLAGS) /F .\libmiscutil.mak CFG="libmiscutil - Win32 Release" 
   cd "..\squid"

"libmiscutil - Win32 ReleaseCLEAN" : 
   cd "\work\nt\port\win32\libmiscutil"
   $(MAKE) /$(MAKEFLAGS) /F .\libmiscutil.mak CFG="libmiscutil - Win32 Release" RECURSE=1 CLEAN 
   cd "..\squid"

!ELSEIF  "$(CFG)" == "squid - Win32 Debug"

"libmiscutil - Win32 Debug" : 
   cd "\work\nt\port\win32\libmiscutil"
   $(MAKE) /$(MAKEFLAGS) /F .\libmiscutil.mak CFG="libmiscutil - Win32 Debug" 
   cd "..\squid"

"libmiscutil - Win32 DebugCLEAN" : 
   cd "\work\nt\port\win32\libmiscutil"
   $(MAKE) /$(MAKEFLAGS) /F .\libmiscutil.mak CFG="libmiscutil - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\squid"

!ENDIF 

!IF  "$(CFG)" == "squid - Win32 Release"

"PerlPreprocessing - Win32 Release" : 
   cd "\work\nt\port\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\PerlPreprocessing.mak CFG="PerlPreprocessing - Win32 Release" 
   cd ".\squid"

"PerlPreprocessing - Win32 ReleaseCLEAN" : 
   cd "\work\nt\port\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\PerlPreprocessing.mak CFG="PerlPreprocessing - Win32 Release" RECURSE=1 CLEAN 
   cd ".\squid"

!ELSEIF  "$(CFG)" == "squid - Win32 Debug"

"PerlPreprocessing - Win32 Debug" : 
   cd "\work\nt\port\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\PerlPreprocessing.mak CFG="PerlPreprocessing - Win32 Debug" 
   cd ".\squid"

"PerlPreprocessing - Win32 DebugCLEAN" : 
   cd "\work\nt\port\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\PerlPreprocessing.mak CFG="PerlPreprocessing - Win32 Debug" RECURSE=1 CLEAN 
   cd ".\squid"

!ENDIF 

!IF  "$(CFG)" == "squid - Win32 Release"

"libntlmauth - Win32 Release" : 
   cd "\work\nt\port\win32\libntlmauth"
   $(MAKE) /$(MAKEFLAGS) /F .\libntlmauth.mak CFG="libntlmauth - Win32 Release" 
   cd "..\squid"

"libntlmauth - Win32 ReleaseCLEAN" : 
   cd "\work\nt\port\win32\libntlmauth"
   $(MAKE) /$(MAKEFLAGS) /F .\libntlmauth.mak CFG="libntlmauth - Win32 Release" RECURSE=1 CLEAN 
   cd "..\squid"

!ELSEIF  "$(CFG)" == "squid - Win32 Debug"

"libntlmauth - Win32 Debug" : 
   cd "\work\nt\port\win32\libntlmauth"
   $(MAKE) /$(MAKEFLAGS) /F .\libntlmauth.mak CFG="libntlmauth - Win32 Debug" 
   cd "..\squid"

"libntlmauth - Win32 DebugCLEAN" : 
   cd "\work\nt\port\win32\libntlmauth"
   $(MAKE) /$(MAKEFLAGS) /F .\libntlmauth.mak CFG="libntlmauth - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\squid"

!ENDIF 

!IF  "$(CFG)" == "squid - Win32 Release"

"libsnmp - Win32 Release" : 
   cd "\work\nt\port\win32\libsnmp"
   $(MAKE) /$(MAKEFLAGS) /F .\libsnmp.mak CFG="libsnmp - Win32 Release" 
   cd "..\squid"

"libsnmp - Win32 ReleaseCLEAN" : 
   cd "\work\nt\port\win32\libsnmp"
   $(MAKE) /$(MAKEFLAGS) /F .\libsnmp.mak CFG="libsnmp - Win32 Release" RECURSE=1 CLEAN 
   cd "..\squid"

!ELSEIF  "$(CFG)" == "squid - Win32 Debug"

"libsnmp - Win32 Debug" : 
   cd "\work\nt\port\win32\libsnmp"
   $(MAKE) /$(MAKEFLAGS) /F .\libsnmp.mak CFG="libsnmp - Win32 Debug" 
   cd "..\squid"

"libsnmp - Win32 DebugCLEAN" : 
   cd "\work\nt\port\win32\libsnmp"
   $(MAKE) /$(MAKEFLAGS) /F .\libsnmp.mak CFG="libsnmp - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\squid"

!ENDIF 

!IF  "$(CFG)" == "squid - Win32 Release"

"modules - Win32 Release" : 
   cd "\work\nt\port\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\modules.mak CFG="modules - Win32 Release" 
   cd ".\squid"

"modules - Win32 ReleaseCLEAN" : 
   cd "\work\nt\port\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\modules.mak CFG="modules - Win32 Release" RECURSE=1 CLEAN 
   cd ".\squid"

!ELSEIF  "$(CFG)" == "squid - Win32 Debug"

"modules - Win32 Debug" : 
   cd "\work\nt\port\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\modules.mak CFG="modules - Win32 Debug" 
   cd ".\squid"

"modules - Win32 DebugCLEAN" : 
   cd "\work\nt\port\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\modules.mak CFG="modules - Win32 Debug" RECURSE=1 CLEAN 
   cd ".\squid"

!ENDIF 

!IF  "$(CFG)" == "squid - Win32 Release"

"squid_conf_default - Win32 Release" : 
   cd "\work\nt\port\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\squid_conf_default.mak CFG="squid_conf_default - Win32 Release" 
   cd ".\squid"

"squid_conf_default - Win32 ReleaseCLEAN" : 
   cd "\work\nt\port\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\squid_conf_default.mak CFG="squid_conf_default - Win32 Release" RECURSE=1 CLEAN 
   cd ".\squid"

!ELSEIF  "$(CFG)" == "squid - Win32 Debug"

"squid_conf_default - Win32 Debug" : 
   cd "\work\nt\port\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\squid_conf_default.mak CFG="squid_conf_default - Win32 Debug" 
   cd ".\squid"

"squid_conf_default - Win32 DebugCLEAN" : 
   cd "\work\nt\port\win32"
   $(MAKE) /$(MAKEFLAGS) /F .\squid_conf_default.mak CFG="squid_conf_default - Win32 Debug" RECURSE=1 CLEAN 
   cd ".\squid"

!ENDIF 

!IF  "$(CFG)" == "squid - Win32 Release"

"libbasic - Win32 Release" : 
   cd "\work\nt\port\win32\libbasic"
   $(MAKE) /$(MAKEFLAGS) /F .\libbasic.mak CFG="libbasic - Win32 Release" 
   cd "..\squid"

"libbasic - Win32 ReleaseCLEAN" : 
   cd "\work\nt\port\win32\libbasic"
   $(MAKE) /$(MAKEFLAGS) /F .\libbasic.mak CFG="libbasic - Win32 Release" RECURSE=1 CLEAN 
   cd "..\squid"

!ELSEIF  "$(CFG)" == "squid - Win32 Debug"

"libbasic - Win32 Debug" : 
   cd "\work\nt\port\win32\libbasic"
   $(MAKE) /$(MAKEFLAGS) /F .\libbasic.mak CFG="libbasic - Win32 Debug" 
   cd "..\squid"

"libbasic - Win32 DebugCLEAN" : 
   cd "\work\nt\port\win32\libbasic"
   $(MAKE) /$(MAKEFLAGS) /F .\libbasic.mak CFG="libbasic - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\squid"

!ENDIF 

!IF  "$(CFG)" == "squid - Win32 Release"

"liblru - Win32 Release" : 
   cd "\work\nt\port\win32\liblru"
   $(MAKE) /$(MAKEFLAGS) /F .\liblru.mak CFG="liblru - Win32 Release" 
   cd "..\squid"

"liblru - Win32 ReleaseCLEAN" : 
   cd "\work\nt\port\win32\liblru"
   $(MAKE) /$(MAKEFLAGS) /F .\liblru.mak CFG="liblru - Win32 Release" RECURSE=1 CLEAN 
   cd "..\squid"

!ELSEIF  "$(CFG)" == "squid - Win32 Debug"

"liblru - Win32 Debug" : 
   cd "\work\nt\port\win32\liblru"
   $(MAKE) /$(MAKEFLAGS) /F .\liblru.mak CFG="liblru - Win32 Debug" 
   cd "..\squid"

"liblru - Win32 DebugCLEAN" : 
   cd "\work\nt\port\win32\liblru"
   $(MAKE) /$(MAKEFLAGS) /F .\liblru.mak CFG="liblru - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\squid"

!ENDIF 

!IF  "$(CFG)" == "squid - Win32 Release"

"libntlm - Win32 Release" : 
   cd "\work\nt\port\win32\libntlm"
   $(MAKE) /$(MAKEFLAGS) /F .\libntlm.mak CFG="libntlm - Win32 Release" 
   cd "..\squid"

"libntlm - Win32 ReleaseCLEAN" : 
   cd "\work\nt\port\win32\libntlm"
   $(MAKE) /$(MAKEFLAGS) /F .\libntlm.mak CFG="libntlm - Win32 Release" RECURSE=1 CLEAN 
   cd "..\squid"

!ELSEIF  "$(CFG)" == "squid - Win32 Debug"

"libntlm - Win32 Debug" : 
   cd "\work\nt\port\win32\libntlm"
   $(MAKE) /$(MAKEFLAGS) /F .\libntlm.mak CFG="libntlm - Win32 Debug" 
   cd "..\squid"

"libntlm - Win32 DebugCLEAN" : 
   cd "\work\nt\port\win32\libntlm"
   $(MAKE) /$(MAKEFLAGS) /F .\libntlm.mak CFG="libntlm - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\squid"

!ENDIF 

!IF  "$(CFG)" == "squid - Win32 Release"

"libufs - Win32 Release" : 
   cd "\work\nt\port\win32\libufs"
   $(MAKE) /$(MAKEFLAGS) /F .\libufs.mak CFG="libufs - Win32 Release" 
   cd "..\squid"

"libufs - Win32 ReleaseCLEAN" : 
   cd "\work\nt\port\win32\libufs"
   $(MAKE) /$(MAKEFLAGS) /F .\libufs.mak CFG="libufs - Win32 Release" RECURSE=1 CLEAN 
   cd "..\squid"

!ELSEIF  "$(CFG)" == "squid - Win32 Debug"

"libufs - Win32 Debug" : 
   cd "\work\nt\port\win32\libufs"
   $(MAKE) /$(MAKEFLAGS) /F .\libufs.mak CFG="libufs - Win32 Debug" 
   cd "..\squid"

"libufs - Win32 DebugCLEAN" : 
   cd "\work\nt\port\win32\libufs"
   $(MAKE) /$(MAKEFLAGS) /F .\libufs.mak CFG="libufs - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\squid"

!ENDIF 

!IF  "$(CFG)" == "squid - Win32 Release"

"libheap - Win32 Release" : 
   cd "\work\nt\port\win32\libheap"
   $(MAKE) /$(MAKEFLAGS) /F .\libheap.mak CFG="libheap - Win32 Release" 
   cd "..\squid"

"libheap - Win32 ReleaseCLEAN" : 
   cd "\work\nt\port\win32\libheap"
   $(MAKE) /$(MAKEFLAGS) /F .\libheap.mak CFG="libheap - Win32 Release" RECURSE=1 CLEAN 
   cd "..\squid"

!ELSEIF  "$(CFG)" == "squid - Win32 Debug"

"libheap - Win32 Debug" : 
   cd "\work\nt\port\win32\libheap"
   $(MAKE) /$(MAKEFLAGS) /F .\libheap.mak CFG="libheap - Win32 Debug" 
   cd "..\squid"

"libheap - Win32 DebugCLEAN" : 
   cd "\work\nt\port\win32\libheap"
   $(MAKE) /$(MAKEFLAGS) /F .\libheap.mak CFG="libheap - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\squid"

!ENDIF 

!IF  "$(CFG)" == "squid - Win32 Release"

"libawin32 - Win32 Release" : 
   cd "\work\nt\port\win32\libawin32"
   $(MAKE) /$(MAKEFLAGS) /F .\libawin32.mak CFG="libawin32 - Win32 Release" 
   cd "..\squid"

"libawin32 - Win32 ReleaseCLEAN" : 
   cd "\work\nt\port\win32\libawin32"
   $(MAKE) /$(MAKEFLAGS) /F .\libawin32.mak CFG="libawin32 - Win32 Release" RECURSE=1 CLEAN 
   cd "..\squid"

!ELSEIF  "$(CFG)" == "squid - Win32 Debug"

"libawin32 - Win32 Debug" : 
   cd "\work\nt\port\win32\libawin32"
   $(MAKE) /$(MAKEFLAGS) /F .\libawin32.mak CFG="libawin32 - Win32 Debug" 
   cd "..\squid"

"libawin32 - Win32 DebugCLEAN" : 
   cd "\work\nt\port\win32\libawin32"
   $(MAKE) /$(MAKEFLAGS) /F .\libawin32.mak CFG="libawin32 - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\squid"

!ENDIF 

!IF  "$(CFG)" == "squid - Win32 Release"

"libnull - Win32 Release" : 
   cd "\work\nt\port\win32\libnull"
   $(MAKE) /$(MAKEFLAGS) /F .\libnull.mak CFG="libnull - Win32 Release" 
   cd "..\squid"

"libnull - Win32 ReleaseCLEAN" : 
   cd "\work\nt\port\win32\libnull"
   $(MAKE) /$(MAKEFLAGS) /F .\libnull.mak CFG="libnull - Win32 Release" RECURSE=1 CLEAN 
   cd "..\squid"

!ELSEIF  "$(CFG)" == "squid - Win32 Debug"

"libnull - Win32 Debug" : 
   cd "\work\nt\port\win32\libnull"
   $(MAKE) /$(MAKEFLAGS) /F .\libnull.mak CFG="libnull - Win32 Debug" 
   cd "..\squid"

"libnull - Win32 DebugCLEAN" : 
   cd "\work\nt\port\win32\libnull"
   $(MAKE) /$(MAKEFLAGS) /F .\libnull.mak CFG="libnull - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\squid"

!ENDIF 

!IF  "$(CFG)" == "squid - Win32 Release"

"libdigest - Win32 Release" : 
   cd "\work\nt\port\win32\libdigest"
   $(MAKE) /$(MAKEFLAGS) /F .\libdigest.mak CFG="libdigest - Win32 Release" 
   cd "..\squid"

"libdigest - Win32 ReleaseCLEAN" : 
   cd "\work\nt\port\win32\libdigest"
   $(MAKE) /$(MAKEFLAGS) /F .\libdigest.mak CFG="libdigest - Win32 Release" RECURSE=1 CLEAN 
   cd "..\squid"

!ELSEIF  "$(CFG)" == "squid - Win32 Debug"

"libdigest - Win32 Debug" : 
   cd "\work\nt\port\win32\libdigest"
   $(MAKE) /$(MAKEFLAGS) /F .\libdigest.mak CFG="libdigest - Win32 Debug" 
   cd "..\squid"

"libdigest - Win32 DebugCLEAN" : 
   cd "\work\nt\port\win32\libdigest"
   $(MAKE) /$(MAKEFLAGS) /F .\libdigest.mak CFG="libdigest - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\squid"

!ENDIF 


!ENDIF 

