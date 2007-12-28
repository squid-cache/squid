@echo off
if %1==release net stop %3

if not exist %2 md %2
if not exist %2\bin md %2\bin
if not exist %2\sbin md %2\sbin
if not exist %2\libexec md %2\libexec
if not exist %2\docs md %2\docs
if not exist %2\etc md %2\etc
if not exist %2\var\logs md %2\var\logs
if not exist %2\share\errors md %2\share\errors
if not exist %2\share\icons md %2\share\icons

copy %0\..\squid\%1\squid.exe %2\sbin\squid.exe
copy %0\..\unlinkd\%1\unlinkd.exe %2\libexec\unlinkd.exe
if exist %0\..\dnsserver\%1\dnsserver.exe copy %0\..\dnsserver\%1\dnsserver.exe %2\libexec\dnsserver.exe
if exist %0\..\pinger\%1\pinger.exe copy %0\..\pinger\%1\pinger.exe %2\libexec\pinger.exe
copy %0\..\squidclient\%1\squidclient.exe %2\bin\squidclient.exe
copy %0\..\fake_auth\%1\fake_auth.exe %2\libexec\fakeauth_auth.exe
copy %0\..\mswin_auth\%1\mswin_auth.exe %2\libexec\mswin_auth.exe
copy %0\..\ncsa_auth\%1\ncsa_auth.exe %2\libexec\ncsa_auth.exe
copy %0\..\mswin_ntlm_auth\%1\mswin_ntlm_auth.exe %2\libexec\mswin_ntlm_auth.exe
copy %0\..\mswin_negotiate_auth\%1\mswin_negotiate_auth.exe %2\libexec\mswin_negotiate_auth.exe
copy %0\..\ldap_auth\%1\ldap_auth.exe %2\libexec\squid_ldap_auth.exe
copy %0\..\ldap_group\%1\ldap_group.exe %2\libexec\squid_ldap_group.exe
copy %0\..\mswin_check_lm_group\%1\mswin_check_lm_group.exe %2\libexec\mswin_check_lm_group.exe
copy %0\..\ip_user_check\%1\ip_user_check.exe %2\libexec\ip_user_check.exe
copy %0\..\digest_ldap_auth\%1\digest_ldap_auth.exe %2\libexec\digest_ldap_auth.exe
copy %0\..\digest_pw_auth\%1\digest_pw_auth.exe %2\libexec\digest_pw_auth.exe
copy %0\..\cachemgr\%1\cachemgr.exe %2\libexec\cachemgr.cgi

copy %0\..\..\..\src\squid.conf.default %2\etc\squid.conf.default
copy %0\..\..\..\src\mime.conf.default %2\etc\mime.conf.default
copy %0\..\..\..\tools\cachemgr.conf %2\etc\cachemgr.conf.default
copy %0\..\..\..\src\mib.txt %2\share\mib.txt

pushd %0\..\..\..\errors
for /D %%d IN (*) DO xcopy /Y /Q %%d\err_* %2\share\errors\%%d\
popd

copy %0\..\..\..\icons\*.gif %2\share\icons > NUL

copy %0\..\..\..\helpers\ntlm_auth\mswin_sspi\readme.txt %2\docs\mswin_ntlm_auth.txt
copy %0\..\..\..\helpers\negotiate_auth\mswin_sspi\readme.txt %2\docs\mswin_negotiate_auth.txt
copy %0\..\..\..\helpers\external_acl\mswin_lm_group\readme.txt %2\docs\mswin_check_lm_group.txt
copy %0\..\..\..\helpers\external_acl\ip_user\README %2\docs\ip_user_check.txt
copy %0\..\..\..\helpers\basic_auth\mswin_sspi\readme.txt %2\docs\mswin_auth.txt
copy %0\..\..\..\doc\win32-relnotes.html %2\docs\win32-relnotes.html
copy %0\..\..\..\doc\debug-sections.txt %2\docs\debug-sections.txt
copy %0\..\..\..\doc\HTTP-codes.txt %2\docs\HTTP-codes.txt
copy %0\..\..\..\doc\release-notes\release-2.5.html %2\docs\release-2.5.html
copy %0\..\..\..\doc\release-notes\release-3.0.html %2\docs\release-3.0.html
type %0\..\..\..\helpers\basic_auth\LDAP\squid_ldap_auth.8 | man2htm2 > %2\docs\squid_ldap_auth.html
type %0\..\..\..\helpers\external_acl\LDAP_group\squid_ldap_group.8 | man2htm2 > %2\docs\squid_ldap_group.html
type %0\..\..\..\doc\squid.8 | man2htm2 > %2\docs\squid.html
type %0\..\..\..\doc\cachemgr.cgi.8 | man2htm2 > %2\docs\cachemgr.cgi.html

copy %0\..\..\..\README %2\README
copy %0\..\..\..\COPYRIGHT %2\COPYRIGHT
copy %0\..\..\..\COPYING %2\COPYING
copy %0\..\..\..\CONTRIBUTORS %2\CONTRIBUTORS
copy %0\..\..\..\CREDITS %2\CREDITS
copy %0\..\..\..\SPONSORS %2\SPONSORS
copy %0\..\..\..\QUICKSTART %2\QUICKSTART
copy %0\..\..\..\ChangeLog %2\ChangeLog

if %1==release net start %3
