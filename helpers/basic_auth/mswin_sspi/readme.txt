This is a simple authentication module for the Squid proxy server running on Windows NT
to authenticate users on an NT domain in native WIN32 mode.

Usage is simple. It accepts a username and password on standard input
and will return OK if the username/password is valid for the domain/machine,
or ERR if there was some problem.
It's possible to authenticate against NT trusted domains specifyng the username 
in the domain\\username Microsoft notation. 


==============
Program Syntax
==============

mswin_auth [-A UserGroup][-D UserGroup][-O DefaultDomain][-d]

-A can specify a Windows Local Group name allowed to authenticate.
-D can specify a Windows Local Group name not allowed to authenticate.
-O can specify the default Domain against to authenticate.
-d enable debugging.

This is released under the GNU General Public License.


==============
Allowing Users
==============

Users that are allowed to access the web proxy must have the Windows NT
User Rights "logon from the network" and must be included in the NT LOCAL User Groups 
specified in the Authenticator's command line. 
This can be accomplished creating a local user group on the NT machine, grant the privilege,
and adding users to it.

Refer to Squid documentation for the required changes to squid.conf.


============
Installation
============

Type 'make', then 'make install', then 'make clean'.

On Cygwin the default is to install 'mswin_auth' into /usr/local/squid/libexec,
with other Windows environments into c:/squid/libexec.

Refer to Squid documentation for the required changes to squid.conf.
You will need to set the following line to enable the authenticator:

auth_param basic program /usr/local/squid/libexec/mswin_auth [options]

or

auth_param basic program c:/squid/libexec/mswin_auth [options]

You will need to set the following lines to enable authentication for
your access list -

  acl <yourACL> proxy_auth REQUIRED
  http_access allow <yourACL>

You will need to specify the absolute path to mswin_auth in the 
'auth_param basic program' directive, and check the 'auth_param basic children'
and 'auth_param basic credentialsttl'.


==================
Compilation issues
==================

The Makefile assumes that GCC is in the current PATH.
mswin_auth compile ONLY on Cygwin Environment, MinGW + MSYS Environment
or MS VC++.


=======
Testing
=======

I strongly urge that mswin_auth is tested prior to being used in a 
production environment. It may behave differently on different platforms.
To test it, run it from the command line. Enter username and password
pairs separated by a space. Press ENTER to get an OK or ERR message.
Make sure pressing <CTRL><D> behaves the same as a carriage return.
Make sure pressing <CTRL><C> aborts the program.

Test that entering no details does not result in an OK or ERR message.
Test that entering an invalid username and password results in an ERR message.
Note that if NT guest user access is allowed on the PDC, an OK message
may be returned instead of ERR.
Test that entering an valid username and password results in an OK message.
Test that entering a guest username and password returns the correct
response for the site's access policy.


===============
Contact details
===============

To contact the maintainer of this package, e-mail on squidnt@acmeconsulting.it.

