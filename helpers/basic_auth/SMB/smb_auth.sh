#!/bin/sh
#
# smb_auth - SMB proxy authentication module
# Copyright (C) 1998  Richard Huveneers <richard@hekkihek.hacom.nl>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

read DOMAINNAME
read PASSTHROUGH
read NMBADDR
read NMBCAST
read AUTHSHARE
read AUTHFILE
read SMBUSER
read SMBPASS

# Find domain controller
echo "Domain name: $DOMAINNAME"
if [ -n "$PASSTHROUGH" ]
then
  echo "Pass-through authentication: yes: $PASSTHROUGH"
else
  echo "Pass-through authentication: no"
  PASSTHROUGH="$DOMAINNAME"
fi
if [ -n "$NMBADDR" ]
then
  if [ "$NMBCAST" = "1" ]
  then
    addropt="-U $NMBADDR -R"
  else
    addropt="-B $NMBADDR"
  fi
else
  addropt=""
fi
echo "Query address options: $addropt"
dcip=`$SAMBAPREFIX/bin/nmblookup $addropt "$PASSTHROUGH#1c" | awk '/^[0-9.]+ / { print $1 ; exit }'`
echo "Domain controller IP address: $dcip"
[ -n "$dcip" ] || exit 1

# All right, we have the IP address of a domain controller,
# but we need its name too
dcname=`$SAMBAPREFIX/bin/nmblookup -A $dcip | awk '$2 == "<00>" { print $1 ; exit }'`
echo "Domain controller NETBIOS name: $dcname"
[ -n "$dcname" ] || exit 1

# Pass password to smbclient through environment. Not really safe.
USER="$SMBUSER%$SMBPASS"
export USER

# Read the contents of the file $AUTHFILE on the $AUTHSHARE share
authfilebs=`echo "$AUTHFILE" | tr / '\\\\'`
authinfo=`$SAMBAPREFIX/bin/smbclient "//$dcname/$AUTHSHARE" -I $dcip -d 0 -E -W "$DOMAINNAME" -c "get $authfilebs -" 2>/dev/null`
echo "Contents of //$dcname/$AUTHSHARE/$AUTHFILE: $authinfo"

# Allow for both \n and \r\n end-of-line termination
[ "$authinfo" = "allow" -o "$authinfo" = "allow" ] || exit 1
exit 0
