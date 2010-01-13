#!/bin/sh
# Used to setup the configure.in, autoheader and Makefile.in's if configure
# has not been generated. This script is only needed for developers when
# configure has not been run, or if a Makefile.am in a non-configured directory
# has been updated

# Autotool versions preferred. To override either edit the script
# to match the versions you want to use, or set the variables on
# the command line like "env acver=.. amver=... ./bootstrap.sh"
acversions="${acver:-2.63 2.62 2.61}"
amversions="${amver:-1.11 1.10 1.9}"
ltversions="${ltver:-2.2 1.5 1.4}"

check_version()
{
  eval $2 --version 2>/dev/null | grep -i "$1.* $3" >/dev/null
}

show_version()
{
  tool=$1
  found="NOT_FOUND"
  shift
  versions="$*"
  for version in $versions; do
    for variant in "" "-${version}" "`echo $version | sed -e 's/\.//g'`"; do
      if check_version $tool ${tool}${variant} $version; then
	found="${version}"
	break
      fi
    done
    if [ "x$found" != "xNOT_FOUND" ]; then
      break
    fi
  done
  if [ "x$found" = "xNOT_FOUND" ]; then
    found="??"
  fi
  echo $found
}

find_variant()
{
  tool=$1
  found="NOT_FOUND"
  shift
  versions="$*"
  for version in $versions; do
    for variant in "" "-${version}" "`echo $version | sed -e 's/\.//g'`"; do
      if check_version $tool ${tool}${variant} $version; then
	found="${variant}"
	break
      fi
    done
    if [ "x$found" != "xNOT_FOUND" ]; then
      break
    fi
  done
  if [ "x$found" = "xNOT_FOUND" ]; then
    echo "WARNING: Cannot find $tool version $versions" >&2
    echo "Trying `$tool --version | head -1`" >&2
    found=""
  fi
  echo $found
}

bootstrap() {
  if "$@"; then
    true # Everything OK
  else
    echo "$1 failed"
    echo "Autotool bootstrapping failed. You will need to investigate and correct" ;
    echo "before you can develop on this source tree" 
    exit 1
  fi
}

bootstrap_libtoolize() {
    ltver=$1

    # TODO: when we have libtool2, tell libtoolize where to put its files
    # instead of manualy moving files from ltdl to lib/libLtdl
    if egrep -q '^[[:space:]]*AC_LIBLTDL_' configure.in
    then
	ltdl="--ltdl"
    else
        ltdl=""
    fi

    bootstrap libtoolize$ltver $ltdl --force --copy --automake

    # customize generated libltdl, if any
    if test -d libltdl
    then
        src=libltdl

        # do not bundle with the huge standard license text
        rm -f $src/COPYING.LIB
        makefile=$src/Makefile.in
        sed 's/COPYING.LIB/ /g' $makefile > $makefile.new;
        chmod u+w $makefile
        mv $makefile.new $makefile
        chmod u-w $makefile
    fi
}

# Adjust paths of required autool packages
amver=`find_variant automake ${amversions}`
acver=`find_variant autoconf ${acversions}`
ltver=`find_variant libtool ${ltversions}`

# Produce debug output about what version actually found.
amversion=`show_version automake ${amversions}`
acversion=`show_version autoconf ${acversions}`
ltversion=`show_version libtool ${ltversions}`

# Set environment variable to tell automake which autoconf to use.
AUTOCONF="autoconf${acver}" ; export AUTOCONF

echo "automake ($amversion) : automake$amver"
echo "autoconf ($acversion) : autoconf$acver"
echo "libtool  ($ltversion) : libtool$ltver"

for dir in \
	"" \
	lib/libTrie \
	helpers/negotiate_auth/squid_kerb_auth
do
    if [ -z "$dir" ] || [ -d $dir ]; then
	if (
	echo "Bootstrapping $dir"
	cd ./$dir
	if [ -n "$dir" ] && [ -f bootstrap.sh ]; then
	    ./bootstrap.sh
	elif [ ! -f $dir/configure ]; then
	    # Make sure cfgaux exists
	    mkdir -p cfgaux

	    # Bootstrap the autotool subsystems
	    bootstrap aclocal$amver
	    bootstrap autoheader$acver
	    bootstrap_libtoolize $ltver
	    bootstrap automake$amver --foreign --add-missing --copy -f
	    bootstrap autoconf$acver --force
	fi ); then
	    : # OK
	else
	    exit 1
	fi
    fi
done

# Fixup autoconf recursion using --silent/--quiet option
# autoconf should inherit this option whe recursing into subdirectories
# but it currently doesn't for some reason.
if ! grep  "configure_args --quiet" configure >/dev/null; then
echo "Fixing configure recursion"
ed -s configure <<'EOS' >/dev/null || true
/ac_sub_configure_args=/
+1
i
  # Add --quiet option if used
  test "$silent" = yes &&
    ac_sub_configure_args="$ac_sub_configure_args --quiet"
.
w
EOS
fi

echo "Autotool bootstrapping complete."
