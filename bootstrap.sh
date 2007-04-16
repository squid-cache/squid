#!/bin/sh
# Used to setup the configure.in, autoheader and Makefile.in's if configure
# has not been generated. This script is only needed for developers when
# configure has not been run, or if a Makefile.am in a non-configured directory
# has been updated

# Autotool versions preferred. To override either edit the script
# to match the versions you want to use, or set the variables on
# the command line like "env acver=.. amver=... ./bootstrap.sh"
acversions="${acver:-2.59 2.57 2.53 2.52}"
amversions="${amver:-1.9 1.7 1.6 1.5}"
ltversions="${ltver:-1.5 1.4}"

check_version()
{
  eval $2 --version 2>/dev/null | grep -i "$1.*$3" >/dev/null
}

find_version()
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

# Adjust paths of required autool packages
amver=`find_version automake ${amversions}`
acver=`find_version autoconf ${acversions}`
ltver=`find_version libtool ${ltversions}`

# Set environment variable to tell automake which autoconf to use.
AUTOCONF="autoconf${acver}" ; export AUTOCONF

echo "automake : $amver"
echo "autoconfg: $acver"
echo "libtool  : $ltver"

for dir in \
	"" \
	lib/libTrie
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
	    bootstrap libtoolize$ltver --force --copy --automake
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
