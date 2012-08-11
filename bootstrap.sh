#!/bin/sh
# Used to setup the configure.ac, autoheader and Makefile.in's if configure
# has not been generated. This script is only needed for developers when
# configure has not been run, or if a Makefile.am in a non-configured directory
# has been updated

# Autotool versions preferred. To override either edit the script
# to match the versions you want to use, or set the variables on
# the command line like "env acver=.. amver=... ./bootstrap.sh"
acversions="${acver:-.}" # 2.68 2.67 2.66 2.65 2.64 2.63 2.62 2.61}"
amversions="${amver:-.}" # 1.11 1.10 1.9}"
ltversions="${ltver:-.}" # 2.2}"

check_version()
{
  eval $2 --version 2>/dev/null | grep -i "$1.* $3" >/dev/null
}

show_version()
{
  tool=$1
  variant=$2
  ${tool}${variant} --version 2>/dev/null | head -1 | sed -e 's/.*) //'
}

find_variant()
{
  tool=$1
  found="NOT_FOUND"
  shift
  versions="$*"
  for version in $versions; do
    for variant in "" "${version}" "-${version}" "`echo $version | sed -e 's/\.//g'`"; do
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

find_path()
{
  tool=$1
  path=`which $tool`
  if test $? -gt 0 ; then
    # path for $tool not found. Not defining, and hoping for the best
    echo 
    return
  fi
  echo $(dirname $path)
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
    tool=$1

    ltdl="--ltdl"

    bootstrap $tool $ltdl --force --copy --automake

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

# On MAC OS X, GNU libtool is named 'glibtool':
if [ `uname -s 2>/dev/null` = 'Darwin' ]
then
  LIBTOOL_BIN="glibtool"
else
  LIBTOOL_BIN="libtool"
fi

# Adjust paths of required autool packages
amver=`find_variant automake ${amversions}`
acver=`find_variant autoconf ${acversions}`
ltver=`find_variant ${LIBTOOL_BIN} ${ltversions}`

# Produce debug output about what version actually found.
amversion=`show_version automake "${amver}"`
acversion=`show_version autoconf "${acver}"`
ltversion=`show_version ${LIBTOOL_BIN} "${ltver}"`

# Find the libtool path to get the right aclocal includes
ltpath=`find_path ${LIBTOOL_BIN}${ltver}`

# Set environment variable to tell automake which autoconf to use.
AUTOCONF="autoconf${acver}" ; export AUTOCONF

echo "automake ($amversion) : automake$amver"
echo "autoconf ($acversion) : autoconf$acver"
echo "libtool  ($ltversion) : ${LIBTOOL_BIN}${ltver}"
echo "libtool path : $ltpath"

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

            if test -n "$ltpath"; then
              acincludeflag="-I $ltpath/../share/aclocal"
            else
              acincludeflag=""
            fi

	    # Bootstrap the autotool subsystems
	    bootstrap aclocal$amver $acincludeflag
	    bootstrap autoheader$acver
	    bootstrap_libtoolize ${LIBTOOL_BIN}ize${ltver}
	    bootstrap automake$amver --foreign --add-missing --copy -f
	    bootstrap autoconf$acver --force
	fi ); then
	    : # OK
	else
	    exit 1
	fi
    fi
done

# Make a copy of SPONSORS we can package
sed -e 's/@Squid-[0-9\.]*://' <SPONSORS.list > SPONSORS || (rm -f SPONSORS && exit 1)

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
