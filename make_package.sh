#!/bin/sh
#
# make_package.sh
#
# Create CertNanny package
#

solaris () {
  Solaris/make_Solaris_package.sh
}

aix () {
  AIX/make_AIX_package.sh
}

linux () {
  Linux/make_Linux_package.sh
}


##### MAIN #####

OS=`uname -s`

if [ x"$OS" = "xSunOS" ]
then
  echo "Packaging for $OS..."
  solaris
elif [ x"$OS" = "xLinux" ]
then
  echo "Packaging for $OS..."
  linux
elif [ x"$OS" = "xAIX" ]
then
  echo "Packaging for $OS..."
  aix
else
  echo "OS $OS not supported, aborting..." 1&>2
  exit 1
fi

