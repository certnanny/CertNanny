#!/usr/bin/bash

echo "Creating package..."
mkdir -p opt/CertNanny/bin
mkdir -p etc/CertNanny
mkdir -p var/CertNanny
cp LICENSE opt/CertNanny/COPYRIGHT.CertNanny
cp QUICKSTART opt/CertNanny/
cp bin/certnanny opt/CertNanny/bin/
tar cf - lib | (cd opt/CertNanny; tar xf -)
tar cf - etc | (cd var/CertNanny; tar xf -)
arch=$(uname -p)
ts=$(date +'%Y%m%d%H%M%S')
version=$(head -n 1 VERSION)
sed "s/UNAME-P-ARCHITECTURE/$arch/" < Solaris/pkginfo.in | sed "s/DATETIMESTAMP/$ts/" | sed "s/VERSIONINFO/$version/" > Solaris/pkginfo
pkgmk -o -r . -d /tmp -f Solaris/Prototype
thisdir=$(pwd)
cd /tmp
tar cf - CertNanny-base | gzip -9 -c > $thisdir/CertNanny-base.$arch.$version.pkg.tar.gz
echo "Solaris installation package created: CertNanny-base.$arch.$version.pkg.tar.gz"


