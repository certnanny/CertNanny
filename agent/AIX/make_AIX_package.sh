#!/usr/bin/ksh

echo "Creating package..."
mkdir -p opt/CertNanny/bin
mkdir -p opt/CertNanny/lib
mkdir -p var/CertNanny/etc
mkdir -p var/CertNanny/log
cp LICENSE opt/CertNanny/LICENSE.CertNanny
cp FAQ opt/CertNanny/FAQ
cp QUICKSTART opt/CertNanny/QUICKSTART
cp bin/certnanny opt/CertNanny/bin/certnanny
tar cf - etc | (cd var/CertNanny; tar xf -)
tar cf - lib | (cd opt/CertNanny; tar xf -)
#arch=$(uname -p)
#ts=$(date +'%Y%m%d%H%M%S')
version=$(head -n 1 VERSION)
version="$version.0"
sed "s/VERSIONINFO/$version/" < AIX/lpp_template.in > AIX/lpp_template
mkinstallp -d . -T AIX/lpp_template

