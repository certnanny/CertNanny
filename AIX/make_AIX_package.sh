#!/usr/bin/ksh

echo "Creating package..."
# clean up directories of previous builds
rm -rf .info
rm -rf tmp
# create the file tree
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
# compute the version number (VRML)
#arch=$(uname -p)
#ts=$(date +'%Y%m%d%H%M%S')
version=$(head -n 1 VERSION)
version="$version.0"
# create the template and building the package
sed "s/VERSIONINFO/$version/" < AIX/lpp_template.in | sed "s#__PACKAGINGDIR__#$PWD#" > AIX/lpp_template
mkinstallp -d . -T AIX/lpp_template

