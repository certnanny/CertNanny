#!/bin/bash

echo "Creating package..."
#arch=$(uname -p)
#ts=$(date +'%Y%m%d%H%M%S')
version=$(head -n 1 VERSION)
sed "s/VERSIONINFO/$version/" < Linux/certnanny.spec.in > Linux/certnanny.spec
tar --transform "s/^\./certnanny-$version/" --exclude '.git' -czf $HOME/rpmbuild/SOURCES/certnanny-$version.tar.gz .
rpmbuild -bb Linux/certnanny.spec

