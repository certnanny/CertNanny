#
# CertNanny spec file
#
# 2006-04-25 Joerg Schneider <js@joergschneider.com>
#

Name:         sscep
License:      BSD
Group:        Productivity/Security
Autoreqprov:  on
Summary:      Simple SCEP client for Unix
Version:      20060426
Release:      1
Source:       %{name}-20040325.tar.gz
Patch0:        sscep-ng2.patch.gz
Patch1:        sscep-non-unix.patch.gz
BuildRoot:    %{_tmppath}/%{name}-build
URL:          http://www.klake.org/~jt/sscep/

%description
SSCEP is a client-only implementation of the SCEP (Cisco System's Simple
Certificate Enrollment Protocol). 

SCEP is a PKI communication protocol which leverages existing technology by
using PKCS#7 and PKCS#10. SCEP is the evolution of the enrollment protocol
developed by Verisign, Inc. for Cisco Systems, Inc. It now enjoys wide support
in both client and CA implementations.

The goal of SCEP is to support the secure issuance of certificates to network
devices in a scalable manner, using existing technology whenever possible. The
protocol supports the following operations:

    * CA and RA public key distribution
    * Certificate enrollment
    * Certificate and CRL query 

Certificate and CRL access can be achieved by using the LDAP protocol, or by
using the query messages defined in SCEP. 

This version has two patches applied, adding automatic approval support for
OpenCA, fixing a problem in matching the certificate returned from the CA and 
support for non-unix plattforms.

Sscep is linked statically against OpenSSL.

%prep
%setup -n %{name}
%patch0 -p1
%patch1 -p1

%build
PREFIXLIST="/usr/local/ssl /opt/local/ssl /usr/local /opt/local /usr /opt"
test -n "$OPENSSL_PREFIX" && PREFIXLIST="$OPENSSL_PREFIX $PREFIXLIST"
VERSIONRE='\(0.9.7[^d]\|0.9.8\)'
for p in $PREFIXLIST; do
        test -d $p || continue
        test -x "$p/bin/openssl" || continue
        test -f "$p/include/openssl/opensslv.h" || continue
        test -d "$p/lib" || continue
        $p/bin/openssl version | grep -s "OpenSSL $VERSIONRE" >/dev/null || continue
        OPENSSL=$p
        break
done
if [ -z $OPENSSL ]; then
	echo "Can't find openssl devel package (version $VERSIONRE) in $PREFIXLIST"
	exit 1
fi
echo "Using `$OPENSSL/bin/openssl version` in $OPENSSL"
make OPENSSL=$OPENSSL

%install
mkdir -p $RPM_BUILD_ROOT
install -D -m 755 sscep $RPM_BUILD_ROOT/usr/bin/sscep
install -D sscep.conf $RPM_BUILD_ROOT/etc/sscep.conf

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc README COPYRIGHT HISTORY TODO
%config /etc/sscep.conf
/usr/bin/sscep

%changelog
* Tue Apr 25 2006 Joerg Schneider <js@joergschneider.com>
Initial RPM

