#
# CertNanny spec file
#
# 2005-11-07 Martin Bartosch <m.bartosch@cynops.de>
#

Name:         certnanny
License:      GPL
Group:        Productivity/Security
Autoreqprov:  on
Summary:      Certificate renewal agent
Version:      0.6
Release:      1
Source:       %{name}-%{version}.tar.gz
BuildRoot:    %{_tmppath}/%{name}-build

%description
CertNanny is a client-side program that allows fully automatic
renewal of certificates. The basic idea is to have a number of local
keystores that are monitored for expiring certificates. If a certificate
is about to expire, the program automatically creates a new certificate
request with the existing certificate data, enrolls the request with the
configured CA and polls the CA for the issued certificate. Once the
certificate is ready, a new keystore with the new certificate is composed
and replaces the old keystore. 


%prep
%setup -n %{name}

%install
mkdir -p $RPM_BUILD_ROOT
install -D -m 755 bin/certnanny $RPM_BUILD_ROOT/usr/bin/certnanny
install -D -m 644 lib/java/ExtractKey.jar $RPM_BUILD_ROOT/usr/lib/certnanny/java/ExtractKey.jar
install -D -m 644 etc/certnanny.cfg $RPM_BUILD_ROOT/etc/certnanny.cfg
mkdir -p $RPM_BUILD_ROOT/usr/lib/perl5/site_perl/
tar -C lib/perl -c -f - . | tar -C $RPM_BUILD_ROOT/usr/lib/perl5/site_perl/ -x -v -f -
mkdir -p $RPM_BUILD_ROOT/var/lib/certnanny/state

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc README INSTALL QUICKSTART FAQ LICENSE ChangeLog
%config /etc/certnanny.cfg

/usr/bin/certnanny
/usr/lib/certnanny/java/ExtractKey.jar
/usr/lib/perl5/site_perl/CertNanny.pm
/usr/lib/perl5/site_perl/CertNanny
%dir /var/lib/certnanny/state

%changelog
* Thu Dec 23 2005 Martin Bartosch <m.bartosch@cynops.de>
Initial public release

* Mon Nov 07 2005 Martin Bartosch <m.bartosch@cynops.de>
Initial release


