# About CertNanny

CertNanny is a client-side program that allows fully automatic renewal of certificates using the SCEP protocol.

The basic idea is to have a number of local keystores that are monitored for expiring certificates. If a certificate is about to expire, the program automatically creates a new certificate request with the existing certificate data, enrolls the request with the configured CA and polls the CA for the issued certificate. Once the certificate is ready, a new keystore with the new certificate is composed and replaces the old keystore.

## Confused? [Watch the movie!](https://cynops.de/download/CertNanny-In-Action.mov)

## Requirements

Clients running CertNanny will need Perl 5.8 or higher installed. 

In addition an OpenSSL executable and the [sscep tool](https://github.com/certnanny/sscep) program is required on the client.

For using CertNanny with Machine Keystores under Windows a patched OpenSSL including a [CAPI patch](https://github.com/certnanny/openssl-capi-patch) is required. The official Windows package of Certnanny will include a patched version of OpenSSL.

On the CA side a SCEP server is required. CertNanny has been extensively tested with the [SCEP server](https://openxpki.readthedocs.org/en/latest/reference/configuration/workflows/scep.html) of [OpenXPKI](http://www.openxpki.org/) but may also work with others.

If the SCEP server supports automatic approval (which is done by signing the certificate request with the existing old certificate on the client side, see http://tools.ietf.org/html/draft-nourse-scep-23#section-2.2) the CertNanny agent can perform in-place keystore replacement without operator interaction. Using hook functions CertNanny can also reload/restart applications after successful renewal.

## Platform and keystore support

CertNanny is designed to run on a large number of platforms. In addition client applications using certificates use lots of different keystore formats, most of which are already supported by the software:

Keystore/OS                | Unix   | Windows
:--------------------------|:-------|:--------
OpenSSL (PEM/DER)          | yes    | yes
PKCS #8 (PEM/DER)          | yes    | yes
PKCS #12                   | yes    | yes
Java Keystore (JKS)        | yes    | yes
IBM GSKit 7 Keystore (CMS) | yes    | yes
Windows Certificate Store  | n/a    | yes

Supported/tested Unix variants: Linux, AIX, Solaris x86, Solaris Sparc, Darwin (Mac OS X).

## Getting the software

You can download the [latest stable source code](https://github.com/certnanny/CertNanny/archive/master.zip) directly from GitHub.

Beginning with version 1.1 we will publish official CertNanny packages for the major operating systems (SuSE SLES, AIX 7, Solaris x86/Sparc 10).

## Development

CertNanny development is hosted on: https://github.com/certnanny/CertNanny

You will also find the [issue tracker](https://github.com/certnanny/CertNanny/issues) there.

## Roadmap/History

[Official milestones/releases are tracked on GitHub.](https://github.com/certnanny/CertNanny/issues/milestones)

### Version 1.1

Release date: ETA 2014-02-28

Currently under development.

Key features:
- improved configuration features
- support of different key sizes in keystores
- Root CA certificates now stored in directory
- fully automatic Root CA update feature via SCEP GetNextCA
- "Root Only" Keystores (for trust anchor configuration)
- improved Windows keystore support (Machine Keystore)
- updated GSKit 7.1 support
- meta data submission in SCEP request
- additional hook functions (expired, invocation)
- improved logging
- packaging for all major platforms

*Note: For administrative reasons there will be no 1.0 release.*

### Version 0.10

Release date: 2007-06-19 **(Latest stable release)** 

This version introduces PKCS#12 support and adds MQ/GSKit support for Windows platforms. When creating a new keystore the configured Root Certificates are now examined for their validity period. Expired (and if desired not-yet-valid) certificates are not imported into the new keystore. This behaviour is fully configurable per keystore.

### Version 0.9

Release date: 2006-08-09

Fixes problems in certificate chain generation that occur if multiple CA certificate hierarchies are returned by the SCEP server. CertNanny now calculates the correct certificate chain based on the newly created certificate.

### Version 0.8

Release date: 2006-06-12

Introduces Windows Certificate Store and Java Keystore support

### Version 0.7

Release date: 2006-02-10

Introduces PKCS#8 support, improved OpenSSL keystore handling. New platforms: Windows, Tandem/NonStop (OSS)

### Version 0.6

Release date: 2005-12-23

Initial public release of CertNanny

--------------------


Last update: 2014-01-31
