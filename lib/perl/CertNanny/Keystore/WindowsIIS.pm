#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2008 Soeren Rinne <srinne@gmail.com>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny::Keystore::WindowsIIS;

use base qw(Exporter CertNanny::Keystore::Windows CertNanny::Keystore::OpenSSL);

use strict;
use vars qw($VERSION);
use Exporter;
use Carp;
use English;
use Data::Dumper;
use Win32::OLE;
use Win32::OLE::Variant;
use Win32::OLE::Const;

# This method is called once the new certificate has been received from
# the SCEP server. Its responsibility is to create a new keystore containing
# the new key, certificate, CA certificate keychain and collection of Root
# certificates configured for CertNanny. The new certificate will be imported
# in the IIS (with given InstanceName from the config), to avoid the loss of
# secure bindings after replacing the certificate in the windows keystore.
# A true return code indicates that the keystore was installed properly and
# the certficate in the IIS has been successfully imported.
sub installCert {
  my $self = shift;
  my %args = (@_,    # argument pair list
             );

  # create prototype PKCS#12 file
  my $keyfile  = $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{KEYFILE};
  my $certfile = $args{CERTFILE};
  my $label    = $self->{CERT}->{LABEL};

  CertNanny::Logging->info("Creating prototype PKCS#12 from certfile $certfile, keyfile $keyfile, label $label");

  # create random PW via OpenSSL
  my $openssl = $self->{OPTIONS}->{CONFIG}->get('cmd.openssl', 'FILE');

  my $open_result = open(my $OPENSSL, "\"$openssl\" rand -base64 15 |");
  if (!$open_result) {
    CertNanny::Logging->error("Could not open OpenSSL for random PIN generation");
    return;
  }

  # the OpenSSL output is saved in $randpin
  my $randpin = do {
    local $/;
    <$OPENSSL>;
  };
  chomp($randpin);
  close($OPENSSL);

  if (!$randpin) {
    CertNanny::Logging->error("No random PIN generated");
  }

  $self->{PIN} = $randpin;

  # pkcs12file must be an absolute filename (see below, gsk6cmd bug)
  my $pkcs12file = $self->createPKCS12(FILENAME  => CertNanny::Util->getTmpFile(),
                                       EXPORTPIN => $self->{PIN},
                                       CACHAIN   => undef)->{FILENAME};

  if (!defined $pkcs12file) {
    CertNanny::Logging->error("Could not create prototype PKCS#12 from received certificate");
    return;
  }
  CertNanny::Logging->info("Created prototype PKCS#12 file $pkcs12file");

  # initialize IIS.CertObj
  my $certobj = Win32::OLE->new('IIS.CertObj');
  if (!defined $certobj) {
    CertNanny::Logging->error("Could not create IIS.CertObj");
    return;
  }

  my $result = $self->_deleteOldCerts($certfile);

  # read IIS Webserver InstanceName(s) from config
  my @instanceidentifier_array = split(/, */, $self->{OPTIONS}->{ENTRY}->{instanceidentifier});

  my $instanceidentifier = '';

  # go through all instances using the same certificate
  foreach $instanceidentifier (@instanceidentifier_array) {
    $certobj->SetProperty('InstanceName', 'w3svc/' . $instanceidentifier);
    CertNanny::Logging->info("Using InstanceName w3svc/$instanceidentifier");

    if ($result == 1) {

      # import the new certificate into IIS
      $certobj->Import($pkcs12file, $self->{PIN}, 1, 1);
    }
  } ## end foreach $instanceidentifier...

  # delete requests
  my $store = $self->openstore('REQUEST', 'machine');
  my $certs = $store->Certificates;

  #go through all certificates in the store
  my $enum = Win32::OLE::Enum->new($certs);
  while (defined(my $cert = $enum->Next)) {
    my $subjectname = $cert->SubjectName;

    #Because the subject names in the certificates from the certificate store are formated in a different way
    #the subject names from the config file. The blanks after the seperating "," need to be deleted.
    $subjectname =~ s/(?<!\\)((\\\\)*),\s*/$1,/g;
    if ($subjectname eq $self->{OPTIONS}->{ENTRY}->{location}) {

      # delete matching requests
      $store->Remove($cert);
    }
  } ## end while (defined(my $cert =...))

  # check if cert is installed (one match on fingerprint - getcertobject())
  my $old_thumbprint = $self->{CERT}->{CERTINFO}->{CertificateFingerprint};
  $old_thumbprint =~ s/://g;

  CertNanny::Logging->info("Thumbprint of old certificate: $old_thumbprint");

  my $new_cert = $self->getcertobject($self->{STORE});

  my $new_thumbprint = $new_cert->thumbprint();

  CertNanny::Logging->info("Thumbprint of new certificate: $new_thumbprint");

  if ($old_thumbprint eq $new_thumbprint) {
    CertNanny::Logging->error("Installation failed, old certificate is still in place.");
    return;
  }

  # only on success:
  return 1;
} ## end sub installCert

1;
