#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2011-05 Stefan Kraus <stefan.kraus05@gmail.com>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#
package CertNanny::Enroll::Sscep;

use strict;
use warnings;
use base qw(Exporter);
use CertNanny::Logging;
use File::Spec;
use vars qw( $VERSION );
use Exporter;
use Data::Dumper;
use Net::Domain;
use POSIX;

#use Cwd;


sub new {
  my $proto         = shift;
  my $class         = ref($proto) || $proto;
  my $entry_options = shift;
  my $config        = shift;
  my $entryname     = shift;
  my $self          = {};

  bless $self, $class;

  # type is determined, now delete it so only sections will be scanned.
  delete $entry_options->{enroll}->{type};
  ##if monitorsysinfo is not set we set it to be enabled by default
  if (!exists $config->{CONFIG}->{certmonitor}->{$entryname}->{enroll}->{sscep}->{monitorsysinfo}) {
    $config->{CONFIG}->{certmonitor}->{$entryname}->{enroll}->{sscep}->{monitorsysinfo} = 'yes';
  }

  #print ' $entryname sscep self is:' .Dumper($config) . $config->{CONFIG}->{certmonitor}->{$entryname}->{enroll}->{sscep}->{monitorsysinfo};
  $self->{OPTIONS} = $self->defaultOptions($config->{CONFIG}->{certmonitor}->{$entryname}->{enroll}->{sscep}->{monitorsysinfo}, $config, $entryname);
  $self->readConfig($entry_options->{enroll});

  # SCEP url
  #	$self->{url} = $config->{url} or die("No SCEP URL given");
  if (!defined $self->{OPTIONS}->{sscep}->{URL}) {
    CertNanny::Logging->error("scepurl not specified for keystore");
    return undef;
  }

  $self->{OPTIONS}->{sscep}->{verbose} = "true" if $config->get("loglevel") >= 5;
  $self->{OPTIONS}->{sscep}->{debug}   = "true" if $config->get("loglevel") >= 6;

  $self->{certdir} = $entry_options->{scepcertdir};
  if (!defined $self->{certdir}) {
    CertNanny::Logging->error("scepcertdir not specified for keystore");
    return undef;
  }
  $self->{entryname}       = $entryname;
  $self->{cmd}             = $config->get('cmd.sscep', 'FILE');
  $self->{config_filename} = File::Spec->catfile($self->{certdir}, $self->{entryname} . "_sscep.cnf");

  if (defined $self->{OPTIONS}->{sscep}->{engine}) {
    my $engine_section = $self->{OPTIONS}->{sscep}->{engine};
    $self->{OPTIONS}->{$engine_section}->{engine_usage} = "both";
  }

  return $self;
} ## end sub new


sub setOption {
  my $self    = shift;
  my $key     = shift;
  my $value   = shift;
  my $section = shift;

  #must provide all three params
  return 0 if (!($key and $value and $section));

  $self->{OPTIONS}->{$section}->{$key} = $value;
  CertNanny::Logging->debug("Option $key in section $section set to $value.");
  return 1;
} ## end sub setOption


sub readConfig {
  my $self   = shift;
  my $config = shift;
  foreach my $section (keys %{$config}) {
    next if $section eq "INHERIT";
    while (my ($key, $value) = each(%{$config->{$section}})) {
      next if $key eq "INHERIT";
      $self->{OPTIONS}->{$section}->{$key} = $value if $value;
    }
  }

  return 1;
} ## end sub readConfig


sub execute {
  my $self      = shift;
  my $operation = shift;

  my @cmd = (qq("$self->{cmd}"), $operation, '-f', qq("$self->{config_filename}"));

  my $cmd = join(' ', @cmd);
  CertNanny::Logging->debug("Exec: $cmd in " . getcwd());
  open FH, "$cmd |" or die "Couldn't execute $cmd: $!\n";
  while (defined(my $line = <FH>)) {
    chomp($line);
    print "$line\n";
  }
  close FH;
  my $exitval = $? >> 8;
  CertNanny::Logging->debug("sscep returned $exitval\n");
  return $exitval;
} ## end sub execute

# Enroll needs
# PrivateKeyFile
# CertReqFile
# SignKeyFile
# SignCertFile
# LocalCertFile
# EncCertFile
sub enroll {
  my $self    = shift;
  my %options = (@_,);

  #($volume,$directories,$file) = File::Spec->splitpath( $path );
  my $olddir = getcwd();
  chdir $self->{certdir};
  foreach my $section (keys %options) {
    while (my ($key, $value) = each(%{$options{$section}})) {
      $options{$section}->{$key} = File::Spec->abs2rel($value);
    }
  }

  CertNanny::Logging->info("Sending request");

  #print Dumper $self->{STATE}->{DATA};

  my %certs = $self->getCA();
  if (!%certs) {
    CertNanny::Logging->error("Could not get CA certs");
    return undef;
  }
  my $rc;
  eval {
    local $SIG{ALRM} = sub {die "alarm\n"};    # NB: \n required
    eval {alarm 120};                          # eval not supported in perl 5.7.1 on win32
    $self->readConfig(\%options);
    $self->writeConfigFile();
    $rc = $self->execute("enroll");
    eval {alarm 0};                            # eval not supported in perl 5.7.1 on win32
    CertNanny::Logging->info("Return code: $rc");
  };

  chdir $olddir;

  if ($@) {

    # timed out
    die unless $@ eq "alarm\n";                # propagate unexpected errors
    CertNanny::Logging->info("Timed out.");
    return undef;
  }

  if ($rc == 3) {

    # request is pending
    CertNanny::Logging->info("Request is still pending");
    return 1;
  }

  if ($rc != 0) {
    CertNanny::Logging->error("Could not run SCEP enrollment");
    return undef;
  }
  return 1;
} ## end sub enroll


sub writeConfigFile {
  my $self = shift;

  my $openssl_cfg;

  foreach my $section (keys %{$self->{OPTIONS}}) {
    $openssl_cfg->{$section} = [];
    foreach my $key (keys %{$self->{OPTIONS}->{$section}}) {
      my $value = $self->{OPTIONS}->{$section}->{$key};
      push(@{$openssl_cfg->{$section}}, {$key => $value});
    }
  }

  my $rc = CertNanny::Util->writeOpenSSLConfig($openssl_cfg, $self->{config_filename});
  unless ($rc) {
    CertNanny::Logging->error("Could not write sscep config file.");
    return undef;
  }
  return 1;
} ## end sub writeConfigFile


sub getCA {

  my $self   = shift;
  my $config = shift;
  unless (defined $self->{certs}->{RACERT} and defined $self->{certs}->{CACERTS}) {
    my $olddir = getcwd();
    chdir $self->{certdir};
    $config->{sscep}->{CACertFile} = 'cacert';

    $self->readConfig($config);
    $config = $self->{OPTIONS};

    # delete existing ca certs
    my $ii = 0;
    while (-e $config->{sscep}->{CACertFile} . "-" . $ii) {
      my $file = $config->{sscep}->{CACertFile} . "-" . $ii;
      CertNanny::Logging->debug("Unlinking $file");
      unlink $file;
      if (-e $file) {
        CertNanny::Logging->error("could not delete CA certificate file $file, cannot proceed");
        return undef;
      }
      $ii++;
    } ## end while (-e $config->{sscep...})

    CertNanny::Logging->info("Requesting CA certificates");

    $self->writeConfigFile();
    if ($self->execute("getca") != 0) {
      return undef;
    }

    my $scepracert = File::Spec->catfile($self->{certdir}, $config->{sscep}->{CACertFile} . "-0");

    # collect all ca certificates returned by the SCEP command
    my @cacerts = ();
    $ii = 1;

    my $certfile = File::Spec->catfile($self->{certdir}, $config->{sscep}->{CACertFile} . "-$ii");
    CertNanny::Logging->debug("getCA(): Adding certfile to stack: $certfile");
    while (-r $certfile) {
      my $certformat = 'PEM';    # always returned by sscep
      my $certinfo = CertNanny::Util->getCertInfoHash(CERTFILE   => $certfile,
                                                      CERTFORMAT => 'PEM');

      if (defined $certinfo) {
        push(@cacerts,
             {CERTINFO   => $certinfo,
              CERTFILE   => $certfile,
              CERTFORMAT => $certformat,});
      }
      $ii++;
      $certfile = File::Spec->catfile($self->{certdir}, $config->{sscep}->{CACertFile} . "-$ii");
    } ## end while (-r $certfile)

    $self->{certs}->{CACERTS} = \@cacerts;
    $self->{certs}->{RACERT}  = $scepracert;
    chdir $olddir;
  } ## end unless (defined $self->{certs...})

  my %certs = (CACERTS => $self->{certs}->{CACERTS},);

  if (-r $self->{certs}->{RACERT}) {
    $certs{RACERT} = $self->{certs}->{RACERT};
  }
  return %certs;
} ## end sub getCA


sub getNextCA {
  # Get next CA via SCEP
  # Pass a file location to the signers certificate chain for signature validation
  # This file will only be used if the returned signed PKCS7 reply is not including the complete chain
  # $enroller->getNextCA($certchainfile);
  #
  my $self                = shift;
  my $ChainRootCACertFile = shift;

  my $scepCertChain;
  my $pemchain;

  my $olddir = getcwd();
  chdir $self->{certdir};

  CertNanny::Logging->debug("CertNanny::Enroll::Scep::getNextCA");

  my $signerCertOutput = "signerCertGetNextCA.pem";
  my $targetCAfile     = "nextRootCA";

  my %options = (
    sscep_getnextca => {
      ChainRootCACertFile => $ChainRootCACertFile,
      # FingerPrint => $requestfile,
      SignerCertificateFile => $signerCertOutput,},
    sscep => {CACertFile => $targetCAfile,});

  $self->readConfig(\%options);
  my $config = $self->{OPTIONS};

  $self->writeConfigFile();

  if ($self->execute("getnextca") != 0) {
    CertNanny::Logging->debug("error executing CertNanny::Enroll::Scep::getNextCA - may no be available at this time or not supported by target SCEP server");
    return undef;
  }

  # collect all ca certificates returned by the SCEP command
  my @nextcacerts = ();
  my $ii          = 0;

  my $certfile = File::Spec->catfile($self->{certdir}, $targetCAfile . "-$ii");
  CertNanny::Logging->debug("getNextCA(): Adding certfile to stack: $certfile");
  while (-r $certfile) {
    my $certformat = 'PEM';    # always returned by sscep
    my $certinfo = CertNanny::Util->getCertInfoHash(CERTFILE   => $certfile,
                                                    CERTFORMAT => 'PEM');

    if (defined $certinfo) {
      push(@nextcacerts, {CERTINFO => $certinfo});
    }
    $ii++;
    $certfile = File::Spec->catfile($self->{certdir}, $targetCAfile . "-$ii");
  } ## end while (-r $certfile)

  # delete next ca cert files
  $ii = 0;
  while (-e $targetCAfile . "-" . $ii) {
    my $file = $targetCAfile . "-" . $ii;
    CertNanny::Logging->debug("Unlinking $file");
    unlink $file;
    if (-e $file) {
      CertNanny::Logging->error("could not delete next CA certificate file $file, cannot proceed");
      return undef;
    }
    $ii++;
  } ## end while (-e $targetCAfile ....)

  my $signercertfile = File::Spec->catfile($self->{certdir}, $signerCertOutput);
  my $SignerCertinfo = CertNanny::Util->getCertInfoHash(CERTFILE   => $signercertfile,
                                                        CERTFORMAT => 'PEM');

  unlink $signercertfile;
  if (-e $signercertfile) {
    CertNanny::Logging->error("could not delete next CA signer certificate file $signercertfile, cannot proceed");
    return undef;
  }

  chdir $olddir;

  my %certs = (NEXTCACERTS => \@nextcacerts,
               SIGNERCERT  => $SignerCertinfo);

  return %certs;
} ## end sub getNextCA


sub defaultOptions {
  my $self           = shift;
  my $monitorSysInfo = shift;
  my $config         = shift;
  my $entryname      = shift;
  my $monitor        = '';

  CertNanny::Logging->debug("get defaultOptions $monitorSysInfo");

  if (defined $monitorSysInfo and $monitorSysInfo ne '' and $monitorSysInfo ne 'no') {
    my @macs         = CertNanny::Util->getMacAddresses();
    my $macaddresses = "macaddress=";

    foreach my $mac (@macs) {
      if ($mac ne '00:00:00:00:00:00') {
        $macaddresses .= $mac . ',';
      }
    }
    $macaddresses = substr($macaddresses, 0, -1);    #remove last ","

    $monitor = $macaddresses . '&cnversion=' . $CertNanny::VERSION;
    $monitor .= '&sysfqdn=' . Net::Domain::hostfqdn();
    $monitor .= '&sysname=' . (POSIX::uname())[0];
    $monitor .= '&sysrelease=' . (POSIX::uname())[2];
    $monitor .= '&sysarch=' . (POSIX::uname())[4];

    CertNanny::Logging->debug("Add monitor information $monitor");
  } ## end if (defined $monitorSysInfo...)

  my %options = (
    sscep_engine_capi => {'new_key_location' => 'REQUEST',},

    sscep_enroll => {'PollInterval' => 5,
                     'MaxPollCount' => 1});

  # user configurable meta data

  # this data structure is an example of configuration settings a user might
  # set in certnanny.cfg, such as
  # keystore.DEFAULT.enroll.sscep.meta.myarg = bar
  # keystore.DEFAULT.enroll.sscep.meta.foo = sub { return 'bar' }
  # keystore.DEFAULT.enroll.sscep.meta.blah = `whoami`
  my $userconfig = $config->{CONFIG}->{certmonitor}->{$entryname}->{enroll}->{sscep}->{meta};

  my %custmetadata;

  foreach my $key (keys %{$userconfig}) {
    my $value = $userconfig->{$key};
    if ($value =~ m{ \A \s* sub \s* \{ }xms) {
      eval {
        $value = eval $value;
        $value = &$value();
      };
    } elsif ($value =~ m{ \A \s* `(.*)` \s* \z }xms) {
      $value = `$1`;
      chomp $value;
    }
    $custmetadata{'CNMCUST' . uc($key)} = $value;
  } ## end foreach my $key (keys %{$userconfig...})

  # now send %metadata hash to SCEP server via GET request
META: foreach my $key (keys %custmetadata) {
    next META if $key eq 'CNMCUSTINHERIT';
    my $value = $custmetadata{$key};
    $monitor .= '&' . $key . '=' . $value;
  }
  CertNanny::Logging->debug("Monitor Info: " . $monitor);

  if ($monitor ne '') {
    $options{sscep} = {MonitorInformation => $monitor};
  }

  return \%options;
} ## end sub defaultOptions

1;

=head1 NAME

CertNanny::Enroll::Sscep - Enrolling new certificates via the sscep protocol.

=head1 SYNOPSIS

    my $sscep = CertNanny::Enroll::Sscep->new($entry_options, $config, $entryname);
    $sscep->getCA();
    $sscep->enroll();


=head1 DESCRIPTION

This module implements the CertNanny::Enroll interface. By running the associated function, it is possible to renew certificates.

=head1 FUNCTIONS

=head2 Function List

=over 4

C<new()>

C<enroll()>

C<getCA()>

C<getNextCA()>

C<defaultOptions()>

C<execute()>

C<readConfig()>

C<setOption()>

C<writeConfigFile()>

=back

=head2 Function Descriptions

=over 4

=item new( $entry_options, $config, $entryname)

Instantiates the sscep client with an instance. The client managing it should only use one instance per certificate which should be renewed.
Configuration is passed through three options:

=over 4

=item $entry_options

Has the options for the specific entry which is all options that are keystore specific. Typically options defined via "keystore." settings.
All options of the format keystore.LABEL.enroll (or $entry_options->{enroll}) are read here with C<readConfig()>.

=item $config

Reads the global configuration. Typical settings here are the loglevel and sscep.cmd. Only specific settings will be loaded, the rest will be discarded.

=item $entryname

The name (label) of the entry. This is the name assinged via keystore.LABEL. where LABEL will be the name. Is expected to be a string.

=back

=item enroll( %options )

The actual renewal of the certificate. The %options hash will consist of all possible configuration params with the standard format.
See C<readConfig()> for details about possible options. sscep expects all files to be in an unencrypted PEM format. Thus is it necessary to convert all
keys to a PEM format without a passphrase. If, however, an engine should be used, you can keep the format in a way the engine understands.
This can either be a PEM formatted file or any file the engine understands (e.g. proprietary formats, IDs).
Typically a hash with at least the key "sscep_enroll" is passed. This hash typically has the following keys:

=over 4

=item PrivateKeyFile
	
Full path to the file of the newly generated csr. This is the private key you want a certificate for.

=item CertReqFile

The generated CSR for the new private key

=item SignKeyFile

With this option your request will be signed. It is your old key for which you have a valid certificate. If omitted, initial enrollment will be performed.

=item SignCertFile

The corresponding, still valid certificate to SignKeyFile

=item LocalCertFile

The target filename for the new certificate

=back

=item getCA()

Retrieves all CA certificates from the SCEP-server. Typically the first certificate returned will be the SCEP RA certificate.

=item getNextCA()

Root Key Roll-Over. Not Yet Implemented.

=item defaultOptions()

Internal function. Stores default options which get overwritten by options that are passed. Modify this if you want other defaults for sscep.

=item execute()

Internal function. Perform an sscep command based on the current configuration. Normally you do not need to call this.

=item readConfig( $hash_ref )

Internal function. Reads the configuration from a passed hash. Gets called by C<new()>. The keys of $hash_ref describe section names. Each element is another hash reference which consists of key => value pairs for this section.
Refer to the sscep documentation and example configuration fine (.cnf extension) on the available options. The syntax used is OpenSSL configuration syntax.

=item setOption( $key, $value, $section)

Function to modify single options. Sets the value $value for key $key in section $section. All three paramters are required for this to work. Refer to the sscep documentation for information on key, value and section.

=item writeConfigFile()

Writes the current state of configuration to an sscep configuration file. It accesses the $self->{OPTIONS} hash and uses the keys as section names and then iterates over any contained hash and uses the $key, $value pair as configuration key and value in the file.
