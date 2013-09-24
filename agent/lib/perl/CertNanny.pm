#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005-02 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny;

use base qw(Exporter);

use strict;

our @EXPORT    = ();
our @EXPORT_OK = ();
use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION $AUTOLOAD);
use Exporter;
use Carp;

use FindBin;
use File::Spec;

use CertNanny::Util;
use CertNanny::Config;
use CertNanny::Keystore;
use CertNanny::Logging;
use CertNanny::Enroll;
use CertNanny::Enroll::Sscep;
use Data::Dumper;
use POSIX;

use IPC::Open3;

$VERSION = 0.12;

my $INSTANCE;


sub getInstance() {
  $INSTANCE ||= (shift)->new(@_);
  return $INSTANCE;
} ## end sub getInstance


sub new {
  if (!defined $INSTANCE) {
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my %args = (@_);      # argument pair list
            
    my $self = {};
    bless $self, $class;
    $INSTANCE = $self;

    # Store singleton objects in CertNanny
    $self->{CONFIG}  = CertNanny::Config->getInstance(%args); return undef unless defined $self->{CONFIG};
    $self->{UTIL}    = CertNanny::Util->getInstance(CONFIG => $self->{CONFIG});
    $self->{LOGGING} = CertNanny::Logging->getInstance(CONFIG => $self->{CONFIG});

    # set default library path
    my @dirs = File::Spec->splitdir($FindBin::Bin);
    pop @dirs;
    if (!$self->{CONFIG}->get("path.lib", "FILE")) {
      $self->{CONFIG}->set("path.lib", File::Spec->catdir(@dirs, 'lib'));
      CertNanny::Logging->debug("set perl path lib to:" . $self->{CONFIG}->get("path.lib", "FILE"));
    }
    if (!$self->{CONFIG}->get("path.libjava", "FILE")) {
      $self->{CONFIG}->set("path.libjava", File::Spec->catdir($self->{CONFIG}->get("path.lib", "FILE"), 'java'));
      CertNanny::Logging->debug("set java path lib to:" . $self->{CONFIG}->get("path.libjava", "FILE"));
    }

    $self->{ITEMS} = ${$self->{CONFIG}->getRef("keystore", 'ref')};

    if (!defined $self->{ITEMS}) {
      # fall back to legacy configuration (backward compatibility to
      # CertMonitor)
      $self->{ITEMS} = ${$self->{CONFIG}->getRef("certmonitor", 'ref')};
    }
    delete $self->{ITEMS}->{DEFAULT};
  }
  return $INSTANCE;
} ## end sub new


sub DESTROY {

  # Windows apparently flushes file handles on close() and ignores autoflush...
  close STDOUT;
  close STDERR;
  $INSTANCE = undef;
}


sub _iterate_entries {
  my $self   = (shift)->getInstance();
  my $action = shift;

  my $loglevel = $self->{CONFIG}->get('loglevel') || 3;

  foreach my $entry (keys %{$self->{ITEMS}}) {    # Instantiate every keystore, that is configured
    CertNanny::Logging->debug("Checking keystore $entry");
    my $keystore = CertNanny::Keystore->new(CONFIG    => $self->{CONFIG},           # give it the whole configuration
                                            ENTRY     => $self->{ITEMS}->{$entry},  # all keystore parameters from configfile
                                            ENTRYNAME => $entry);                   # and the keystore name from configfile 
    if ($keystore) {
      $self->$action(ENTRY    => $entry,
                     KEYSTORE => $keystore);
    } else {
      CertNanny::Logging->error("Could not instantiate keystore $entry");
      if ($action eq 'do_renew' or $action eq 'do_enroll') {
        CertNanny::Logging->info("Check for initial enrollment configuration.");
        if ($self->{ITEMS}->{$entry}->{initialenroll}->{auth}) {
          CertNanny::Logging->info("Fund initial enrollment configuration for " . $self->{ITEMS}->{$entry}->{initialenroll}->{subject});
          $self->do_enroll(ENTRY     => $self->{ITEMS}->{$entry},
                           ENTRYNAME => $entry);
        }
      } ## end if ($action eq ' renew'...)
    } ## end else [ if ($keystore) ]
    print "\n\n";
  } ## end foreach my $entry (keys %{$self...})

  return 1;
} ## end sub _iterate_entries


sub AUTOLOAD {
  my $self = (shift)->getInstance();
  my $attr = $AUTOLOAD;
  $attr =~ s/.*:://;
  return undef if $attr eq 'DESTROY';

  # automagically call
  if ($attr =~ /(?:info|check|renew|enroll|sync|test)/) {
    return $self->_iterate_entries("do_$attr");
  }
} ## end sub AUTOLOAD


sub getConfigValue {
  my $self = (shift)->getInstance();
  return $self->{CONFIG}->get(@_);
}


sub setOption {
  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3]);
  my $self  = (shift)->getInstance();
  my $key   = shift;
  my $value = shift;

  $self->{$key} = $value;

  CertNanny::Logging->debug(eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3]);
  return 1;
} ## end sub setOption


sub do_info {
  my $self = (shift)->getInstance();
  my %args = (@_);

  my $keystore = $args{KEYSTORE};

  my $info = $keystore->{INSTANCE}->k_getInfo("SubjectName", "NotAfter");
  print Dumper $info;

  return 1;
} ## end sub do_info


sub do_check {
  my $self = (shift)->getInstance();
  my %args = (@_);

  my $keystore = $args{KEYSTORE};
  $keystore->{CERT} = $keystore->{INSTANCE}->getCert();
  $keystore->{CERT}->{CERTINFO} =
    CertNanny::Util->getCertInfoHash(%{$keystore->{CERT}});

  if (!$keystore->{INSTANCE}->k_checkValidity(0)) {
    CertNanny::Logging->error("Certificate has expired. No automatic renewal can be performed.");
    return 1;
  }

  if (!$keystore->{INSTANCE}->k_checkValidity($self->{ITEMS}->{$args{ENTRY}}->{autorenew_days})) {
    CertNanny::Logging->info("Certificate is to be scheduled for automatic renewal ($self->{ITEMS}->{$args{ENTRY}}->{autorenew_days}; days prior to expiry)");
  }

  if (!$keystore->{INSTANCE}->k_checkValidity($self->{ITEMS}->{$args{ENTRY}}->{warnexpiry_days})) {
    CertNanny::Logging->notice("Certificate is valid for less than $self->{ITEMS}->{$args{ENTRY}}->{warnexpiry_days} days");
    $keystore->{INSTANCE}->k_warnExpiry();
  }
  return 1;
} ## end sub do_check


sub do_enroll {
  my $self      = (shift)->getInstance();
  my %args      = (@_);

  my $entry     = $args{ENTRY};
  my $entryname = $args{ENTRYNAME};

  CertNanny::Util->backoffTime($self->{CONFIG});

  if ($self->{ITEMS}->{$entryname}->{initialenroll}->{auth}->{mode} eq 'certificate') {
    CertNanny::Logging->info("Start initial enrollment with authentication method certificate.");

    my $keystore;
    ##Change keystore attributes to instantitae a openSSL keystore with the entrollment certificate
    $entry->{initialenroll}->{targetType} = $entry->{type};
    $entry->{type}                        = 'OpenSSL';
    $entry->{location}                    = $entry->{initialenroll}->{auth}->{cert};
    $entry->{format}                      = 'PEM';
    $entry->{keyfile}                     = $entry->{initialenroll}->{auth}->{key};
    $entry->{pin}                         = $entry->{initialenroll}->{auth}->{pin};

    if (exists $self->{ITEMS}->{$entryname}->{hsm}) {
      $self->{ITEMS}->{$entryname}->{hsm} = undef;
    }
    if (exists $self->{ITEMS}->{$entryname}->{certreqinf}) {
      $self->{ITEMS}->{$entryname}->{certreqinf} = undef;
    }
    if (exists $self->{ITEMS}->{$entryname}->{certreq}) {
      $self->{ITEMS}->{$entryname}->{certreq} = undef;
    }

    $keystore = CertNanny::Keystore->new(CONFIG    => $self->{CONFIG},
                                         ENTRY     => $self->{ITEMS}->{$entryname},
                                         ENTRYNAME => $entryname);

    $keystore->{INSTANCE}->{INITIALENROLLEMNT} = 'yes';

    #disable engine specific configuration
    $keystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{enroll}->{engine_section}  = undef;
    $keystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{enroll}->{sscep}->{engine} = undef;

    #Start the initial enrollment runining an native openSSL keystore renewal
    my $ret = $keystore->{INSTANCE}->k_renew();

    my $conf = CertNanny::Config->new($self->{CONFIG}->{CONFIGFILE});

    #reset the keystore configuration after the inital enrollment back to the .cfg file specified settings including engine
    $self->{ITEMS}->{$entryname} = $conf->{CONFIG}->{certmonitor}->{$entryname};

    $conf->{CONFIG}->{INITIALENROLLEMNT} = 'yes';

    my $newkeystore = CertNanny::Keystore->new(CONFIG    => $self->{CONFIG},
                                               ENTRY     => $self->{ITEMS}->{$entryname},
                                               ENTRYNAME => $entryname);

    $newkeystore->{INSTANCE}->k_retrieveState() or return undef;

    my $autorenew    = $self->{ITEMS}->{$args{ENTRY}}->{autorenew_days};
    my $renewalstate = $newkeystore->{INSTANCE}->{STATE}->{DATA}->{RENEWAL}->{STATUS};

    if ($renewalstate eq 'sendrequest') {
      CertNanny::Logging->info("Initial enrollment request send.");

      # get previous renewal status
      #$self->{INSTANCE}->k_retrieveState() or return undef;

      # check if we can write to the file
      $newkeystore->{INSTANCE}->k_storeState() || croak "Could not write state file $newkeystore->{STATE}->{FILE}";
    } ## end if ($renewalstate eq 'sendrequest')
    if ($renewalstate eq 'completed') {
      my $isValid = $newkeystore->{INSTANCE}->k_checkValidity($self->{ITEMS}->{$args{ENTRY}}->{autorenew_days});
      CertNanny::Logging->info("Initial enrollment completed successfully. Onbehalf.");
      $newkeystore->{INSTANCE}->k_storeState() || croak "Could not write state file $newkeystore->{STATE}->{FILE}";
    }

    return 1;
  } else {
    if ($self->{ITEMS}->{$entryname}->{initialenroll}->{auth}->{mode} eq 'password' or
        $self->{ITEMS}->{$entryname}->{initialenroll}->{auth}->{mode} eq 'anonymous') {
      CertNanny::Logging->info("Start initial enrollment with authentication method " . $self->{ITEMS}->{$entryname}->{initialenroll}->{auth}->{mode});

      ##Change keystore attributes to instantitae a openSSL keystore with the entrollment certificate
      $entry->{initialenroll}->{targetType} = $entry->{type};
      $entry->{type}                        = 'OpenSSL';
      $self->{CONFIG}->{INITIALENROLLEMNT}  = 'yes';

      my $newkeystore = CertNanny::Keystore->new(CONFIG    => $self->{CONFIG},
                                                 ENTRY     => $self->{ITEMS}->{$entryname},
                                                 ENTRYNAME => $entryname);
      $newkeystore->{INSTANCE}->k_retrieveState() || croak "Could not write state file $newkeystore->{STATE}->{FILE}";
      $newkeystore->{INSTANCE}->{INITIALENROLLEMNT} = 'yes';

      if ($self->{ITEMS}->{$entryname}->{initialenroll}->{auth}->{mode} eq 'password') {
        if (!defined $newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{initialenroll}->{auth}->{challengepassword}) {

          CertNanny::Logging->debug('Using commandline argument challangePassword for initial enrollment');
          if (exists $self->{globalchallengepassword} && $self->{globalchallengepassword} ne '') {
            $newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{initialenroll}->{auth}->{challengepassword} = $self->{globalchallengepassword};
          }
        } ## end if (!defined $newkeystore...)
      } ## end if ($self->{ITEMS}->{$entryname...})

      my $key     = $newkeystore->{INSTANCE}->{OPTIONS}->{ENTRYNAME} . "-key.pem";
      my $keyfile = File::Spec->catfile($newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{statedir}, $key);

      unless (-e $keyfile) {
        # Todo pgk Testen: {KEYFILE}
        my $newkey = $newkeystore->{INSTANCE}->generateKey()->{KEYFILE};

        CertNanny::Logging->debug("keyfile $newkey->{KEYFILE} ,  ");
        $newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{keyfile} = $newkey->{KEYFILE};
        CertNanny::Logging->debug("keyfile $newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{keyfile} ,  ");
        $newkeystore->{INSTANCE}->{ENTRY}->{format} = 'PEM';
      } else {
        CertNanny::Logging->debug("Key already generated");
        #CertNanny::Logging->debug('newkeystore with key : '.Dumper($newkeystore));
        $newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{keyfile} = $keyfile;
        $entry->{keyfile} = $entry->{initialenroll}->{auth}->{key};
        $entry->{pin}     = $entry->{initialenroll}->{auth}->{pin};
      } ## end else

      my $selfsigncert = $newkeystore->{INSTANCE}->{OPTIONS}->{ENTRYNAME} . "-selfcert.pem";
      my $outCert = File::Spec->catfile($newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{statedir}, $selfsigncert);

      unless (-e $outCert) {
        CertNanny::Logging->debug("Initial enrollment started, generate new selfsigned cert ");
        my $newSelfsignCert = $newkeystore->{INSTANCE}->selfSign();

        #CertNanny::Logging->debug(Dumper($newSelfsignCert));
        $newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{location} = $newSelfsignCert->{CERT};
      } else {
        $newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{location} = $outCert;
      }

      $newkeystore->{CERT} = $newkeystore->{INSTANCE}->getCert();

      if (defined $newkeystore->{CERT}) {
        $newkeystore->{CERT}->{CERTINFO} = CertNanny::Util->getCertInfoHash(%{$newkeystore->{CERT}});
        my $subjectname = $newkeystore->{CERT}->{CERTINFO}->{SubjectName};
        my $serial      = $newkeystore->{CERT}->{CERTINFO}->{SerialNumber};
        my $issuer      = $newkeystore->{CERT}->{CERTINFO}->{IssuerName};
        CertNanny::Logging->debug("Certificate Information:\n\tSubjectName: $subjectname\n\tSerial: $serial\n\tIssuer: $issuer");

        my %convopts = %{$newkeystore->{CERT}};

        $convopts{OUTFORMAT} = 'PEM';
        $newkeystore->{CERT}->{RAW}->{PEM} = CertNanny::Util->convertCert(%convopts)->{CERTDATA};
#          $newkeystore->{INSTANCE}->k_convertCert(%convopts)->{CERTDATA};
        $convopts{OUTFORMAT} = 'DER';
        $newkeystore->{CERT}->{RAW}->{DER} = CertNanny::Util->convertCert(%convopts)->{CERTDATA};
#          $newkeystore->{INSTANCE}->k_convertCert(%convopts)->{CERTDATA};
      } else {
        CertNanny::Logging->error("Could not parse instance certificate");
        return undef;
      }

      $newkeystore->{INSTANCE}->k_setCert($newkeystore->{CERT});

      #disable engine specific configuration
      $newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{keyfile}  = $keyfile;
      $newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{location} = $outCert;
      $newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{enroll}->{engine_section}  = undef;
      $newkeystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{enroll}->{sscep}->{engine} = undef;

      #Start the initial enrollment runining an native openSSL keystore renewal
      my $ret = $newkeystore->{INSTANCE}->k_renew();

      my $renewalstate = $newkeystore->{INSTANCE}->{STATE}->{DATA}->{RENEWAL}->{STATUS};

      if (defined $renewalstate) {
        CertNanny::Logging->debug("renewalstate is " . $renewalstate);
      }

      if (defined $renewalstate and $renewalstate eq 'sendrequest') {
        CertNanny::Logging->info("Initial enrollment request send.");
        $newkeystore->{INSTANCE}->k_storeState() || croak "Could not write state file $newkeystore->{STATE}->{FILE}";
      }

      if (!defined $renewalstate) {
        unlink $selfsigncert;
        CertNanny::Logging->info("Initial enrollment completed successfully. Mode:" . $self->{ITEMS}->{$entryname}->{initialenroll}->{auth}->{mode});
      }

      return 1;
    } else {
      CertNanny::Logging->error("Initial enrollment authentication method " . $self->{ITEMS}->{$entryname}->{initialenroll}->{auth}->{mode} . " not supported");
    }
  } ## end else [ if ($self->{ITEMS}->{$entryname...})]

  #		my $keystore = $args{KEYSTORE};
  #			$keystore->{INSTANCE}->k_renew();
  #
  #
  #	    if (! $keystore->{INSTANCE}->k_checkValidity($self->{ITEMS}->{$args{ENTRY}}->{warnexpiry_days})) {
  #		CertNanny::Logging->notice("Certificate is valid for less than $self->{ITEMS}->{$args{ENTRY}}->{warnexpiry_days} days");
  #		$keystore->{INSTANCE}->k_warnExpiry();
  #
  #		}

  return 1;
} ## end sub do_enroll


sub do_renew {
  my $self   = (shift)->getInstance();
  my %args = (@_);

  my $keystore = $args{KEYSTORE};

  if (defined $self->{ITEMS}->{$args{ENTRY}}->{rootcaupdate}->{enable}
      && $self->{ITEMS}->{$args{ENTRY}}->{rootcaupdate}->{enable} eq "true") {
    CertNanny::Logging->debug("RootCA update activated running k_getNextTrustAnchor");
    $keystore->{INSTANCE}->k_getNextTrustAnchor();
  } else {
    CertNanny::Logging->debug("RootCA update deactivated");
  }

  if (!$keystore->{INSTANCE}->k_checkValidity(0)) {
    CertNanny::Logging->error("Certificate has expired. No automatic renewal can be performed.");
    return 1;
  }

  if (!$keystore->{INSTANCE}->k_checkValidity($self->{ITEMS}->{$args{ENTRY}}->{autorenew_days})) {

    # schedule automatic renewal
    CertNanny::Util->backoffTime($self->{CONFIG});
    $keystore->{INSTANCE}->k_renew();
  }

  if (!$keystore->{INSTANCE}->k_checkValidity($self->{ITEMS}->{$args{ENTRY}}->{warnexpiry_days})) {
    CertNanny::Logging->notice("Certificate is valid for less than $self->{ITEMS}->{ $args{ENTRY} }->{warnexpiry_days} days");
    $keystore->{INSTANCE}->k_warnExpiry();
  }

  return 1;
} ## end sub do_renew


sub do_sync {
  my $self = (shift)->getInstance();
  my %args = (@_);

  my $keystore = $args{KEYSTORE};

  #  my $root

  if (!$keystore->{INSTANCE}->k_checkValidity(0)) {
    CertNanny::Logging->error("Certificate has expired. No automatic renewal can be performed.");
    return 1;
  }

  if (!$keystore->{INSTANCE}->k_checkValidity($self->{ITEMS}->{$args{ENTRY}}->{autorenew_days})) {

    # schedule automatic renewal
    CertNanny::Util->backoffTime($self->{CONFIG});
    $keystore->{INSTANCE}->k_renew();
  }

  if (!$keystore->{INSTANCE}->k_checkValidity($self->{ITEMS}->{$args{ENTRY}}->{warnexpiry_days})) {
    CertNanny::Logging->notice("Certificate is valid for less than $self->{ITEMS}->{ $args{ENTRY} }->{warnexpiry_days} days");
    $keystore->{INSTANCE}->k_warnExpiry();
  }

  return 1;
} ## end sub do_sync


sub do_test {
  my $self = (shift)->getInstance();
  my %args = (@_);

  shift(@ARGV);
  my $cmd = shift(@ARGV);
  # my $a1  = shift(@ARGV);
  # my $a2  = shift(@ARGV);

  CertNanny::Logging->log2Console(); 
  my $ret = $args{KEYSTORE}->{INSTANCE}->$cmd(@ARGV);

  return 1;
} ## end sub do_test


sub do_updateRootCA {
  my $self = (shift)->getInstance();
  my %args = (@_);

  my $keystore = $args{KEYSTORE};

  if (defined $self->{ITEMS}->{$args{ENTRY}}->{rootcaupdate}->{enable}
      && $self->{ITEMS}->{$args{ENTRY}}->{rootcaupdate}->{enable} eq "true") {
    CertNanny::Logging->debug("RootCA update activated running k_getNextTrustAnchor");
    $keystore->{INSTANCE}->k_getNextTrustAnchor();
  } else {
    CertNanny::Logging->debug("RootCA update deactivated");
  }

  return 1;
} ## end sub do_updateRootCA


1;
