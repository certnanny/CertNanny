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

$VERSION = "1.2.0";

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
    CertNanny::Logging->info('MSG', "============================================================");
    CertNanny::Logging->info('MSG', "CertNanny Version $VERSION Command(s) " . join('|', @ARGV));
    CertNanny::Logging->info('MSG', "============================================================");
    
    # Store singleton objects in CertNanny
    $self->{CONFIG}  = CertNanny::Config->getInstance(%args); return undef unless defined $self->{CONFIG};
    $self->{UTIL}    = CertNanny::Util->getInstance(CONFIG => $self->{CONFIG});
    $self->{LOGGING} = CertNanny::Logging->getInstance(CONFIG => $self->{CONFIG});

    use Config;
    use Sys::Hostname;

    CertNanny::Logging->info('MSG', "CertNanny running on " . CertNanny::Util->os_type() . " ($Config{myuname}) under Perl $Config{version}");
    
    # set default library path
    my @dirs = File::Spec->splitdir($FindBin::Bin);
    pop @dirs;
    if (!$self->{CONFIG}->get("path.lib", "FILE")) {
      $self->{CONFIG}->set("path.lib", File::Spec->catdir(@dirs, 'lib'));
      CertNanny::Logging->debug('MSG', "set perl path lib to: <" . $self->{CONFIG}->get("path.lib", "FILE") . ">");
    }
    if (!$self->{CONFIG}->get("path.libjava", "FILE")) {
      $self->{CONFIG}->set("path.libjava", File::Spec->catdir($self->{CONFIG}->get("path.lib", "FILE"), 'java'));
      CertNanny::Logging->debug('MSG', "set java path lib to: <" . $self->{CONFIG}->get("path.libjava", "FILE") . ">");
    }


    if($self->{CONFIG}->get("cmd.opensslconf", "FILE")){
      $ENV{OPENSSL_CONF} = $self->{CONFIG}->get("cmd.opensslconf", "FILE");
      CertNanny::Logging->debug('MSG', "set OPENSSL_CONF enviroment var to  to: <" . $self->{CONFIG}->get("cmd.opensslconf", "FILE") . ">");
    }

    $self->{ITEMS} = ${$self->{CONFIG}->getRef("keystore", 'ref')};
    delete $self->{ITEMS}->{DEFAULT};
  }
  return $INSTANCE;
} ## end sub new


sub DESTROY {
  # Windows apparently flushes file handles on close() and ignores autoflush...
  $INSTANCE = undef;
}


sub getConfigValue {
  my $self = (shift)->getInstance();
  return $self->{CONFIG}->get(@_);
}


sub setOption {
  CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3]);
  my $self  = (shift)->getInstance();
  my $key   = shift;
  my $value = shift;

  $self->{OPTION}->{$key} = $value;

  CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Key: <$key>  Value: <$value>");
  return 1;
} ## end sub setOption


sub getOption {
  # CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3]);
  my $self  = (shift)->getInstance();
  my $key   = shift;

  my $value;
  if (defined($self->{OPTION}->{$key}) && ($self->{OPTION}->{$key} ne '')) {
    $value = $self->{OPTION}->{$key};
  }
  
  # CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Key: <$key>  Value: <", defined($value) ? $value.">" : "undefined>");
  return $value;
} ## end sub setOption


sub AUTOLOAD {
  my $self = (shift)->getInstance();
  my $attr = $AUTOLOAD;
  $attr =~ s/.*:://;
  return undef if $attr eq 'DESTROY';
  
  if ($attr =~ /^(?:dump|test)$/) {
    my $action = "do_$attr";
    return $self->$action();
  }
  if ($attr =~ /^(?:check|renew|enroll|cleanup|updateRootCA|executeHook)$/) {
    return $self->_iterate_entries("do_$attr");
  }
  
  CertNanny::Logging->error('MSG', "Invalid action specified: <$attr>");
} ## end sub AUTOLOAD


sub _iterate_entries {
  my $self   = (shift)->getInstance();
  my $action = shift;

  my $loglevel = $self->{CONFIG}->get('log.level') || 3;

  foreach my $entryname (keys %{$self->{ITEMS}}) {    # Instantiate every keystore, that is configured
    CertNanny::Util->setVariable('NAME',  'KEYSTORE', 
                                 'VALUE', $entryname);
    CertNanny::Logging->debug('MSG', "Checking keystore <$entryname>");
    my $keystore = CertNanny::Keystore->new(CONFIG    => $self->{CONFIG},              # give it the whole configuration
                                            ENTRY     => $self->{ITEMS}->{$entryname}, # all keystore parameters from configfile
                                            ENTRYNAME => $entryname);                  # and the keystore name from configfile
    # Keystore exists -> normal Operation
    if ($keystore) {
      $self->$action(ENTRYNAME => $entryname,
                     KEYSTORE  => $keystore);
    } else {
      # Keystore does not exists -> create new Keystore (enroll) no matter wether we did a renew or an enroll
      CertNanny::Logging->error('MSG', "Could not instantiate keystore <$entryname>");
      if ($action eq 'do_renew' or $action eq 'do_enroll') {
        CertNanny::Logging->info('MSG', "Check for initial enrollment configuration.");
        if ($self->{ITEMS}->{$entryname}->{initialenroll}->{auth}) {
          CertNanny::Logging->info('MSG', "Found initial enrollment configuration for " . $self->{ITEMS}->{$entryname}->{initialenroll}->{subject});
          $self->do_enroll(ENTRY     => $self->{ITEMS}->{$entryname},
                           ENTRYNAME => $entryname);
        }
      } ## end if ($action eq ' renew'...)
    } ## end else [ if ($keystore) ]
    CertNanny::Util->setVariable('NAME',  'KEYSTORE', 
                                 'VALUE', 'Common');
  } ## end foreach my $entryname (keys %{$self...})

  return 1;
} ## end sub _iterate_entries


sub _dumpValue {
  my $self = shift;
  my $cref = shift;
  my $aref = shift;

  # First handle all values
  foreach my $key (sort {lc($a) cmp lc($b)} keys %{$cref}) {
    if (ref($cref->{$key}) ne "HASH") {
      next if ($key eq 'INHERIT');                  # We do not dump this INHERIT stuff since it does give no information
      my $name  = '  ' x ($#$aref + 1) . $key . ' = ';
      my $value = $name =~ /(pin|pw|target_pw|storepass|keypass|srcstorepass|deststorepass|srckeypass|destkeypass)/ ? "*HIDDEN*" : $cref->{$key};
      my $fillup = ' ' x (100 - length($name) - length($value));
      CertNanny::Logging->Out('STR', $name . $fillup . $value . "\n");
    }
  }
  # Then handle all HASHs
  # no $self->{keystore}              : print all
  foreach my $key (sort {lc($a) cmp lc($b)} keys %{$cref}) {
    if (ref($cref->{$key}) eq "HASH") {
      my $target = $self->getOption('keystore');
      next if (!defined($$aref[0]) && ($key eq 'keystore') && (uc($target) eq 'COMMON')); # print all but the keystores
      next if (defined($$aref[0]) && !defined($$aref[1]) && $target &&
              ($$aref[0] eq 'keystore') && ($key ne $target)); # $self->{keystore} = <keystore>: print all but the keystores plus <keystore>
      push(@$aref, $key);
      CertNanny::Logging->Out('STR', '  ' x $#$aref . "$key Start\n");
      $self->_dumpValue(\%{$cref->{$key}}, $aref);
      CertNanny::Logging->Out('STR', '  ' x $#$aref . "$key End\n");
      pop(@$aref);
    }
  }
}


sub do_dump {
  CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Dump");
  my $self = (shift)->getInstance();
  my %args = (@_);

  my $config    = $self->{CONFIG};
  my $target = $self->getOption('keystore');

  if ($self->{OPTION}->{object} eq 'data') {
    my @hashname;
    $self->_dumpValue(\%{$config->{CONFIG}}, \@hashname);
  } elsif ($self->{OPTION}->{object} eq 'cfg') {
    foreach my $configFileName (sort {lc($a) cmp lc($b)} keys %{$config->{CONFIGFILES}}) {
      my $printthiskeystore = 0;
      if (defined($target)) {
        my @keystore = @{$config->{CONFIGFILES}->{$configFileName}->{KEYSTORE}};
        if (@keystore) {
          foreach my $ks (@keystore) {
            if (($ks eq $target) || ($ks eq 'DEFAULT')) {
              $printthiskeystore = 1;
            }
          }
        } else {
          $printthiskeystore = 1;
        }  
      } else {
        $printthiskeystore = 1;
      }
      if ($printthiskeystore) {
        CertNanny::Logging->Out('STR', "File: <$configFileName> SHA1: $config->{CONFIGFILES}->{$configFileName}->{SHA}\n");
        foreach my $lnr (sort {lc($a) <=> lc($b)} keys %{$config->{CONFIGFILES}->{$configFileName}->{CONTENT}}) {
          my $content = $config->{CONFIGFILES}->{$configFileName}->{CONTENT}->{$lnr};
          my $name = (split('=', $content))[0];
          if ($name =~ /(pin|pw|target_pw|storepass|keypass|srcstorepass|deststorepass|srckeypass|destkeypass)/) {
            $content = "${name}= *HIDDEN*";
          }
          CertNanny::Logging->Out('STR', sprintf("Line: %3s Content: <%s>\n", $lnr, $content));
        }
        CertNanny::Logging->Out('STR', "\n");
      }
    }
  } elsif ($self->{OPTION}->{object} eq 'keystore') {
    my @keystores = (sort {lc($a) cmp lc($b)} keys(%{$config->{CONFIG}->{'keystore'}}));
    foreach my $keystore (@keystores) {
      next if (defined($target) && ($target ne $keystore));
      CertNanny::Logging->Out('STR', "Keystore <$keystore>:\n");
      foreach my $configFileName (keys %{$config->{CONFIGFILES}}) {
        foreach my $cfgFileKeystore (@{$config->{CONFIGFILES}->{$configFileName}->{KEYSTORE}}) {
          if ($keystore eq $cfgFileKeystore) {
            CertNanny::Logging->Out('STR', "  File: <$configFileName> SHA1: $config->{CONFIGFILES}->{$configFileName}->{SHA}\n");
          }
        }
      }
    }
  } elsif ($self->{OPTION}->{object} =~ /cert.*/) {
    my @keystores = (sort {lc($a) cmp lc($b)} keys(%{$config->{CONFIG}->{'keystore'}}));
    foreach my $keystore (@keystores) {
      next if (defined($target) && ($target ne $keystore));
      CertNanny::Logging->Out('STR', "Keystore <$keystore>:\n");
      foreach my $configFileName (keys %{$config->{CONFIGFILES}}) {
        foreach my $cfgFileKeystore (@{$config->{CONFIGFILES}->{$configFileName}->{KEYSTORE}}) {
          if ($keystore eq $cfgFileKeystore) {
            CertNanny::Logging->Out('STR', "  File: <$configFileName> SHA1: $config->{CONFIGFILES}->{$configFileName}->{SHA}\n");
          }
        }
      }
      CertNanny::Util->setVariable('NAME',  'KEYSTORE', 
                                   'VALUE', $keystore);
      my $keystore = CertNanny::Keystore->new(CONFIG    => $self->{CONFIG},             # give it the whole configuration
                                              ENTRY     => $self->{ITEMS}->{$keystore}, # all keystore parameters from configfile
                                              ENTRYNAME => $keystore);                  # and the keystore name from configfile
      if ($keystore) {
        my $instance  = $keystore->{INSTANCE};
        my $options   = $instance->{OPTIONS};
        if ($options->{ENTRY}->{'location'} ne 'rootonly') {
          $keystore->{CERT} = $instance->getCert();
          if (defined($keystore->{CERT})) {
            CertNanny::Util->dumpCertInfoHash(%{$keystore->{CERT}},
                                              'LOCATION', $options->{ENTRY}->{'location'},
                                              'TYPE',     $options->{ENTRY}->{'type'});
          }
        }
      }
      CertNanny::Util->setVariable('NAME',  'KEYSTORE', 
                                   'VALUE', 'Common');
    }
  } else {
    CertNanny::Logging->switchConsoleErr('STATUS', 1);
    CertNanny::Logging->Err('STR', "Missing Argument: --object cfg|data|keystore|certificate   specifies the object to be dumped\n");
  }
  
  CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Dump");
  return 1;
} ## end sub do_cfgdump


sub do_check {
  CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Check");
  my $self = (shift)->getInstance();
  my %args = (@_);

  my $keystore  = $args{KEYSTORE};
  my $instance  = $keystore->{INSTANCE};
  my $options   = $instance->{OPTIONS};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};


  if($options->{ENTRY}->{'location'} eq 'rootonly') {
    CertNanny::Logging->debug('MSG', "rootonly keystore no EE Certificate to parse");
    return 1;
  }

  $keystore->{CERT} = $instance->getCert();

  if (defined($keystore->{CERT})) {
    $keystore->{CERT}->{CERTINFO} = CertNanny::Util->getCertInfoHash(%{$keystore->{CERT}});

    if (!$instance->k_checkValidity(0)) {
      CertNanny::Logging->error('MSG', "Certificate has expired. No automatic renewal can be performed.");
      CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Check");
      return $instance->k_executeHook($config->get("keystore.$entryname.hook.warnexpired"));
      #return 1;
    }

    if (!$instance->k_checkValidity($self->{ITEMS}->{$args{ENTRYNAME}}->{autorenew_days})) {
      CertNanny::Logging->info('MSG', "Certificate is to be scheduled for automatic renewal ($self->{ITEMS}->{$args{ENTRYNAME}}->{autorenew_days}; days prior to expiry)");
    } else {
      CertNanny::Logging->info('MSG', "Certificate has not been scheduled for automatic renewal ($self->{ITEMS}->{$args{ENTRYNAME}}->{autorenew_days}; days prior to expiry)");    
    }

    if (!$instance->k_checkValidity($self->{ITEMS}->{$args{ENTRYNAME}}->{warnexpiry_days})) {
      CertNanny::Logging->notice('MSG', "WARNEXPIRY Certificate is valid for less than $self->{ITEMS}->{$args{ENTRYNAME}}->{warnexpiry_days} days");
      CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Check");
      return $instance->k_executeHook($config->get("keystore.$entryname.hook.warnexpiry"));
#      $keystore->{INSTANCE}->k_warnExpiryHook();
    }
  } else {
    CertNanny::Logging->error('MSG', "Could not parse instance certificate");
    CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Check");
    return undef;
  }
  CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Check");
  return 1;
} ## end sub do_check


sub do_renew {
  CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Renew");
  my $self   = (shift)->getInstance();
  my %args = (@_);

  my $keystore  = $args{KEYSTORE};
  my $instance  = $keystore->{INSTANCE};
  my $options   = $instance->{OPTIONS};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  if($self->{ITEMS}->{$entryname}->{'location'} ne 'rootonly') {
    $keystore->k_executeHook($config->get("keystore.$entryname.hook.execution"));
  }

  if (defined $self->{ITEMS}->{$entryname}->{rootcaupdate}->{enable} &&
      $self->{ITEMS}->{$entryname}->{rootcaupdate}->{enable} eq "true") {
    CertNanny::Logging->debug('MSG', "RootCA update activated running k_getNextTrustAnchor");
    $instance->k_getNextTrustAnchor();

    if( $instance->k_syncRootCAs() != 0 ) {
      CertNanny::Logging->debug('MSG', "syncRoots failed.");
    }
  } else {
    CertNanny::Logging->debug('MSG', "RootCA update deactivated");
  }

  if($self->{ITEMS}->{$entryname}->{'location'} eq 'rootonly') {
    CertNanny::Logging->debug('MSG', "rootonly keystore skip certificfate check and renewal");
  } else {
    if (!$instance->k_checkValidity(0)) {
      CertNanny::Logging->error('MSG', "Certificate has expired. No automatic renewal can be performed.");
      CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Renew");
      return $instance->k_executeHook($config->get("keystore.$entryname.hook.warnexpired"));
    }

    if (!$instance->k_checkValidity($self->{ITEMS}->{$entryname}->{autorenew_days})) {
      # schedule automatic renewal
      CertNanny::Util->backoffTime($self->{CONFIG});
      $instance->k_renew();
    } else {
      if ($self->getOption('force')) {
        CertNanny::Logging->debug('MSG', "Renewal forced (Certificate is still valid for more than $self->{ITEMS}->{ $entryname }->{warnexpiry_days} days)");
        # schedule automatic renewal
        CertNanny::Util->backoffTime($self->{CONFIG});
        $instance->k_renew();
      } else {
        CertNanny::Logging->debug('MSG', "Certificate is still valid for more than $self->{ITEMS}->{ $entryname }->{warnexpiry_days} days");
      }
    }

    if (!$instance->k_checkValidity($self->{ITEMS}->{$entryname}->{warnexpiry_days})) {
      if ($self->getOption('force')) {
        CertNanny::Logging->notice('MSG', "Renewal forced (Certificate is valid for less than $self->{ITEMS}->{ $entryname }->{warnexpiry_days} days)");
      } else {
        CertNanny::Logging->notice('MSG', "Certificate is valid for less than $self->{ITEMS}->{ $entryname }->{warnexpiry_days} days");
        $instance->k_executeHook($config->get("keystore.$entryname.hook.warnexpiry"));
        # $instance->k_warnExpiryHook();
      }
    }
  }

  CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Renew");
  return 1;
} ## end sub do_renew


sub do_enroll {
  CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Enrollment");
  my $self      = (shift)->getInstance();
  my %args      = (@_);

  # NO KEYSTORE in %args!!!
  my $entry     = $args{ENTRY};
  my $entryname = $args{ENTRYNAME};
  my %save      = {};

  CertNanny::Util->backoffTime($self->{CONFIG});

  if ($self->{ITEMS}->{$entryname}->{initialenroll}->{auth}->{mode} eq 'certificate') {
    CertNanny::Logging->info('MSG', "Start initial enrollment with authentication method certificate.");

    $self->{CONFIG} = CertNanny::Config->getInstance();
    my $keystore;

    # Change keystore attributes to instantitate a openSSL keystore with the entrollment certificate
    $entry->{initialenroll}->{targetType}     = $entry->{type};
    $entry->{initialenroll}->{targetLocation} = $entry->{location};
    $entry->{initialenroll}->{targetPIN}      = $entry->{key}->{pin};

    # Saving old Values
    $save{type}                               = $entry->{type};
    $save{location}                           = $entry->{location};
    $save{keyformat}                          = $entry->{key}->{format};
    $save{keyfile}                            = $entry->{key}->{file};
    $save{pin}                                = $entry->{key}->{pin};

    # Setting new values
    $entry->{type}                            = 'OpenSSL';
    $entry->{location}                        = CertNanny::Config->get("keystore.$entryname.initialenroll.auth.cert", 'FILE');
    $entry->{key}->{format}                   = 'PEM';
    $entry->{key}->{file}                     = CertNanny::Config->get("keystore.$entryname.initialenroll.auth.key", 'FILE');
    $entry->{key}->{pin}                      = $entry->{initialenroll}->{auth}->{pin};

    if (exists $entry->{hsm}) {
      $save{hsm}    = $entry->{hsm};
      $entry->{hsm} = undef;
    }
    if (exists $entry->{certreqinf}) {
      $save{certreqinf}    = $entry->{certreqinf};
      $entry->{certreqinf} = undef;
    }
    if (exists $entry->{certreq}) {
      $save{certreq}    = $entry->{certreq};
      $entry->{certreq} = undef;
    }

    CertNanny::Util->setVariable('NAME',  'KEYSTORE', 
                                 'VALUE', $entryname);
    $keystore = CertNanny::Keystore->new(CONFIG    => $self->{CONFIG},
                                         ENTRY     => $self->{ITEMS}->{$entryname},
                                         ENTRYNAME => $entryname);
    if ($keystore) {

      #$keystore->{INSTANCE}->{INITIALENROLLEMNT} = 'yes';
      $keystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{INITIALENROLLEMNT} = 'yes';

      #disable engine specific configuration
      $keystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{enroll}->{engine_section}  = undef;
      $keystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{enroll}->{sscep}->{engine} = undef;

      #Start the initial enrollment runining an native openSSL keystore renewal
      my $ret = $keystore->{INSTANCE}->k_renew();
    
      # Restoring old values
      $entry->{type}          = $save{type};
      $entry->{location}      = $save{location};
      $entry->{key}->{format} = $save{keyformat};
      $entry->{key}->{file}   = $save{keyfile};
      $entry->{key}->{pin}    = $save{pin};

      $entry->{hsm}           = $save{hsm}        if (exists $save{hsm});
      $entry->{certreqinf}    = $save{certreqinf} if (exists $save{certreqinf});
      $entry->{certreq}       = $save{certreq}    if (exists $save{certreq});

      #reset the keystore configuration after the inital enrollment back to the .cfg file specified settings including engine
      # $self->{ITEMS}->{$entryname} = $conf->{CONFIG}->{keystore}->{$entryname};

      # $conf->{CONFIG}->{ENTRY}->{INITIALENROLLEMNT} = 'yes';
      # $self->{CONFIG} = CertNanny::Config->popConf();
      $entry->{INITIALENROLLEMNT} = 'no';

      CertNanny::Util->setVariable('NAME',  'KEYSTORE', 
                                   'VALUE', $entryname);
      my $newkeystore = CertNanny::Keystore->new(CONFIG    => $self->{CONFIG},
                                                 ENTRY     => $self->{ITEMS}->{$entryname},
                                                 ENTRYNAME => $entryname);

      if ($newkeystore) {
        if (!$newkeystore->{INSTANCE}->k_retrieveState()) {
          CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Enrollment");
          return undef;
        }
        my $renewalstate = $newkeystore->{INSTANCE}->{STATE}->{DATA}->{RENEWAL}->{STATUS};

        if ($renewalstate eq 'sendrequest') {
          CertNanny::Logging->info('MSG', "Initial enrollment request still pending.");

          # get previous renewal status
          #$self->{INSTANCE}->k_retrieveState() or return undef;

          # check if we can write to the file
          $newkeystore->{INSTANCE}->k_storeState() || croak "Could not write state file $newkeystore->{STATE}->{FILE}";
        } ## end if ($renewalstate eq 'sendrequest')

        if ($renewalstate eq 'completed') {
          my $isValid = $newkeystore->{INSTANCE}->k_checkValidity($self->{ITEMS}->{$args{ENTRY}}->{autorenew_days});
          CertNanny::Logging->info('MSG', "Initial enrollment completed successfully. Onbehalf.");
          $newkeystore->{INSTANCE}->k_storeState() || croak "Could not write state file $newkeystore->{STATE}->{FILE}";
        }
      } else {
        CertNanny::Logging->info('MSG', "Initial enrollment request still pending.");
      }
    } else {
      CertNanny::Logging->info('MSG', "Can't run initial enrollment on behalf, check enrollment on behalf certificate configuration.");
    }
    CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Enrollment");
    CertNanny::Util->setVariable('NAME',  'KEYSTORE', 
                                 'VALUE', 'Common');
    return 1;
  } else {
    if ($self->{ITEMS}->{$entryname}->{initialenroll}->{auth}->{mode} eq 'password' or
        $self->{ITEMS}->{$entryname}->{initialenroll}->{auth}->{mode} eq 'anonymous') {
      CertNanny::Logging->info('MSG', "Start initial enrollment with authentication method " . $self->{ITEMS}->{$entryname}->{initialenroll}->{auth}->{mode});

      ##Change keystore attributes to instantitae a openSSL keystore with the entrollment certificate
      $self->{CONFIG} = CertNanny::Config->getInstance();
      my $keystore;

      # Change keystore attributes to instantitate a openSSL keystore with the entrollment certificate
      $entry->{initialenroll}->{targetType}     = $entry->{type};
      $entry->{initialenroll}->{targetLocation} = $entry->{location};
      $entry->{initialenroll}->{targetPIN}      = $entry->{key}->{pin};

      # Saving old Values
      $save{type}                               = $entry->{type};
      $save{location}                           = $entry->{location};
      $save{keyformat}                          = $entry->{key}->{format};
      $save{keyfile}                            = $entry->{key}->{file};
      $save{pin}                                = $entry->{key}->{pin};

      # Setting new values
      $entry->{type}                            = 'OpenSSL';
      $entry->{location}                        = CertNanny::Config->get("keystore.$entryname.initialenroll.auth.cert", 'FILE');
      $entry->{key}->{format}                   = 'PEM';
      $entry->{key}->{file}                     = CertNanny::Config->get("keystore.$entryname.initialenroll.auth.key", 'FILE');
      $entry->{key}->{pin}                      = $entry->{initialenroll}->{auth}->{pin};

      if (exists $entry->{hsm}) {
        $save{hsm}    = $entry->{hsm};
        $entry->{hsm} = undef;
      }
      if (exists $entry->{certreqinf}) {
        $save{certreqinf}    = $entry->{certreqinf};
        $entry->{certreqinf} = undef;
      }
      if (exists $entry->{certreq}) {
        $save{certreq}    = $entry->{certreq};
        $entry->{certreq} = undef;
      }
    

      $entry->{INITIALENROLLEMNT} = 'yes';

      CertNanny::Util->setVariable('NAME',  'KEYSTORE', 
                                   'VALUE', $entryname);
      my $keystore = CertNanny::Keystore->new(CONFIG    => $self->{CONFIG},
                                              ENTRY     => $self->{ITEMS}->{$entryname},
                                              ENTRYNAME => $entryname);
      $keystore->{INSTANCE}->k_retrieveState() || croak "Could not write state file $keystore->{STATE}->{FILE}";
      $keystore->{INSTANCE}->{ENTRY}->{INITIALENROLLEMNT} = 'yes';

      if ($self->{ITEMS}->{$entryname}->{initialenroll}->{auth}->{mode} eq 'password') {
        if (!defined $keystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{initialenroll}->{auth}->{challengepassword}) {
          CertNanny::Logging->debug('MSG', 'Using commandline argument challangePassword for initial enrollment');
          $keystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{initialenroll}->{auth}->{challengepassword} = $self->getOption('challengepassword');
        } ## end if (!defined $newkeystore...)
      } ## end if ($self->{ITEMS}->{$entryname...})
      
      my $key     = $keystore->{INSTANCE}->{OPTIONS}->{ENTRYNAME} . "-key.pem";
      my $keyfile = File::Spec->catfile($keystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{statedir}, $key);

      unless (-e $keyfile) {
        my $newkey = $keystore->{INSTANCE}->generateKey();

        CertNanny::Logging->debug('MSG', "keyfile <$newkey->{KEYFILE}> ,  ");
        $keystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{key}->{file} = $newkey->{KEYFILE};
        CertNanny::Logging->debug('MSG', "keyfile <$keystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{key}->{file}> ,  ");
        $keystore->{INSTANCE}->{ENTRY}->{key}->{format} = 'PEM';
      } else {
        CertNanny::Logging->debug('MSG', "Key already generated");
        #CertNanny::Logging->debug('MSG', 'newkeystore with key : '.Dumper($newkeystore));
        $keystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{key}->{file} = $keyfile;
        $entry->{key}->{file} = $entry->{initialenroll}->{auth}->{key};
        $entry->{key}->{pin}  = $entry->{initialenroll}->{auth}->{pin};
      } ## end else

      my $selfsigncert = $keystore->{INSTANCE}->{OPTIONS}->{ENTRYNAME} . "-selfcert.pem";
      my $outCert = File::Spec->catfile($keystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{statedir}, $selfsigncert);

      unless (-e $outCert) {
        CertNanny::Logging->debug('MSG', "Initial enrollment started, generate new selfsigned cert ");
        my $newSelfsignCert = $keystore->{INSTANCE}->selfSign();

        #CertNanny::Logging->debug('MSG', Dumper($newSelfsignCert));
        $keystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{location} = $newSelfsignCert->{CERT};
      } else {
        $keystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{location} = $outCert;
      }

      $keystore->{CERT} = $keystore->{INSTANCE}->getCert();

      if (defined $keystore->{CERT}) {
        $keystore->{CERT}->{CERTINFO} = CertNanny::Util->getCertInfoHash(%{$keystore->{CERT}});
        my $subjectname = $keystore->{CERT}->{CERTINFO}->{SubjectName};
        my $serial      = $keystore->{CERT}->{CERTINFO}->{SerialNumber};
        my $issuer      = $keystore->{CERT}->{CERTINFO}->{IssuerName};
        CertNanny::Logging->debug('MSG', "Certificate Information: SubjectName: <$subjectname>");
        CertNanny::Logging->debug('MSG', "                         Serial:      <$serial>");
        CertNanny::Logging->debug('MSG', "                         Issuer:      <$issuer>");

        my %convopts = %{$keystore->{CERT}};

        $convopts{OUTFORMAT} = 'PEM';
        $keystore->{CERT}->{RAW}->{PEM} = CertNanny::Util->convertCert(%convopts)->{CERTDATA};
#        $newkeystore->{INSTANCE}->k_convertCert(%convopts)->{CERTDATA};
        $convopts{OUTFORMAT} = 'DER';
        $keystore->{CERT}->{RAW}->{DER} = CertNanny::Util->convertCert(%convopts)->{CERTDATA};
#        $newkeystore->{INSTANCE}->k_convertCert(%convopts)->{CERTDATA};
      } else {
        CertNanny::Logging->error('MSG', "Could not parse instance certificate");
        CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Enrollment");
        return undef;
      }

      $keystore->{INSTANCE}->k_setCert($keystore->{CERT});

      #disable engine specific configuration
      $keystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{key}->{file}               = $keyfile;
      $keystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{location}                  = $outCert;
      $keystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{enroll}->{engine_section}  = undef;
      $keystore->{INSTANCE}->{OPTIONS}->{ENTRY}->{enroll}->{sscep}->{engine} = undef;

      #Start the initial enrollment runining an native openSSL keystore renewal
      my $ret = $keystore->{INSTANCE}->k_renew();

      my $renewalstate = $keystore->{INSTANCE}->{STATE}->{DATA}->{RENEWAL}->{STATUS};

      if (defined $renewalstate) {
        CertNanny::Logging->debug('MSG', "renewalstate is <" . $renewalstate . ">");
      }

      if (defined $renewalstate and $renewalstate eq 'sendrequest') {
        CertNanny::Logging->info('MSG', "Initial enrollment request send.");
        $keystore->{INSTANCE}->k_storeState() || croak "Could not write state file $keystore->{STATE}->{FILE}";
      }

      if (!defined $renewalstate) {
           # Restoring old values
        $entry->{type}          = $save{type};
        $entry->{location}      = $save{location};
        $entry->{key}->{format} = $save{keyformat};
        $entry->{key}->{file}   = $save{keyfile};
        $entry->{key}->{pin}    = $save{pin};

        $entry->{hsm}           = $save{hsm}        if (exists $save{hsm});
        $entry->{certreqinf}    = $save{certreqinf} if (exists $save{certreqinf});
        $entry->{certreq}       = $save{certreq}    if (exists $save{certreq});
    
        #reset the keystore configuration after the inital enrollment back to the .cfg file specified settings including engine
        # $self->{ITEMS}->{$entryname} = $conf->{CONFIG}->{keystore}->{$entryname};

        # $conf->{CONFIG}->{ENTRY}->{INITIALENROLLEMNT} = 'yes';
        # $self->{CONFIG} = CertNanny::Config->popConf();
        $entry->{INITIALENROLLEMNT} = 'no';

       CertNanny::Util->setVariable('NAME',  'KEYSTORE', 
                                    'VALUE', $entryname);
        my $newkeystore = CertNanny::Keystore->new(CONFIG    => $self->{CONFIG},
                                                   ENTRY     => $self->{ITEMS}->{$entryname},
                                                   ENTRYNAME => $entryname);

        if ($newkeystore) {
          unlink $selfsigncert;
          CertNanny::Logging->info('MSG', "Initial enrollment completed successfully. Mode:" . $self->{ITEMS}->{$entryname}->{initialenroll}->{auth}->{mode});
        } else {
          CertNanny::Logging->info('MSG', "Initial enrollment still ongoing. Mode:" . $self->{ITEMS}->{$entryname}->{initialenroll}->{auth}->{mode});
        }
      }
      CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Enrollment");
      CertNanny::Util->setVariable('NAME',  'KEYSTORE', 
                                   'VALUE', 'Common');
      return 1;
    } else {
      CertNanny::Logging->error('MSG', "Initial enrollment authentication method " . $self->{ITEMS}->{$entryname}->{initialenroll}->{auth}->{mode} . " not supported");
    }
  } ## end else [ if ($self->{ITEMS}->{$entryname...})]
  CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Enrollment");
  return 1;
} ## end sub do_enroll


sub do_cleanup {
  CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "CleanUp");
  my $self = (shift)->getInstance();
  my %args = (@_);

  my $keystore  = $args{KEYSTORE};
  my $instance  = $keystore->{INSTANCE};
  my $options   = $instance->{OPTIONS};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  my $myKeystore  = $self->getOption('keystore');
  if (!defined($myKeystore) || ($myKeystore eq $entryname)) {
    $instance->k_checkclearState(1);
  }

  CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "CleanUp");
  return 1;
} ## end sub do_info


sub do_updateRootCA {
  CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Update Root CA");
  my $self = (shift)->getInstance();
  my %args = (@_);

  my $keystore  = $args{KEYSTORE};
  my $instance  = $keystore->{INSTANCE};
  my $options   = $instance->{OPTIONS};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  if (defined $self->{ITEMS}->{$entryname}->{rootcaupdate}->{enable} &&
      $self->{ITEMS}->{$entryname}->{rootcaupdate}->{enable} eq "true") {
    CertNanny::Logging->debug('MSG', "RootCA update activated running k_getNextTrustAnchor");
    $instance->k_getNextTrustAnchor();
  } else {
    CertNanny::Logging->debug('MSG', "RootCA update deactivated");
  }

  CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Update Root CA");
  return 1;
} ## end sub do_updateRootCA


sub do_executeHook {
  CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Info");
  my $self = (shift)->getInstance();
  my %args = (@_);

  my $keystore  = $args{KEYSTORE};
  my $instance  = $keystore->{INSTANCE};
  my $options   = $instance->{OPTIONS};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  my $myKeystore  = $self->getOption('keystore');
  if (!defined($myKeystore) || ($myKeystore eq $entryname)) {
    my $hook        = $self->getOption('hook');
    my $definitions = $self->getOption('define');
    my %args;
    foreach (@{$definitions}) {
      (my $key, my $value) = split('=');
      $args{$key} = $value;
    }
  
    if ($hook) {
      my $hookdef = "keystore.$entryname.hook.$hook";
      my $hookcmd = $config->get($hookdef);
      if ($hookcmd) {
        CertNanny::Logging->Out('STR', "Executing hook <$hookdef> with command <$hookcmd>\n");
        $keystore->k_executeHook($hookcmd, %args);
      } else {
        CertNanny::Logging->Out('STR', "No command defined for hook <$hookdef>\n");
      }
    } else {
      CertNanny::Logging->Out('STR', "No hook specified for execHook\n");
    }
  }
  
  CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Info");
  return 1;
} ## end sub do_info


sub do_test {
  CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Test");
  my $self = (shift)->getInstance();
  my %args = (@_);

  my $config = $self->{CONFIG};
  my $target = $self->getOption('keystore');

  my @keystores = (sort {lc($a) cmp lc($b)} keys(%{$config->{CONFIG}->{'keystore'}}));
  foreach my $keystore (@keystores) {
    next if (defined($target) && ($target ne $keystore));
    CertNanny::Logging->Out('STR', "Keystore <$keystore:>\n");
    foreach my $configFileName (keys %{$config->{CONFIGFILES}}) {
      foreach my $cfgFileKeystore (@{$config->{CONFIGFILES}->{$configFileName}->{KEYSTORE}}) {
        if ($keystore eq $cfgFileKeystore) {
          CertNanny::Util->setVariable('NAME',  'KEYSTORE', 
                                       'VALUE', $keystore);
          my $keystore = CertNanny::Keystore->new(CONFIG    => $self->{CONFIG},             # give it the whole configuration
                                                  ENTRY     => $self->{ITEMS}->{$keystore}, # all keystore parameters from configfile
                                                  ENTRYNAME => $keystore);                  # and the keystore name from configfile
          if ($keystore) {
            $keystore     = $keystore->{INSTANCE};
            my $options   = $keystore->{OPTIONS};
            my $entry     = $options->{ENTRY};
            my $enroller  = $keystore->k_getEnroller();
            if (defined($enroller)) {
              my %certs = $enroller->getCA();
              if (%certs) {
                CertNanny::Logging->Out('STR', "  Certificate <$certs{RACERT}>:\n");
                CertNanny::Util->dumpCertInfoHash('CERTINFO', $keystore->{CERT}->{CERTINFO},
                                                  'CERTDATA', $keystore->{CERT}->{CERTDATA},
                                                  'CERTFILE', $keystore->{CERT}->{CERTFILE},
                                                  'PADDING',  4,
                                                  'LOCATION', $entry->{'location'}, 
                                                  'TYPE',     $entry->{'type'});
                foreach my $cert (@{$certs{CACERTS}}) {
                  CertNanny::Logging->Out('STR', "  Certificate <$cert->{CERTFILE}>:\n");
                  CertNanny::Util->dumpCertInfoHash('CERTINFO', $cert->{CERTINFO},
                                                    'CERTDATA', $cert->{CERTDATA},
                                                    'CERTFILE', $cert->{CERTFILE},
                                                    'PADDING',  4,
                                                    'LOCATION', $entry->{'location'}, 
                                                    'TYPE',     $entry->{'type'});
                }
              } else {
                CertNanny::Logging->Out('STR', "  Could not instantiate Keystore: <$keystore>\n");
              }
            }
          }
          CertNanny::Util->setVariable('NAME',  'KEYSTORE', 
                                       'VALUE', 'Common');
        }
      }
    }
  }

  CertNanny::Logging->debug('MSG', eval 'ref(\$self)' ? "End" : "Start", (caller(0))[3], "Test");
  return 1;
} ## end sub do_test


1;
