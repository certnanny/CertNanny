#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2011-05 Florian Ruechel <florian.ruechel@gmail.com>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#
package CertNanny::HSM::Utimaco;
use strict;
use warnings;
use base qw(Exporter);
use CertNanny::Logging;
use CertNanny::Util;
use File::Spec;
use vars qw( $VERSION );
use Exporter;
use Cwd;

sub new() {
  my $proto          = shift;
  my $class          = ref($proto) || $proto;
  my $entry_options  = shift;
  my $hsm_options    = $entry_options->{hsm};
  my $config         = shift;
  my $entryname      = shift;
  my $self           = {};
  my @avail_keytypes = ("file", "token");

  bless $self, $class;

  #remove type, we know that here
  delete $hsm_options->{type};

  my $engine_section = $entry_options->{enroll}->{sscep}->{engine} || 'engine_section';
  $entry_options->{enroll}->{sscep}->{engine}                 = $engine_section;
  $entry_options->{enroll}->{$engine_section}->{engine_id}    = $self->engineid();
  $entry_options->{enroll}->{$engine_section}->{dynamic_path} = $hsm_options->{dynamic_path};
  $entry_options->{enroll}->{$engine_section}->{MODULE_PATH}  = $hsm_options->{MODULE_PATH};
  if ($hsm_options->{key}->{type} ne "file") {
    $entry_options->{enroll}->{sscep_engine_pkcs11}->{PIN} = $entry_options->{key}->{pin};
  }

  unless (defined $hsm_options->{key}->{type} and (grep $_ eq $hsm_options->{key}->{type}, @avail_keytypes)) {
    CertNanny::Logging->error(qq("$hsm_options->{key}->{type} is not an available keytype."));
    return undef;
  }

  if ($hsm_options->{key}->{type} eq "file") {
    CertNanny::Logging->error("File-type keys are not supported yet due to an incomplete engine, sorry.");
    return undef;
  } else {

    # keytype = token
    unless (defined $hsm_options->{p11tool} and -x $hsm_options->{p11tool}) {
      CertNanny::Logging->error("No executable defined or found to generate a key for Utimaco HSM.");
      return undef;
    }

    #make all params lowercase
    my @parameters = $self->availparams();
    foreach my $param (keys %{$hsm_options->{key}}) {
      my $value = $hsm_options->{key}->{$param};
      $param = lc($param);
      delete $hsm_options->{key}->{$param};
      $hsm_options->{key}->{$param} = $value;

    }

    #set pin from keystore config
    if ($hsm_options->{key}->{login}) {
      CertNanny::Logging->info("hsm.key.login is set, but it will be overwritten by PIN setting.");
    }

    unless ($entry_options->{key}->{pin}) {
      CertNanny::Logging->error("You need to set the keystore option key.pin to your login pin.");
      return undef;
    }
    $hsm_options->{key}->{login} = $entry_options->{key}->{pin};
    $hsm_options->{key}->{id}    = $entry_options->{key}->{file};

    #check mandatory params
    foreach my $param (qw(slot login id)) {
      unless (defined $hsm_options->{key}->{$param}) {
        CertNanny::Logging->error("The parameter key.$param is mandatory and needs to be set. Aborting...");
        return undef;
      }
    }

  } ## end else [ if ($hsm_options->{key}->{type...})]

  $self->{hsm_options} = $hsm_options;
  $self->{ENTRY}       = $entry_options;
  $self->{ENTRYNAME}   = $entryname;
  $self->{CONFIG}      = $config;

  unless ($self->{all_keys} = $self->loadKeyInfo()) {
    CertNanny::Logging->error("Could not load key information.");
    return undef;
  }

  return $self;
} ## end sub new


sub genkey() {
  my $self         = shift;
  my $p11tool      = $self->{hsm_options}->{p11tool};
  my @generateopts = ();
  my @parameters   = $self->availparams();
  my $genkeyopt    = "genkey=RSA,1024";
  my $new_label;

  unless ($self->checkKeySanity()) {
    CertNanny::Logging->error("genkey(): Could not complete key sanity check, aborting.");
    return undef;
  }

  foreach my $param (keys %{$self->{hsm_options}->{key}}) {
    my $value = $self->{hsm_options}->{key}->{$param};
    next if (lc($param) eq "inherit");
    next if (!$value);
    if ((grep $_ eq $param, @parameters)) {
      if ($param eq "id") {
        my $current_id = $self->getCurrentKeyNumber();
        if ($current_id == -1) {
          CertNanny::Logging->error("genkey(): Could not get a valid number for the current key.");
          return undef;
        }
        $current_id += 1;
        $value =~ s/%i/$current_id/;
        $new_label = $value;
      } ## end if ($param eq "id")
      push(@generateopts, qq($param=$value));
    } elsif ($param eq "genkey") {
      $genkeyopt = qq($param=$value);
    } else {
      CertNanny::Logging->error(qq("Could not handle parameter $param with value $value."));
      return undef;
    }
  } ## end foreach my $param (keys %{$self...})

  my @cmd = ($p11tool, @generateopts, $genkeyopt);

  # CertNanny::Logging->debug("Execute: " . $self->hidepin(join(" ", @cmd)));
  # Todo pgk: Testen hidePin
  my $rc = CertNanny::Util->runCommand(\@cmd, HIDEPWD => 1);
  if ($rc != 0) {
    CertNanny::Logging->error("genkey(): Could not generate new key in HSM, see logging output.");
    return undef;
  }

  #refresh keys since it has changed
  $self->{all_keys} = $self->loadKeyInfo();
  my $new_key_id = $self->getKeyID($new_label);
  return $new_key_id;
} ## end sub genkey


sub loadKeyInfo() {
  my $self    = shift;
  my $p11tool = $self->{hsm_options}->{p11tool};
  my $slot    = $self->{hsm_options}->{key}->{slot};
  my $login   = $self->{hsm_options}->{key}->{login};
  my @cmd     = ($p11tool, "slot=$slot", "login=$login", "ListObjects");
  my $cmd     = join(" ", @cmd);
  # CertNanny::Logging->debug("Exec: " . $self->hidepin($cmd));
  # Todo pgk: Testen hidePin
  CertNanny::Logging->debug("Exec: " . CertNanny::Util->hidePin($cmd));
  my $output;

  open FH, "$cmd |" or die "Couldn't execute $cmd: $!\n";
  while (defined(my $line = <FH>)) {
    $output .= $line;
  }
  close FH;
  my $exitval = $? >> 8;
  if ($exitval != 0) {
    CertNanny::Logging->error("Could not execute command successfully.");
    return undef;
  }

  my $keys = {};
  my @groups = split(/\+ \d+\.\d+/, $output);
  foreach my $group (@groups) {
    next unless $group =~ /id\s*:\s*[a-f0-9\s]+/;
    $group =~ /id\s*:\s*([a-f0-9\s]+).*?\|(.*?)\|/;
    my $id    = $1;
    my $label = $2;
    $label =~ s/\s*//g;
    $id =~ s/\s*//g;
    unless ($id and $label) {
      CertNanny::Logging->error("Could not get id and label from following output: $group");
      return undef;
    }
    $keys->{$id} = $label;
  } ## end foreach my $group (@groups)

  CertNanny::Logging->debug("Printing all keys...");
  foreach my $id (keys %{$keys}) {
    my $label = $keys->{$id};
    CertNanny::Logging->debug("Found key with id $id and label $label");
  }

  return $keys;
} ## end sub loadKeyInfo


sub getKeyID() {
  my $self  = shift;
  my $label = shift;
  foreach my $id (keys %{$self->{all_keys}}) {
    my $current_label = $self->{all_keys}->{$id};
    if ($current_label eq $label) {
      return $id;
    }
  }
  return undef;
} ## end sub getKeyID


sub getCurrentKeyNumber() {
  my $self           = shift;
  my $highest_number = -1;
  my $token_pattern  = $self->{hsm_options}->{key}->{id};
  $token_pattern =~ s/%i/(\\d+)/;
  CertNanny::Logging->debug("getCurrentKeyNumber(): Will match on token pattern $token_pattern");

  my %all_keys = %{$self->{all_keys}};
  foreach my $id (keys %{$self->{all_keys}}) {
    my $label = $self->{all_keys}->{$id};
    next unless ($label =~ m/$token_pattern/);
    my $number = int($1);
    if ($number > $highest_number) {
      $highest_number = $number;
    } elsif ($number == $highest_number) {
      CertNanny::Logging->error("getCurrentKeyNumber(): Found the same label twice, aborting.");
      return -1;
    }
  } ## end foreach my $id (keys %{$self...})

  if ($highest_number == -1) {
    CertNanny::Logging->error("getCurrentKeyNumber(): Could not get a valid number, returning");
    return -1;
  }

  return $highest_number;
} ## end sub getCurrentKeyNumber


sub availparams() {
  return ("dev", "device", "lib", "password", "slot", "subject", "timeout", "id", "label", "login");
}


sub engineid() {
  my $self    = shift;
  my $keytype = $self->{hsm_options}->{key}->{type};
  if (defined $keytype and $keytype eq "file") {
    return "cs";
  } else {
    return "pkcs11";
  }
} ## end sub engineid


sub keyform() {
  my $self    = shift;
  my $keytype = $self->{hsm_options}->{key}->{type};
  if (defined $keytype and $keytype eq "file") {
    return undef;
  } else {
    return "engine";
  }
} ## end sub keyform


sub getEngineConfiguration() {
  my $self        = shift;
  my $hsm_options = $self->{hsm_options};
  my $keytype     = $hsm_options->{key}->{type};
  my @config      = ();
  if (CertNanny::Util->staticEngine($self->engineid())) {
    CertNanny::Logging->debug("getEngineConfiguration(): Engine reports to be statically compiled with OpenSSL, not return a configuration as none should be needed.");
    return undef;
  }

  unless (defined $hsm_options->{dynamic_path} and -r $hsm_options->{dynamic_path}) {
    CertNanny::Logging->error("getEngineConfiguration(): You need to configure a dynamic path or else engine can not be loaded");
    die;
  }
  push(@config, {dynamic_path => $hsm_options->{dynamic_path}});

  push(@config, {engine_id => $self->engineid()});

  if ($self->engineid() eq "pkcs11") {
    unless (defined $hsm_options->{MODULE_PATH} and -r $hsm_options->{MODULE_PATH}) {
      CertNanny::Logging->error("getEngineConfiguration(): You need to configure a MODULE_PATH since engineid is pkcs11");
      die;
    }
    push(@config, {MODULE_PATH => $hsm_options->{MODULE_PATH}});
  }

  push(@config, {init => '1'});
  push(@config, {PIN  => $hsm_options->{key}->{login}});

  return \@config;
} ## end sub getEngineConfiguration


sub getKey() {
  my $self          = shift;
  my $entry_options = $self->{ENTRY};

  # since we already generated a new key, the old one is the one with one number less
  my $old_key_number = $self->getCurrentKeyNumber() - 1;
  unless ($old_key_number) {
    CertNanny::Logging->error("Could not get number for old key");
    return undef;
  }

  my $old_key = $entry_options->{key}->{file};
  $old_key =~ s/%i/$old_key_number/;

  unless ($old_key) {
    CertNanny::Logging->error("Could not get old key");
    return undef;
  }

  my $old_key_id = $self->getKeyID($old_key);
  unless ($old_key_id) {
    CertNanny::Logging->error("Could not get ID for label $old_key");
    return undef;
  }

  return $old_key_id;
} ## end sub getKey


sub checkKeySanity() {
  my $self = shift;

  CertNanny::Logging->debug("checkKeySanity(): Checking key sanity.");

  # 1: get modulus of current certificate
  my $certfile = $self->{ENTRY}->{location};
  unless (-r $certfile) {
    CertNanny::Logging->error("checkKeySanity(): Cannot find current certificate.");
    return undef;
  }

  my $certinfo = CertNanny::Util->getCertInfoHash(CERTFILE   => $certfile, 
                                                  CERTFORMAT => 'PEM');
  unless ($certinfo) {
    CertNanny::Logging->error("checkKeySanity(): Cannot get certificate information for current certificate.");
    return undef;
  }

  my $certificate_modulus = $certinfo->{Modulus};
  unless ($certificate_modulus) {
    CertNanny::Logging->error("checkKeySanity(): Cannot get modulus of current certificate.");
    return undef;
  }

  # 2: get modulus of each key by generating a csr and checking against it
  my $current_key_id;
  my $openssl = $self->{CONFIG}->get('cmd.openssl', 'CMD');
  $self->{all_keys} = $self->loadKeyInfo();
  foreach my $id (keys %{$self->{all_keys}}) {
    my $label       = $self->{all_keys}->{$id};
    my $requestfile = $self->createDummyCSR($id);
    my @cmd         = (qq("$openssl"), 'req', '-in', qq("$requestfile"), '-modulus', '-noout');

    my $cmd = join(" ", @cmd);
    CertNanny::Logging->debug("Execute: $cmd");
    my $output;
    open FH, "$cmd |" or die "checkKeySanity(): Couldn't execute $cmd: $!\n";
    while (defined(my $line = <FH>)) {
      $output .= $line;
    }
    close FH;
    $output =~ m/Modulus=([A-F0-9]+)$/;
    my $modulus = $1;
    unless ($modulus) {
      CertNanny::Logging->error("checkKeySanity(): Could not retreive Modulus from csr $requestfile, output was: $output");
      return undef;
    }

    if ($modulus eq $certificate_modulus) {
      $current_key_id = $id;
      last;
    }
  } ## end foreach my $id (keys %{$self...})

  # 3: delete keys that are *NEWER* than the current one (old ones are backups)
  my $current_key_label = $self->{all_keys}->{$current_key_id};
  # Todo pgk : Alle Hashkeys nach lowercase aendern!!!!!
  my $key_pattern       = $self->{ENTRY}->{key}->{file};
  $key_pattern =~ s/%i/(\\d+)/;
  $current_key_label =~ m/$key_pattern/;
  my $current_key_number = $1;
  unless ($current_key_number) {
    CertNanny::Logging->error("checkKeySanity(): Could not get current key number for label $current_key_label");
    return undef;
  }
  $current_key_number = int($current_key_number);
  foreach my $id (keys %{$self->{all_keys}}) {
    my $label = $self->{all_keys}->{$id};
    $label =~ m/$key_pattern/;
    my $key_number = int($1);
    next unless ($key_number);
    next unless ($key_number > $current_key_number);
    unless ($self->deleteKey($id)) {
      CertNanny::Logging->error("checkKeySanity(): Key deletion process not successful, aborting.");
      return undef;
    }
  } ## end foreach my $id (keys $self->...)

  # update current set of keys
  $self->{all_keys} = $self->loadKeyInfo();

  return 1;

} ## end sub checkKeySanity

#used only for sanity checks
sub createDummyCSR() {
  my $self    = shift;
  my $keyid   = shift;
  my $openssl = $self->{CONFIG}->get('cmd.openssl', 'CMD');
  CertNanny::Logging->debug("Creating dummy CSR for key ID $keyid to get its modulus");
  my $dummy_cfg = {
    openssl_conf => "openssl_def",

    req_distinguished_name => [{"1.DC" => "com"}, {"O" => "Some ORG"}, {"CN" => "MyCN"}],

    req => [{prompt => "no"}, {distinguished_name => "req_distinguished_name"}],

    openssl_def => [{engines => "engine_section"}],

    engine_section => [{pkcs11 => "pkcs11_section"}],

    pkcs11_section => $self->getEngineConfiguration()};

  my $tmpconfigfile = CertNanny::Util->writeOpenSSLConfig($dummy_cfg);
  my $requestfile   = CertNanny::Util->getTmpFile();
  my $pin           = $self->{hsm_options}->{key}->{login};

  my @engine_cmd;
  push(@engine_cmd, '-engine',  $self->engineid());
  push(@engine_cmd, '-keyform', $self->keyform());

  my @cmd = (qq("$openssl"), 'req', '-config', qq("$tmpconfigfile"), '-new', '-sha1', '-out', qq("$requestfile"), '-key', qq("$keyid"),);
  push(@cmd, @engine_cmd);

  if (CertNanny::Util->runCommand(\@cmd) != 0) {
    CertNanny::Logging->error("Could not create dummy CSR for key ID $keyid");
    return undef;
  }

  return $requestfile;
} ## end sub createDummyCSR


sub deleteKey() {
  my $self        = shift;
  my $keyid       = shift;
  my $hsm_options = $self->{hsm_options};
  my $p11tool     = $hsm_options->{p11tool};
  my @deleteopts;
  CertNanny::Util->timeStamp();

  CertNanny::Logging->debug("deleteKey(): Deleting key with ID $keyid");
  push(@deleteopts, 'Slot=' . $hsm_options->{key}->{slot});
  push(@deleteopts, 'Login=' . $hsm_options->{key}->{login});
  push(@deleteopts, 'Id=$' . $keyid);

  my @cmd = (qq("$p11tool"), @deleteopts, 'DeleteObject');

  # CertNanny::Logging->debug("Execute: " . $self->hidepin(join(" ", @cmd)));
  # Todo pgk: Testen hidePin
  if (CertNanny::Util->runCommand(\@cmd, HIDEPWD => 1) != 0) {
    CertNanny::Logging->error("deleteKey(): Could not delete key with ID $keyid");
    return undef;
  }

  CertNanny::Logging->debug("deleteKey(): Successfully deleted key with ID $keyid");
  return 1;

} ## end sub deleteKey


#sub hidepin() {
#  my $self = shift;
#  my $cmd  = shift;
#
#  $cmd =~ s/Login=\S+/Login=*HIDDEN*/;
#  return $cmd;
#}

1;

=head1 NAME

CertNanny::HSM::Utimaco - Interface for using Utimacos Se-/Ce-Series and all similar with CertNanny.

=head1 SYNOPSIS

my $hsm = new CertNanny::HSM::Utimaco();
my $newkey = $hsm->genkey();

=head1 DESCRIPTION

Implements the CertNanny::HSM interface. Currently supports key generation.

=head1 ISSUES

=over 4

=item User PIN on command line

Utimaco's p11tool accepts PINs via command line by passing the Login=*PIN* command. For every operation that works on a user's token (all operations within the HSM do that). Unfortunately, this means the PIN has to be passed to the tool, which in turn means it could be read from the command line. This issue can only be resolved by providing a different way to pass the PIN or generating keys in another way.

=back

=head1 FUNCTIONS

=head2 Function List

=over 4

C<new()>

C<genkey()>

=back

=head2 Function Descriptions

=over 4

=item new()

Create a new instance for an HSM. The implementation should provide all necessary information to use all implemented functions.

=item genkey()

Generate a new key within the HSM. The exact method may depend on the configuration and implementation.
