#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2011-05 Florian Ruechel <florian.ruechel@gmail.com>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#
package CertNanny::HSM::Chil;
use strict;
use warnings;
use base qw(Exporter);
use CertNanny::Logging;
use File::Spec;
use vars qw( $VERSION );
use Exporter;
use Cwd;
use CertNanny::Util;
use Data::Dumper;

$VERSION = 0.10;


sub new() {
  my $proto          = shift;
  my $class          = ref($proto) || $proto;
  my $entry_options  = shift;
  my $hsm_options    = $entry_options->{hsm};
  my $config         = shift;
  my $entryname      = shift;
  my $self           = {};
  my @avail_keytypes = ("embed", "hwcrhk");

  bless $self, $class;

  #remove type, we know that here
  delete $hsm_options->{type};

  my $engine_section = $entry_options->{enroll}->{sscep}->{engine} || 'engine_section';
  $entry_options->{enroll}->{sscep}->{engine}                 = $engine_section;
  $entry_options->{enroll}->{$engine_section}->{engine_id}    = $self->engineid();
  $entry_options->{enroll}->{$engine_section}->{dynamic_path} = $self->{OPTIONS}->{ENTRY}->{hsm}->{dynamic_path};

  unless (defined $hsm_options->{generatekey} and -x $hsm_options->{generatekey}) {
    CertNanny::Logging->error("No executable defined or found to generate a key for Chil HSM");
    return undef;
  }

  unless (defined $hsm_options->{key}->{type} and (grep $_ eq $hsm_options->{key}->{type}, @avail_keytypes)) {
    CertNanny::Logging->error(qq("$hsm_options->{key}->{type} is not an available keytype."));
    return undef;
  }

  $self->{hsm_options} = $hsm_options;
  $self->{ENTRY}       = $entry_options;
  $self->{ENTRYNAME}   = $entryname;
  $self->{CONFIG}      = $config;

  return $self;
} ## end sub new


sub genkey() {
  my $self = shift;
  my $key;
  my @generateopts = ();
  foreach my $param (keys %{$self->{hsm_options}->{key}}) {
    push(@generateopts, qq("$param=$self->{hsm_options}->{key}->{$param}"));
  }

  my @cmd;
  push(@cmd, $self->{hsm_options}->{generatekey});
  push(@cmd, '-b');
  push(@cmd, $self->{hsm_options}->{key}->{type});
  if ($self->{hsm_options}->{key}->{type} eq "embed") {
    my $keyfile = $self->{ENTRYNAME} . "-key.pem";
    my $outfile = File::Spec->catfile($self->{ENTRY}->{statedir}, $keyfile);
    push(@cmd, "embedsavefile=$outfile");
    $key = $outfile;
  } else {

    #hwcrhk key
    # TODO sub genkey WARNING! THIS CANNOT WORK RIGHT NOW
    # IT WILL OVERWRITE THE OLD KEY OR FAIL!
    # DO NOT USE LIKE THIS !!!
    # How to fix this? - Need to have both keys active
    # but on installation the new key must replace the old one.
    # The old one should be archived if possible, else overwritten.
    # How do applications do this, if they get a new certificate currently?
    CertNanny::Logging->error("hwcrhk keys not implemented yet. Aborting...");
    return undef;
    $key = $self->{ENTRY}->{location};
    push(@cmd, "ident=$key");
  } ## end else [ if ($self->{hsm_options...})]
  push(@cmd, @generateopts);

  my $rc = CertNanny::Util->runCommand(\@cmd);
  if ($rc != 0) {
    CertNanny::Logging->error("Could not generate new key in HSM, see logging output.");
    return undef;
  }

  # It may not actually be a file (see hwcrhk) but we stay in
  # line with the terminology used in CertNanny.
  return $key;
} ## end sub genkey


sub keyform() {
  my $self = shift;
  if ($self->{hsm_options}->{key}->{type} eq "hwcrhk") {
    return "engine";
  } else {
    return undef;
  }
}


sub engineid() {
  my $self = shift;
  return "chil";
}

# too bad, OpenSSL csr generation does not work with this engine
sub createRequest() {
  my $self        = shift;
  my $result      = shift;
  # Todo pgk: {KEYFILE} oder {key}->{file}
  my $keyfile     = $result->{KEYFILE};
  my $requestfile = $keyfile;
  $requestfile =~ s/-key.pem$/-key_req.pem/;
  $result->{REQUESTFILE} = $requestfile;
  return $result;
}


sub getEngineConfiguration() {
  my $self = shift;

  if (CertNanny::Util->staticEngine($self->engineid())) {
    CertNanny::Logging->debug("getEngineConfiguration(): Engine reports to be statically compiled with OpenSSL, not return a configuration as none should be needed.");
    return undef;
  }

  # NYI: Not yet implemented. See Utimaco.pm for reference / help
  CertNanny::Logging->error("getEngineConfiguration(): Unfortunately, the engine is not static and dynamic loading is not yet supported. Please make a version of OpenSSL with a static engine or implement this.");
  die;
} ## end sub getEngineConfiguration

1;

=head1 NAME

CertNanny::HSM::Chil - Interface for using Thales nShield/nCipher and all similar with CertNanny.

=head1 SYNOPSIS

my $hsm = new CertNanny::HSM::Chil();
my $newkey = $hsm->genkey();

=head1 DESCRIPTION

Implements the CertNanny::HSM interface. Currently supports key generation.

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
