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
use File::Spec;
use vars qw( $VERSION );
use Exporter;
use Cwd;

$VERSION = 0.10;

sub new() {
    
}

sub genkey() {
    
}


1;

=head1 NAME

CertNanny::HSM::Utimaco - Interface for using Utimacos Se-/Ce-Seriens and all similar with CertNanny.

=head1 SYNOPSIS

my $hsm = new CertNanny::HSM::Utimaco();
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
