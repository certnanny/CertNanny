#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2011-05 Florian Ruechel <florian.ruechel@gmail.com>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#
package CertNanny::HSM;

use vars qw( $VERSION );
use Exporter;

$VERSION = 0.10;

sub new() {
    
}

sub genkey() {
    
}


1;

=head1 NAME

CertNanny::HSM - Interface for using HSMs with CertNanny.

=head1 SYNOPSIS

This module is normally not called by itself but is implemented.

=head1 DESCRIPTION

This module needs submodules to implement its interface. It is not called by itself.

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
