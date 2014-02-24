#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2011-05 Stefan Kraus <stefan.kraus05@gmail.com>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#
package CertNanny::Enroll;

use vars qw( $VERSION );
use Exporter;

$VERSION = 0.10;


sub new() {

}


sub enroll() {

}


sub getCA() {

}


sub getNextCA() {
}

1;

=head1 NAME

CertNanny::Enroll - Interface for enrolling certificates.

=head1 SYNOPSIS

This module is normally not called by itself but is implemented

=head1 DESCRIPTION

This module needs submodules to implement its interface. It is not called by itself.

=head1 FUNCTIONS

=head2 Function List

=over 4

C<new()>

C<enroll()>

C<getCA()>

C<getNextCA()>

=back

=head2 Function Descriptions

=over 4

=item new()

Create a new "enroller" to act upon. Implementation should get global options and store data for execution. Anything that is needed between runs should be passed here.
A single instance per certificate should be created. It is up to the application user (not the implementer) to make sure a single instance is used per certificate.

=item enroll()

Implement the certificate enrollment (renewal) process. Can support initial enrollment, refer to documentation of implementation.

=item getCA()

Command to retrieve current valid CA ceritficates from the server.

=item getNextCA()

Root Key Roll-Over. Implement this to provide functionality for automatic renewal of root CA certificates.
