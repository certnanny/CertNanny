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

This module provides the interface for using HSMs in CertNanny. Follow this documentation to get a full implementation of an HSM without every touching the rest of CertNanny.

=head1 CONFIGURATION

You will need to configure your HSM and thus you need to defined options on how to acheive the desired configuration. All configuration is done inside CertNanny's configuration file (usually certnanny.cfg) and the HSM will be configured in keystore configuration's hsm option group. Therefore, all HSM options are defined inside the keystore.label.hsm option group, for example:

=over 4

=item keystore.label.hsm.dynamic_path=/path/to/engine.so

=item keystore.label.hsm.type=MyHSM

=back

There you see the only mandatory setting in this group: type *must* the name of your HSM class and .pm file (without the .pm). For example, the HSM Chil has a classname of Chil and a filename of Chil.pm, so type=Chil is the correct setting.

Additionally, it is recommended to defined a special option group keystore.label.hsm.key which contains all information relevant to key generation. Usually key generation is done by the HSM's special program (e.g. generatekey in Chil's case). They usually take a lot of arguments (like the keysize, e.g. 2048) and it is recommended, that all options in this group are passed to the generation function as (key,value) pairs. This makes it possible to automatically iterate over all entries and pass them to your key generation program enabling both full configuration through config file and support for unexpected settings. Of course, you will overwrite some of these options when initializing your HSM (for example, PIN or key id/filename).

Refer to the Chil and Utimaco implementations for details (their configuration is also documented inside CertNanny's default configuration file).

=head1 FUNCTIONS

=head2 Function List

=over 4

C<new()>

C<genkey()>

C<createrequest()>

C<engineid()>

C<keyform()>

C<getEngineConfiguration()>

=back

=head2 Function Descriptions

=over 4

=item new($entry_options, $config, $entryname)

The keystore is instatiated here. This functions fills all required variables and performs sanity checks. The last part is very important: If an HSM is an use, a lot of sanity checks will be delegated. This includes

=over 4

=item checking for key format (see C<keyform()>)

=item filling options from keystore configuration into HSM (think PINs or keynames)

=item initialize all information necessary later on

=back

It is also very imporant to remember to intialize the enroll options. Currently CertNanny only supports a single enrollment, Sscep, and there is no complete interface yet. Thus, you have to explicitly fill all variables required by sscep. You can take a look at the Utimaco and Chil implementations to see an example, it is simple but very important. The syntax of the parameters is described in C<CertNanny::Enroll::Sscep::readConfig()>.

=over 4

=item $entry_options

Entry options contains all options that are referenced in a keystore by $self->{OPTIONS}->{ENTRY} and are a hash reference of the configuration set like keystore.label.option=value which is referenced by $entry_options->{option} and returns value. Furthermore, it is possible to have sets and the most important one is keystore.label.hsm.option=value. The hsm option group contains all your hsm's configuration and all custom options should be set here. See documentation for this in the CONFIGURATION section.

=item $config

This passed all the options that are not part of a keystore and which can be referenced by $self->{OPTIONS}->{CONFIG} inside the keystore. These options have a C<get()> methodso you can get the parameters. Take a look at CertNanny::Config for further information. You may not need  this, but if you want to use openssl, you will get your executable from there.

=item $entryname

A simple string containing the label of the keystore. May be used for logging information or similar.

=back

=item genkey()

[Optional]: Generate a new key within the HSM. The exact method may depend on the configuration and implementation. It is expected that it returns the identifier used for the key. This may be the full path to a file or an identifier. It is important that OpenSSL will recognize this key if passed to the usual req & similar. The format is determined by C<keyform()>. If this function is not provided, CertNanny will use OpenSSL's native mechanism with the engine. In that case it will call C<keyform()> and C<engineid()>.

=item createrequest()

[Optional]: Creates a certificate signing request (CSR). Returns a string with the full path to the CSR. If this function is not provided, CertNanny will use OpenSSL's native mechanism with the engine. In that case it will call C<keyform()> and C<engineid()>.

=item engineid()

Returns a string with the engine ID used by the engine for OpenSSL. This can be a static value, but if there are multiple engines, it can for example depend on the key format.

=item keyform()

Returns the keyform variable or undef. This usually only returns "engine" and only in case where -keyform engine is desired. Otherwise it will just return undef, as then OpenSSL will use its default mechanism for keyform. This can also return any other parameter accepted by OpenSSL's -keyform option.

=item getEngineConfiguration()

Returns an array reference which contains the configuration for the engine which is written to an OpenSSL configuration file. It is very important that this array has a specific format, so the order is kept as OpenSSL expects a specific order depending on the engine. May return undef if the engine is static (use C<CertNanny::Util::staticEngine()> for this). Otherwise the format is as follows: each entry in the array is a hash reference which contains a single key => value pair:

=over 4

=item example configuration array

my $configuration = [ {key => "value"}, {key2 => "value2"} ];

=back

Only this way the order is kept (key is used before key2) and it is written correctly into the OpenSSL configuration file. If this is not done correctly, the behavior is unexpected and can lead from the program exiting to OpenSSL segmentation faults.