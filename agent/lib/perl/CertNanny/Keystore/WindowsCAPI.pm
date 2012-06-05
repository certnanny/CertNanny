#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005-02 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny::Keystore::WindowsCAPI;

use base qw(Exporter CertNanny::Keystore::OpenSSL);

use strict;
use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);
use Exporter;
use Carp;

use IO::File;
use File::Spec;
use File::Copy;
use Data::Dumper;
use CertNanny::Util;

$VERSION = 0.01;

#implement new?
sub new
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my %args = ( 
        @_,         # argument pair list
    );

    my $self = {};
    bless $self, $class;

    $self->{OPTIONS} = \%args;


    # Througout this class you will be able to access entry configuration
    # settings via
    # $self->{OPTIONS}->{ENTRY}->{setting}
    # It is possible to introduce new entry settings this way you might
    # need for your keystore implementation. 
    # It is also possible to introduce additional hierarchy layers in
    # the configuration, e. g. if you have a
    #   keystore.foobar.my.nifty.setting = bla
    # you will be able to access this via
    # $self->{OPTIONS}->{ENTRY}->{my}->{nifty}->{setting}
    # Be sure to check all configuration settings for plausiblitiy.


    # You will have to obtain the keystore pin somehow, for some keystores
    # it will be configured in certnanny's config file, for others you
    # might want to deduce it from the keystore itself
    #my $pin = "";
#    $pin = $self->{OPTIONS}->{ENTRY}->{pin};
    if (! exists $self->{OPTIONS}->{ENTRY}->{pin}) {
	    $self->{OPTIONS}->{ENTRY}->{pin} = "";
    }

    # export the pin to this instance
    $self->{PIN} = $self->{OPTIONS}->{ENTRY}->{pin};
    
    # sample sanity checks for configuration settings
     foreach my $entry qw( location ) {
		if (! defined $self->{OPTIONS}->{ENTRY}->{$entry} ) {
			croak("keystore.$entry $self->{OPTIONS}->{ENTRY}->{$entry} not defined.");
			return;
		}
	}
    
    $self->{OPTIONS}->{ENTRY}->{storename} ||= 'MY';
    $self->{OPTIONS}->{ENTRY}->{storelocation} ||= 'machine';

	#$self->{STORE}=$self->openstore( $self->{OPTIONS}->{ENTRY}->{storename},$self->{OPTIONS}->{ENTRY}->{storelocation});
    # the rest should remain untouched

    # get previous renewal status
    #$self->retrieve_state() || return;

    # check if we can write to the file
    #$self->store_state() || croak "Could not write state file $self->{STATE}->{FILE}";

    # instantiate keystore
    return $self;
}

sub getcert()
{
	my $self = shift;
	my $certdata = "";
	CertNanny::Logging->debug("Called getcert() for WindowsCAPI");
	my $serial;
	my $returned_data = "";
	my $derfile_tmp = $self->CertutilWriteCerts($serial);
	if(!defined($derfile_tmp)) {
		CertNanny::Logging->debug("No serial was defined before so all certs were dumped and are now parsed");
		my @certs = glob "Blob*.crt";
		my $active_cert;
		foreach my $certfilename (@certs) {
			my $certinfo = $self->getcertinfo( CERTFILE => $certfilename );
			CertNanny::Logging->debug("Parsing certificate with filname $certfilename and subjectname $certinfo->{SubjectName}");
			my $notbefore = CertNanny::Util::isodatetoepoch($certinfo->{NotBefore});
			my $notafter = CertNanny::Util::isodatetoepoch($certinfo->{NotAfter});
			my $now = time;
			CertNanny::Logging->debug("Searching for $self->{OPTIONS}->{ENTRY}->{location} in $certinfo->{SubjectName} and NotAfter $notafter where current time is $now");
			CertNanny::Logging->debug("Result of index: ". index($certinfo->{SubjectName}, $self->{OPTIONS}->{ENTRY}->{location}));
			if (index($certinfo->{SubjectName}, $self->{OPTIONS}->{ENTRY}->{location}) != -1 && $notafter > $now) {
				CertNanny::Logging->debug("Found something!");
				my $active_notafter = CertNanny::Util::isodatetoepoch($active_cert->{NotAfter}) if (defined($active_cert));
				if(!defined($active_cert) || $active_notafter < $notafter) {
					$active_cert = $certinfo;
					$serial = $certinfo->{SerialNumber};
					$serial =~ s/://g;
					CertNanny::Logging->debug("The current certificate is the newest and thus will be used from hereon");
				}
			}
		}
		if(!defined($serial)) {
			CertNanny::Logging->error("Could not retrieve a valid certificate from the keystore");
			return;
		}
		$derfile_tmp = $self->CertutilWriteCerts($serial);
	}
	my @cmd;
	my $cmd;
	my $openssl = $self->{OPTIONS}->{CONFIG}->get('cmd.openssl', 'FILE');
	@cmd = (qq("$openssl"), 'x509', '-in', qq("$derfile_tmp"), '-inform', 'DER');
	$cmd = join(" ", @cmd);
	CertNanny::Logging->debug("Execute: $cmd");
	$certdata  = `$cmd`;
	CertNanny::Logging->debug("Dumping resulting certificate in PEM format:\n$certdata");
	return { CERTDATA => $certdata,
	      CERTFORMAT => 'PEM'};
}

sub CertutilWriteCerts()
{
	my $self = shift;
	my $serial = shift;
	CertNanny::Logging->debug("Calling certutil to retrieve certificates.");
	CertNanny::Logging->debug("Serial is $serial.") if defined($serial);
	my $outfile_tmp = $self->gettmpfile() if defined($serial);
	my @cmd;
	push(@cmd, 'certutil');
	push(@cmd, '-split');
	push(@cmd, '-user') if $self->{OPTIONS}->{ENTRY}->{storelocation} eq "user";
	push(@cmd, '-store');
	push(@cmd, qq("My")); # NOTE: It is *mandatory* to have double quotes here!
	push(@cmd, $serial) if (defined($serial));
	push(@cmd, $outfile_tmp) if defined(($serial));
	my $cmd = join(" ", @cmd);
	CertNanny::Logging->debug("Execute: $cmd.");
	my $cmd_output = `$cmd`;
	CertNanny::Logging->debug("Dumping output of above command:\n $cmd_output");
	CertNanny::Logging->debug("Output was written to $outfile_tmp") if defined($outfile_tmp);
	return $outfile_tmp;
}

=comment
sub createrequest()
{
	my $self = shift;
    my %args = ( 
        @_,         # argument pair list
    );
	
	#open template inf file
	my $inf_file_in = $self->{CONFIG}->get('path.certreqinf', 'FILE');
	open INF_FILE_IN, "<", $inf_file_in
		or CertNanny::Logging->error("createrequest(): Could not open input file: $inf_file_in");
	my $inf_file_out = $self->gettmpfile();
	my $out_file_str;
	$out_file_str .= $_ while <INF_FILE_IN>;
	close INF_FILE_IN;
	$out_file_str = sprintf($out_file_str, $self->{ENTRY}->{commonname});
	my $result;
	
	if(! CertNanny::Util->write_file(
		FILENAME => $inf_file_out,
		CONTENT => $out_file_str,
		FORCE => 1,
	)) {
		CertNanny::Logging->error("createrequest(): Could not write temporary inffile $inf_file_out");
		return;
	}
	
	my $requestfile = $self->{OPTIONS}->{ENTRYNAME} . ".csr";
	$result->{REQUESTFILE} = File::Spec->catfile($self->{OPTIONS}->{ENTRY}->{statedir}, $requestfile);
	my @cmd = ('certreq', '-new', qq("$inf_file_out"), qq("$result->{REQUESTFILE}"));
	my $cmd = join(' ', @cmd);
	`$cmd`;
	if($? != 0) {
		CertNanny::Logging->error("createrequest(): Executing certreq cmd error: $cmd");
		return;
	}
	
	return $result;
}
=cut

sub installcert()
{
	# convert cert to pkcs#12
	# execute import_cert.exe import test100-cert.pfx
	my $self = shift;
    my %args = ( 
        @_,         # argument pair list
    );
	
	#my $keyfile = $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{KEYFILE};
	my $certfile = $args{CERTFILE};
	my @cmd = ('certreq', '-accept', qq("$certfile"));
	my $cmd = join(" ", @cmd);
	CertNanny::Logging->debug("Execute: $cmd");
	my $cmd_output = `$cmd`;
	CertNanny::Logging->debug("certreq output:\n$cmd_output");
	if ($? != 0) {
		CertNanny::Logging->error("installcert(): Certificate could not be imported. Output of command $cmd was:\n$cmd_output");
		return;
	}
	
	return 1;

=comment
	# ..\openssl-mingw\bin\openssl.exe pkcs12 -export -inkey test100-key.pem -in test100-cert.pem -out test100-cert.pfx
	my $openssl = $self->{OPTIONS}->{openssl_shell};
	my @cmd = (qq("$openssl"),
			'pkcs12',
			'-export',
			'-inkey',
			qq("$keyfile"),
			'-in',
			qq("$certfile"),
			'-out',
			qq("$outfile"),
	);
	
	my $cmd = join(' ', @cmd);
	CertNanny::Logging->debug("Execute: ");
	
	$output->{CERTDATA} = `$cmd`;
	
	if ($? != 0) {
	CertNanny::Logging->error("installcert(): Could not convert cert to PKCS12");
	return;
	}
	
	
	
	return $output;
=cut
	
}