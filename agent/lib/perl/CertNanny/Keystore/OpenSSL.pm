#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005-02 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny::Keystore::OpenSSL;

use base qw(Exporter CertNanny::Keystore);

use strict;
use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);
use Exporter;
use Carp;

use IO::File;
use File::Spec;
use File::Copy;
use Data::Dumper;

$VERSION = 0.6;


# constructor parameters:
# location - base name of keystore (required)
# type - keystore type (default: auto)
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

    # propagate PIN to class options
    $self->{PIN} = $self->{OPTIONS}->{ENTRY}->{pin};

    foreach my $entry qw( keyfile location ) {
	if (! defined $self->{OPTIONS}->{ENTRY}->{$entry} ||
	    (! -r $self->{OPTIONS}->{ENTRY}->{$entry})) {
	    croak("keystore.$entry $self->{OPTIONS}->{ENTRY}->{$entry} not defined, does not exist or unreadable");
	    return;
	}
    }
    


    # desired target
    $self->{FORMAT} = $self->{OPTIONS}->{ENTRY}->{format};
    if (! defined $self->{FORMAT}) {
	$self->{FORMAT} = 'PEM';
    }

    if ($self->{FORMAT} !~ m{ \A (?: DER | PEM ) \z }xms) {
	croak("Incorrect keystore format $self->{FORMAT}");
	return;
    }

    $self->{KEYTYPE} = $self->{OPTIONS}->{ENTRY}->{keytype};
    if (! defined $self->{KEYTYPE}) {
	$self->{KEYTYPE} = 'PKCS8';
    }

    if ($self->{KEYTYPE} !~ m{ \A (?: OpenSSL | PKCS8 ) \z }xms) {
	croak("Incorrect keystore type $self->{KEYTYPE}");
	return;
    }
    
    # sanity check: DER encoded OpenSSL keys cannot be encrypted
    if (defined $self->{PIN} &&
	($self->{PIN} ne "") &&
	($self->{KEYTYPE} eq 'OpenSSL') &&
	($self->{FORMAT} eq 'DER')) {
	croak("DER encoded OpenSSL keystores cannot be encrypted");
	return;
    }

    # get previous renewal status
    $self->retrieve_state() || return undef;

    # check if we can write to the file
    $self->store_state() || croak "Could not write state file $self->{STATE}->{FILE}";

    # instantiate keystore
    return ($self);
}


sub DESTROY {
    my $self = shift;
    # call parent destructor
    $self->SUPER::DESTROY if $self->can("SUPER::DESTROY");
}



###########################################################################
# mandatory functions
# export certificate in DER or PEM format
sub getcert {
    my $self = shift;
    my $filename = $self->{OPTIONS}->{ENTRY}->{location};

    my $fh = new IO::File("<$filename");
    if (! $fh)
    {
    	$self->seterror("getcert(): Could not open input file $filename");
    	return undef;
    }
    my $format = "DER";

    while (<$fh>) {
	if (/^-----.*CERTIFICATE.*-----/) {
	    $format = "PEM";
	    last;
	}
    }
    $fh->close();

    $self->debug("OpenSSL keystore loglevel: " . $self->loglevel());

    return ({ CERTFILE => $filename,
	      CERTFORMAT => $format });
}


sub getkey {
    my $self = shift;
    my $filename = $self->{OPTIONS}->{ENTRY}->{keyfile};
    my $openssl = $self->{OPTIONS}->{CONFIG}->get('cmd.openssl', 'FILE');
    if (! defined $openssl) {
	$self->seterror("No openssl shell specified");
	return undef;
    }

    if (! -r $filename) {
	$self->seterror("getkey(): Could not open private key file");
	return undef;
    }

    my $keydata = $self->read_file($filename);
    if (! defined $keydata || ($keydata eq "")) {
	$self->seterror("getkey(): Could not read private key");
	return undef;
    }
    
    my $pin = $self->{PIN} || $self->{OPTIONS}->{ENTRY}->{pin};
    
    my $keyformat = 'DER';
    if ($keydata =~ m{ -----BEGIN.*KEY----- }xms) {
	$keyformat = 'PEM';
    }

    return (
	{ 
	    KEYDATA => $keydata,
	    KEYTYPE => $self->{KEYTYPE},
	    KEYFORMAT => $keyformat,
	    KEYPASS => $pin,
	});
}

# create pkcs12 file
# in:
# FILENAME => pkcs12 file to create
# FRIENDLYNAME => cert label to be used in pkcs#12 structure
# EXPORTPIN => PIN to be set for pkcs#12 structure
# CERTFILE => certificate to include in the pkcs#12 file, instance certificate
#             if not specified
# CERTFORMAT => PEM|DER, instance cert format if not specified
# KEYFILE => keyfile, instance key if not specified
# PIN => keyfile pin
# CACHAIN => arrayref containing the certificate info structure of 
#            CA certificate files to be included in the PKCS#12
#            Required keys for entries: CERTFILE, CERTFORMAT, CERTINFO

sub createpkcs12 {
    my $self = shift;
    my %args = (FILENAME => undef,
		FRIENDLYNAME => undef,
		EXPORTPIN => undef,
		CACHAIN => undef,
		CERTFILE => $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{CERTFILE},
		CERTFORMAT => 'PEM',
		KEYFILE => $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{KEYFILE},
		PIN => $self->{PIN} || $self->{OPTIONS}->{ENTRY}->{pin},
		@_);

    my $openssl = $self->{OPTIONS}->{CONFIG}->get('cmd.openssl', 'FILE');
    if (! defined $openssl) {
	$self->seterror("No openssl shell specified");
	return undef;
    }

    if (! defined $args{FILENAME}) {
	$self->seterror("createpks12(): No output file name specified");
	return undef;
    }

    if (! defined $args{CERTFILE}) {
	$self->seterror("createpks12(): No certificate file specified");
	return undef;
    }

    if (! defined $args{KEYFILE}) {
	$self->seterror("createpks12(): No key file specified");
	return undef;
    }

    $self->debug("Certformat: $args{CERTFORMAT}");

    if (! defined $args{CERTFORMAT} or $args{CERTFORMAT} !~ /^(PEM|DER)$/) {
	$self->seterror("createpks12(): Illegal certificate format specified");
	return undef;
    }

    if (! defined $args{EXPORTPIN}) {
	$self->seterror("createpks12(): No export PIN specified");
	return undef;
    }

    my @cmd;

    my $certfile = $args{CERTFILE};

    # openssl pkcs12 command does not support DER input format, so
    # convert it to PEM first
    # FIXME: use SUPER::convertcert?
    if ($args{CERTFORMAT} eq "DER") {
	$certfile = $self->gettmpfile();

	@cmd = (qq("$openssl"),
		'x509',
		'-in',
		qq("$args{CERTFILE}"),
		'-inform',
		qq("$args{CERTFORMAT}"),
		'-out',
		qq("$certfile"),
		'-outform',
		'PEM',
		);

	$self->log({ MSG => "Execute: " . join(" ", @cmd),
		     PRIO => 'debug' });
	
	if (system(join(' ', @cmd)) != 0) {
	    $self->seterror("Certificate format conversion failed");
	    return undef;
	}
    }

    my @passin = ();
    if (defined $args{PIN} and $args{PIN} ne "") {
	@passin = ('-passin',
		   'env:PIN');
	$ENV{PIN} = $args{PIN};
    }

    my @passout = ();
    if (defined $args{EXPORTPIN} and $args{EXPORTPIN} ne "") {
	@passout = ('-password',
		    'env:EXPORTPIN');
	$ENV{EXPORTPIN} = $args{EXPORTPIN};
    }

    my @name = ();
    if (defined $args{FRIENDLYNAME} and $args{FRIENDLYNAME} ne "") {
	@name = ('-name',
		 qq("$args{FRIENDLYNAME}"));
    }

    my $cachainfile;
    my @cachain = ();
    if (defined $args{CACHAIN} and ref $args{CACHAIN} eq "ARRAY") {
	$cachainfile = $self->gettmpfile;
	my $fh = new IO::File(">$cachainfile");
	if (! $fh)
	{
	    $self->seterror("createpkcs12(): Could not create temporary CA chain file");
	    return undef;
	}
	
	# add this temp file
	push (@cachain, '-certfile');
	push (@cachain, qq("$cachainfile"));
	
	foreach my $entry (@{$args{CACHAIN}}) {
	    my $file = $entry->{CERTFILE};
	    my @RDN = split(/(?<!\\),\s*/, $entry->{CERTINFO}->{SubjectName});
	    my $CN = $RDN[0];
	    $CN =~ s/^CN=//;
	    $self->debug("Adding CA certificate '$CN' in $file");
	    my $certfh = new IO::File("<$file");
	    if ($certfh) {
		local $/;
		my $content = <$certfh>;
		$certfh->close();

		print $fh $content;
		push(@cachain, '-caname');
		push(@cachain, qq("$CN"));
	    }
	}
	$fh->close;
    }

    @cmd = (qq("$openssl"),
	    'pkcs12',
	    '-export',
	    '-out',
	    qq("$args{FILENAME}"),
	    @passout,
	    '-in',
	    qq("$certfile"),
	    '-inkey',
	    qq("$args{KEYFILE}"),
	    @passin,
	    @name,
	    @cachain,
	    );


    $self->log({ MSG => "Execute: " . join(" ", @cmd),
		 PRIO => 'debug' });

    if (system(join(' ', @cmd)) != 0) {
	$self->seterror("PKCS#12 export failed");
	delete $ENV{PIN};
	delete $ENV{EXPORTPIN};
	unlink $certfile if ($args{CERTFORMAT} eq "DER");
	unlink $cachainfile if (defined $cachainfile);
	return undef;
    }

    delete $ENV{PIN};
    delete $ENV{EXPORTPIN};
    unlink $certfile if ($args{CERTFORMAT} eq "DER");
    unlink $cachainfile if (defined $cachainfile);

    return $args{FILENAME};
}


sub generatekey {
    my $self = shift;

    my $keyfile = $self->{OPTIONS}->{ENTRYNAME} . "-key.pem";
    my $outfile = File::Spec->catfile($self->{OPTIONS}->{ENTRY}->{statedir},
				      $keyfile);

    my $pin = $self->{PIN} || $self->{OPTIONS}->{ENTRY}->{pin} || "";

    my $openssl = $self->{OPTIONS}->{CONFIG}->get('cmd.openssl', 'FILE');
    if (! defined $openssl) {
	$self->seterror("No openssl shell specified");
	return undef;
    }

    my $bits = '1024';

    my @passout = ();
    if (defined $pin and $pin ne "") {
	@passout = ('-des3',
		    '-passout',
		    'env:PIN');
    }

    # generate key
    my @cmd = (qq("$openssl"),
	       'genrsa',
	       '-out',
	       qq("$outfile"),
	       @passout,
	       $bits);

    $self->log({ MSG => "Execute: " . join(" ", @cmd),
		 PRIO => 'debug' });

    $ENV{PIN} = $pin;
    if (system(join(' ', @cmd)) != 0) {
	$self->seterror("RSA key generation failed");
	delete $ENV{PIN};
	return undef;
    }
    chmod 0600, $outfile;
    delete $ENV{PIN};
    
    return ({ KEYFILE => $outfile });
}

sub createrequest {
    my $self = shift;
    $self->info("Creating request");

    #print Dumper $self;
    my $result = $self->generatekey();
    
    if (! defined $result) {
	$self->seterror("Key generation failed");
	return undef;
    }    

    my $requestfile = $self->{OPTIONS}->{ENTRYNAME} . ".csr";
    $result->{REQUESTFILE} = 
	File::Spec->catfile($self->{OPTIONS}->{ENTRY}->{statedir},
			    $requestfile);

    my $pin = $self->{PIN} || $self->{OPTIONS}->{ENTRY}->{pin} || "";

    my $openssl = $self->{OPTIONS}->{CONFIG}->get('cmd.openssl', 'FILE');
    if (! defined $openssl) {
	$self->seterror("No openssl shell specified");
	return undef;
    }

    my $DN = $self->{CERT}->{INFO}->{SubjectName};

    $self->debug("DN: $DN");
    # split DN into individual RDNs. This regex splits at the ','
    # character if it is not escaped with a \ (negative look-behind)
    my @RDN = split(/(?<!\\),\s*/, $DN);
    
    my %RDN_Count;
    foreach (@RDN) {
	my ($key, $value) = (/(.*?)=(.*)/);
	$RDN_Count{$key}++;
    }

    # delete all entries that only showed up once
    # all other keys now indicate the total number of appearance
    map { delete $RDN_Count{$_} if ($RDN_Count{$_} == 1); } keys %RDN_Count;

    # create OpenSSL config file
    my $tmpconfigfile = $self->gettmpfile();
    my $fh = new IO::File(">$tmpconfigfile");
    if (! $fh)
    {
    	$self->seterror("createrequest(): Could not create temporary OpenSSL config file");
    	return undef;
    }
    print $fh "[ req ]\n";
    print $fh "prompt = no\n";
    print $fh "distinguished_name = req_distinguished_name\n";
    
    # handle subject alt name
    if (exists $self->{CERT}->{INFO}->{SubjectAlternativeName}) {
	print $fh "req_extensions = v3_ext\n";
    }
    
    print $fh "[ req_distinguished_name ]\n";
    foreach (reverse @RDN) {
	my ($key, $value) = (/(.*?)=(.*)/);
	if (exists $RDN_Count{$key}) {
	    print $fh $RDN_Count{$key} . ".";
	    $RDN_Count{$key}--;
	}
	print $fh $_ . "\n";
    }
    
    if (exists $self->{CERT}->{INFO}->{SubjectAlternativeName}) {
	print $fh "[ v3_ext ]\n";
	print $fh "subjectAltName = " . $self->{CERT}->{INFO}->{SubjectAlternativeName} . "\n";
    }
    
    $fh->close();

    # generate request
    my @cmd = (qq("$openssl"),
	       'req',
	       '-config',
	       qq("$tmpconfigfile"),
	       '-new',
	       '-sha1',
	       '-out',
	       qq("$result->{REQUESTFILE}"),
	       '-key',
	       qq("$result->{KEYFILE}"),
	);

    push (@cmd, ('-passin', 'env:PIN')) unless $pin eq "";

    $self->log({ MSG => "Execute: " . join(" ", @cmd),
		 PRIO => 'debug' });

    $ENV{PIN} = $pin;
    if (system(join(' ', @cmd)) != 0) {
	$self->seterror("Request creation failed");
	delete $ENV{PIN};
	unlink $tmpconfigfile;
	return undef;
    }
    delete $ENV{PIN};
    unlink $tmpconfigfile;

    return $result;
}

sub installcert {
    my $self = shift;
    my %args = ( 
        @_,         # argument pair list
    );
    my $keyfile = $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{KEYFILE};
    my $pin = $self->{PIN} || $self->{OPTIONS}->{ENTRY}->{pin} || "";

    #print Dumper $self;

    $self->info("Installing certificate: $args{CERTFILE}");
    $self->info("Installing key: $keyfile");

    my $newcert = $self->convertcert(
	CERTFILE => $args{CERTFILE},
	CERTFORMAT => 'PEM',
	OUTFORMAT => $self->{FORMAT},
	);

    if (! defined $newcert) {
	$self->seterror("Could not read/convert new certificate");
	return undef;
    }

    my $newkey = $self->convertkey(
	KEYFILE => $keyfile,
	KEYFORMAT => 'PEM',
	KEYTYPE   => 'OpenSSL',
	KEYPASS   => $pin,
	OUTFORMAT => $self->{FORMAT},
	OUTTYPE   => $self->{KEYTYPE},
	OUTPASS   => $pin,
	);

    if (! defined $newkey) {
	$self->seterror("Could not read/convert new key");
	return undef;
    }
	
    # backup old certificate and key
    my $oldcert = $self->{OPTIONS}->{ENTRY}->{location};
    my $oldkey = $self->{OPTIONS}->{ENTRY}->{keyfile};

    $self->info("Archiving old certificate $oldcert");
    unlink $oldcert . ".backup";
    rename $oldcert, $oldcert . ".backup";

    $self->info("Archiving old key $oldkey");
    unlink $oldkey . ".backup";
    rename $oldkey, $oldkey . ".backup";


    # install key
    if (! $self->write_file(FILENAME => $oldkey,
			    CONTENT  => $newkey->{KEYDATA})) {
	$self->seterror("Could not install keyfile");
	unlink $oldkey;
	rename $oldkey . ".backup", $oldkey;
	return undef;
    }

    if (! $self->write_file(FILENAME => $oldcert,
			    CONTENT  => $newcert->{CERTDATA})) {
	$self->seterror("Could not install certificate");
	unlink $oldkey;
	rename $oldkey . ".backup", $oldkey;
	unlink $oldcert;
	rename $oldcert . ".backup", $oldcert;
	return undef;
    }

    # done
    $self->renewalstate("completed");
    return 1;
}


1;
