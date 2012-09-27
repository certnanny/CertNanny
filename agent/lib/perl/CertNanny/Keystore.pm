#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005-02 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny::Keystore;
use base qw(Exporter);

# use Smart::Comments;

use IO::File;
use File::Glob qw(:globally :nocase);
use File::Spec;

use File::Copy;
use File::Temp;
use File::Basename;
use Carp;
use Data::Dumper;
use CertNanny::Logging;

use CertNanny::Util;

use strict;
use vars qw( $VERSION );
use Exporter;

$VERSION = 0.10;


# constructor parameters:
# location - base name of keystore (required)
sub new 
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my %args = ( 
        @_,         # argument pair list
    );

    my $self = {};
    bless $self, $class;

    $self->{CONFIG} = $args{CONFIG};

    foreach my $item (qw(statedir scepcertdir)) {
	if (! exists $args{ENTRY}->{$item}) {
	    croak "No $item specified for keystore " . $args{ENTRY}->{location};
	}

	if (! -d $args{ENTRY}->{$item}) {
	    croak "$item directory $args{ENTRY}->{$item} does not exist";
	}

	if (! -x $args{ENTRY}->{$item} or
	    ! -r $args{ENTRY}->{$item} or
	    ! -w $args{ENTRY}->{$item}) {
	    croak "Insufficient permissions for $item $args{ENTRY}->{$item}";
	}
    }

    if (! exists $args{ENTRY}->{statefile}) {
	my $entry = $args{ENTRYNAME} || "entry";
	my $statefile = File::Spec->catfile($args{ENTRY}->{statedir}, "$entry.state");
	$args{ENTRY}->{statefile} = $statefile;
    }
    
    CertNanny::Logging->loglevel($args{CONFIG}->get('loglevel') || 3);

    # set defaults
    $self->{OPTIONS}->{tmp_dir} = 
	$args{CONFIG}->get('path.tmpdir', 'FILE');
    $self->{OPTIONS}->{openssl_shell} =
	$args{CONFIG}->get('cmd.openssl', 'FILE');
    $self->{OPTIONS}->{sscep_cmd} =
	$args{CONFIG}->get('cmd.sscep', 'FILE');
    $self->{OPTIONS}->{ENTRYNAME} = $args{ENTRYNAME};
    
    croak "No tmp directory specified" 
	unless defined $self->{OPTIONS}->{tmp_dir};
    croak "No openssl binary configured or found" 
	unless (defined $self->{OPTIONS}->{openssl_shell} and
		-x $self->{OPTIONS}->{openssl_shell});

    croak "No sscep binary configured or found" 
	unless (defined $self->{OPTIONS}->{sscep_cmd} and
		-x $self->{OPTIONS}->{sscep_cmd});
    

    # instantiate keystore
    my $type = $args{ENTRY}->{type};
    if (! defined $type || ($type eq "none")) {
	print STDERR "Skipping keystore (no keystore type defined)\n";
	return;
    }

    if (! $self->load_keystore_handler($type)) {
	print STDERR "ERROR: Could not load keystore handler '$type'\n";
	return;
    }

    # attach keystore handler
    # backend constructor is expected to perform sanity checks on the
    # configuration and return undef if options are not appropriate
    eval "\$self->{INSTANCE} = new CertNanny::Keystore::$type((\%args, \%{\$self->{OPTIONS}}))";
    if ($@) {
	print STDERR $@;
	return;
    }

    croak "Could not initialize keystore handler '$type'. Aborted." 
	unless defined $self->{INSTANCE};

    # get certificate
    $self->{CERT} = $self->{INSTANCE}->getcert();

    if (defined $self->{CERT}) {
	$self->{CERT}->{INFO} = $self->getcertinfo(%{$self->{CERT}});
	my $subjectname = $self->{CERT}->{INFO}->{SubjectName};
	my $serial = $self->{CERT}->{INFO}->{SerialNumber};
	my $issuer = $self->{CERT}->{INFO}->{IssuerName};
	CertNanny::Logging->info("Certificate Information:\n\tSubjectName: $subjectname\n\tSerial: $serial\n\tIssuer: $issuer");

	my %convopts = %{$self->{CERT}};

	$convopts{OUTFORMAT} = 'PEM';
	$self->{CERT}->{RAW}->{PEM}  = $self->convertcert(%convopts)->{CERTDATA};
	$convopts{OUTFORMAT} = 'DER';
	$self->{CERT}->{RAW}->{DER}  = $self->convertcert(%convopts)->{CERTDATA};
    } 
    else
    {
	print STDERR "ERROR: Could not parse instance certificate\n";
	return;
    }
    $self->{INSTANCE}->setcert($self->{CERT});

    # get previous renewal status
    #$self->retrieve_state() or return;

    # check if we can write to the file
    #$self->store_state() || croak "Could not write state file $self->{STATE}->{FILE}";

    return ($self);
}

sub DESTROY
{
    my $self = shift;
    
    $self->store_state();

    return unless (exists $self->{TMPFILE});

    foreach my $file (@{$self->{TMPFILE}}) {
	unlink $file;
    }
}

sub setcert {
    my $self = shift;
    
    $self->{CERT} = shift;
}


# convert certificate to other formats
# input: hash
# CERTDATA => string containing certificate data OR
# CERTFILE => file containing certificate data
# CERTFORMAT => certificate encoding format (PEM or DER), default: DER
# OUTFORMAT => desired output certificate format (PEM or DER), default: DER
#
# return: hash ref
# CERTDATA => string containing certificate data
# CERTFORMAT => certificate encoding format (PEM or DER)
# or undef on error
sub convertcert {
    my $self = shift;
    my %options = (
	CERTFORMAT => 'DER',
	OUTFORMAT => 'DER',
	@_,         # argument pair list
	);

    # sanity checks
    foreach my $key (qw( CERTFORMAT OUTFORMAT )) {
	if ($options{$key} !~ m{ \A (?: DER | PEM ) \z }xms) {
	    CertNanny::Logging->error("convertcert(): Incorrect $key: $options{$key}");
	    return;
	}
    }

    my $output;

    my $openssl = $self->{OPTIONS}->{openssl_shell};
    my $infile;

    my @cmd = (qq("$openssl"),
	       'x509',
	       '-in',
	);
    
    if (exists $options{CERTDATA}) {
	$infile = $self->gettmpfile();
	if (! CertNanny::Util->write_file(FILENAME => $infile,
				CONTENT  => $options{CERTDATA},
	    )) {
	    CertNanny::Logging->error("convertcert(): Could not write temporary file");
	    return;
	}

	push(@cmd, qq("$infile"));
    } else {
	push(@cmd, qq("$options{CERTFILE}"));
    }
    
    push(@cmd, ('-inform', $options{CERTFORMAT}));
    push(@cmd, ('-outform', $options{OUTFORMAT}));

    $output->{CERTFORMAT} = $options{OUTFORMAT};

    my $cmd = join(' ', @cmd);
    CertNanny::Logging->log({ MSG => "Execute: " . $cmd,
		 PRIO => 'debug' });

    $output->{CERTDATA} = `$cmd`;
    unlink $infile if defined $infile;

    if ($? != 0) {
	CertNanny::Logging->error("convertcert(): Could not convert certificate");
	return;
    }
    
    return $output;
}


# convert private keys to other formats
# input: hash
# KEYDATA => string containing private key data OR
# KEYFILE => file containing private key
# KEYTYPE => private key type (OpenSSL or PKCS8), default: OpenSSL
# KEYFORMAT => private key encoding format (PEM or DER), default: DER
# KEYPASS => private key pass phrase, may be undef or empty
# OUTFORMAT => desired output key format (PEM or DER), default: DER
# OUTTYPE => desired output private key type (OpenSSL or PKCS8), 
#            default: OpenSSL
# OUTPASS => private key pass phrase, may be undef or empty
#
# return: hash
# KEYDATA => string containing key data
# KEYFORMAT => key encoding format (PEM or DER)
# KEYTYPE => key type (OpenSSL or PKCS8)
# KEYPASS => private key pass phrase
# or undef on error
sub convertkey {
    my $self = shift;
    my %options = (
	KEYFORMAT => 'DER',
	KEYTYPE   => 'OpenSSL',
	OUTFORMAT => 'DER',
	OUTTYPE   => 'OpenSSL',
	@_,         # argument pair list
	);

    # sanity checks
    foreach my $key (qw( KEYFORMAT OUTFORMAT )) {
	if ($options{$key} !~ m{ \A (?: DER | PEM ) \z }xms) {
	    CertNanny::Logging->error("convertkey(): Incorrect $key: $options{$key}");
	    return;
	}
    }

    foreach my $key (qw( KEYTYPE OUTTYPE )) {
	if ($options{$key} !~ m{ \A (?: OpenSSL | PKCS8 ) \z }xms) {
	    CertNanny::Logging->error("convertkey(): Incorrect $key: $options{$key}");
	    return;
	}
    }

    my $openssl = $self->{OPTIONS}->{openssl_shell};
    my $output;

    my @cmd = (qq("$openssl"),
	);

    # KEYTYPE OUTTYPE  CMD
    # OpenSSL OpenSSL  rsa
    # OpenSSL PKCS8    pkcs8 -topk8
    # PKCS8   OpenSSL  pkcs8
    # PKCS8   PKCS8    pkcs8 -topk8
    if ($options{KEYTYPE} eq 'OpenSSL') {
	if ($options{OUTTYPE} eq 'OpenSSL') {
	    push(@cmd, 'rsa');
	} 
	else 
	{
	    # must be PKCS#8, see above
	    push(@cmd, 'pkcs8');
	}
    } 
    else 
    {
	# must be PKCS#8, see above
	push(@cmd, 'pkcs8');

	if (! defined $options{KEYPASS}
	    || ($options{KEYPASS} eq "")) {
	    push(@cmd, '-nocrypt');

	    if (defined($options{OUTPASS}) && $options{OUTPASS} ne "") {
		# if -nocrypt is specified on the command line, the output
		# is always unencrypted, even if -passout is specified.
		CertNanny::Logging->error("convertkey(): PKCS8 conversion from unencrypted to encrypted key is not supported");
		return;
	    }
	}
    }
    
    if ($options{OUTTYPE} eq 'PKCS8') {
	push(@cmd, '-topk8');
    } 

    push(@cmd, 
	 '-inform', $options{KEYFORMAT},
	 '-outform', $options{OUTFORMAT},
	);
    

    # prepare output
    $output->{KEYTYPE}   = $options{OUTTYPE};
    $output->{KEYFORMAT} = $options{OUTFORMAT};
    $output->{KEYPASS}   = $options{OUTPASS};
    
    my $infile;
    push(@cmd, '-in');
    if (defined $options{KEYDATA}) {
	$infile = $self->gettmpfile();
	if (! CertNanny::Util->write_file(FILENAME => $infile,
				CONTENT  => $options{KEYDATA},
	    )) {
	    CertNanny::Logging->error("convertkey(): Could not write temporary file");
	    return;
	}

	push(@cmd, qq("$infile"));
    } else {
	push(@cmd, qq("$options{KEYFILE}"));
    }

    $ENV{PASSIN} = "";
    if (defined($options{KEYPASS}) && ($options{KEYPASS} ne "")) {
	$ENV{PASSIN} = $options{KEYPASS};
    }
    if ($ENV{PASSIN} ne "") {
        push(@cmd, '-passin', 'env:PASSIN');
    }

    $ENV{PASSOUT} = "";
    if (defined $options{OUTPASS} && ($options{OUTPASS} ne "")) {
	$ENV{PASSOUT} = $options{OUTPASS};
	if (($options{KEYTYPE} eq 'OpenSSL')
	    && ($options{OUTTYPE} eq 'OpenSSL')) {
	    push(@cmd, '-des3');
	}
    }
    if ($ENV{PASSOUT} ne "") {
        push(@cmd, '-passout', 'env:PASSOUT');
    }
    
    my $cmd = join(' ', @cmd);

    CertNanny::Logging->log({ MSG => "Execute: " . $cmd,
		 PRIO => 'debug' });

    ### PASSIN: $ENV{PASSOUT}
    ### PASSOUT: $ENV{PASSOUT}
    #$output->{KEYDATA} = `$cmd`;
    $output->{KEYDATA} = `$cmd`;
    ### keydata: $output->{KEYDATA}

    delete $ENV{PASSIN};
    delete $ENV{PASSOUT};
    unlink $infile if defined $infile;
    
    if ($? != 0) {
	CertNanny::Logging->error("convertkey(): Could not convert key");
	return;
    }
    
    return $output;
}

sub loglevel {
    my $self = shift;
    $self->{OPTIONS}->{LOGLEVEL} = shift if (@_);

    if (! defined $self->{OPTIONS}->{LOGLEVEL}) {
	return 3;
    }
    return $self->{OPTIONS}->{LOGLEVEL};
}

# accessor method for renewal state
sub renewalstate {
    my $self = shift;
    if (@_) {
	$self->{STATE}->{DATA}->{RENEWAL}->{STATUS} = shift;
	my $hook = $self->{INSTANCE}->{OPTIONS}->{ENTRY}->{hook}->{renewal}->{state} || $self->{OPTIONS}->{ENTRY}->{hook}->{renewal}->{state};
	$self->executehook($hook,
			   '__STATE__' => $self->{STATE}->{DATA}->{RENEWAL}->{STATUS},
			   );
    }
    return $self->{STATE}->{DATA}->{RENEWAL}->{STATUS};
}


sub retrieve_state
{
    my $self = shift;

    my $file = $self->{OPTIONS}->{ENTRY}->{statefile};
    return 1 unless (defined $file and $file ne "");
    
    if (-r $file) {
	$self->{STATE}->{DATA} = undef;
	
	my $fh;
	if (! open $fh, '<', $file) {
	    croak "Could not read state file $file";
	}
	eval do { local $/; <$fh> };

	if (! defined $self->{STATE}->{DATA}) {
	    croak "Could not read state from file $file";
	}
    }
    return 1;
}

sub store_state
{
    my $self = shift;

    my $file = $self->{OPTIONS}->{ENTRY}->{statefile};
    return 1 unless (defined $file and $file ne "");

    # store internal state
    if (ref $self->{STATE}->{DATA}) {
	my $dump = Data::Dumper->new([$self->{STATE}->{DATA}],
				     [qw($self->{STATE}->{DATA})]);

	$dump->Purity(1);

	my $fh;
	if (! open $fh, '>', $file) {
	    croak "Could not write state to file $file";
	}
	print $fh $dump->Dump;
	close $fh;
    }
    
    return 1;
}


# get error message
# arg:
# return: error message description caused by the last operation (cleared 
#         after each query)
#TODO Is this used anywhere?
sub geterror
{
    my $self = shift;
    my $arg = shift;

    my $my_errmsg = $self->{ERRMSG};
    # clear error message
    $self->{ERRMSG} = undef if (defined $my_errmsg);

    # compose output
    my $errmsg;
    $errmsg = $my_errmsg if defined ($my_errmsg);

    $errmsg;
}


# dynamically load keystore instance module
sub load_keystore_handler
{
    my $self = shift;
    my $arg = shift;
    
    eval "require CertNanny::Keystore::${arg}";
    if ($@) {
	print STDERR $@;
	return 0;
    }
    
    return 1;
}


# NOTE: this is UNSAFE (beware of race conditions). We cannot use a file
# handle here because we are calling external programs to use these
# temporary files.
sub gettmpfile
{
    my $self = shift;

    my $tmpdir = $self->{OPTIONS}->{tmp_dir};
    #if (! defined $tmpdir);
    my $template = File::Spec->catfile($tmpdir,
				       "cbXXXXXX");

    my $tmpfile =  mktemp($template);
    
    push (@{$self->{TMPFILE}}, $tmpfile);
    return ($tmpfile);
}


# File/keystore installation convenience method
# This method is very careful about rolling back all modifications if
# any error happened. Unless something really ugly happens, the original
# state is always restored even if this method returns an error.
# This includes permission problems, ownership, file system errors etc.
# and even if multiple files are to be installed and the error occurs
# after a portion of them have been installed successfully.
#
# options:
# filespec-hashref or array containing filespec-hashrefs
# examples:
# $self->installfile({ FILENAME => 'foo', CONTENT => $data, DESCRIPTION => 'some file...'});
# or
# @files = (
#    { FILENAME => 'foo', CONTENT => $data1, DESCRIPTION => 'some file...'},
#    { FILENAME => 'bar', CONTENT => $data2, DESCRIPTION => 'other file...'},
# );
# $self->installfile(@files);
# 
sub installfile 
{
    my ($self, @args) = @_;

    my $error = 0;

    ###########################################################################
    # write new files

  WRITENEWFILES:
    foreach my $entry (@args) {
	# file to replace
	my $filename = $entry->{FILENAME};

	my $ii = 0;
	my $tmpfile  = $filename . ".new";

	# write content data to suitable temporary file
	my $tries = 10;
	while ($ii < $tries 
	       && (! CertNanny::Util->write_file(
			 FILENAME => $tmpfile,
			 CONTENT  => $entry->{CONTENT}))) {
	    # write_file() will not overwrite existing files, an error
	    # indicates that e. g. the file already existed, so:
	    # try next filename candidate
	    $tmpfile = $filename . ".new$ii";
	    $ii++;
	}

	# error: could not write one of the tempory files
	if (($ii == $tries) || (! -e $tmpfile)) {
	    # remember to clean up the files created up to now
	    $error = 1;
	    last WRITEFILES;
	}

	# the temporary file should be given the existing owner/group and
	# mode - if possible
	my @stats = stat($filename);

	# NOTE/FIXME: we ignore problems with setting user, group or
	# permissions here on purpose, we don't want to rollback the
	# operation due to permission problems or because this is not
	# supported by the target system
	if (scalar(@stats)){
	    #           uid        gid
	    chown $stats[4], $stats[5], $tmpfile;

	    #          mode, integer - which is OK for chmod
	    chmod $stats[2] & 07777, $tmpfile; # mask off file type
	}

	# remember new file name for file replacement
	$entry->{TMPFILENAME} = $tmpfile;
    }

    ###########################################################################
    # error checking for temporary file creation
    if ($error) {
	# something went wrong, clean up and bail out
	foreach my $entry (@args) {
	    unlink $entry->{TMPFILENAME};
	}
	CertNanny::Logging->error("installfile(): could not create new file(s)");
	return;
    }

    ###########################################################################
    # temporary files have been created with proper mode and permissions,
    # now back up original files

    my @original_files = ();
    foreach my $entry (@args) {
	my $file = $entry->{FILENAME};
	my $backupfile = $file . ".backup";

	# remove already existing backup file
	if (-e $backupfile) {
	    unlink $backupfile;
	}

	# check if it still persists
	if (-e $backupfile) {
	    CertNanny::Logging->error("installfile(): could not unlink backup file $backupfile");

	    # clean up and bail out

	    # undo rename operations
	    foreach my $undo (@original_files) {
		rename $undo->{DST}, $undo->{SRC};
	    }

	    # clean up temporary files
	    foreach my $entry (@args) {
		unlink $entry->{TMPFILENAME};
	    }
	    return;
	}
	
	# rename orignal files: file -> file.backup
	if (-e $file) { 
	    # only if the file exists
	    if ((! rename $file, $backupfile)  # but cannot be moved away
		|| (-e $file)) {               # or still exists after moving
		CertNanny::Logging->error("installfile(): could not rename $file to backup file $backupfile");
		
		# undo rename operations
		foreach my $undo (@original_files) {
		    rename $undo->{DST}, $undo->{SRC};
		}
		
		# clean up temporary files
		foreach my $entry (@args) {
		    unlink $entry->{TMPFILENAME};
		}
		return;
	    }

	    # remember what we did here already
	    push(@original_files, 
		 { 
		     SRC => $file,
		     DST => $backupfile,
		 });	
	}
    }

    
    # existing keystore files have been renamed, now rename temporary
    # files to original file names
    foreach my $entry (@args) {
	my $tmpfile = $entry->{TMPFILENAME};
	my $file = $entry->{FILENAME};

	my $msg = "Installing file $file";
	if (exists $entry->{DESCRIPTION}) {
	    $msg .= " ($entry->{DESCRIPTION})";
	}

	CertNanny::Logging->info($msg);

	if (! rename $tmpfile, $file) {
	    # should not happen!
	    # ... but we have to handle this nevertheless

	    CertNanny::Logging->error("installfile(): could not rename $tmpfile to target file $file");
	    # undo rename operations
	    foreach my $undo (@original_files) {
		unlink $undo->{SRC};
		rename $undo->{DST}, $undo->{SRC};
	    }

	    # clean up temporary files
	    foreach my $entry (@args) {
		unlink $entry->{TMPFILENAME};
	    }
	    return;
	}
    }

    return 1;
}



# parse DER encoded X.509v3 certificate and return certificate information 
# in a hash ref
# Prerequisites: requires external openssl executable
# options: hash
#   CERTDATA => directly contains certificate data
#   CERTFILE => cert file to parse
#   CERTFORMAT => PEM|DER (default: DER)
#
# return: hash reference containing the certificate information
# returns undef if both CERTDATA and CERTFILE are specified or on error
#
# Returned hash reference contains the following values:
# Version => <cert version, optional> Values: 2, 3
# SubjectName => <cert subject common name>
# IssuerName => <cert issuer common name>
# SerialNumber => <cert serial number> Format: xx:xx:xx... (hex, upper case)
# NotBefore => <cert validity> Format: YYYYDDMMHHMMSS
# NotAfter  => <cert validity> Format: YYYYDDMMHHMMSS
# PublicKey => <cert public key> Format: Base64 encoded (PEM)
# Certificate => <certifcate> Format: Base64 encoded (PEM)
# BasicConstraints => <cert basic constraints> Text (free style)
# KeyUsage => <cert key usage> Format: Text (free style)
# CertificateFingerprint => <cert SHA1 fingerprint> Format: xx:xx:xx... (hex, 
#   upper case)
#
# optional:
# SubjectAlternativeName => <cert alternative name> 
# IssuerAlternativeName => <issuer alternative name>
# SubjectKeyIdentifier => <X509v3 Subject Key Identifier>
# AuthorityKeyIdentifier => <X509v3 Authority Key Identifier>
# CRLDistributionPoints => <X509v3 CRL Distribution Points>
# 
sub getcertinfo
{
    my $self = shift;
    return CertNanny::Util->getcertinfo(@_);
=comment  
    my %options = (
		   CERTFORMAT => 'DER',
		   @_,         # argument pair list
		   );
    

    my $certinfo = {};
    my %month = (
		 Jan => 1, Feb => 2,  Mar => 3,  Apr => 4,
		 May => 5, Jun => 6,  Jul => 7,  Aug => 8,
		 Sep => 9, Oct => 10, Nov => 11, Dec => 12 );

    my %mapping = (
		   'serial' => 'SerialNumber',
		   'subject' => 'SubjectName',
		   'issuer' => 'IssuerName',
		   'notBefore' => 'NotBefore',
		   'notAfter' => 'NotAfter',
		   'SHA1 Fingerprint' => 'CertificateFingerprint',
		   'PUBLIC KEY' => 'PublicKey',
		   'CERTIFICATE' => 'Certificate',
		   'ISSUERALTNAME' => 'IssuerAlternativeName',
		   'SUBJECTALTNAME' => 'SubjectAlternativeName',
		   'BASICCONSTRAINTS' => 'BasicConstraints',
		   'SUBJECTKEYIDENTIFIER' => 'SubjectKeyIdentifier',
		   'AUTHORITYKEYIDENTIFIER' => 'AuthorityKeyIdentifier',
		   'CRLDISTRIBUTIONPOINTS' => 'CRLDistributionPoints',
		   );
	

    # sanity checks
    if (! (defined $options{CERTFILE} or defined $options{CERTDATA}))
    {
	CertNanny::Logging->error("getcertinfo(): No input data specified");
	return;
    }
    if ((defined $options{CERTFILE} and defined $options{CERTDATA}))
    {
	CertNanny::Logging->error("getcertinfo(): Ambigous input data specified");
	return;
    }
    
    my $outfile = $self->gettmpfile();
    my $openssl = $self->{OPTIONS}->{openssl_shell};

    my $inform = $options{CERTFORMAT};

    my @input = ();
    if (defined $options{CERTFILE}) {
	@input = ('-in', qq("$options{CERTFILE}"));
    }

    # export certificate
    my @cmd = (qq("$openssl"),
	       'x509',
	       @input,
	       '-inform',
	       $inform,
	       '-text',
	       '-subject',
	       '-issuer',
	       '-serial',
	       '-email',
	       '-startdate',
	       '-enddate',
	       '-modulus',
	       '-fingerprint','-sha1',
	       '-pubkey',
	       '-purpose',
	       '>',
	       qq("$outfile"));

    CertNanny::Logging->log({ MSG => "Execute: " . join(" ", @cmd),
		 PRIO => 'debug' });	
    my $fh;
    if (!open $fh, "|" . join(' ', @cmd))
    {
    	CertNanny::Logging->error("getcertinfo(): open error");
	unlink $outfile;
	return;

    }

    binmode $fh;
    if (defined $options{CERTDATA}) {
	print $fh $options{CERTDATA};
    }

    close $fh;
    
    if ($? != 0)
    {
    	CertNanny::Logging->error("getcertinfo(): Error ASN.1 decoding certificate");
	unlink $outfile;
	return;
    }

    open $fh, '<', $outfile;
    if (! $fh)
    {
    	CertNanny::Logging->error("getcertinfo(): Error analysing ASN.1 decoded certificate");
	unlink $outfile;
    	return;
    }

    my $state = "";
    my @purposes;
    while (<$fh>)
    {
	chomp;
	tr/\r\n//d;

	$state = "PURPOSE" if (/^Certificate purposes:/);
	$state = "PUBLIC KEY" if (/^-----BEGIN PUBLIC KEY-----/);
	$state = "CERTIFICATE" if (/^-----BEGIN CERTIFICATE-----/);
	$state = "SUBJECTALTNAME" if (/X509v3 Subject Alternative Name:/);
	$state = "ISSUERALTNAME" if (/X509v3 Issuer Alternative Name:/);
	$state = "BASICCONSTRAINTS" if (/X509v3 Basic Constraints:/);
	$state = "SUBJECTKEYIDENTIFIER" if (/X509v3 Subject Key Identifier:/);
	$state = "AUTHORITYKEYIDENTIFIER" if (/X509v3 Authority Key Identifier:/);
	$state = "CRLDISTRIBUTIONPOINTS" if (/X509v3 CRL Distribution Points:/);

	if ($state eq "PURPOSE")
	{
	    my ($purpose, $bool) = (/(.*?)\s*:\s*(Yes|No)/);
	    next unless defined $purpose;
	    push (@purposes, $purpose) if ($bool eq "Yes");

	    # NOTE: state machine will leave PURPOSE state on the assumption
	    # that 'OCSP helper CA' is the last cert purpose printed out
	    # by OpenCA. It would be best to have OpenSSL print out
	    # purpose information, just to be sure.
	    $state = "" if (/^OCSP helper CA :/);
	    next;
	}
	# Base64 encoded sections
	if ($state =~ /^(PUBLIC KEY|CERTIFICATE)$/)
	{
	    my $key = $state;
	    $key = $mapping{$key} if (exists $mapping{$key});

	    $certinfo->{$key} .= "\n" if (exists $certinfo->{$key});
	    $certinfo->{$key} .= $_ unless (/^-----/);

	    $state = "" if (/^-----END $state-----/);
	    next;
	}

	# X.509v3 extension one-liners
	if ($state =~ /^(SUBJECTALTNAME|ISSUERALTNAME|BASICCONSTRAINTS|SUBJECTKEYIDENTIFIER|AUTHORITYKEYIDENTIFIER|CRLDISTRIBUTIONPOINTS)$/)
	{
	    next if (/X509v3 .*:/);
	    my $key = $state;
	    $key = $mapping{$key} if (exists $mapping{$key});
	    # remove trailing and leading whitespace
	    s/^\s*//;
	    s/\s*$//;
	    $certinfo->{$key} = $_ unless ($_ eq "<EMPTY>");
	    
	    # alternative line consists of only one line 
	    $state = "";
	    next;
	}
	
 	if (/(Version:|subject=|issuer=|serial=|notBefore=|notAfter=|SHA1 Fingerprint=)\s*(.*)/)
 	{
	    my $key = $1;
 	    my $value = $2;
	    # remove trailing garbage
	    $key =~ s/[ :=]+$//;
	    # apply key mapping
	    $key = $mapping{$key} if (exists $mapping{$key});

	    # store value
 	    $certinfo->{$key} = $value;
 	}
    }
    close $fh;
    unlink $outfile;

    # compose key usage text field
    $certinfo->{KeyUsage} = join(", ", @purposes);
    
    # sanity checks
    foreach my $var (qw(Version SerialNumber SubjectName IssuerName NotBefore NotAfter CertificateFingerprint))
    {
	if (! exists $certinfo->{$var})
	{
	    CertNanny::Logging->error("getcertinfo(): Could not determine field '$var' from X.509 certificate");
	    return;
	}
    }


    ####
    # Postprocessing, rewrite certain fields

    ####
    # serial number
    # extract hex certificate serial number (only required for -text format)
    #$certinfo->{SerialNumber} =~ s/.*\(0x(.*)\)/$1/;

    # store decimal serial number
    #$certinfo->{Serial} = hex($certinfo->{SerialNumber});

    # pad with a leading zero if length is odd
    if (length($certinfo->{SerialNumber}) % 2)
    {
	$certinfo->{SerialNumber} = '0' . $certinfo->{SerialNumber};
    }
    # convert to upcase and insert colons to separate hex bytes
    $certinfo->{SerialNumber} = uc($certinfo->{SerialNumber});
    $certinfo->{SerialNumber} =~ s/(..)/$1:/g;
    $certinfo->{SerialNumber} =~ s/:$//;

    ####
    # get certificate version
    $certinfo->{Version} =~ s/(\d+).*/$1/;

    ####
    # reverse DN order returned by OpenSSL
    foreach my $var (qw(SubjectName IssuerName))
    {
	$certinfo->{$var} = join(", ", 
				 reverse split(/[\/,]\s*/, $certinfo->{$var}));
	# remove trailing garbage
	$certinfo->{$var} =~ s/[, ]+$//;
    }

    ####
    # rewrite dates from human readable to ISO notation
    foreach my $var (qw(NotBefore NotAfter))
    {
	my ($mon, $day, $hh, $mm, $ss, $year, $tz) =
	    $certinfo->{$var} =~ /(\S+)\s+(\d+)\s+(\d+):(\d+):(\d+)\s+(\d+)\s*(\S*)/;
	my $dmon = $month{$mon};
	if (! defined $dmon)
	{
	    CertNanny::Logging->error("getcertinfo(): could not parse month '$mon' in date '$certinfo->{$var}' returned by OpenSSL");
	    return;
	}
	
	$certinfo->{$var} = sprintf("%04d%02d%02d%02d%02d%02d",
				    $year, $dmon, $day, $hh, $mm, $ss);
    }
=cut	
}


# return certificate information for this keystore
# optional arguments: list of entries to return
sub getinfo
{
    my $self = shift;
    my @elements = @_;

    return $self->{CERT}->{INFO} unless @elements;

    my $result;
    foreach (@elements) {
	$result->{$_} = $self->{CERT}->{INFO}->{$_};
    }
    return $result;
}

# return true if certificate is still valid for more than <days>
# return false otherwise
# return undef on error
sub checkvalidity {	
    my $self = shift;
    my $days = shift || 0;
    
    my $notAfter = isodatetoepoch($self->{CERT}->{INFO}->{NotAfter});
    return unless defined $notAfter;

    my $cutoff = time + $days * 24 * 3600;

    return ($cutoff < $notAfter);
}


# handle renewal operation
sub renew {
    my $self = shift;

    $self->renewalstate("initial") unless defined $self->renewalstate();
    my $laststate = "n/a";

    while ($laststate ne $self->renewalstate()) {
	$laststate = $self->renewalstate();
	# renewal state machine
	if ($self->renewalstate() eq "initial") {
	    CertNanny::Logging->log({ MSG => "State: initial",
			 PRIO => 'debug' });
	    
	    $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST} = $self->createrequest();
	    
	    if (! defined $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}) {
		CertNanny::Logging->log({ MSG => "Could not create certificate request",
			     PRIO => 'error' });
		return;
	    }	    
	    $self->renewalstate("sendrequest");
	} 
	elsif ($self->renewalstate() eq "sendrequest") 
	{
	    CertNanny::Logging->log({ MSG => "State: sendrequest",
			 PRIO => 'debug' });
	    
	    if (! $self->sendrequest()) {
		CertNanny::Logging->log({ MSG => "Could not send request",
			     PRIO => 'error' });
		return;
	    }
	}
	elsif ($self->renewalstate() eq "completed") 
	{
	    CertNanny::Logging->log({ MSG => "State: completed",
			 PRIO => 'debug' });

	    # reset state
	    $self->renewalstate(undef);

	    # clean state entry
	    foreach my $entry (qw( CERTFILE KEYFILE REQUESTFILE )) {
		unlink $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{$entry};
	    }

	    # delete state file
	    unlink $self->{OPTIONS}->{ENTRY}->{statefile};
	    last;
	}
	else
	{
	    CertNanny::Logging->log({ MSG => "State unknown: " . $self->renewalstate(),
			 PRIO => 'error' });
	    return;
	}

    }

    return 1;
}



###########################################################################
# abstract methods to be implemented by the instances

# get main certificate from keystore
# caller must return a hash ref:
# CERTFILE => file containing the cert OR
# CERTDATA => string containg the cert data
# CERTFORMAT => 'PEM' or 'DER'
sub getcert {
    return;
}

# get private key for main certificate from keystore
# caller must return a hash ref containing the unencrypted private key in
# OpenSSL format
# Return:
# hashref (as expected by convertkey()), containing:
# KEYDATA => string containg the private key OR
# KEYFILE => file containing the key data
# KEYFORMAT => 'PEM' or 'DER'
# KEYTYPE => format (e. g. 'PKCS8' or 'OpenSSL'
# KEYPASS => key pass phrase (only if protected by pass phrase)
sub getkey {
    return;
}

sub createrequest {
    return;
}

sub installcert {
    return;
}

# get all root certificates from the configuration that are currently
# valid
# return:
# arrayref of hashes containing:
#   CERTINFO => hash as returned by getcertinfo()
#   CERTFILE => filename
#   CERTFORMAT => cert format (PEM, DER)
sub getrootcerts {
    my $self = shift;
    my @result = ();

  ROOTCERT:
    foreach my $index (keys %{$self->{OPTIONS}->{ENTRY}->{rootcacert}}) {
		next if ($index eq "INHERIT");
		#....{$index} is a valid cert?
		my $res = $self->checkCert($self->{OPTIONS}->{ENTRY}->{rootcacert}->{$index});
		if ($res !=0) {
			push(@result,$res);
		}
		else{ 
			#check if ...{$index} is folder
			if ( not opendir(inFolder,$self->{OPTIONS}->{ENTRY}->{rootcacert}->{$index})){
				CertNanny::Logging->error("can't open folder: $index"); 
				next ROOTCERT; #eventuell die? 
			}
			#go through each file in the folder and check if it is avalid cert
			my @files = readdir inFolder;
			foreach my $file (@files){
				my $res = $self->checkCert("$self->{OPTIONS}->{ENTRY}->{rootcacert}->{$index}$file");
				if ($res !=0) {
					push(@result,$res);
				}	
			}	
		}		
    }
	return \@result;
    
}
	
sub checkCert{
	my $self=shift;
	my $certfile=shift;	
	
	my $exclude_expired 
	= $self->{OPTIONS}->{ENTRY}->{excludeexpiredrootcerts} || 'yes';
    my $exclude_notyetvalid 
	= $self->{OPTIONS}->{ENTRY}->{excludenotyetvalidrootcerts} || 'no';
		
	# FIXME: determine certificate format of root certificate
	#my $certfile = $self->{OPTIONS}->{ENTRY}->{rootcacert}->{$index};
	my $certformat = 'PEM';
	my $certinfo = $self->getcertinfo(CERTFILE => $certfile,
					  CERTFORMAT => $certformat);

	return 0 if (! defined $certinfo);
	my $notbefore = CertNanny::Util::isodatetoepoch($certinfo->{NotBefore});
	my $notafter  = CertNanny::Util::isodatetoepoch($certinfo->{NotAfter});
	my $now = time;
	
	if ($exclude_expired =~ m{ yes }xmsi
	    && ($now > $notafter)) {
	    CertNanny::Logging->info("Skipping expired root certificate " . $certinfo->{SubjectName});
	    return 0;
	}

	if ($exclude_notyetvalid =~ m{ yes }xmsi
	    && ($now < $notbefore)) {
	    CertNanny::Logging->info("Skipping not yet valid root certificate " . $certinfo->{SubjectName});
	    return 0;
	}
	CertNanny::Logging->info("Trusted root certificate: " . $certinfo->{SubjectName});

	return {CERTINFO => $certinfo,
			 CERTFILE => $certfile,
			 CERTFORMAT => $certformat,
	      };
    }
    


# build a certificate chain for the specified certificate. the certificate 
# chain will NOT be verified cryptographically.
# return:
# arrayref containing ca certificate information, starting at the
# root ca
# undef on error (e. g. root certificate could not be found)
sub buildcertificatechain {
    my $self = shift;
    my $cert = shift;

    # local helper function that accepts two cert entries.
    # returns undef if the elements are unrelated
    # returns true if the first argument is the issuer of the second arg
    #   (1: authority key identifier chaining, 2: DN chaining)
    my $is_issuer = sub {
	### is_issuer...
	my $parent = shift;
	my $child  = shift;
	if (! defined $parent || ! defined $child) {
	    print STDERR "ERROR: is_issuer: missing parameters\n";
	    return;
	}

	if (ref $parent ne 'HASH' || ref $child ne 'HASH') {
	    print STDERR "ERROR: is_issuer: illegal parameters\n";
	    return;
	}

	my $child_issuer;
	my $child_akeyid;
	my $parent_subject;
	my $parent_skeyid;

	foreach my $field (qw( INFO CERTINFO )) {
	    $child_issuer   ||= $child->{$field}->{IssuerName};
	    $child_akeyid   ||= $child->{$field}->{AuthorityKeyIdentifier};
	    $parent_subject ||= $parent->{$field}->{SubjectName};
	    $parent_skeyid  ||= $parent->{$field}->{SubjectKeyIdentifier};
	}
	### $child_issuer
	### $child_akeyid
	### $parent_subject
	### $parent_skeyid

	if (defined $child_akeyid) {
	    ### keyid chaining...
	    if (defined $parent_skeyid &&
		'keyid:' . $parent_skeyid eq $child_akeyid) {
		### MATCHED via keyid...
		return 1;
	    }
	} else {
	    ### DN chaining...
	    if ($child_issuer eq $parent_subject) {
		### MATCHED via DN...
		return 2;
	    }
	}

	### no match...
	return;
    };


    # list of trusted root certificates
    my @trustedroots = @{$self->{STATE}->{DATA}->{ROOTCACERTS}};
    ### @trustedroots

    my %rootcertfingerprint;
    foreach my $entry (@trustedroots) {
	my $fingerprint = $entry->{CERTINFO}->{CertificateFingerprint};
	$rootcertfingerprint{$fingerprint}++;
    }

    # remove root certs from certificate list
    my @cacerts = grep(! exists $rootcertfingerprint{ $_->{CERTINFO}->{CertificateFingerprint} }, 
		       @{$self->{STATE}->{DATA}->{SCEP}->{CACERTS}});
    
    # @cacerts now contains the certificates delivered by SCEP minus
    # the configured root certificates.
    # NOTE: it may still contain root certificates NOT specified in
    # the config file!
    ### @cacerts

    # output structure, for building the chain start with the end entity cert
    my @chain = ( $cert );

    CertNanny::Logging->info("Building certificate chain");
  BUILDCHAIN:
    while (1) {
	### check if the first cert in the chain is a root certificate...
	if (&$is_issuer($chain[0], 
			$chain[0])) {
	    ### found root certificate...
	    last BUILDCHAIN;
	}

	my $cert;
	my $issuer_found = 0;

	my $subject = $chain[0]->{CERTINFO}->{SubjectName} || $chain[0]->{INFO}->{SubjectName};
	CertNanny::Logging->info("Subject: $subject");

      FINDISSUER:
	foreach my $entry (@cacerts, @trustedroots) {
	    # work around a bug in Perl (?): when using $cert instead of 
	    # $entry in the foreach loop the value of $cert was lost 
	    # after leaving the loop!?
	    $cert = $entry;
	    if (! defined $entry) {
		### undefined entry 1 - should not happen...
	    }
	    ### scanning ca entry...
	    ### $entry->{CERTINFO}->{SubjectName}
	    ### $chain[0]

	    $issuer_found = &$is_issuer($entry, $chain[0]);
	    if (! defined $entry) {
		### undefined entry 2 - should not happen...
	    }

	    $subject = $entry->{CERTINFO}->{SubjectName} || $entry->{INFO}->{SubjectName};
	    if ($issuer_found) {
		if ($issuer_found == 1) {
		    CertNanny::Logging->info("  Issuer identified via AuthKeyID match: $subject");
		} else {
		    CertNanny::Logging->info("  Issuer identified via DN match: $subject");
		}
	    } else {
		CertNanny::Logging->debug("  Unrelated: $subject");
	    }

	    last FINDISSUER if ($issuer_found);
	}

	if (! $issuer_found) {
	    CertNanny::Logging->error("No matching issuer certificate was found");
	    return;
	}
	if (! defined $cert) {
	    ### undefined entry 3 - should not happen...
	}

	### prepend to chain...
	### $cert
	unshift @chain, $cert;
    }

    # remove end entity certificate
    pop @chain;

    ### @chain

    # verify that the first certificate in the chain is a trusted root
    if (scalar @chain == 0) {
	CertNanny::Logging->error("Certificate chain could not be built");
	return;
    }

    my $fingerprint = $chain[0]->{CERTINFO}->{CertificateFingerprint};
    if (! exists $rootcertfingerprint{ $fingerprint }) {
	CertNanny::Logging->error("Root certificate is not trusted");
	CertNanny::Logging->info("Untrusted root certificate DN: " . 
		    $chain[0]->{CERTINFO}->{SubjectName});
	return;
    }
    CertNanny::Logging->info("Root certificate is marked as trusted in configuration");
    
    return \@chain;
}

# cryptographically verify certificate chain
# TODO
sub verifycertificatechain {

    return 1;
}

# call an execution hook
sub executehook {
    my $self = shift;
    my $hook = shift;
    my %args = ( 
        @_,         # argument pair list
    );
    
    # hook not defined -> success
    return 1 unless defined $hook;
    
    CertNanny::Logging->info("Running external hook function");
    
    if ($hook =~ /::/) {
	# execute Perl method
	CertNanny::Logging->info("Perl method hook not yet supported");
	return;
    } 
    else {
	# assume it's an executable
	CertNanny::Logging->debug("Calling shell hook executable");

	$args{'__LOCATION__'} = qq("$self->{INSTANCE}->{OPTIONS}->{ENTRY}->{location}") || qq("$self->{OPTIONS}->{ENTRY}->{location}");
	$args{'__ENTRY__'}    =  $self->{INSTANCE}->{OPTIONS}->{ENTRYNAME} || $self->{OPTIONS}->{ENTRYNAME};
	# TODO: Test Subject/Serial Hook!
	$args{'__SUBJECT__'}  = $self->{CERT}->{INFO}->{SubjectName} || 'UnknownSubject';
	$args{'__SERIAL__'}   = $self->{CERT}->{INFO}->{SerialNumber} || 'UnknownSerial';

	# replace values passed to this function
	foreach my $key (keys %args) {
	    my $value = $args{$key} || "";
	    $hook =~ s/$key/$value/g;
	}
	
	CertNanny::Logging->info("Exec: $hook");
	return run_command($hook);
    }
}

# call warnexpiry hook for notification event
sub warnexpiry {
    my $self = shift;
    my $notification = shift;
    return
	$self->executehook($self->{INSTANCE}->{OPTIONS}->{ENTRY}->{hook}->{warnexpiry},
			   '__NOTAFTER__' => $self->{CERT}->{INFO}->{NotAfter},
			   '__NOTBEFORE__' => $self->{CERT}->{INFO}->{NotBefore},
			   '__STATE__' => $self->{STATE}->{DATA}->{RENEWAL}->{STATUS},
			   );
}



# obtain CA certificates via SCEP
# returns a hash containing the following information:
# RACERT => SCEP RA certificate (scalar, filename)
# CACERTS => CA certificate chain, starting at highes (root) level 
#            (array, filenames)
sub getcacerts {
    my $self = shift;

    # get root certificates
    # these certificates are configured to be trusted
    $self->{STATE}->{DATA}->{ROOTCACERTS} = $self->getrootcerts();

    my $scepracert = $self->{STATE}->{DATA}->{SCEP}->{RACERT};    
    
    my $enroller = $self->get_enroller();
    my %certs = $enroller->getCA();
    
    $self->{STATE}->{DATA}->{SCEP}->{CACERTS} = $certs{CACERTS};
    $self->{STATE}->{DATA}->{SCEP}->{RACERT} = $certs{RACERT};
    
    return $certs{RACERT} if -r $certs{RACERT};
    return;
}

sub sendrequest {
    my $self = shift;

    CertNanny::Logging->info("Sending request");
    #my $enroller = $self->get_enroller();
    #return $enroller->enroll();
    #print Dumper $self->{STATE}->{DATA};

    if (! $self->getcacerts()) {
	CertNanny::Logging->error("Could not get CA certs");
	#return;
    }

    my $requestfile = $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{REQUESTFILE};
    my $requestkeyfile = $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{KEYFILE};
    my $pin = $self->{PIN} || $self->{OPTIONS}->{ENTRY}->{pin};
    my $sscep = $self->{OPTIONS}->{CONFIG}->get('cmd.sscep');
    my $scepurl = $self->{OPTIONS}->{ENTRY}->{enroll}->{sscep}->{URL};
    my $scepsignaturekey = $self->{OPTIONS}->{ENTRY}->{scepsignaturekey};
    my $scepchecksubjectname = 
    	$self->{OPTIONS}->{ENTRY}->{scepchecksubjectname} || 'no';
    my $scepracert = $self->{STATE}->{DATA}->{SCEP}->{RACERT};

    if (! exists $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{CERTFILE}) {
	my $certfile = $self->{OPTIONS}->{ENTRYNAME} . "-cert.pem";
	$self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{CERTFILE} = 
	    File::Spec->catfile($self->{OPTIONS}->{ENTRY}->{statedir}, 
				$certfile);
    }

    my $newcertfile = $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{CERTFILE};
    my $openssl = $self->{OPTIONS}->{openssl_shell};
    
    
    CertNanny::Logging->debug("request: $requestfile");
    CertNanny::Logging->debug("keyfile: $requestkeyfile");
    CertNanny::Logging->debug("sscep: $sscep");
    CertNanny::Logging->debug("scepurl: $scepurl");
    CertNanny::Logging->debug("scepsignaturekey: $scepsignaturekey");
    CertNanny::Logging->debug("scepchecksubjectname: $scepchecksubjectname");
    CertNanny::Logging->debug("scepracert: $scepracert");
    CertNanny::Logging->debug("newcertfile: $newcertfile");
    CertNanny::Logging->debug("openssl: $openssl");
	my $newkey;
	unless($self->hasEngine()) {
	    # get unencrypted new key in PEM format
	    $newkey = $self->convertkey(
		KEYFILE   => $requestkeyfile,
		KEYPASS   => $pin,
		KEYFORMAT => 'PEM',
		KEYTYPE   => 'OpenSSL',
		OUTFORMAT => 'PEM',
		OUTTYPE   => 'OpenSSL',
		# no pin
		);
	
	    if (! defined $newkey) {
		CertNanny::Logging->error("Could not convert new key");
		return;
	    }
	    

	    # write new PEM encoded key to temp file
	    $requestkeyfile = $self->gettmpfile();
	    CertNanny::Logging->debug("requestkeyfile: $requestkeyfile");
	    chmod 0600, $requestkeyfile;
	
	    if (! CertNanny::Util->write_file(
		FILENAME => $requestkeyfile,
		CONTENT  => $newkey->{KEYDATA},
		FORCE    => 1,
		)) {
		CertNanny::Logging->error("Could not write unencrypted copy of new file to temp file");
		return;
	    }
	}

    my @autoapprove = ();
    my $oldkeyfile;
    my $oldcertfile;
    if ($scepsignaturekey =~ /(old|existing)/i) {
		# get existing private key from keystore
		my $oldkey = $self->getkey();
		if (! defined $oldkey) {
		    CertNanny::Logging->error("Could not get old key from certificate instance");
		    return;
		}
		
		unless($self->hasEngine()) {
    		# convert private key to unencrypted PEM format
    		# only necessary if no engine support is available
    		# otherwise the keystore or engine is responsible for returning
    		# the correct format
    		my $oldkey_pem_unencrypted = $self->convertkey(
    		    %{$oldkey},
    		    OUTFORMAT => 'PEM',
    		    OUTTYPE   => 'OpenSSL',
    		    OUTPASS   => '',
    		    );
    	
    		if (! defined $oldkey_pem_unencrypted) {
    		    CertNanny::Logging->error("Could not convert (old) private key");
    		    return;
    		}
    	
    	 	$oldkeyfile = $self->gettmpfile();
    	        chmod 0600, $oldkeyfile;
    	
    		if (! CertNanny::Util->write_file(
    			  FILENAME => $oldkeyfile,
    			  CONTENT  => $oldkey_pem_unencrypted->{KEYDATA},
    			  FORCE    => 1,
    		    )) {
    		    CertNanny::Logging->error("Could not write temporary key file (old key)");
    		    return;
    		}
		} else {
		    $oldkeyfile = $oldkey;
		}
		
		CertNanny::Logging->debug("Old keyfile: $oldkeyfile");
		
		$oldcertfile = $self->gettmpfile();
		if (! CertNanny::Util->write_file(
			  FILENAME => $oldcertfile,
			  CONTENT  => $self->{CERT}->{RAW}->{PEM},
			  FORCE    => 1,
		    )) {
		    CertNanny::Logging->error("Could not write temporary cert file (old certificate)");
		    return;
		}
		
		CertNanny::Logging->debug("Old certificate: $oldcertfile");
    }
	
	my %options = (
		sscep_enroll => {
			PrivateKeyFile => $requestkeyfile,
			CertReqFile => $requestfile,
			SignKeyFile => $oldkeyfile,
			SignCertFile => $oldcertfile,
			LocalCertFile => $newcertfile
		},
		
		sscep => {
			CACertFile => $scepracert
		}
	);
	
	my $enroller = $self->get_enroller();
	$enroller->enroll(%options);

    unless($self->hasEngine()) {
        unlink $requestkeyfile;
        unlink $oldkeyfile if (defined $oldkeyfile);
        unlink $oldcertfile if (defined $oldcertfile);
    }

    if (-r $newcertfile) {
	# successful installation of the new certificate.
	# parse new certificate.
	# NOTE: in previous versions the hooks reported the old certificate's
	# data. here we change it in a way that the new data is reported
	my $newcert;
	$newcert->{INFO} = $self->getcertinfo(CERTFILE => $newcertfile,
					      CERTFORMAT => 'PEM');


	# build new certificate chain
	$self->{STATE}->{DATA}->{CERTCHAIN} = 
	    $self->buildcertificatechain($newcert);
	
	if (! defined $self->{STATE}->{DATA}->{CERTCHAIN}) {
	    CertNanny::Logging->error("Could not build certificate chain, probably trusted root certificate was not configured");
	    return;
	}


	$self->executehook($self->{OPTIONS}->{ENTRY}->{hook}->{renewal}->{install}->{pre},
			   '__NOTAFTER__' => $self->{CERT}->{INFO}->{NotAfter},
			   '__NOTBEFORE__' => $self->{CERT}->{INFO}->{NotBefore},
			   '__NEWCERT_NOTAFTER__' => $newcert->{INFO}->{NotAfter},
			   '__NEWCERT_NOTBEFORE__' => $newcert->{INFO}->{NotBefore},
	    );

	my $rc = $self->installcert(CERTFILE => $newcertfile,
				    CERTFORMAT => 'PEM');
	if (defined $rc and $rc) {

	    $self->executehook($self->{OPTIONS}->{ENTRY}->{hook}->{renewal}->{install}->{post},
			       '__NOTAFTER__' => $self->{CERT}->{INFO}->{NotAfter},
			       '__NOTBEFORE__' => $self->{CERT}->{INFO}->{NotBefore},
			       '__NEWCERT_NOTAFTER__' => $newcert->{INFO}->{NotAfter},
			       '__NEWCERT_NOTBEFORE__' => $newcert->{INFO}->{NotBefore},
		);

	    # done
	    $self->renewalstate("completed");
	    
	    return $rc;
	}
	return;
    }
    
    return 1;
}

sub get_enroller {
	my $self = shift;
	
	unless(defined $self->{OPTIONS}->{ENTRY}->{ENROLLER}) {
		my $enrollertype_cfg = $self->{OPTIONS}->{ENTRY}->{enroll}->{type} || 'sscep';
		my $enrollertype = ucfirst($enrollertype_cfg);
		eval "use CertNanny::Enroll::$enrollertype";
        if ($@) {
            print STDERR $@;
            return;
        }
        my $entry_options = $self->{OPTIONS}->{ENTRY};
        my $config = $self->{OPTIONS}->{CONFIG};
        my $entryname = $self->{OPTIONS}->{ENTRYNAME};
		eval "\$self->{OPTIONS}->{ENTRY}->{ENROLLER} = CertNanny::Enroll::$enrollertype->new(\$entry_options, \$config, \$entryname)";
		if ($@) {
		    print STDERR $@;
		    return;
	    }
	}
	
	return $self->{OPTIONS}->{ENTRY}->{ENROLLER};
}

sub hasEngine {
	my $self = shift;
	
	return defined $self->{OPTIONS}->{ENTRY}->{hsm};
}

sub getDefaultEngineSection {
    my $self = shift;
    
    return $self->{OPTIONS}->{ENTRY}->{enroll}->{sscep}->{engine} || 'engine_section';
}

1;
