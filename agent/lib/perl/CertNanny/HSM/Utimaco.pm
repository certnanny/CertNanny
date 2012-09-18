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
    my $proto = shift;
	my $class = ref($proto)  || $proto;
	my $entry_options = shift;
	my $hsm_options = $entry_options->{hsm};
	my $config = shift;
    my $entryname = shift;
	my $self = {};
	my @avail_keytypes = ("file", "token");
	
	bless $self, $class;
	
	#remove type, we know that here
	delete $hsm_options->{type};
	
	
	my $engine_section = $entry_options->{enroll}->{sscep}->{engine} || 'engine_section';
    $entry_options->{enroll}->{sscep}->{engine} = $engine_section;
    $entry_options->{enroll}->{$engine_section}->{engine_id} = $self->engineid();
    $entry_options->{enroll}->{$engine_section}->{dynamic_path} = $self->{OPTIONS}->{ENTRY}->{hsm}->{dynamic_path};
    
    unless(defined $hsm_options->{keytype} and (grep $_ eq $hsm_options->{keytype}, @avail_keytypes)) {
        CertNanny::Logging->error(qq("$hsm_options->{keytype} is not an available keytype."));
        return;
    }
    
    if($hsm_options->{keytype} eq "file") {
        CertNanny::Logging->error("File-type keys are not supported yet due to an incomplete engine, sorry.");
        return;
    } else {
        # keytype = token
        unless(defined $hsm_options->{p11tool} and -x $hsm_options->{p11tool}) {
            CertNanny::Logging->error("No executable defined or found to generate a key for Utimaco HSM.");
            return;
        }
        
        #make all params lowercase
        my @parameters = $self->availparams();
        foreach my $param (keys %{$hsm_options->{key}}) {
            my $value = $hsm_options->{key}->{$param};
            $param = lc($param);
            delete $hsm_options->{key}->{$param};
            $hsm_options->{key}->{$param}=$value;
            
        }
        
        #set pin from keystore config
        if($hsm_options->{key}->{login}) {
            CertNanny::Logging->info("hsm.key.login is set, but it will be overwritten by PIN setting.");
        }
        
        unless($entry_options->{pin}) {
            CertNanny::Logging->error("You need to set the keystore option pin to your login pin.");
            return;
        }
        $hsm_options->{key}->{login} = $entry_options->{pin};
        
        #check mandatory params
        foreach my $param (qw(slot login)) {
            unless(defined $hsm_options->{key}->{$param}) {
                CertNanny::Logging->error("The parameter key.$param is mandatory and needs to be set. Aborting...");
                return;
            }    
        }
        
        
        
    }
    
    
    
    
    
    $self->{hsm_options} = $hsm_options;
    $self->{ENTRY} = $entry_options;
    $self->{ENTRYNAME} = $entryname;
    $self->{CONFIG} = $config;
	
	return $self;
}

sub genkey() {
    my $self = shift;
    my $p11tool = $self->{hsm_options}->{p11tool};
    my @generateopts = ();
    my @parameters = $self->availparams();
    my $genkeyopt = "genkey=RSA,1024";
    foreach my $param (keys %{$self->{hsm_options}->{key}}) {
        my $value = $self->{hsm_options}->{key}->{$param};
        if((grep $_ eq $param , @parameters)) {
            if($param eq "id") {
                my $current_id = $self->getKeyID();
                $value =~ s/%i/$current_id/;
            }
            push(@generateopts, qq($param=$value));
        } elsif ($param eq "genkey") {
            $genkeyopt = qq($param=$value);
        } else {
            CertNanny::Logging->error(qq("Could not handle parameter $param with value $value."));
            return;
        }
    }
    
    
    my @cmd = ($p11tool,@parameters, $genkeyopt);
    
    my $cmd = join(" ", @cmd);
    CertNanny::Logging->debug("Execute: $cmd");
	my $rc = run_command($cmd);
	if($rc != 0) {
	    CertNanny::Logging->error("Could not generate new key in HSM, see logging output.");
	    return;
	}
	
	
}

sub loadKeyInfo() {
    my $self = shift;
    my $p11tool = $self->{hsm_options}->{p11tool};
    my $slot = $self->{hsm_options}->{key}->{slot};
    my $login = $self->{hsm_option}->{key}->{login};
    my $token_pattern = $self->{ENTRY}->{keyfile};
    $token_pattern =~ s/%i/(\\d+)/;
    CertNanny::Logging->debug("Will match on token pattern $token_pattern");
    my @cmd = ($p11tool, "slot=$slot", "login=$login", "ListObjects");
    my $cmd = join(" ",  @cmd);
    CertNanny::Logging->debug("Exec: $cmd");
    my $output;
    my $highest_id = -1;
	open FH, "$cmd |" or die "Couldn't execute $cmd: $!\n"; 
	while(defined(my $line = <FH>)) {
	    chomp($line);
	    $output .= $line;
	    
	    
	    
	    my $line_content = $1;
	    if($line =~ m/^.*?$token_pattern.*$/) {
	        
	        my $id = $1;
	        if($id > $highest_id) {
	            $highest_id = $id;
	        }
	    }
	}
	close FH;
	my $exitval = $? >> 8;
	if($exitval != 0) {
	    CertNanny::Logging->error("Could not execute command successfully.");
	    return;
	}
	
	my @groups = split(/^\+.*$/, $output);
	foreach my $group (@groups) {
	    
	}
	
	
	if($highest_id == -1) {
	    CertNanny::Logging->error("Could not get a valid id, returning");
	    return -1;
	}
	
	return $highest_id;
}

sub availparams() {
    return ("dev", "device", "lib", "password", "slot", "subject", "timeout", "id", "label");
}


1;

=head1 NAME

CertNanny::HSM::Utimaco - Interface for using Utimacos Se-/Ce-Series and all similar with CertNanny.

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
