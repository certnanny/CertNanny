#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005 - 2007 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny::Keystore::SAP;

use base qw( Exporter CertNanny::Keystore::PKCS12 );

use strict;
use vars qw($VERSION);
use Exporter;
use Carp;
use English;
use MIME::Base64;
if($^O eq "MSWin32") {
    use File::Copy;
}


$VERSION = 0.10;

###########################################################################

# constructor
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
    
    my $entry = $self->{OPTIONS}->{ENTRY};
    my $entryname = $self->{OPTIONS}->{ENTRYNAME};
    
    # check that both directories exist
    my $sap_to_certnanny_dir;
    my $certnanny_to_sap_dir;
    
    $certnanny_to_sap_dir = $entry->{certnanny_to_sap_dir};
    if(! $certnanny_to_sap_dir or ! -d $certnanny_to_sap_dir) {
        $self->seterror("keystore.$entryname.certnanny_to_sap_dir is either missing or not a directory, please check.");
        return;
    }
        
    $sap_to_certnanny_dir = $entry->{sap_to_certnanny_dir};
    if(! $sap_to_certnanny_dir or ! -d $sap_to_certnanny_dir) {
        $self->seterror("keystore.$entryname.sap_to_certnanny_dir is either missing or not a directory, please check.");
        return;
    }
    # To enable hooks and to keep in line with
    # the rest of CertNanny's stores, we set the 
    # location to where the keystore *currently*
    # can be found. Once a new keystore is created,
    # we will set it to the directory the keystore
    # was written.
    
    my $filename = $entry->{filename};
    if(! $filename) {
        $self->info("keystore.$entryname.filename is not specified, will look into $sap_to_certnanny_dir to find a file");
        opendir(DIR, $sap_to_certnanny_dir);
        my @files = grep ! /^\.{1,2}$/, readdir(DIR);
        closedir(DIR);
        if(@files > 1) {
            $self->seterror("More than one file in $sap_to_certnanny_dir, cannot determine correct file. Please specify keystore.$entryname.filename.");
            return;
        }
        
        if(@files == 1) {
            $self->seterror("No file in $sap_to_certnanny_dir, cannot determine correct file. Please specify keystore.$entryname.filename.");
            return;
        }
    }
    $entry->{location} = File::Spec->catfile($sap_to_certnanny_dir, $filename);
    $self->{PKCS12}->{XMLFILENAME} = $filename;
    $self->{PKCS12}->{CERTNANNY_TO_SAP_DIR} = $certnanny_to_sap_dir;
    $self->{PKCS12}->{SAP_TO_CERTNANNY_DIR} = $sap_to_certnanny_dir;
    
    my $p12_xml_file;
    if( ! $filename or ! -r ($p12_xml_file = File::Spec->catfile($sap_to_certnanny_dir, $filename))) {
        $self->info("No file present in $sap_to_certnanny_dir, no renewal required.");
        die("Aborting...");
        return;
    }
    
    if( -r File::Spec->catfile($certnanny_to_sap_dir, $filename)) {
        $self->info("The renewed keystore was not imported yet. Will not continue");
        die("Aborting...");
        return;
    }
    
    my $p12_data_tag = $entry->{p12_data_tag};
    if(!$p12_data_tag) {
        $self->info("keystore.$entryname.p12_data_tag no specified, will use default 'P12DATA'");
        $p12_data_tag = 'P12DATA';
    }
    $entry->{p12_data_tag} = $p12_data_tag;
    
    my $p12_pwd_tag = $entry->{p12_pwd_tag};
    if(!$p12_pwd_tag) {
        $self->info("keystore.$entryname.p12_pwd_tag no specified, will use default 'PWD'");
        $p12_pwd_tag = 'PWD';
    }
    $entry->{p12_pwd_tag} = $p12_pwd_tag;
    
    my $p12_xml = $self->read_file($p12_xml_file);
    if(!$p12_xml) {
        $self->seterror("XML file $p12_xml is empty.");
        return;
    }
    $self->{PKCS12}->{XML} = $p12_xml;
    #$p12_xml =~ m/.*?\<$p12_data_tag\>([A-Za-z0-9\+\/=]+)\<\/$p12_data_tag\>.*?\<$p12_pwd_tag\>(.*)?\<\/$p12_pwd_tag\>.*/s;
    $p12_xml =~ m/.*?<$p12_data_tag>([\w\d\s+=\/]+?)<\/$p12_data_tag>.*?<$p12_pwd_tag>(.*?)<\/$p12_pwd_tag>.*?/s;
    if(! $p12_xml ) {
        $self->seterror("Could not parse XML file. Incorrect format");
        return;
    }
    
    my $p12_data = $1;
    my $p12_pwd = $2;
    $p12_data =~ s/\s//g;
    $p12_data = MIME::Base64::decode($p12_data);
    if(!$p12_data) {
        $self->seterror("Could not retrieve PKCS#12 data.");
        return;
    }
    
    if(!$p12_pwd) {
        $self->seterror("Could not get the PKCS#12 password, cannot parse data");
        return;
    }
    
    $self->{PKCS12}->{DATA} = $p12_data;
    $self->{PKCS12}->{PWD} = $p12_pwd;
       


    # the rest should remain untouched

    # get previous renewal status
    $self->retrieve_state() || return;

    # check if we can write to the file
    $self->store_state() || croak "Could not write state file $self->{STATE}->{FILE}";

    # instantiate keystore
    return $self;
}


# you may add additional destruction code here but be sure to retain
# the call to the parent destructor
sub DESTROY {
    my $self = shift;
    # check for an overridden destructor...
    $self->SUPER::DESTROY if $self->can("SUPER::DESTROY");
}

# returns filename with all PKCS#12 data
sub get_pkcs12_file {
    my $self = shift;
    my $p12_file = $self->gettmpfile();
    my $p12_data = $self->{PKCS12}->{DATA};
    if(!$self->write_file((FILENAME => $p12_file, CONTENT => $p12_data, FORCE => 1))) {
        $self->seterror("Could not write temporary PKCS#12 file");
        return;
    }
    return $p12_file;
}

sub get_pin {
    my $self = shift;
    return $self->{PKCS12}->{PWD};
}

# This method should generate a new private key and certificate request.
# You may want to inherit this class from CertNanny::Keystore::OpenSSL if
# you wish to generate the private key and PKCS#10 request 'outside' of
# your keystore and import this information later.
# In this case use the following code:
# sub createrequest
# {
#   return $self->SUPER::createrequest() 
#     if $self->can("SUPER::createrequest");
# }
#
# If you are able to directly operate on your keystore to generate keys
# and requests, you might choose to do all this yourself here:
sub createrequest {
    my $self = shift;
    return $self->SUPER::createrequest() 
	if $self->can("SUPER::createrequest");
    return;
}



# This method is called once the new certificate has been received from
# the SCEP server. Its responsibility is to create a new keystore containing
# the new key, certificate, CA certificate keychain and collection of Root
# certificates configured for CertNanny.
# A true return code indicates that the keystore was installed properly.
sub installcert {
    my $self = shift;
    my %args = ( 
		 @_,         # argument pair list
		 );

    my $data = MIME::Base64::encode($self->get_new_pkcs12_data(%args));
    return unless $data;
    
    my $p12_config = $self->{PKCS12};
    my $new_p12_xml = $p12_config->{XML};
    my $old_data = MIME::Base64::encode($p12_config->{DATA});
    my $p12_data_tag = $self->{OPTIONS}->{ENTRY}->{p12_data_tag};
    my $p12_pwd_tag = $self->{OPTIONS}->{ENTRY}->{p12_pwd_tag};
    $new_p12_xml =~ s/<$p12_data_tag>([\w\d\s+=\/]+?)<\/$p12_data_tag>/<$p12_data_tag>$data<\/$p12_data_tag>/s;
    
    # create a temporary file which then will be moved over to the correct dir
    my $tmp_dir = $self->{OPTIONS}->{CONFIG}->get('path.tmpdir', 'FILE');
    my $xml_filename = $p12_config->{XMLFILENAME};
    # This is the TEMPORARY file we store the keystore in
    my $new_p12_xml_file = File::Spec->catfile($tmp_dir, $xml_filename);
    if(!$self->write_file((FILENAME => $new_p12_xml_file, CONTENT => $new_p12_xml, FORCE => 1))) {
        $self->seterror("Could not create temporary file to store PKCS12 XML file");
        return;
    }
    
    # temporary file written, before moving it to certnanny_to_sap_dir, remove old file from
    my $sap_to_certnanny_dir = $p12_config->{SAP_TO_CERTNANNY_DIR}; 
    my $old_xml_file = File::Spec->catfile($sap_to_certnanny_dir, $xml_filename);
    my $certnanny_to_sap_dir = $p12_config->{CERTNANNY_TO_SAP_DIR};
    # This is the location for the NEW XML
    my $new_xml_file = File::Spec->catfile($certnanny_to_sap_dir, $xml_filename);
    if(! unlink $old_xml_file) {
        $self->seterror("Could not delete old XML file. Will continue to prevent loss of renewed certificate.");
    }
    # temporary file written, move it to the certnanny_to_sap_dir
    if($^O eq "MSWin32") {
        if(!move($new_p12_xml_file, $new_xml_file)) {
            my $output = $!;
            $self->seterror("Could not move temporary file to $certnanny_to_sap_dir: $output");
            return;
        }
    } else {
        my $output = `mv "$new_p12_xml_file" "$new_xml_file"`;
        if($?) {
            chomp($output);
            $self->seterror("Could not move temporary file to $certnanny_to_sap_dir: $output");
            return;
        }
    }
    
    # Certificate was successfully installed, so we can
    # change the location to the path of the new keystore.
    # This way, a hook will always a receive the expected 
    # valid keystore path as a parameter.
    $self->{OPTIONS}->{ENTRY}->{location} = "$new_xml_file";
    
    # only on success:
    return 1;
}

1;
