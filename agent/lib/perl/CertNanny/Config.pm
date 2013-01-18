#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005-02 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#
#
# CertNanny::Config
#
# 2002-11-05 Martin Bartosch; Cynops GmbH <m.bartosch@cynops.de>
#
#
# Configuration variable overview:
#
# Variable		Configuration item	
# -----------------------------------------------------------------------------
#
# * Global configuration
#
# tmpdir		Path to temporary directory (defaults to /tmp)
#
#
# * Keystore instance configuration
#
# All keystores to monitor are configured below the keystore.* using
# the following notation:
#
# keystore.<instance>.<var>
#
# 
# Note: for backward compatibility with the old 'CertMonitor' release
# it is also possible to use certmonitor.* instead of keystore.*
#

package CertNanny::Config;

use base qw(Exporter);

use IO::File;

use strict;
use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);
use Exporter;

$VERSION = 0.10;

#@EXPORT      = qw(...);       # Symbols to autoexport (:DEFAULT tag)



sub new 
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $configfile = shift || 'certnanny.cfg';
    
    my $self = {};
    bless $self, $class;
    
    $self->{CONFIGFILE} = $configfile;
    
    $self->parse() || return;

    return ($self);
}

# get  file name
sub getconfigfilename
{
    my $self = shift;
    $self->{CONFIGFILE};
}


# recursively deep-copy a hash tree, NOT overwriting already existing
# values in destination tree
sub deepcopy
{
    my $source = shift;
    my $dest = shift;

    foreach my $key (keys %{$source})
    {
	if (ref($source->{$key}) eq "HASH")
	{
	    # create new node if it does not exist yet
	    $dest->{$key} = {} unless exists $dest->{$key};
	    deepcopy($source->{$key}, $dest->{$key});
	}
	else
	{
	    if (!exists $dest->{$key})
	    {
		# use default/parent value
		$dest->{$key} = $source->{$key};
	    } 
            # else keep existing (configured) value
	}
    }
    
    1;
}

# recursively determine CA inheritance settings
sub inherit_config
{
    my $caconfref = shift;
    my $subca = shift;

    # postprocess sub-ca settings (configuration inheritance)
    if (defined $caconfref->{$subca}->{INHERIT})
    {
	# inherit settings from parent config
	my $parent = $caconfref->{$subca}->{INHERIT};

	# make sure the parent already inherited its values from its own
	# parent
	inherit_config($caconfref, $parent);

	# copy subtree
	deepcopy($caconfref->{$parent}, $caconfref->{$subca});
    }
}


# get nested configuration entry
# arg1: variable name "xx.yy.zz"
# arg2: optional options: 
#   undef: return variable value
#   'ref': return reference to variable
sub get_ref
{
    my $self = shift;
    my $var = shift;
    my $option = shift;

    my @var = split(/\./, $var); # internal variable path

    my $target = $self->{CONFIG};
    my $tmp = pop @var;
    foreach (@var)
    {
	if (!exists $target->{$_})
	{
	    $target = undef;
	    last;
	}
	$target = $target->{$_};
    }
    if (defined $option and $option eq 'ref')
    {
	$target->{$tmp} = undef	unless exists $target->{$tmp};
	$target = \$target->{$tmp};
	return $target;
    }
    else
    {
	# get value
	$target = $target->{$tmp} if exists $target->{$tmp};
	$target = undef unless (defined $target and (ref($target) ne "HASH"));
	return $target;
    }
}


# replace internal variables
sub replace_variables
{
    my $self = shift;
    my $configref = shift;
    my $thiskey = shift;

    # determine if this entry is a string or a hash array
    if (ref($configref->{$thiskey}) eq "HASH")
    {
	foreach (keys %{$configref->{$thiskey}})
	{
	    replace_variables($self, $configref->{$thiskey}, $_);
	}
    }
    else
    {
	# actually replace variables
	while ($configref->{$thiskey} =~ /\$\((.*?)\)/)
	{
	    my $var = $1;
	    my $target = get_ref($self, $var);
	    $target = "" unless defined $target;
	    
	    $var =~ s/\./\\\./g;
	    $configref->{$thiskey} =~ s/\$\($var\)/$target/g;
	}
    }
}


sub parse
{
    my $self = shift;

    my $handle = new IO::File "<" . $self->{CONFIGFILE};

    return if (!defined $handle);

    $self->{CFGMTIME} = (stat($self->{CONFIGFILE}))[9];

    # set implicit defaults
    $self->{CONFIG} = { 
	keystore => { 
	    DEFAULT => {
		autorenew_days => 30,
		warnexpiry_days => 20,
		abortifcertexpired => 'yes',
		type => 'none',
		scepsignaturekey => 'new',
	    },
	},
    };

    # backward compatibility
    $self->{CONFIG}->{certmonitor} = $self->{CONFIG}->{keystore};
    
    my $lnr = 0;
    while (<$handle>)
    {
	chomp;
	$lnr++;
	tr/\r\n//d;
	next if (/^\s*\#/);
	next if (/^\s*$/);

	if (/^\s*(.*?)\s*=\s*(.*)/)
	{
	    my @path = split(/\./, $1);
	    my $val = $2;
	    my $key = pop(@path);

	    my $var = $self->{CONFIG};
	    foreach (@path)
	    {
		if (!exists $var->{$_})
		{
		    $var->{$_} = {};
		    $var->{$_}->{INHERIT} = "DEFAULT";
		}
		$var = $var->{$_};
	    }
	    $val =~ s/\s*$//g;
	    $var->{$key} = $val;
	}
	else
	{
	    print STDERR "Config file error: parse error in line $lnr\n";
	}
    }
    $handle->close();

    # replace internal variables
    foreach (keys %{$self->{CONFIG}})
    {
	replace_variables($self, $self->{CONFIG}, $_);
    }

    # postprocess sub-ca settings (configuration inheritance)
    foreach my $toplevel (qw(certmonitor keystore)) {
        foreach my $entry (keys (%{$self->{CONFIG}->{$toplevel}})) {
	    inherit_config($self->{CONFIG}->{$toplevel}, $entry);
        }
    }
    1;
}



# get entire configuration or a single value
# arg: configuration variable to get
#      undef: get whole configuration tree
#      string: get configuration entry (does not return subtrees)
# mangle: postprocess returned text, values:
#      'FILE': apply File::Spec->canonpath
#      'LC':   return config entry lower case
#      'UC':   return config entry upper case
#      'UCFIRST': return config entry ucfirst
sub get
{
    my $self = shift;
    my $arg = shift;
    my $mangle = shift;
    
     if (! defined $arg)
     {
		return $self->{CONFIG};
     } 
     else
     {
		my $value = get_ref($self, $arg);
	 
		return $value unless defined $mangle;

		$value = "" if !defined $value;

		if ($value ne '') {
			# mangle only if value is not "", otherwise File::Spec converts "" into "\", which doesn't make much sense ...
			return File::Spec->catfile(File::Spec->canonpath($value)) if ($mangle eq "FILE");
			return uc($value) if ($mangle eq "UC");
			return lc($value) if ($mangle eq "LC");
			return ucfirst($value) if ($mangle eq "UCFIRST");
			return; # don't know how to handle this mangle option
		}
     }
	 
	 return;
}


# set configuration value
# arg1: configuration variable to set
# arg2: value to set
sub set
{
    my $self = shift;
    my $var = shift;
    my $value = shift;
    
    return if (! defined $var);
    my $ref = get_ref($self, $var, 'ref');

    $$ref = $value;
    1;
}



1;
