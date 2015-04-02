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

package CertNanny::Config;

use base qw(Exporter);

use IO::File;
use File::Basename;
use File::Glob qw(:globally :case);
use Net::Domain;

use Data::Dumper;
use Carp;

use CertNanny::Util;
use CertNanny::Logging;

use strict;

our @EXPORT    = qw(getConfigFilename getRef get set getFlagRef getFlag setFlag pushConf popConf);
our @EXPORT_OK = ();
use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);
use Exporter;

#@EXPORT      = qw(...);       # Symbols to autoexport (:DEFAULT tag)

my $INSTANCE;
my @INSTANCESTACK;
my $INSTANCESTACKIDX;


sub getInstance {
  $INSTANCE ||= (shift)->new(@_);
}


sub new {
  if (!defined $INSTANCE) {
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my %args = (@_);    # argument pair list

    my $self = {};
    bless $self, $class;
    $INSTANCE = $self;
    $INSTANCESTACKIDX = -1;

    $self->{CONFIGFILE} = $args{config};
    $self->{CONFIGPATH} = (fileparse($self->{CONFIGFILE}))[1];

    CertNanny::Logging->info('MSG', "CertNanny started with configfile <$self->{CONFIGFILE}>");

    $self->_parse() || return undef;
  }
  return $INSTANCE;
} ## end sub new


sub DESTROY {
  $INSTANCE = undef;
}


sub getConfigFilename {
  # get configuration file name
  my $self = (shift)->getInstance();
  $self->{CONFIGFILE};
}


sub _getRef {
  # get nested configuration/flag entry
  # arg1: variable name "xx.yy.zz"
  # arg2: optional options:
  # arg3: CONFIG | CFGFLAG
  #   undef: return variable value
  #   'ref': return reference to variable
  my $self   = (shift)->getInstance();
  my $var    = shift;
  my $option = shift;
  my $where  = shift;

  my @var = split(/\./, $var);    # internal variable path

  my $target = $self->{$where};
  my $tmp    = pop @var;
  foreach (@var) {
    if (!exists $target->{$_}) {
      $target = undef;
      last;
    }
    $target = $target->{$_};
  }
  if (defined $option and $option eq 'ref') {
    if (!defined $target) {
      $target = $self->{$where};
      foreach (@var) {
        $target->{$_} = {} unless exists $target->{$_};
        $target       = $target->{$_};
      }
    }
    $target->{$tmp} = undef unless exists $target->{$tmp};
    $target = \$target->{$tmp};
    return $target;
  } else {
    # get value
    if ($where eq 'CFGFLAG') {
      if (defined $target) {
        if (exists $target->{$tmp}) {
          $target = (ref($target->{$tmp}) eq "HASH") ? $target->{$tmp} : 1;
        } else {
          $target = undef;
        }  
      }
      $target = 1               if (defined $target and (ref($target) ne "HASH"))
    } else {
      $target = $target->{$tmp} if exists $target->{$tmp};
      $target = undef           if (!defined $target or (ref($target) eq "HASH"));
    }
    return $target;
  }
} ## end sub _getRef


sub getRef {
  # get nested configuration entry
  # arg1: variable name "xx.yy.zz"
  # arg2: optional options:
  #   undef: return variable value
  #   'ref': return reference to variable
  my $self   = (shift)->getInstance();
  my $var    = shift;
  my $option = shift;
  
  return $self->_getRef($var, $option, 'CONFIG');
} ## end sub getRef


sub getFlagRef {
  # get nested flag entry
  # arg1: variable name "xx.yy.zz"
  # arg2: optional options:
  #   undef: return variable value
  #   'ref': return reference to variable
  my $self   = (shift)->getInstance();
  my $var    = shift;
  my $option = shift;
  
  return $self->_getRef($var, $option, 'CFGFLAG');
} ## end sub getFlagRef


sub _get {
  # get entire configuration/flag or a single value
  # arg1: configuration/flag variable to get
  #       undef: get whole configuration/flag tree
  #       string: get configuration/flag entry (does not return subtrees)
  # arg2: mangle: postprocess returned text, values:
  #               'FILE': apply File::Spec->canonpath
  #               'LC':   return config entry lower case
  #               'UC':   return config entry upper case
  #               'UCFIRST': return config entry ucfirst
  # arg3: CONFIG | CFGFLAG
  my $self   = (shift)->getInstance();
  my $arg    = shift;
  my $mangle = shift;
  my $where  = shift;

  if (!defined $arg) {
    return $self->{$where};
  } else {
    my $value = $self->_getRef($arg, '', $where);
    
    if ($value =~ m{ \A \s* sub \s* \{ }xms) {
      eval {
        $value = eval $value;
        $value = &$value();
      };
    } elsif ($value =~ m{ \A \s* `(.*)` \s* \z }xms) {
      $value = `$1`;
      chomp $value;
    } elsif ($value =~ m{__SYS_FQDN__}xms) {
      my $hostname = Net::Domain::hostfqdn();
      while ($value =~ m{__SYS_FQDN__}xms) {
       $value =~ s{__SYS_FQDN__}{$hostname}xms;
      }
     
    }

    return $value unless defined $mangle and ($where eq 'CONFIG');

    $value = "" if !defined $value;

    if ($value ne '') {
      # mangle only if value is not "", otherwise File::Spec converts "" into "\", which doesn't make much sense ...
      return File::Spec->catfile(File::Spec->canonpath($value)) if ($mangle eq "FILE");
      return uc($value)                                         if ($mangle eq "UC");
      return lc($value)                                         if ($mangle eq "LC");
      return ucfirst($value)                                    if ($mangle eq "UCFIRST");
      return undef                                              if ($mangle eq "CMD" && !-x $value);
      return $value;    # don't know how to handle this mangle option
    } ## end if ($value ne '')
  } ## end else [ if (!defined $arg) ]

  return undef;
} ## end sub _get


sub get {
  # get entire configuration or a single value
  # arg: configuration variable to get
  #      undef: get whole configuration tree
  #      string: get configuration entry (does not return subtrees)
  # mangle: postprocess returned text, values:
  #      'FILE': apply File::Spec->canonpath
  #      'LC':   return config entry lower case
  #      'UC':   return config entry upper case
  #      'UCFIRST': return config entry ucfirst
  my $self   = (shift)->getInstance();
  my $arg    = shift;
  my $mangle = shift;
  
  return $self->_get($arg, $mangle, 'CONFIG');
} ## end sub get


sub getFlag {
  # get entire flag or a single value
  # arg: configuration variable to get
  #      undef: get whole configuration tree
  #      string: get configuration entry (does not return subtrees)
  # mangle: postprocess returned text, values:
  #      'FILE': apply File::Spec->canonpath
  #      'LC':   return config entry lower case
  #      'UC':   return config entry upper case
  #      'UCFIRST': return config entry ucfirst
  my $self   = (shift)->getInstance();
  my $arg    = shift;
  
  return $self->_get($arg, undef, 'CFGFLAG');
} ## end sub getFlag


sub _set {
  # set configuration/flag value
  # arg1: configuration variable to set
  # arg2: value to set
  # arg3: CONFIG | CFGFLAG
  my $self   = (shift)->getInstance();
  my $var   = shift;
  my $value = shift;
  my $where = shift;

  return undef if (!defined $var);
  my $ref = $self->_getRef($var, 'ref', $where);

  if (!$value && $where eq 'CFGFLAG') {
    delete($$ref->{$var});
  } else {
    $$ref = $value;
  }
  1;
} ## end sub _set


sub set {
  # set configuration value
  # arg1: configuration variable to set
  # arg2: value to set
  my $self   = (shift)->getInstance();
  my $var   = shift;
  my $value = shift;
  
  return $self->_set($var, $value, 'CONFIG');
} ## end sub set


sub setFlag {
  # set flag
  # arg1: configuration variable to set
  # arg2: 1: set (default) 0: unset
  my $self   = (shift)->getInstance();
  my $var   = shift;
  my $value = shift || 1;

  return $self->_set($var, $value, 'CFGFLAG');
} ## end sub setFlag


#sub pushConf {
#  # pushes the current config beside
#  # Any modifications will be lost when the next popConf is done
#  my $self   = (shift)->getInstance();
#  
#  my $newConf = Storable::dclone($self);
#  # push(@INSTANCESTACK, $newConf);
#  # Don't ask me why: pop kills $INSTANCE. Therefor I do it by foot
#  $INSTANCESTACKIDX++;
#  $INSTANCESTACK[$INSTANCESTACKIDX] = $newConf;
#
#  return 0;
#} ## end sub pushConf


#sub popConf {
#
#  sub _deepPop {
#    # recursively deep-copy a hash tree, overwriting already existing
#    # values in destination tree
#    my $source = shift;
#    my $dest   = shift;
#
#    # delete all existing keys in dest that are not hashes
#    foreach my $key (keys %{$dest}) {
#      if (ref($dest->{$key}) ne "HASH") {
#        delete($dest->{$key});
#      }
#    }
#  
#    foreach my $key (keys %{$source}) {
#      if (ref($source->{$key}) eq "HASH") {
#        # create new node if it does not exist yet
#        $dest->{$key} = {} unless exists $dest->{$key};
#        _deepPop($source->{$key}, $dest->{$key});
#      } else {
#        # use default/parent value
#        $dest->{$key} = $source->{$key};
#      }
#    } ## end foreach my $key (keys %{$source...})
#    return 1;
#  } ## end sub _deepPop
#
#  # pop the formerly pushed config back
#  # Any modifications that have been done since the last pushConf are lost
#  my $self = (shift)->getInstance();
#
#  my $rc = undef;  # Error
#  
#  # my $oldConf = pop(@INSTANCESTACK);
#  # Don't ask me why: pop kills $INSTANCE. Therefor I do it by foot
#  if ($INSTANCESTACKIDX >= 0) {
#    my $oldConf = $INSTANCESTACK[$INSTANCESTACKIDX];
#    if ($oldConf) {
#      _deepPop($oldConf, $INSTANCE);
#      $rc = $INSTANCE;  # No error
#    }
#    $INSTANCESTACKIDX--;
#  }
#
#  return $rc
#} ## end sub popConf


sub _deepCopy {
  # recursively deep-copy a hash tree, NOT overwriting already existing
  # values in destination tree
  my $self   = (shift)->getInstance();
  my $source = shift;
  my $dest   = shift;

  foreach my $key (keys %{$source}) {
    if (ref($source->{$key}) eq "HASH") {

      # create new node if it does not exist yet
      $dest->{$key} = {} unless exists $dest->{$key};
      $self->_deepCopy($source->{$key}, $dest->{$key});
    } else {
      if (!exists $dest->{$key}) {

        # use default/parent value
        $dest->{$key} = $source->{$key};
      }

      # else keep existing (configured) value
    }
  } ## end foreach my $key (keys %{$source...})

  1;
} ## end sub _deepCopy


sub _deepForceCopy {
  # recursively deep-copy a hash tree, NOT overwriting already existing
  # values in destination tree
  my $self   = (shift)->getInstance();
  my $source = shift;
  my $dest   = shift;

  foreach my $key (keys %{$source}) {
    if (ref($source->{$key}) eq "HASH") {
      # create new node if it does not exist yet
      $dest->{$key} = {} unless exists $dest->{$key};
      $self->_deepCopy($source->{$key}, $dest->{$key});
    } else {
        $dest->{$key} = $source->{$key};
    }
  } ## end foreach my $key (keys %{$source...})

  1;
} ## end sub _deepForceCopy


sub _inheritConfig {
  # recursively determine CA inheritance settings
  my $self      = (shift)->getInstance();
  my $caconfref = shift;
  my $subca     = shift;

  # postprocess sub-ca settings (configuration inheritance)
  if (defined $caconfref->{$subca}->{INHERIT}) {

    # inherit settings from parent config
    my $parent = $caconfref->{$subca}->{INHERIT};

    # make sure the parent already inherited its values from its own
    # parent
    $self->_inheritConfig($caconfref, $parent);

    # copy subtree
    $self->_deepCopy($caconfref->{$parent}, $caconfref->{$subca});
  } ## end if (defined $caconfref...)
} ## end sub _inheritConfig


sub _parse {
  my $self = (shift)->getInstance();

  my $rc = 1;
  # $self->{LOGBUFFER} = \my @dummy;
  $self->_parseFile();

  #  - replace all found variables
  foreach (keys %{$self->{CONFIG}}) {
    _replaceVariables($self, $self->{CONFIG}, $_);
  }

  my $openssl = $self->get('cmd.openssl', 'CMD');
  if (defined $openssl && -e $openssl) {
    # All the parsing is done, now check for double parsing
    if (exists($self->{CONFIGFILES})) {
      foreach (keys %{$self->{CONFIGFILES}}) {
        $self->{CONFIGFILES}{$_}{SHA} = $self->_sha1_hex($_);
      }
      foreach my $filename1 (keys %{$self->{CONFIGFILES}}) {
        foreach my $filename2 (keys %{$self->{CONFIGFILES}}) {
          if (($filename1 ne $filename2) && ($self->{CONFIGFILES}{$filename1}{SHA} eq $self->{CONFIGFILES}{$filename2}{SHA})) {
            CertNanny::Logging->error('MSG', "double configfile: <$filename1> SHA1: $self->{CONFIGFILES}{$filename1}{SHA} <> $filename2 SHA1: $self->{CONFIGFILES}{$filename2}{SHA}");
          }
        }
        CertNanny::Logging->info('MSG', "<$filename1> SHA1: $self->{CONFIGFILES}{$filename1}{SHA}");
      }
    } ## end else [ if (exists($self->{CONFIGFILES...}))]

    # postprocess sub-ca settings (configuration inheritance)
    foreach my $entry (keys(%{$self->{CONFIG}->{keystore}})) {
      $self->_inheritConfig($self->{CONFIG}->{keystore}, $entry);
    }
  } else {
    $rc = "No valid openssl shell specified";
    CertNanny::Logging->error('MSG', $rc);
    CertNanny::Logging->Err('STR', "Configuration File Error: " . $rc . "\n");
    $rc = undef;
  }
  
  return $rc;
} ## end sub _parse


sub _sha1_hex {
  my $self = (shift)->getInstance();
  my $file = shift;
  
  return $self->{CONFIGFILES}{$file}{SHA} if ($self->{CONFIGFILES}{$file}{SHA});
  
  my $sha;
  my $openssl = $self->get('cmd.openssl', 'CMD');
  if (defined($openssl)) {
    my @cmd = (CertNanny::Util->osq($openssl), 'dgst', '-sha', CertNanny::Util->osq($file));
    chomp($sha = shift(@{CertNanny::Util->runCommand(\@cmd)->{STDOUT}}));
    if ($sha =~ /^.*\)= (.*)$/) {
      $sha = $1;
    }
  }
  return $sha;
}


sub _parseFile {
  my $self         = (shift)->getInstance();
  my $configPath   = shift || $self->{CONFIGPATH};
  my $configFile   = shift || $self->{CONFIGFILE};
  my $configPrefix = shift;
  
  my $rc = undef;
  
  # Parsing is done in the following steps
  #  - initialize datastructures (only done once)
  #  - read all lines
  #  - evaluate all lines
  #  - replace all found variables
  #  - recursive execute _parsfile for all includes
  
  #  - initialize datastructures (only done once)
  my $handle = new IO::File "<" . $configFile;
  if (!defined $handle) {
    $configFile = $configPath . $configFile;
    $handle     = new IO::File "<" . $configFile;
  }
  if (!defined $handle) {
    CertNanny::Logging->error('STR', "Config file <$configFile> ERROR: Could not read file!\n");
  } else {
    # Initialize Hash
    if (!exists($self->{CONFIGFILES})) {
      $self->{CONFIGFILES} = \my %dummy;
      $self->{CFGMTIME} = (stat($configFile))[9];

      # set implicit defaults
      $self->{CONFIG}  = {keystore => {DEFAULT => {autorenew_days   => 30,
                                                   warnexpiry_days  => 20,
                                                   type             => 'none',
                                                   scepsignaturekey => 'new',},},};
      $self->{CFGFLAG} = {};
    } ## end if (!exists($self->{CONFIGFILES...}))

    CertNanny::Logging->debug('MSG', "Config file <$configFile> INFO: Reading");

    #  - read all lines
    seek $handle,0,0;
    my $lnr = 0;
    my $line; 
    my %lines;
    while (chomp($line = <$handle>)) {
      $lnr++;
      $line =~ s/^\s+|\s+$|\r\n//g; # Remove leading Blanks, trailing Blanks, Windows EOL
      $line =~ s/^#.*//g;           # comment lines
      $lines{$lnr} = $line if $line;
    }
    $handle->close();
  
    #  - evaluate all lines
    my %keystore;
    my @prefix = split(/\./, $configPrefix);
    while (($lnr, $line) = each(%lines)) {
      if ($line =~ /^(.+?)\s*=\s*(\S.*?)\s*(\s#\s.*)?$/ || /^(\S.*?)\s*=?\s*(\s#\s.*)?$/) {
        my @path = split(/\./, $1);
        for (my $i=0; $i<=$#prefix; $i++) {
          if ($prefix[$i] ne $path[$i]) {
            @path = (@prefix, @path); 
            last;
          }
        }
        $keystore{$path[1]} = 1 if (lc($path[0]) eq 'keystore');
        my ($val, $var);
        if (defined($2) && $2 !~ /^\s*#\s.*$/) {
          $val = $2;
          $var = $self->{CONFIG};
        } else {
          $var = $self->{CFGFLAG};
        }
        my $key  = pop(@path);

        my $doDupCheck;
        foreach my $confPart (@path) {
          $doDupCheck = ("$confPart" ne "DEFAULT");
          # if ("$confPart" eq "DEFAULT") {
          #   $doDupCheck = 0;
          # } else {
          #   $doDupCheck = 1;
          #   $confPart = lc($confPart);
          # }
          if (!exists $var->{$confPart}) {
            $var->{$confPart} = {};
            $var->{$confPart}->{INHERIT} = "DEFAULT";
          }
          $var = $var->{$confPart};
        }
        if ($doDupCheck && defined($var->{$key})) {
          CertNanny::Logging->error('STR', "Config file <$configFile> ERROR: Duplicate value definition in line $lnr ($line)\n");
        }
      
        while ($val =~ m{__ENV__(.*?)__}xms) {
          my $envvar = $1;
          if (! exists $ENV{$envvar}) {
            CertNanny::Logging->info('MSG', "Config file <$configFile> WARNING: Environment variable $envvar referenced in line $lnr does not exist");
          }
          my $myENVvar = $ENV{$envvar} || '';
          $val =~ s{__ENV_(.*?)__}{$myENVvar}xms;
        }

        $var->{$key} = $val;
      } else {
        if ($line !~ /^(include|keystores)\s+(.+)$/) {
          CertNanny::Logging->error('STR', "Config file <$configFile> ERROR: Parse error in line $lnr ($line)\n");
        }
      }
    }

    #  - replace all found variables
    while (($lnr, $line) = each(%lines)) {
      _replaceVariables($self, \%lines, $lnr);
    }

    #  - store content for operation 'status'
    $self->{CONFIGFILES}{$configFile}{CONTENT} = \%lines;

    #  - store keystores, that are defined by this configfile
    my @dummy;
    foreach (keys(%keystore)) {push (@dummy, $_)}
    $self->{CONFIGFILES}{$configFile}{KEYSTORE} = \@dummy;

    #  - recursive execute _parsefile for all includes
    while (($lnr, $line) = each(%lines)) {
      if ($line =~ /^\s*(include|keystores)[\s=]+(.+)\s*$/) {
        my $includeType = $1;
        my @includeList = split(' ', $2);
        foreach my $item (@includeList) {
          my $prefix;
          my $configFileGlob;
          my @configFileList;
          if ($includeType eq 'keystores') {
            $configFileGlob = 'Keystore-'.$item.'.cfg';
            $prefix         = 'keystore.' . $item;
          } else {
            $configFileGlob = $item;
          }

          # Test if $configFileGlob contains regular files
          @configFileList = @{CertNanny::Util->fetchFileList($configFileGlob)};
   
          if (!@configFileList) {
            $configFileGlob = $configPath . $configFileGlob;
            @configFileList = @{CertNanny::Util->fetchFileList($configFileGlob)};
          }
          foreach my $file (@configFileList) {
            $self->_parseFile((fileparse($file))[1], $file, $prefix);
          }
        }
      }
    }
    $rc = 1;
  };
  
  return $rc;
  } ## end sub _parseFile


sub _replaceVariables {
  # replace internal variables
  my $self   = (shift)->getInstance();
  my $cfgref = shift;
  my $key    = shift;

  # determine if this entry is a string or a hash array
  if (ref($cfgref->{$key}) eq "HASH") {
    foreach (keys %{$cfgref->{$key}}) {
      _replaceVariables($self, $cfgref->{$key}, $_);
    }
  } else {
    # actually replace variables
    while ($cfgref->{$key} =~ /\$\((.*?)\)/) {
      my $var    = $1;
      # my $lcvar  = lc($var);
      # my $target = getRef($self, $lcvar);
      my $target = getRef($self, $var);
      $target     = "" unless defined $target;

      $var            =~ s/\./\\\./g;
      $cfgref->{$key} =~ s/\$\($var\)/$target/g;
    }
  } ## end else [ if (ref($cfgref->{$key}...)]
  
  return $cfgref->{$key};
} ## end sub _replaceVariables

1;
