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
use File::Basename;
use File::Glob qw(:globally :case);
use Net::Domain;

use Data::Dumper;

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

    $self->{CONFIGFILE} = $args{CONFIG} || 'certnanny.cfg';
    $self->{CONFIGPATH} = (fileparse($self->{CONFIGFILE}))[1];

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

  # replace internal variables
  foreach (keys %{$self->{CONFIG}}) {
    _replaceVariables($self, $self->{CONFIG}, $_);
  }

  # postprocess sub-ca settings (configuration inheritance)
  foreach my $toplevel (qw(certmonitor keystore)) {
    foreach my $entry (keys(%{$self->{CONFIG}->{$toplevel}})) {
      $self->_inheritConfig($self->{CONFIG}->{$toplevel}, $entry);
    }
  }
  
  my $openssl = $self->get('cmd.openssl', 'FILE');
  if (!defined $openssl) {
    CertNanny::Logging->error("No openssl shell specified");
    $rc = undef;
  }
  
  if ($rc) {
    foreach (keys %{$self->{CONFIGFILES}}) {
      CertNanny::Logging->info("$_ SHA1: $self->{CONFIGFILES}{$_}");
    }
  }

  return $rc;
} ## end sub _parse


sub _sha1_hex {
  my $self = (shift)->getInstance();
  my $file = shift;
  
  return $self->{CONFIGFILES}{$file} if ($self->{CONFIGFILES}{$file});
  
  my $sha;
  my $openssl = $self->get('cmd.openssl', 'FILE');
  if (defined($openssl)) {
    my @cmd = (qq("$openssl"), 'dgst', '-sha', qq("$file"));
    chomp($sha = CertNanny::Util->runCommand(\@cmd, WANTOUT => 1));
    if ($sha =~ /^.*\)= (.*)$/) {
      $sha = $1;
    }
  }
  return $sha;
}


sub _parseFile {
  my $self       = (shift)->getInstance();
  my $configPath = shift || $self->{CONFIGPATH};
  my $configFile = shift || $self->{CONFIGFILE};

  my $handle = new IO::File "<" . $configFile;

  if (!defined $handle) {
    $configFile = $configPath . $configFile;
    $handle     = new IO::File "<" . $configFile;
  }

  return undef if (!defined $handle);

  my ($configFileSha, $openssl);

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

    # backward compatibility
    $self->{CONFIG}->{certmonitor} = $self->{CONFIG}->{keystore};
  } ## end if (!exists($self->{CONFIGFILES...}))

  CertNanny::Logging->debug("reading $configFile");

  # avoid double parsing
  $configFileSha = $self->_sha1_hex($configFile);
  if (exists($self->{CONFIGFILES})) {
    foreach (keys(%{$self->{CONFIGFILES}})) {
      if ($configFile eq $_ || ($configFileSha && ($configFileSha eq $self->{CONFIGFILES}{$_}))) {
        CertNanny::Logging->error("double configfile: $configFile SHA1: $configFileSha <> $_ SHA1: $self->{CONFIGFILES}{$_}");
        return undef;
      }
    }
  } ## end else [ if (exists($self->{CONFIGFILES...}))]
  $self->{CONFIGFILES}{$configFile} = $configFileSha;

  my $lnr = 0;
  seek $handle,0,0;
  while (<$handle>) {
    chomp;
    $lnr++;
    tr/\r\n//d;
    next if (/^\s*\#|^\s*$/);

    if (/^\s*include\s+(.+)\s*$/) {
      my $configFileGlob = $1;
      my @configFileList;

      # Test if $configFileGlob contains regular files
      @configFileList = @{CertNanny::Util->fetchFileList($configFileGlob)};
   
      if (!@configFileList) {
        $configFileGlob = $configPath . $configFileGlob;
        @configFileList = @{CertNanny::Util->fetchFileList($configFileGlob)};
      }
      foreach (@configFileList) {
        # in case we did not define openssl up to now
        $self->{CONFIGFILES}{$configFile} = $self->_sha1_hex($configFile);
        $self->_parseFile((fileparse($_))[1], $_);
      }
    } elsif (/^\s*(.+?)\s*=\s*(\S.*?)\s*(\s#\s.*)?$/ || /^\s*(\S.*?)\s*=?\s*(\s#\s.*)?$/) {
      my @path = split(/\./, $1);
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
        print STDERR "Config file error: duplicate value definition in line $lnr ($_)\n";
      }
      
      while ($val =~ m{__ENV__(.*?)__}xms) {
        my $envvar = $1;
        if (! exists $ENV{$envvar}) {
          CertNanny::Logging->info("Environment variable $envvar referenced in line $lnr does not exist");
        }
        my $myENVvar = $ENV{$envvar} || '';
        $val =~ s{__ENV_(.*?)__}{$myENVvar}xms;
      }

      $var->{$key} = $val;
    } else {
      print STDERR "Config file error: parse error in line $lnr ($_)\n";
    }
  } ## end while (<$handle>)
  $handle->close();
  
  # in case we did not defien openssl up to now
  $self->{CONFIGFILES}{$configFile} = $self->_sha1_hex($configFile);

  1;
} ## end sub _parseFile


sub _replaceVariables {
  # replace internal variables
  my $self      = (shift)->getInstance();
  my $configref = shift;
  my $thiskey   = shift;

  # determine if this entry is a string or a hash array
  if (ref($configref->{$thiskey}) eq "HASH") {
    foreach (keys %{$configref->{$thiskey}}) {
      _replaceVariables($self, $configref->{$thiskey}, $_);
    }
  } else {

    # actually replace variables
    while ($configref->{$thiskey} =~ /\$\((.*?)\)/) {
      my $var    = $1;
      # my $lcvar  = lc($var);
      # my $target = getRef($self, $lcvar);
      my $target = getRef($self, $var);
      $target     = "" unless defined $target;

      $var =~ s/\./\\\./g;
      $configref->{$thiskey} =~ s/\$\($var\)/$target/g;
    }
  } ## end else [ if (ref($configref->{$thiskey...}))]
} ## end sub _replaceVariables

1;
