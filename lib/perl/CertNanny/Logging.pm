#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2011-04 Stefan Kraus <stefan.kraus05@gmail.com>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny::Logging;

#use base qw(Exporter);

use Data::Dumper;
use FindBin qw($Script);
use Carp;

use File::Basename;

use strict;
use warnings;
use English;
use utf8;

use CertNanny::Util;

use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);

@EXPORT = qw(printerr printout 
             logLevel
             switchLogging
             switchFileOut switchConsoleOut switchSysLogOut outOff
             switchFileErr switchConsoleErr switchSysLogErr errOff
             log debug info notice error fatal);    # Symbols to autoexport (:DEFAULT tag)

my $INSTANCE;

my ($stdOutFake, $stdErrFake, @outBuffer, @errBuffer);
my %logTarget;
my %logTargetOpen;
my $dbgInfo;
my $bufferOut;

BEGIN {
  open($stdOutFake, ">&", STDOUT);
  open($stdErrFake, ">&", STDERR);
  $dbgInfo = 1;
  $bufferOut = 1;
}


sub getInstance {
  $INSTANCE ||= (shift)->new(@_);

  # If Configuration is not present, we are still in initialisation phase
  if (!defined($INSTANCE->{CONFIG})) {
    shift;
    my %args = (@_);
    $INSTANCE->{CONFIG} = $args{CONFIG};
    if (defined $INSTANCE->{CONFIG}) {
      # only instantiate if $self->{CONFIG} exists.
      # otherwise initalisation phase is not yet finished
      # and we determine the loglevel

      # Determining Debug Level
      # Downward compatibility
      if (!defined($args{CONFIG}->get('log.out.file')))      {$args{CONFIG}->set('log.out.file',      $args{CONFIG}->get('logfile'))}
      if (!defined($args{CONFIG}->get('log.err.file')))      {$args{CONFIG}->set('log.err.file',      $args{CONFIG}->get('logfile'))}
      
      foreach my $target ('console', 'file', 'syslog') {
        # Downward compatibility
        if (!defined($args{CONFIG}->get('log.level.'.$target))) {$args{CONFIG}->set('log.level.'.$target, $args{CONFIG}->get('loglevel'))}

        # Debug Level is determined in 5 Steps (highest Prio wins)
        # Prio 0: Default : 3
        my $logLevel = 3;
        # Prio 1: If a config file value is given, take this
        if (defined($args{CONFIG}->get('log.level.'.$target))) {$logLevel = $args{CONFIG}->get('log.level.'.$target)}
        if (defined($args{debug})) {
          my $debug = lc($args{debug});
          if ($debug eq '') {
            # Prio 2: If a commandline parameter debug is given without value, take 4
            $logLevel = 4
          } else {
            # Prio 3: If a commandline parameter debug is given with value, take the value of debug
            # Commandline format:
            #   Option 1: # : Take the given Level for console, file and syslog
            if ($debug =~/^\d$/) {
              $logLevel = $args{debug}
            }
            if ($debug =~/^([cfs]\d){1,3}$/) {
              my %debugLevel = split(//, $debug);
              $logLevel = $debugLevel{substr($target, 0, 1)} if defined($debugLevel{substr($target, 0, 1)});
            }
          }
        }
        # Prio 4: If a commandline parameter verbose is given, take 6
        if (defined($args{verbose})) {$logLevel = 6} 

        # set Loglevel
        $INSTANCE->logLevel('TARGET', $target, 'LEVEL', $logLevel);
      }

      # Determine Logtargets
      $INSTANCE->switchFileOut   ('STATUS', defined($args{CONFIG}->get('log.out.file')) && ($args{CONFIG}->get('log.out.file') ne ''));
      $INSTANCE->switchConsoleOut('STATUS', $args{CONFIG}->get('log.out.console'));
      $INSTANCE->switchSysLogOut ('STATUS', defined($args{CONFIG}->get('log.out.syslog')) && ($args{CONFIG}->get('log.out.syslog') ne ''));
      # Determine Errtargets
      $INSTANCE->switchFileErr   ('STATUS', defined($args{CONFIG}->get('log.err.file')) && ($args{CONFIG}->get('log.err.file') ne ''));
      $INSTANCE->switchConsoleErr('STATUS', $args{CONFIG}->get('log.err.console'));
      $INSTANCE->switchSysLogErr ('STATUS', defined($args{CONFIG}->get('log.err.syslog')) && ($args{CONFIG}->get('log.err.syslog') ne ''));
      if (defined($args{verbose})) {
        $INSTANCE->switchConsoleOut('STATUS', 1);
        $INSTANCE->switchConsoleErr('STATUS', 1);
      }
      # Now we now, what to do with Logs and it's no more buffering needed
      $bufferOut = 0;

      # Determining Debug Details
      # 0: level, PID, text                         i.E.: 2013-09-13 15:58:26 : [info] [788] reading H:\data\Config\CertNanny\CfgFiles\Keystore\uat-certnanny-test Keystore openssl.cfg SHA1: BeCBVMvnNzl8HZU5tF4vzR4uIog
      # 1: last detail w/o getInstance and Logging  i.E.: 2013-09-13 15:58:26 : [info] [788] [CertNanny::Config::_parseFile(406)] reading H:\data\Config\CertNanny\CfgFiles\Keystore\uat-certnanny-test Keystore openssl.cfg SHA1: BeCBVMvnNzl8HZU5tF4vzR4uIog
      # 2: full details w/o getInstance and Logging i.E.: 2013-09-13 15:58:26 : [info] [788] [CertNanny::Config::Config::new(83)->CertNanny::Config::_parse(343)->CertNanny::Config::_parseFile(428)->CertNanny::Config::_parseFile(406)] reading H:\data\Config\CertNanny\CfgFiles\Keystore\uat-certnanny-test Keystore openssl.cfg SHA1: BeCBVMvnNzl8HZU5tF4vzR4uIog
      # 3: full details                             i.E.: 2013-09-13 15:58:26 : [info] [788] [CertNanny::Config::getInstance(65)->CertNanny::Config::new(83)->CertNanny::Config::_parse(343)->CertNanny::Config::_parseFile(428)->CertNanny::Config::_parseFile(406)->CertNanny::Logging::info(224)->CertNanny::Logging::log(168)] reading H:\data\Config\CertNanny\CfgFiles\Keystore\uat-certnanny-test Keystore openssl.cfg SHA1: BeCBVMvnNzl8HZU5tF4vzR4uIog
      $dbgInfo = 1;
      if (defined($args{CONFIG}->get('log.detail')))    {$dbgInfo = $args{CONFIG}->get('log.detail')}
    }
  }
  return $INSTANCE;
}


sub new {
  if (!defined $INSTANCE) {
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my %args = (@_);    # argument pair list

    my $self = {};
    bless $self, $class;
    $INSTANCE = $self;
    $self->setVariable('NAME',  'KEYSTORE', 
                       'VALUE', 'Common');
  }
  return $INSTANCE;
} ## end sub new


sub DESTROY {
  my $self = shift;

  $self->printerr();
  $self->printout();
  return undef unless (exists $self->{TMPFILE});
  foreach my $file (@{$self->{TMPFILE}}) {
    unlink $file;
  }
  close STDOUT;
  close STDERR;
}


sub _print {
  my $self = (shift)->getInstance();
  my %args = (@_);

  my $target    = $args{TARGET};
  my $str       = $args{STR};
  my $dbg       = 0;
  my $buffer;
  
  my $myFile     = defined($self->{CONFIG}) ? CertNanny::Util->expandStr($self->{CONFIG}->get('log.'.lc($target).'.file', "FILE"), %args)     :  undef;
  my $myLastFile = defined($self->{CONFIG}) ? CertNanny::Util->expandStr($self->{CONFIG}->get('log.'.lc($target).'.filelast', "FILE"), %args) :  undef;

  my $fileTarget     = $logTarget{$target.'file'} && defined($myFile) && ($myFile ne '');
  my $lastFileTarget = $logTarget{$target.'file'} && defined($myLastFile) && ($myLastFile ne '');
  my $consoleTarget  = $logTarget{$target.'console'};
  my $sysLogTarget   = $logTarget{$target.'syslog'};
  
  if ($target eq 'out') {
    my $prio = lc($args{PRIO} || "info");
    my %level = ('debug'  => 4,
                 'info'   => 3,
                 'notice' => 2,
                 'error'  => 1,
                 'fatal'  => 0);
    $buffer     = \@outBuffer;

    if (exists $level{$prio}) {
      $dbg = $level{$prio};
    } else {
      push @$buffer, "${dbg}:WARNING: log called with undefined priority '$prio'" unless exists $level{$prio};
    }
  }

  if ($target eq 'err') {
    $buffer     = \@errBuffer;
  }
  
  push(@$buffer, "${dbg}:${str}");
  
  if (!$bufferOut) {
    while (@$buffer) {
      $str = shift(@$buffer);
      if ($str =~ /^([^:]):(.*)$/s) {
        $dbg = $1;
        $str = $2;
      }
      # Log to file
      if ($fileTarget && ($target eq 'err') && ($dbg <= $self->logLevel('TARGET', 'file'))) {
        $| = 1;
        open STDERR, ">>", $myFile || die "Could not redirect STDERR to <$myFile>. Stopped";
        print STDERR $str;
        close STDERR;
      }
      if ($fileTarget && ($target eq 'out') && ($dbg <= $self->logLevel('TARGET', 'file'))) {
        open STDOUT, ">>", $myFile || die "Could not redirect STDOUT to <$myFile>. Stopped";
        print STDOUT $str;
        close STDOUT;
      }
      
      #Log to LastFile
      if ($lastFileTarget && ($target eq 'err') && ($dbg <= $self->logLevel('TARGET', 'file'))) {
        $| = 1;
        if (!$logTargetOpen{$myLastFile}) {
          open STDERR, ">", $myLastFile || die "Could not redirect STDERR to <$myLastFile>. Stopped";
          $logTargetOpen{$myLastFile} = 1;
        } else {
          open STDERR, ">>", $myLastFile || die "Could not redirect STDERR to <$myLastFile>. Stopped";
        }
        print STDERR $str;
        close STDERR;
      }
      if ($lastFileTarget && ($target eq 'out') && ($dbg <= $self->logLevel('TARGET', 'file'))) {
        $| = 1;
        if (!$logTargetOpen{$myLastFile}) {
          open STDOUT, ">", $myLastFile || die "Could not redirect STDOUT. Stopped";
          $logTargetOpen{$myLastFile} = 1;
        } else {
          open STDOUT, ">>", $myLastFile || die "Could not redirect STDOUT. Stopped";
        }
        print STDOUT $str;
        close STDOUT;
      }
      
      # Log to console
      if ($consoleTarget && ($target eq 'err') && ($dbg <= $self->logLevel('TARGET', 'console'))) {
        $| = 1;
        open STDERR, ">&", $stdErrFake;
        print STDERR $str;
        close STDERR;
      }
      if ($consoleTarget && ($target eq 'out') && ($dbg <= $self->logLevel('TARGET', 'console'))) {
        $| = 1;
        open STDOUT, ">&", $stdOutFake;
        print STDOUT $str;
        close STDOUT;
      }
      
      # Log to syslog
      if ($sysLogTarget && ($target eq 'err') && ($dbg <= $self->logLevel('TARGET', 'syslog'))) {
        $| = 1;
      }
      if ($sysLogTarget && ($target eq 'out') && ($dbg <= $self->logLevel('TARGET', 'syslog'))) {
        $| = 1;
      }
    }
  }
  return 1;
} ## end sub _print


sub printerr {
  my $self = (shift)->getInstance();
  $self->_print('TARGET', 'err', 
                'STR', '',
                @_);
  return 1;
} ## end sub printerr


sub printout {
  my $self = (shift)->getInstance();
  $self->_print('TARGET', 'out',
                'STR', '',
                @_);
  return 1;
} ## end sub printout


sub logLevel {
  my $self = (shift)->getInstance();
  my %args = ('TARGET', 'console',
              @_);
              
  $self->{OPTIONS}->{LOGLEVEL}->{$args{TARGET}} = $args{LEVEL} if defined($args{LEVEL});

  if (!defined($self->{OPTIONS}->{LOGLEVEL}->{$args{TARGET}})) {
    $self->{OPTIONS}->{LOGLEVEL}->{$args{TARGET}} = 3;
  }
  return $self->{OPTIONS}->{LOGLEVEL}->{$args{TARGET}};
} ## end sub logLevel


sub _Off {
  my $self = (shift)->getInstance();
  my $target = shift;

  if ($logTarget{$target.'console'} != 0 ||
      $logTarget{$target.'file'}    != 0 ||
      $logTarget{$target.'syslog'}  != 0) {
    $| = 1;
    if ($target eq 'err') {
      $self->debug('MSG', 'Error Logging is disabled');
      open STDERR, ">", "/dev/null";
    } else {
      $self->debug('MSG', 'Logging is disabled');
      open STDOUT, ">", "/dev/null";
    }  
    $logTarget{$target.'console'} = 0;
    $logTarget{$target.'file'}    = 0;
    $logTarget{$target.'syslog'}  = 0;
  } ## end $logTarget{$target.'Cons ... 

  return 1;
} ## end sub _Off


sub errOff {
  my $self = (shift)->getInstance();
  $self->_Off('err');
  return 1;
} ## end sub errOff


sub outOff {
  my $self = (shift)->getInstance();
  $self->_Off('out');
  return 1;
} ## end sub outOff


sub switchLogging {
  my $self  = (shift)->getInstance();
  my %args = (STATUS => 0,
              @_);
              
  my $type   = substr($args{TARGET}, 0, 3);
  my $target = substr($args{TARGET}, 3);
  if ($args{STATUS}) {
    if (defined($args{FILE})) {
      eval {unlink $args{FILE}} if $args{CLEAR};
      eval {mkdir(dirname($args{FILE}))};
      $target .= ":$args{FILE}";
    }
    if (defined($args{FILELAST})) {
      eval {unlink $args{FILELAST}} if $args{CLEAR};
      eval {mkdir(dirname($args{FILELAST}))};
      $target .= " (last):$args{FILELAST}";
    }
    if (!$logTarget{$args{TARGET}}) {
      $type = ($type eq 'err') ? 'Errorlogging to ' : 'Logging to ';
      $self->debug('MSG', $type . $target . ' enabled')
    }
    $logTarget{$args{TARGET}} = 1;
  } else {
    if (defined($args{FILE})) {
      eval {unlink $args{FILE}} if $args{CLEAR};
      $target .= ": $args{FILE}";
    }
    if (defined($args{FILELAST})) {
      eval {unlink $args{FILELAST}} if $args{CLEAR};
      $target .= " (last): $args{FILELAST}";
    }
    if ($logTarget{$args{TARGET}})  {
      $type = ($type eq 'err') ? 'Errorlogging to ' : 'Logging to ';
      $self->debug('MSG', $type . $target . ' disabled')
    }
    $logTarget{$args{TARGET}} = 0;
  }

  return 1;
} ## end sub switchLogging


sub switchConsoleErr {
  my $self  = (shift)->getInstance();
  $self->switchLogging('TARGET', 'errconsole',
                       'STATUS', !$logTarget{'errconsole'},
                       @_);
  return 1;
} ## end sub switchConsoleErr


sub switchFileErr {
  my $self = (shift)->getInstance();
  $self->switchLogging('TARGET',   'errfile',
                       'STATUS',   !$logTarget{'errfile'},
                       'FILE',     $self->{CONFIG}->get('log.err.file', "FILE"),
                       'FILELAST', $self->{CONFIG}->get('log.err.filelast', "FILE"),
                       'CLEAR',    undef,
                       @_);
  return 1;
} ## end sub switchFileErr


sub switchSysLogErr {
  my $self  = (shift)->getInstance();
  $self->switchLogging('TARGET', 'errsyslog',
                       'STATUS', !$logTarget{'errsyslog'},
                       @_);
  return 1;
} ## end sub switchSysLogErr


sub switchConsoleOut {
  my $self  = (shift)->getInstance();
  $self->switchLogging('TARGET', 'outconsole',
                       'STATUS', !$logTarget{'outconsole'},
                       @_);
  return 1;
} ## end sub switchConsoleOut


sub switchFileOut {
  my $self = (shift)->getInstance();
  $self->switchLogging('TARGET',   'outfile',
                       'STATUS',   !$logTarget{'outfile'},
                       'FILE',     $self->{CONFIG}->get('log.out.file', "FILE"),
                       'FILELAST', $self->{CONFIG}->get('log.out.filelast', "FILE"),
                       'CLEAR',    undef,
                       @_);
  return 1;
} ## end sub switchFileOut


sub switchSysLogOut {
  my $self  = (shift)->getInstance();
  $self->switchLogging('TARGET', 'outsyslog',
                       'STATUS', !$logTarget{'outsyslog'},
                       @_);
  return 1;
} ## end sub switchSysLogOut


sub log {
  my $self = (shift)->getInstance();
  my %args = (@_);

  # confess "Not a hash ref" unless (ref($arg) eq "HASH");
  return undef unless (defined $args{MSG});

  my $logStr = '';
  my ($subroutine, $i, $line) = ('', 0, 0);
  while (defined(caller($i))) {
    $logStr = (caller($i))[3];
    $line = $line ? (caller($i-1))[2] : __LINE__;
    $i++;
    if ($dbgInfo > 0) {
      if ((($dbgInfo <= 2) && ($logStr !~ /getInstance|Logging/)) || ($dbgInfo >= 3)) {
        if ($dbgInfo == 1) {
          $subroutine = "$logStr($line)" if (!$subroutine);  
        } else {
          $subroutine = $subroutine ? "$logStr($line)->$subroutine" : "$logStr($line)";  
        }
      }
    }
  }
  $subroutine = "[$subroutine] " if ($subroutine);
  $logStr = CertNanny::Util->expandStr("__YEAR__-__MONTH__-__DAY__ __HOUR__:__MINUTE__:__SECOND__ : [__PRIO__] [__PID__] __SUB____MSG__\n", 
                                       '__PRIO__', lc($args{PRIO} || "info"),
                                       '__SUB__',  $subroutine,
                                       '__MSG__',  $args{MSG});
  $self->printout('STR', $logStr, %args);

  return 1;
} ## end sub log


sub debug {
  my $self = (shift)->getInstance();
  my %args = (@_);

  $self->log(PRIO => 'debug', %args);
  
  return 0
} ## end sub debug


sub info {
  my $self = (shift)->getInstance();
  my %args = (@_);

  $self->log(PRIO => 'info', %args);
  
  return 0
} ## end sub info


sub notice {
  my $self = (shift)->getInstance();
  my %args = (@_);

  $self->log(PRIO => 'notice', %args);
  
  return 0
} ## end sub notice


sub error {
  my $self = (shift)->getInstance();
  my %args = (@_);
  
  $self->log(PRIO => 'error', %args);
  
  return 1
} ## end sub error


sub fatal {
  my $self = (shift)->getInstance();
  my %args = (@_);

  $self->log(PRIO => 'fatal', %args);
  
  return 1
} ## end sub fatal


1;
