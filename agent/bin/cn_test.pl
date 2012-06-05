use strict;
use warnings;
use English;

use File::Spec;

use Pod::Usage;
use Getopt::Long;

use FindBin;
use lib "$FindBin::Bin/../lib/perl";

use CertNanny;

use base qw(Exporter);

use strict;
use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION $AUTOLOAD);
use Exporter;
use Carp;

use FindBin;
use File::Spec;

use CertNanny::Config;
use CertNanny::Keystore;
use Data::Dumper;

use IPC::Open3;

foreach my $name qw(SERVICE_STOPPED SERVICE_START_PENDING SERVICE_STOP_PENDING SERVICE_PAUSE_PENDING SERVICE_PAUSED SERVICE_CONTINUE_PENDING SERVICE_RUNNING SERVICE_CONTROL_NONE SERVICE_CONTROL_INTERROGATE SERVICE_CONTROL_SHUTDOWN) {
		no strict;
		# declare a dummy function for symbols listed in Win32(::Daemon)
		*{$name} = sub { 1; };
		use strict; }
		
my %config;

my $msg = "CertNanny, version $CertNanny::VERSION";
GetOptions(\%config,
	   qw(
	      help|?
	      man
	      cfg|cfgfile|conf|config=s
			win_user=s
			win_password=s
	      )) or pod2usage(-msg => $msg, -verbose => 0);

pod2usage(-exitstatus => 0, -verbose => 2) if $config{man};
pod2usage(-msg => $msg, -verbose => 1) if ($config{help} or
		 (! exists $config{cfg}));

die "Could not read config file $config{cfg}. Stopped" 
    unless (-r $config{cfg});

my $monitor = CertNanny->new(CONFIG => $config{cfg});
foreach my $entry (keys %{$monitor->{ITEMS}}) {
	my $keystore = CertNanny::Keystore->new(CONFIG => $monitor->{CONFIG}, ENTRY =>  $monitor->{ITEMS}->{$entry}, ENTRYNAME => $entry);
	#$monitor->$action(ENTRY => $entry, KEYSTORE => $keystore) if ($keystore);
	$keystore->getcert();

	
}