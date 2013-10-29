#!c:/ActivePerl/bin/perl.exe
use Wx::Perl::Packager;
use strict;
use warnings;

use Wx qw(wxBITMAP_TYPE_BMP);

package WizTest;
use base qw(Wx::App);   # Inherit from Wx::App
use Wx::Event qw(EVT_WIZARD_FINISHED EVT_WIZARD_PAGE_CHANGED EVT_WIZARD_PAGE_CHANGING);
use English;
use Data::Dumper;
$| = 1;

if ($OSNAME eq "MSWin32") {
    require Win32::OLE;
    Win32::OLE->import();
    require Win32::OLE::Const;
    Win32::OLE::Const->import();
}

sub OnInit {
	my $self = shift;
	
	my $location = join q{ }, @ARGV;
	chop($location);
	
	my $cfg_location = "$location\\etc\\certnanny_wizard.cfg";
	
	$self->{CFGLOCATION} = $cfg_location;

	my $wizard = Wx::Wizard->new( undef, -1, "CertNanny Configuration Wizard", Wx::Bitmap->new('dependencies/certnanny_cfg.bmp', 1));
	$wizard->SetPageSize(Wx::Size->new(453,270));
	
	my $panelLeft = Wx::Panel->new( $wizard, -1, [0, 0], Wx::Size->new(174, 337) );
	$panelLeft->SetBackgroundColour(Wx::Colour->new(219, 230, 243));
	
	# welcome page
	my $page0 = Wx::WizardPageSimple->new( $wizard );
	$page0->SetId(0); # page 0
	my $introText = Wx::StaticText->new( $page0, -1,"Welcome to the CertNanny Configuration Wizard");
	$introText->SetBackgroundColour(Wx::Colour->new(255, 255, 255));
	
	my $font12 = Wx::Font->new(	12,	# font size
								-1,	# font family
								-1,	# style
								-1,	# weight
								0,
								-1,	#'Verdana',	# face name
								-1);
								
	$introText->SetFont($font12);
	
	my $introText2 = Wx::StaticText->new( $page0, -1,"The configuration wizard allows you to change the CertNanny config.\nClick Next to continue or Cancel to exit and change the configuration file by hand.",[0, 50], Wx::Size->new(455, 50) );
	$introText2->SetBackgroundColour(Wx::Colour->new(255, 255, 255));
	
	if (-e $cfg_location) {
		warn "file exists\n";
		my $warningText = Wx::StaticText->new( $page0, -1,"The configuration file at $self->{CFGLOCATION} already exists.\n\nYou may want to backup the existing file, otherwise it will be overwritten by this wizard.",[0, 120], Wx::Size->new(455, 70) );
		$warningText->SetBackgroundColour(Wx::Colour->new(255, 255, 255));
		$warningText->SetForegroundColour(Wx::Colour->new(255, 0, 0));
	}
	
	my $panelRight = Wx::Panel->new( $wizard, -1, [174, 0], Wx::Size->new(686, 337) );
	$panelRight->SetBackgroundColour(Wx::Colour->new(255, 255, 255));

	# first page
	my $page1 = Wx::WizardPageSimple->new( $wizard );
	$page1->SetId(1); # page 1
	Wx::StaticText->new( $page1, -1,"To define the correct SCEP URL to be used for the renewal request, we need to know if your certificate is used in an UAT or Production environment.",[0, 0], Wx::Size->new(455, 50) );
	Wx::StaticText->new( $page1, -1,"Please choose one of the following options.",[0, 60]);
	Wx::RadioBox->new( $page1, -1,"Environment",[0, 80], Wx::Size->new(170,50), ['UAT', 'Production'], 0, 0 );

	# second page
	my $page2 = Wx::WizardPageSimple->new( $wizard );
	$page2->SetId(2); # page 2
	Wx::StaticText->new( $page2, -1,"Since CertNanny is able to work on different types of keystores, you have to select the type of keystore depending on your prerequisites.",[0, 0], Wx::Size->new(455, 50) );
	Wx::StaticText->new( $page2, -1,"Please select the type of your keystore.",[0, 60]);
	Wx::RadioBox->new( $page2, -1,"Keystore type",[0, 80], Wx::Size->new(320,50), ['Internet Information Server', 'Windows Certificate Store'], 0, 0 );

	# third page
	#my $page3 = WizardPageChoice->new( $wizard ); # , $self );
	#bless($page3, 'WizardPageChoice');
	#print 'page3: ' . Dumper $page3;
	my $page3 = Wx::WizardPageSimple->new( $wizard );
	$page3->SetId(3); # page 3
	
	my @choices = $self->list_certificates;
	$self->{CERTIFICATES}->{ALL} = \@choices;
	
	my $page4 = Wx::WizardPageSimple->new( $wizard );
	$page4->SetId(4); # page 4
	
	if (scalar @choices == 0) {
		Wx::StaticText->new( $page3, -3, 'No certificates found, we can only generate a configuration file if certificates are already installed', [0, 0], Wx::Size->new(455, 50) );
		
	}
	else {
		# only continue if certificates are actually available
		Wx::StaticText->new( $page3, -1,"In the following list you will find all the certificates installed on your machine account. You can select one ore more certificates which you want to be renewed by CertNanny.",[0, 0], Wx::Size->new(455,30) );
		Wx::StaticText->new( $page3, -1,"Please select one or more certificates from the list below.",[0, 60]);
		
		my $lb = Wx::ListCtrl->new( $page3, -1, [0, 80], Wx::Size->new(450, 200), 32 );
		$lb->InsertColumn( 0, "Certificate" );
		$lb->SetColumnWidth(0, 430);
		$lb->SetItemCount(scalar @choices);
		for (my $i = 0; $i <scalar @choices; $i++) {
			my $idx = $lb->InsertStringItem( $i, $choices[$i]->{SUBJECT} );
			$lb->SetItemData( $idx, $i );
		}
	}
	
	# page 4
	Wx::StaticText->new( $page4, -1,"You can choose between different log levels now. For common usage level 2 or 3 should be OK. The higher the level the more will be logged.",[0, 0], Wx::Size->new(455,30) );
	Wx::StaticText->new( $page4, -1,"Please select a log level.",[0, 60]);
	my @levels = (
		'0: fatal',
		'1: error',
		'2: notice',
		'3: info',
		'4: debug',
		'5: SCEP verbose',
		'6: SCEP debug',
	);
	my $rb = Wx::RadioBox->new( $page4, -1,"Loglevel",[0, 80], Wx::Size->new(120,160), \@levels, 1, 0 );
	$rb->SetSelection(3);
	
	# page 5
	my $page5 = Wx::WizardPageSimple->new( $wizard );
	$page5->SetId(5); # page 5
	Wx::StaticText->new( $page5, -1,"CertNanny can be run automatically as a windows service. If you want to register CertNanny now in the services list, click the ckeckbox below.\n\nThe service starts automatically with the the configuration defined in this wizard after the next reboot. You may want it to start manually without rebooting your machine.",[0, 0], Wx::Size->new(455,70) );
	# checkbox looks better than radio box...
	my $cb = Wx::CheckBox->new( $page5, -1, "register CertNanny as a service", [0, 80], Wx::Size->new(450,30) );
	$cb->SetValue(1);
	
	# page 6
	my $page6 = Wx::WizardPageSimple->new( $wizard );
	$page6->SetId(6); # page 6
	
	my $finishedText1 = Wx::StaticText->new( $page6, -1, "Congratulations!",[0, 0], Wx::Size->new(455,20) );
	$finishedText1->SetBackgroundColour(Wx::Colour->new(255, 255, 255));
	my $finishedText2 = Wx::StaticText->new( $page6, -1, "You have successfully completed the CertNanny Configuration Wizard.\n\nPlease manually check the generated configuration file before using CertNanny.\nThe config file can be found at:", [0, 50], Wx::Size->new(455,70) );
	$finishedText2->SetBackgroundColour(Wx::Colour->new(255, 255, 255));
	my $cfgLocationText = Wx::StaticText->new( $page6, -1, "(You can copy&&paste the path above)", [5, 160], Wx::Size->new(455,70) );
	$cfgLocationText->SetBackgroundColour(Wx::Colour->new(255, 255, 255));	
	
	#my $fontBig->SetNativeFontInfoUserDesc("12");
	my $fontBig = Wx::Font->new(	12,	# font size
								-1,	# font family
								-1,	# style
								-1,	# weight
								0,
								-1,	#'Verdana',	# face name
								-1);
	my $fontFixedWidth = Wx::Font->new( 8, 2, -1, -1, 0, -1, -1);
	#$fontFixedWidth->SetNativeFontInfoUserDesc("Courier New 10");
	$finishedText1->SetFont($fontBig);
	#$cfgLocationText->SetFont($fontFixedWidth);
	
	my $txtCtrl = Wx::TextCtrl->new( $page6, -1, $self->{CFGLOCATION}, [0, 130], Wx::Size->new(455,20) );
	$txtCtrl->SetEditable(0);
	
	my $panelRightPage6 = Wx::Panel->new( $wizard, -1, [174, 0], Wx::Size->new(686, 337) );
	$panelRightPage6->SetBackgroundColour(Wx::Colour->new(255, 255, 255));
	
	# global chain
	Wx::WizardPageSimple::Chain( $page0, $page1 );
	Wx::WizardPageSimple::Chain( $page1, $page2 );
	Wx::WizardPageSimple::Chain( $page2, $page3 );
	Wx::WizardPageSimple::Chain( $page3, $page4 );
	
	Wx::WizardPageSimple::Chain( $page5, $page6 );

	EVT_WIZARD_FINISHED( 
		$self, $wizard, 
		sub {
			print "Identifiers: " . Dumper $self->{IDENTIFIERS};
			print "IIS: " . Dumper $self->{IIS};
			print "UAT: " . Dumper $self->{UAT};
			print "Loglevel: " . Dumper $self->{LOGLEVEL};
			print "Register Service: " . Dumper $self->{REGISTERSERVICE};
			
			open my $HANDLE, '>', $self->{CFGLOCATION} or die "could not open file: $!";		
			print $HANDLE "# CertNanny configuration created by CertNanny Configuration Wizard\n";
			print $HANDLE "# For examples take a look at the sample config files\n\n";
			print $HANDLE "# OpenSSL location (required)\ncmd.openssl = C:/Program Files/OpenSSL/bin/openssl.exe\n\n";
			print $HANDLE "# sscep binary location (required)\ncmd.sscep = ${location}\\bin\\sscep.exe\n\n";
			print $HANDLE "path.tmpdir = " . $ENV{TEMP} . "\n\n";
			print $HANDLE "loglevel = $self->{LOGLEVEL}\n\n";
			print $HANDLE "logfile = ${location}\\Log\n\n";
			if ($self->{UAT}) {
				print $HANDLE "keystore.DEFAULT.scepurl = http://epki001.rze.de.db.com/cgi-bin/scep/scep\n\n";
			} else {
				print $HANDLE "keystore.DEFAULT.scepurl = http://dbca.tools.intranet.db.com/cgi-bin/scep/scep\n\n";
			}
			print $HANDLE "keystore.DEFAULT.statedir = ${location}State\n";
			print $HANDLE "keystore.DEFAULT.scepcertdir = ${location}State\n\n";
			if ($self->{UAT}) {
				print $HANDLE "keystore.DEFAULT.rootcacert.1 = ${location}\\RootCerts\\db-uat-root-ca-4.pem\n";
				print $HANDLE "keystore.DEFAULT.rootcacert.2 = ${location}\\RootCerts\\db-uat-root-ca-5.pem\n\n";
			} else {
				print $HANDLE "keystore.DEFAULT.rootcacert.1 = ${location}\\RootCerts\\db-root-ca-2.pem\n";
				print $HANDLE "keystore.DEFAULT.rootcacert.2 = ${location}\\RootCerts\\db-root-ca-3.pem\n\n";
			}
			if ($self->{IIS}) {
				for (my $i = 0; $i < scalar @{ $self->{CERTIFICATES}->{SELECTED}}; $i++) {
					print $HANDLE "keystore.MadeByCCWizard$i.location = " . $self->__fix_windows_dn($self->{CERTIFICATES}->{SELECTED}->[$i]->{SUBJECT}) . "\n";
					print $HANDLE "keystore.MadeByCCWizard$i.type = WindowsIIS\n";
					print $HANDLE "keystore.MadeByCCWizard$i.issuerregex = " . $self->__fix_windows_dn($self->{CERTIFICATES}->{SELECTED}->[$i]->{ISSUER}) . "\n";
					print $HANDLE "keystore.MadeByCCWizard$i.storelocation = machine\n";
					print $HANDLE "keystore.MadeByCCWizard$i.instanceidentifier = ". join(",", @{$self->{IDENTIFIERS}->[$i]}) . "\n\n";
				}
			} else {
				for (my $i = 0; $i < scalar @{ $self->{CERTIFICATES}->{SELECTED}}; $i++) {
					print $HANDLE "keystore.MadeByCCWizard$i.location = " . $self->__fix_windows_dn($self->{CERTIFICATES}->{SELECTED}->[$i]->{SUBJECT}) . "\n";
					print $HANDLE "keystore.MadeByCCWizard$i.type = Windows\n";
					print $HANDLE "keystore.MadeByCCWizard$i.issuerregex = " . $self->__fix_windows_dn($self->{CERTIFICATES}->{SELECTED}->[$i]->{ISSUER}) . "\n";
					print $HANDLE "keystore.MadeByCCWizard$i.storelocation = machine\n\n";
				}
			}
			close $HANDLE or die "could not close file";
			
			if ($self->{REGISTERSERVICE}) {
				my $command = "perl \"$location\\bin\\certnanny\" --cfg=\"$cfg_location\" install";
				print $command . "\n";
				my $register = system($command);
				print Dumper $register;
				warn $register;
			}
			warn "Wizard finished\n";
	} );

	EVT_WIZARD_PAGE_CHANGED(
		$self, $wizard,
		sub {
			my ($self, $event) = @_;
			if ($self->{wizard}->GetCurrentPage()->GetId() == 3) {
				my @prev_children = $self->{wizard}->GetCurrentPage()->GetPrev()->GetChildren();
				
				if ($prev_children[-1]->GetSelection != 0) {
					# the user did not choose IIS, record that
					$self->{IIS} = 0;
				}
				else {
					# if the user changes his mind ...
					$self->{IIS} = 1;
				}
			}
			if ($self->{wizard}->GetCurrentPage()->GetId() == 0) {
				$panelRight->Show();
			} elsif ($self->{wizard}->GetCurrentPage()->GetId() == 6) {
				$panelRightPage6->Show();
			} elsif ($self->{wizard}->GetCurrentPage()->GetId() < 6 &&  $self->{wizard}->GetCurrentPage()->GetId() != 0) {
				$panelRight->Hide();
				$panelRightPage6->Hide();
			}
			if(0) {
				if ($self->{IIS}) {
					if ($self->{wizard}->GetCurrentPage()->GetId() == 11 && scalar @{ $self->{CERTIFICATES}->{SELECTED}} == 0) {
						# show right text on dummy page
						print "selected == 0?: " . scalar @{ $self->{CERTIFICATES}->{SELECTED}} . "\n";
						my @dummy_children = $self->{wizard}->GetCurrentPage()->GetChildren();
						$dummy_children[-1]->Show();
					} elsif ($self->{wizard}->GetCurrentPage()->GetId() == 11 && scalar @{ $self->{CERTIFICATES}->{SELECTED}} != 0) {
						# show right text on dummy page
						print "selected != 0?: " . scalar @{ $self->{CERTIFICATES}->{SELECTED}} . "\n";
						my @dummy_children = $self->{wizard}->GetCurrentPage()->GetChildren();
						$dummy_children[-1]->Hide();
					}
				}
			}
		},
	);
	
	EVT_WIZARD_PAGE_CHANGING(
		$self, $wizard,
		sub {
			my ($self, $event) = @_;
			my $current_page_id = $self->{wizard}->GetCurrentPage()->GetId();
			# if we change from page three to the next one, and the user has chosen IIS, we have to 
			# create new pages that ask for the instance identifiers per certificate
			if ($current_page_id == 3 && $event->GetDirection() && $self->{IIS}) {
				my @children = $self->{wizard}->GetCurrentPage->GetChildren();
				print "children: " . Dumper \@children . "\n";
				print 'item count: ' . $children[2]->GetItemCount() . "\n";
				my @selected_certs = ();
				my $page = $self->{wizard}->GetCurrentPage()->GetNext();
				
				# get available instance identifier(s)
				my $computer = Win32::OLE->new("WScript.Network") or die;
				my $computer_name = $computer->ComputerName();
				#print "getComputer?: " . $computer_name . "\n";
				my $IISObjectPath = "IIS://" . $computer_name . "/W3svc";
				#print "ObjectPath?: " . $IISObjectPath . "\n";
				my $IISObject = Win32::OLE->GetObject("$IISObjectPath");
				my $i = 0;
				my @identifiers;
				foreach my $IISChildObject (in $IISObject) {
					if (($IISChildObject->Class eq 'IIsWebServer')) { # note the lower case s in IIs, otherwise it won't work
						my $ChildObjectName = $IISChildObject->name;
						print "name?: " . $ChildObjectName . "\n";
						$identifiers[$i][0] = $ChildObjectName;
						$identifiers[$i][1] = $IISChildObject->{"ServerComment"};
						$i++;
					}
				}
				
				my $switch = 1;
				my $j = 0;
				# why we have to divide by 2 here shall remain wx's secret ...
				for (my $i = 0; $i < $children[2]->GetItemCount() / 2; $i++) {
					if ($children[2]->GetItemState($i, 4) == 4) {
						push @selected_certs, $self->{CERTIFICATES}->{ALL}->[$i];
						
						# build additional pages
						my $tmp_page = Wx::WizardPageSimple->new( $wizard );
						$tmp_page->SetId(100 + $j);
						$j++;
						Wx::StaticText->new( $tmp_page, -1, "Previously chosen certificate for renewal:", [0, 0], Wx::Size->new(455,20) );
						my $certText = Wx::StaticText->new( $tmp_page, -1, $self->{CERTIFICATES}->{ALL}->[$i]->{SUBJECT}, [0, 20], Wx::Size->new(455,20)  );
						my $fontBold = Wx::Font->new(	8,	# font size
														-1,	# font family
														-1,	# style
														-1,	# weight (doesn't seem to work)
														0,	# underline
														-1,	#'Verdana',	# face name
														-1);# encoding
						# set the font weight (this seems to work)
						$fontBold->SetNativeFontInfoUserDesc("bold");
						$certText->SetFont($fontBold);
						Wx::StaticText->new( $tmp_page, -1, "Please select one or more instance identifiers of your IIS server for the above mentioned certificate. If you want to install the same certificate into multiple instances, just select more than one identifier.", [0, 40], Wx::Size->new(455,40)  );
						Wx::StaticText->new( $tmp_page, -1, "Please select one or more identifiers from the list below.", [0, 90], Wx::Size->new(455,20)  );
						my $lb_identifiers = Wx::ListCtrl->new( $tmp_page, -1, [0, 110], Wx::Size->new(450, 200), 32 );
						$lb_identifiers->InsertColumn( 0, "Identifier" );
						$lb_identifiers->InsertColumn( 1, "Description" );
						$lb_identifiers->SetColumnWidth(0, 75);
						$lb_identifiers->SetColumnWidth(1, 355);
						$lb_identifiers->SetItemCount(scalar @identifiers);
						for (my $i = 0; $i <scalar @identifiers; $i++) {
							my $idx = $lb_identifiers->InsertStringItem( $i, $identifiers[$i][0]);
							$lb_identifiers->SetItem( $i, 1, $identifiers[$i][1] );
							# wozu war das hier gut??
							$lb_identifiers->SetItemData( $idx, $i );
						}
						
						# build chain
						Wx::WizardPageSimple::Chain( $page, $tmp_page );
						if ($switch) {
							$page->SetNext($tmp_page);
							$switch = 0;
						}
						$page = $tmp_page;
					}
				}
				print "next one?: " . $self->{wizard}->GetCurrentPage()->GetNext()->GetId() . "\n";
				print "previous one?: " . $self->{wizard}->GetCurrentPage()->GetPrev()->GetId() . "\n";
				print "current?: " . $self->{wizard}->GetCurrentPage()->GetId() . "\n";
				
				# chaining added by SR
				Wx::WizardPageSimple::Chain( $page, $page5 );
				#$self->{wizard}->GetCurrentPage()->SetNext($page4);
				$self->{CERTIFICATES}->{SELECTED} = \@selected_certs;
				print Dumper $self->{CERTIFICATES};
				print "IIS?: " . $self->{IIS} . "\n";
			} elsif ($current_page_id == 3 && $event->GetDirection() && !$self->{IIS}) {
				my @selected_certs = ();
				my @children = $self->{wizard}->GetCurrentPage->GetChildren();
				for (my $i = 0; $i < $children[2]->GetItemCount() / 2; $i++) {
					if ($children[2]->GetItemState($i, 4) == 4) {
						push @selected_certs, $self->{CERTIFICATES}->{ALL}->[$i];
					}
				}
				$self->{CERTIFICATES}->{SELECTED} = \@selected_certs;
				Wx::WizardPageSimple::Chain($page4, $page5);
				$self->{wizard}->GetCurrentPage()->SetNext($page5);
			} elsif ($current_page_id >= 100 && $event->GetDirection() && $self->{IIS}) {
				my @children = $self->{wizard}->GetCurrentPage->GetChildren();
				print "children IDs: " . Dumper \@children;
				print 'item count IDs: ' . $children[-1]->GetItemCount() . "\n";
				my @selected_identifiers = ();
				for (my $i = 0; $i < $children[-1]->GetItemCount() / 2; $i++) {
					if ($children[-1]->GetItemState($i, 4) == 4) {
						push @selected_identifiers, $children[-1]->GetItem($i, 0)->GetText();
						print "GetItemText?: " . $children[-1]->GetItem($i, 0)->GetText() . "\n";
					}
				}
				print "saving to array entry " . ($current_page_id - 100) . "\n";
				$self->{IDENTIFIERS}->[$current_page_id - 100] = \@selected_identifiers;
			} elsif ($current_page_id == 1 && $event->GetDirection()) {
				my @children = $self->{wizard}->GetCurrentPage()->GetChildren();
				
				if ($children[-1]->GetSelection != 0) {
					# the user did not choose UAT, record that
					$self->{UAT} = 0;
				}
				else {
					# if the user changes his mind ...
					$self->{UAT} = 1;
				}
			} elsif ($current_page_id == 4 && $event->GetDirection()) {
				my @children = $self->{wizard}->GetCurrentPage()->GetChildren();
				$self->{LOGLEVEL} = $children[-1]->GetSelection();
			} elsif ($current_page_id == 5 && $event->GetDirection()) {
				my @children = $self->{wizard}->GetCurrentPage()->GetChildren();
				if ($children[-1]->GetValue) {
					# the user did not choose to register CertNanny as a service, record that
					$self->{REGISTERSERVICE} = 1;
				}
				else {
					# if the user changes his mind ...
					$self->{REGISTERSERVICE} = 0;
				}
			}
		}
	);
	
	# Preempt everything and run the wizard now.
	$self->{wizard} = $wizard;
	$self->{start_page} = $page0;

}

sub list_certificates {
	my $self			= shift;
	my $const			= Win32::OLE::Const->Load('CAPICOM');
	my $MACHINE_STORE	= $const->{CAPICOM_LOCAL_MACHINE_STORE};
	
	my $store_mode = $const->{CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED};

	my $store = Win32::OLE->new ('CAPICOM.Store');

	#Open() has no return value
	$store->Open ($MACHINE_STORE, 'MY', $store_mode);

	my $cert;
	my @certificates;

	#go through all certificates in the store
	my $enum = Win32::OLE::Enum->new($store->Certificates);
	while (defined( $cert = $enum->Next)) {
		my $subjectname = $cert->SubjectName;
		my $issuername = $cert->IssuerName;
		push @certificates, {
			SUBJECT => $subjectname,
			ISSUER  => $issuername,
		};
	}
	$enum->Reset;

	return @certificates;    
}

sub __fix_windows_dn {
	my $self = shift;
	my $dn   = shift;
	# black magic to delete the spaces after q{,}, but not after q{\,} ...
	$dn =~ s/(?<!\\)((\\\\)*),\s*/$1,/g; 
	return $dn;
}
	
package  main;

my $app = WizTest->new();

$app->{wizard}->RunWizard( $app->{start_page} );