#!/usr/local/cpanel/3rdparty/bin/perl
# Copyright 2019, cPanel, L.L.C.
# All rights reserved.
# http://cpanel.net
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the owner nor the names of its contributors may be
# used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use warnings;
use Cpanel::Config::LoadWwwAcctConf();
use Cpanel::Config::LoadCpConf();
use File::Path;

use File::stat;
use Cpanel::Exception       ();
use Cpanel::Sys             ();
use Cpanel::Sys::OS         ();
use Cpanel::FindBin         ();
use Cpanel::Version         ();
use Cpanel::Kernel          ();
use Cpanel::KernelCare      ();
use Cpanel::IONice          ();
use Cpanel::PwCache         ();
use Cpanel::PwCache::Get    ();
use Cpanel::SafeRun::Object ();
use Math::Round;
use File::Find::Rule;
use POSIX;
use Getopt::Long;
use IO::Socket::INET;
use IO::Prompt;
use Term::ANSIColor qw(:constants);
use Time::Piece;
use Time::Seconds;
$Term::ANSIColor::AUTORESET = 1;

my $version = "3.4.21";
my $rootdir = "/root";
my $csidir  = "$rootdir/CSI";
our $KernelChk;
our $spincounter;
our $CPANEL_CONFIG_FILE    = q{/var/cpanel/cpanel.config};
my $conf             = Cpanel::Config::LoadWwwAcctConf::loadwwwacctconf();
my $cpconf           = Cpanel::Config::LoadCpConf::loadcpconf();
my $allow_accesshash = $cpconf->{'allow_deprecated_accesshash'};
my $sha256only;
our $HOMEDIR       = $conf->{'HOMEDIR'};
our @FILESTOSCAN   = undef;
our $rootkitsfound = 0;
###################################################
# Check to see if the calling user is root or not #
###################################################
if ( $> != 0 ) {
    logit("Must be run as root");
    die "This script must be run as root\n";
}
###########################################################
# Parse positional parameters for flags and set variables #
###########################################################
# Set defaults for positional parameters
my $full;
my $skipELF;
my $help;
my $userscan;
my $binscan;
my $scan;
my $skipClam;
our @process_list = get_process_list();
my %process;
&get_process_pid_hash( \%process );
my %ipcs;
&get_ipcs_hash( \%ipcs );
my $distro         = Cpanel::Sys::OS::getos();
my $distro_version = Cpanel::Sys::OS::getreleaseversion();
our $OS_RELEASE = ucfirst($distro) . " Linux release " . $distro_version;
our $HTTPD_PATH = get_httpd_path();
our $LIBKEYUTILS_FILES_REF = build_libkeyutils_file_list();
our $IPCS_REF;
our $PROCESS_REF;
our $EA4 = isEA4();
our @RPM_LIST;
our $OPT_TIMEOUT;
GetOptions(
    'bincheck'   => \$binscan,
    'userscan=s' => \$userscan,
    'full'       => \$full,
    'skipELF'    => \$skipELF,,
    'skipClamAV' => \$skipClam,
    'help'       => \$help,
);
#######################################
# Set variables needed for later subs #
#######################################
chomp( my $wget = qx[which wget] );
chomp( my $tar  = qx[which tar] );
our $CSISUMMARY;
our @SUMMARY;
my $docdir = '/usr/share/doc';
check_for_touchfile();
my @logfiles = (
    '/var/log/apache2/access_log',
    '/var/log/apache2/error_log',
    '/var/log/messages',
    '/var/log/maillog',
	'/var/log/secure',
	'/var/log/cron',
    '/var/log/wtmp',
);
######################
# Run code main body #
######################
if ($help) {
    show_help();
    exit;
}
check_previous_scans();
logit("=== STARTING CSI ===");

my %cpconf = get_conf( $CPANEL_CONFIG_FILE );
if ( Cpanel::IONice::ionice( 'best-effort', exists $cpconf{'ionice_import_exim_data'} ? $cpconf{'ionice_import_exim_data'} : 6 ) ) {
	print_info ("Setting I/O priority to reduce system load: " . Cpanel::IONice::get_ionice() . "\n");
   	setpriority( 0, 0, 19 );
}
my $scanstarttime = Time::Piece->new;
print_header("Scan started on $scanstarttime");
logit("Scan started on $scanstarttime");
logit("Showing disclaimer");
print_info("Usage: /root/csi.pl [functions] [options]");
print_info("See --help for a full list of options");
print_normal('');
disclaimer();
print_header( "Checking for RPM database corruption and repairing as necessary..." );
my $findRPMissues=qx[ /usr/local/cpanel/scripts/find_and_fix_rpm_issues ];
my $isRPMYUMrunning = rpm_yum_running_chk();
if ($binscan) {
    logit("Running with --bincheck");
    bincheck();
    exit;
}
if ($userscan) {
    my $usertoscan = $userscan;
    chomp($usertoscan);
    userscan($usertoscan);
    exit;
}

logit("Running default scan");
scan();
my $scanendtime = Time::Piece->new;
print_header("Scan completed on $scanendtime");
logit("Scan completed on $scanendtime");
my $scantimediff = ( $scanendtime - $scanstarttime );
my $scanTotTime = $scantimediff->pretty;
$scanTotTime = $scanTotTime . "\n";
print_header("Elapsed Time: $scanTotTime");
logit("Elapsed Time: $scanTotTime");
logit("=== COMPLETED CSI ===");
exit;
########
# Subs #
########

sub show_help {
    print_header("\ncPanel Security Inspection Version $version");
    print_header("Usage: perl csi.pl [options] [function]\n");
    print_header("Functions");
    print_header("=================");
    print_status("A scan starts by default. It performs a variety of checks to detect root level compromises.");
    print_status("--bincheck                 Performs RPM verification on core system binaries and prints active aliases.");
    print_status("--userscan cPanelUser      Performs a clamscan and string match search for a single cPanel User..");
    print_normal(" ");
    print_header("Available default scan options");
    print_header("=================");
    print_header("--full                     Includes symlink hack check for entire server, and RPM check for non-owned RPM's.");
    print_header("         		             Also does a check for any ELF binary files masquerading as images unless --skipELF is passed.");
    print_normal("--skipELF                  Skip the ELF binary files masquerading as images as it can take a very long time. ");
    print_normal(" ");
    print_header("Available options for --userscan");
    print_header("=================");
    print_status("--skipClam                 Skips ClamAV Scan.");
    print_normal(" ");
    print_header("Examples");
    print_header("=================");
    print_status("            /root/csi.pl [DEFAULT] quick scan");
    print_status("            /root/csi.pl --full");
    print_status("Bincheck: ");
    print_status("            /root/csi.pl --bincheck");
    print_status("Userscan ");
    print_status("            /root/csi.pl --userscan myuser");
    print_status("            /root/csi.pl --userscan myuser --skipClam [skips ClamAV Scan]");
    print_normal(" ");
}

sub bincheck {
    logit("Starting bincheck");
    print_normal('');
    print_header('[ Starting cPanel Security Inspection: Bincheck Mode ]');
    print_header("[ System: $OS_RELEASE ]");
    print_normal('');
    print_header('[ Generating Installed RPM List - Please wait... ]');
    logit("Generating Installed RPM List");
    print_normal('');
    my $rpmissues = 0;
    my %okbins    = (
        '/usr/bin/at',                      '.M.......',
        '/bin/su',                          '.M....G..',
        '/bin/ping',                        '.M.......',
        '/bin/ping6',                       '.M.......',
        '/usr/bin/locate',                  '.M.......',
        '/usr/bin/quota',                   '.M.......',
        '/usr/bin/screen',                  '.M.......',
        '/usr/sbin/userhelper',             '.M.......',
        '/usr/bin/chsh',                    '.M.......',
        '/usr/bin/ld',                      '.M....G..',
        '/usr/bin/c99',                     '.M....G..',
        '/usr/bin/gcc',                     '.M....G..',
        '/usr/bin/x86_64-redhat-linux-gcc', '.M....G..',
        '/usr/bin/c++',                     '.M....G..',
        '/usr/bin/g++',                     '......G..',
        '/usr/bin/x86_64-redhat-linux-c++', '......G..',
        '/usr/bin/x86_64-redhat-linux-g++', '......G..',
        '/usr/bin/ssh-agent',               '.M.......',
        '/usr/bin/chage',                   '.M.......',
    );
    my @BINARIES;
    my $rpmline;
    my $verify_string;
    my $verify;
    my $binary;
    my $binaryline;

    # We skip cpanel and ea- provided RPM's since those are checked via /usr/local/cpanel/scripts/check_cpanel_rpms
    my @RPMS   = qx[ /usr/bin/rpm -qa --qf "%{NAME}\n" | egrep -v "^(ea-|cpanel|kernel)" | sort -n | uniq ];
    my $RPMcnt = @RPMS;
    print_status('Done - Found: ' . $RPMcnt . ' RPMs to verify');
    print_header('[ Verifying RPM binaries - This may take some time... ]');
    logit("Verifying RPM binaries");
    foreach $rpmline (@RPMS) {
        chomp($rpmline);
        $verify = qx[ /usr/bin/rpm -V $rpmline | egrep "/(s)?bin" ];
        chomp($verify);
        spin();
        push( @BINARIES, $verify ) unless ( $verify eq "" );
    }
    foreach $binaryline (@BINARIES) {
        chomp($binaryline);
        ( $verify_string, $binary ) = ( split( /\s+/, $binaryline ) );
        chomp($verify_string);
        chomp($binary);
        if ( exists $okbins{$binary} ) {
            my $verify_okstring = $okbins{$binary};
            if ( $verify_string ne $verify_okstring ) {
                push( @SUMMARY, "> Modified Attribute: $binary [$verify_string]" );
                $rpmissues = 1;
            }
        }
    }
    if ( $rpmissues == 0 ) {
        print_info("No RPM issues found!");
    }
    logit("Creating summary");
    dump_summary();
    return;
}

sub disclaimer {
    print_normal('');
    print_header('########################################################################');
    print_header('### DISCLAIMER! cPanel\'s Technical Support does not provide            #');
    print_header('### security consultation services. The only support services we       #');
    print_header('### can provide at this time is to perform a minimal analysis of the   #');
    print_header('### possible security breach solely for the purpose of determining if  #');
    print_header('### cPanel\'s software was involved or used in the security breach.     #');
    print_header('########################################################################');
    print_header('### As with any anti-malware scanning system false positives may occur #');
    print_header('### If anything suspicious is found, it should be investigated by a    #');
    print_header('### professional security consultant. There are never any guarantees   #');
    print_header('########################################################################');
    print_normal('');
}

sub scan {
    print_normal('');
    print_header('[ Starting cPanel Security Inspection: DEFAULT SCAN Mode ]');
    print_header("[ System: $OS_RELEASE ]");
    print_normal('');
    print_header("[ Available flags when running csi.pl scan ]");
    print_header('[     --full Performs a more compreshensive scan ]');
    print_normal('');
	# Checking for suspicious files, known rootkits and other anomalies
    print_header('[ Checking logfiles ]');
    logit("Checking logfiles");
    check_logfiles();
    print_header('[ Checking for bad UIDs ]');
    logit("Checking for bad UIDs");
    check_uids();
    print_header('[ Checking for suspicious files/directories of known rootkits ]');
    logit("Checking for suspicious files/directories of known rootkits");
    all_malware_checks();
    print_header('[ Checking Apache configuration ]');
    logit("Checking Apache configuration");
    check_httpd_config();
    print_header('[ Checking for index.html in /tmp and /home ]');
    logit("Checking for index file in /tmp and $HOMEDIR");
    check_index();
    print_header('[ Checking for modified suspended page ]');
    logit("Checking web template [suspendedpage]");
    check_suspended();
    print_header('[ Checking if root bash history has been tampered with ]');
    logit("Checking roots bash_history for tampering");
    check_history();
    print_header('[ Checking /etc/ld.so.preload for compromised library ]');
    check_preload();
    print_header('[ Checking process list for suspicious processes ]');
    logit("Checking process list for suspicious processes");
    check_processes();
    print_header('[ Checking for suspicious bitcoin miners ]');
    logit("Checking for suspicious bitcoin miners");
    bitcoin_chk();
	print_header('[ Checking for miscellaneous compromises ]');
	logit("Checking for miscellaneous compromises");
	misc_checks();
    print_header('[ Checking for deprecated plugins/modules ]');
    logit("Checking for deprecated plugins");
    check_for_deprecated();
    print_header('[ Checking for sshd_config ]');
    logit("Checking sshd_config");
    check_sshd_config();
    print_header('[ Checking for modified/hacked SSH ]');
    logit("Checking for modified/hacked ssh");
    check_ssh();
	print_header('[ Checking for spam sending script in /tmp ]');
	logit("Checking for spam sending script in /tmp");
	spamscriptchk();
	spamscriptchk2();
	print_header('[ Checking /usr/bin/ for rogue http binary ]');
	logit("Checking /usr/bin for rogue http binary");
	chkbinforhttp();
	if ( -e "/etc/grub.conf" ) {
    	print_header('[ Checking kernel status ]');
    	logit("Checking kernel status");
    	check_kernel_updates();
	}
    print_header('[ Checking for MySQL users with Super privileges ]');
    logit("Checking for MySQL users with Super privileges");
	check_for_Super_privs();
    if ( !$full ) {
        print_info("full option not passed, skipping non-owned files/libraries check");
        logit("full option not passed - skipping lib check");
        print_info("full option not passed, skipping symlink hack check");
        logit("full option not passed - skipping symlink hack check");
        print_info("full option not passed, skipping shadow.roottn.bak hack check");
        logit("full option not passed - skipping shadow.roottn.bak hack check");
        print_info("full option not passed, skipping check for ELF binaries masquerading as images");
        logit("full option not passed - skipping check for ELF binaries masquerading as images");
    }
    else {
        print_header('[ Checking for files/libraries not owned by an RPM ]');
        logit("Checking for non-owned files/libraries");
        check_lib();
        print_header('[ Checking for symlink hacks ]');
        logit("Checking for symlink hacks");
        check_for_symlinks();
        print_header('[ Checking for shadow.roottn.bak hacks ]');
        logit("Checking for shadow.roottn.bak hacks");
        chk_shadow_hack();
		if (!$skipELF) { 
        	print_header('[ Checking for ELF binaries disguised as image files ]');
        	logit("Checking for ELF binaries disguised as image files");
        	check_for_ELF_images();
		}
    }
	# Checking for recommendations
    print_header('[ Checking for mod_security ]');
    logit("Checking if ModSecurity is enabled");
    check_modsecurity();
    print_header('[ Checking for Two-Factor Authentication ]');
    logit("Checking if Two-Factor Authentication is enabled");
    check_2FA_enabled();
    print_header('[ Checking for accesshash ]');
    logit("Checking for accesshash");
    check_for_accesshash();
    print_header('[ Gathering the IP addresses that logged on successfully as root ]');
    logit("Gathering IP address that logged on as root successfully");
	get_last_logins_WHM();
	get_last_logins_SSH();
    print_header('[ Running Security Advisor ]');
    logit("Running Security Advisor");
    security_advisor();
    print_header('[ cPanel Security Inspection Complete! ]');
    print_header('[ CSI Summary ]');
    print_normal('');
    dump_summary();
}

sub check_previous_scans {
    print_info("CSI version: $version");
    print_status('Checking for a previous run of CSI');
    if ( -d $csidir ) {
        chomp( my $date = qx[ date "+%Y-%m-%d-%H:%M:%S" ] );
        print_info("Existing $csidir is present, moving to $csidir-$date");
        rename "$csidir", "$csidir-$date";
    }
    mkdir( "$csidir", 0755 );
}

sub check_kernel_updates {
    my $CanModify             = Cpanel::Kernel::can_modify_kernel();
    my $boot_kernelversion    = Cpanel::Kernel::get_default_boot_version();
    my $running_kernelversion = Cpanel::Kernel::get_running_version();
    my $custom_kernel         = 0;
    if ( $running_kernelversion !~ m/\.(?:noarch|x86_64|i[3-6]86)$/ ) {
        $custom_kernel = 1;
    }
    my $has_kernelcare = 0;
	if ( Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '>', '11.68') ) { 
        # The next command can fail if there is an update to kernelcare available that hasn't been installed!
    	if ( Cpanel::KernelCare::kernelcare_responsible_for_running_kernel_updates() ) {
        	$has_kernelcare = 1;
    	}
	}
    my $reboot_required = 0;
    if ( $running_kernelversion ne $boot_kernelversion ) {
        $reboot_required = 1;
    }
    if ($custom_kernel) {
        push @SUMMARY, "> You have a custom kernel installed [ $running_kernelversion ]";
        return;
    }
    if ($has_kernelcare) {
        if ($reboot_required) {
            if ($CanModify) {
                push @SUMMARY, "> KernelCare installed but running kernel version does not match boot version (run kcarectl --update or reboot):";
				push @SUMMARY, CYAN "\t \\_ Running Version: [ " . $running_kernelversion . " ]"; 
				push @SUMMARY, CYAN "\t \\_ Boot Version: [ " . $boot_kernelversion . " ]";
            }
            else {
                push @SUMMARY, "> KernelCare installed but running kernel version does not match boot version (contact provider):";
				push @SUMMARY, CYAN "\t \\_ Running Version: [ " . $running_kernelversion . " ]"; 
				push @SUMMARY, CYAN "\t \\_ Boot Version: [ " . $boot_kernelversion . " ]";
                push @SUMMARY, CYAN "\t \\_ Please check with your VM provider.";
            }
        }
    }
    else {
        if ($reboot_required) {
            if ($CanModify) {
                push @SUMMARY, "> KernelCare not installed and running kernel version does not match boot version (reboot required):";
				push @SUMMARY, CYAN "\t \\_ Running Version: [ " . $running_kernelversion . " ]"; 
				push @SUMMARY, CYAN "\t \\_ Boot Version: [ " . $boot_kernelversion . " ]";
            }
            else {
                push @SUMMARY, "> KernelCare not installed and running kernel version does not match boot version (contact provider):";
				push @SUMMARY, CYAN "\t \\_ Running Version: [ " . $running_kernelversion . " ]"; 
				push @SUMMARY, CYAN "\t \\_ Boot Version: [ " . $boot_kernelversion . " ]";
                push @SUMMARY, CYAN "\t \\_ Please check with your VM provider.";
            }
        }
    }
    logit("Kernel status check completed.");
}

sub check_logfiles {
    my $apachelogpath;
    if ($EA4) {
        $apachelogpath = "/etc/apache2/logs";
    }
    else {
        $apachelogpath = "/usr/local/apache/logs";
    }
    chomp($apachelogpath);
    if ( !-d $apachelogpath ) {
        push @SUMMARY, "> $apachelogpath directory is not present";
    }
    foreach my $log (@logfiles) {
        if ( !-f $log ) {
            push @SUMMARY, "> Log file $log is missing or not a regular file";
        }
        elsif ( -z $log ) {
            push @SUMMARY, "> Log file $log exists, but is empty";
        }
    }
}

sub check_index {
    if ( -f '/tmp/index.htm' or -f '/tmp/index.html' ) {
        push @SUMMARY, '> Index file found in /tmp';
    }
}

sub check_suspended {
    if ( -f '/var/cpanel/webtemplates/root/english/suspended.tmpl' ) {
        push @SUMMARY, '> Custom account suspended template found at /var/cpanel/webtemplates/root/english/suspended.tmpl';
        push @SUMMARY, '     This could mean the admin just created a custom template or that an attacker gained access';
        push @SUMMARY, '     and created it (hack page)';
    }
}

sub check_history {
    if ( -e '/root/.bash_history' ) {
        if ( -l '/root/.bash_history' ) {
            my $result = qx(ls -la /root/.bash_history);
            push @SUMMARY, "> /root/.bash_history is a symlink, $result";
        }
        elsif ( !-s '/root/.bash_history' and !-l '/root/.bash_history' ) {
            push @SUMMARY, "> /root/.bash_history is a 0 byte file";
        }
    }
    else {
        push @SUMMARY, "> /root/.bash_history is not present, this indicates probable tampering";
    }
}

sub check_modsecurity {
    my $result = qx[ /usr/sbin/whmapi1 modsec_is_installed | grep 'installed: 1' ];
    if ( !$result ) {
        push @SUMMARY, "> Mod Security is disabled";
        return;
    }
    $result = qx[ /usr/sbin/whmapi1 modsec_get_configs | grep -c 'active: 1' ];
    if ( $result == 0 ) {
        push @SUMMARY, "> Mod Security is installed but there were no active Mod Security vendor rules found.";
    }
}

sub check_2FA_enabled {
    my $result = qx[ /usr/sbin/whmapi1 twofactorauth_policy_status | grep 'is_enabled: 1' ];
    if ( !$result ) {
        push @SUMMARY, "> Two-Factor Authentication Policy is disabled - Consider enabling this.";
        return;
    }
}

sub check_uids {
    my @baduids;
    while ( my ( $user, $pass, $uid, $gid, $group, $home, $shell ) = getpwent() ) {
        if ( $uid == 0 && $user ne 'root' ) {
            push( @baduids, $user );
        }
		if ($user eq 'firefart') { 
        	push @SUMMARY, "> firefart user found [Possible DirtyCow root compromise].";
		}
		if ($user eq 'sftp') { 
        	push @SUMMARY, "> sftp user found [Possible HiddenWasp root compromise].";
		}
    }
    endpwent();
    if (@baduids) {
        push @SUMMARY, '> Users with UID of 0 detected:';
        foreach (@baduids) {
            push( @SUMMARY, CYAN "\t \\_ " . $_ );
        }
    }
}

sub check_httpd_config {
    my $httpd_conf;
    if ($EA4) {
        $httpd_conf = '/etc/apache2/conf/httpd.conf';
    }
    else {
        $httpd_conf = '/usr/local/apache/conf/httpd.conf';
    }
    if ( -f $httpd_conf ) {
        my $apache_options = qx(grep -A1 '<Directory "/">' $httpd_conf);
        if (    $apache_options =~ 'FollowSymLinks'
            and $apache_options !~ 'SymLinksIfOwnerMatch' ) {
            push @SUMMARY, '> Apache configuration allows symlinks without owner match';
        }
    }
    else {
        push @SUMMARY, '> Apache configuration file is missing';
    }
}

sub check_processes {
    chomp( my @ps_output = qx(ps auxf) );
    foreach my $line (@ps_output) {
        if ( $line =~ 'sleep 7200' ) {
            push @SUMMARY, "> ps output contains 'sleep 7200' which is a known part of a hack process:";
            push @SUMMARY, "\t$line";
        }
        if ( $line =~ 'sleep 30' ) {
            push @SUMMARY, "> ps output contains 'sleep 30/300' which is a known part of a root infection";
            push @SUMMARY, "\t$line";
        }
        if ( $line =~ / perl$/ ) {
            push @SUMMARY, "> ps output contains 'perl' without a command following, which could indicate a hack:";
            push @SUMMARY, "\t$line";
        }
        if ( $line =~ /eggdrop/ ) {
            push @SUMMARY, "> ps output contains 'eggdrop' which is a known IRC bot";
            push @SUMMARY, "\t$line";
        }
        if ( $line =~ /mine/ ) {
            push @SUMMARY, "> ps output contains 'mine' could indicate a bitcoin mining hack:";
            push @SUMMARY, "\t$line";
        }
        if ( $line =~ /cryptonight/ ) {
            push @SUMMARY, "> ps output contains 'cryptonight' could indicate a bitcoin mining hack:";
            push @SUMMARY, "\t$line";
        }
        if ( $line =~ /manero/ ) {
            push @SUMMARY, "> ps output contains 'manero' could indicate a bitcoin mining hack:";
            push @SUMMARY, "\t$line";
        }
        if ( $line =~ /zcash/ ) {
            push @SUMMARY, "> ps output contains 'zcash' could indicate a bitcoin mining hack:";
            push @SUMMARY, "\t$line";
        }
        if ( $line =~ /xmr-stak/ ) {
            push @SUMMARY, "> ps output contains 'xmr-stak' could indicate a bitcoin mining hack:";
            push @SUMMARY, "\t$line";
        }
        if ( $line =~ /xmrig/ ) {
            push @SUMMARY, "> ps output contains 'xmrig' could indicate a bitcoin mining hack:";
            push @SUMMARY, "\t$line";
        }
        if ( $line =~ /xm2sg/ ) {
            push @SUMMARY, "> ps output contains 'xm2sg' could indicate a bitcoin mining hack:";
            push @SUMMARY, "\t$line";
        }
        if ( $line =~ /DSST/ ) {
            push @SUMMARY, "> ps output contains 'DSST' could indicate a bitcoin mining hack:";
            push @SUMMARY, "\t$line";
        }
        if ( $line =~ /pty.spwan\(\"\/bin\/sh\"\)/ ) {
            push @SUMMARY, "> ps output contains 'pty.spwan(\"/bin/ssh\")' indicates potential compromise";
            push @SUMMARY, "\t$line";
        }
		if ( $line =~ /xmr.crypto-pool.fr/ ) { 
            push @SUMMARY, "> ps output contains 'xmr.crypto-pool.fr' indicates potential compromise";
            push @SUMMARY, "\t$line";
		}
		if ( $line =~ /xmrpool/ ) { 
            push @SUMMARY, "> ps output contains 'xmrpool' indicates potential compromise";
            push @SUMMARY, "\t$line";
		}
		if ( $line =~ /stratum.f2pool.com/ ) { 
            push @SUMMARY, "> ps output contains 'stratum.f2pool.com' indicates potential compromise";
            push @SUMMARY, "\t$line";
		}
		if ( $line =~ /\/var\/tmp\/java/ ) { 
            push @SUMMARY, "> ps output contains '/var/tmp/java' indicates potential compromise";
            push @SUMMARY, "\t$line";
		}
		if ( $line =~ /ddgs/ ) { 
            push @SUMMARY, "> ps output contains 'ddgs' indicates potential compromise";
            push @SUMMARY, "\t$line";
		}
		if ( $line =~ /qW3xT/ ) { 
            push @SUMMARY, "> ps output contains 'qW3xT' indicates potential compromise";
            push @SUMMARY, "\t$line";
		}
		if ( $line =~ /t00ls.ru/ ) { 
            push @SUMMARY, "> ps output contains 't00ls.ru' indicates potential compromise";
            push @SUMMARY, "\t$line";
		}
		if ( $line =~ /\/var\/tmp\/sustes/ ) { 
            push @SUMMARY, "> ps output contains '/var/tmp/sustes' indicates potential compromise";
            push @SUMMARY, "\t$line";
		}
		if ( $line =~ /biosetjenkins/ ) { 
            push @SUMMARY, "> ps output contains 'biosetjenkins' indicates potential compromise";
            push @SUMMARY, "\t$line";
		}
		if ( $line =~ /AnXqV.yam/ ) { 
            push @SUMMARY, "> ps output contains 'AnXqV.yam' indicates potential compromise";
            push @SUMMARY, "\t$line";
		}
		if ( $line =~ /Loopback/ ) { 
            push @SUMMARY, "> ps output contains 'Loopback' indicates potential compromise";
            push @SUMMARY, "\t$line";
		}
		if ( $line =~ /httpntp/ ) { 
            push @SUMMARY, "> ps output contains 'httpntp' indicates potential watchdog coin miner compromise";
            push @SUMMARY, "\t$line";
		}
		if ( $line =~ /ftpsdns/ ) { 
            push @SUMMARY, "> ps output contains 'ftpsdns' indicates potential watchdog coin miner compromise";
            push @SUMMARY, "\t$line";
		}
    }
}

sub bitcoin_chk {
    my $xmrig_cron = qx[ grep '\.xmr' /var/spool/cron/* ];
    if ($xmrig_cron) {
        push @SUMMARY, "> Found evidence of possilbe bitcoin miner: " . CYAN $xmrig_cron;
    }
    my $xm2sg_socket = qx[ netstat -plant | grep xm2sg ];
    if ($xm2sg_socket) {
        push @SUMMARY, "> Found evidence of possible bitcoin miner: " . CYAN $xm2sg_socket;
    }
    if ( -e ("/tmp/.FILE/stak /") ) {
        my $FILE_stak = qx[ stat -c "%U %n" '/tmp/.FILE/stak /' ];
        if ($FILE_stak) {
            push @SUMMARY, "> Found evidence of a bitcoin miner: " . CYAN $FILE_stak;
        }
    }
    if ( -e ("/tmp/e3ac24a0bcddfacd010a6c10f4a814bc") ) {
        push @SUMMARY, "> Found evidence of the SpeakUp Trojan: ";
    }
	my @HasPastebinURL=qx[ grep -srl 'pastebin' /etc/cron* ];
    my $PastebinCnt=@HasPastebinURL;
    my $PastebinLine="";
	if ($PastebinCnt > 0) { 
        push @SUMMARY, "> Found pastebin URL's in cron files: ";
        foreach $PastebinLine(@HasPastebinURL) { 
            chomp($PastebinLine);
            push @SUMMARY, CYAN "\t\\_ $PastebinLine";
		}
	}
}

sub get_process_list {
    return split /\n/, timed_run( 0, 'ps', 'axwwwf', '-o', 'user,pid,cmd' );
}

sub check_ssh {
    my @ssh_errors;
    my $ssh_verify;
    foreach my $rpm (qx(rpm -qa openssh*)) {
        chomp($rpm);
        $ssh_verify = qx(rpm -V $rpm | egrep -v 'ssh_config|sshd_config|pam.d|/usr/libexec/openssh/ssh-keysign|/usr/bin/ssh-agent');
        if ( $ssh_verify ne '' ) {
            push( @ssh_errors, " RPM verification on $rpm failed:\n" );
            push( @ssh_errors, " $ssh_verify" );
        }
    }
    my $keyutils_verify = qx(rpm -V keyutils-libs);
    if ( $keyutils_verify ne "" ) {
        push( @ssh_errors, " RPM verification on keyutils-libs failed:\n" );
        push( @ssh_errors, " $keyutils_verify" );
    }
    my @sshd_process_found = qx(ps aux | grep "sshd: root@" | egrep -v 'pts|priv');
    if ( @sshd_process_found and $sshd_process_found[0] =~ 'root' ) {
        push( @ssh_errors, " Suspicious SSH process(es) found:\n" );
        push( @ssh_errors, " $sshd_process_found[0]" );
    }
    if (@ssh_errors) {
        push @SUMMARY, "> System has detected the presence of a *POSSIBLY* compromised SSH:\n";
        foreach (@ssh_errors) {
            push( @SUMMARY, $_ );
        }
    }
}

sub check_lib {
	my @dirs = qw( /lib /lib64 /usr/lib /usr/lib64 /usr/local/include /usr/local/include64 );
	my $dir="";
	my @AllDirs=undef;
	my @array=undef;
	foreach $dir (@dirs) { 
		chomp($dir);
		next unless -d $dir;
		@array = File::Find::Rule->directory->in($dir);
		push @AllDirs,@array;
	}
	my $line="";
	splice(@AllDirs,0,1);
	my @RPMNotOwned=undef;
	foreach $line(@AllDirs) { 
		chomp($line);
		next if $line =~ m{/usr/lib/systemd/system|/lib/modules|/lib/firmware|/usr/lib/vmware-tools|/lib64/xtables|jvm|php|perl5|/usr/lib/ruby|python|golang|fontconfig};
		next if -d $line;
		my $NotOwned=qx[ rpm -qf $line | grep 'not owned' ];
		next unless($NotOwned);
		push @RPMNotOwned, $NotOwned;
	}
	splice(@RPMNotOwned,0,1);
    if (@RPMNotOwned) {
        push @SUMMARY, "> Found library files not owned by an RPM, *MAY* indicate a compromise\n> or could be custom installed by an administrator.";
        foreach (@RPMNotOwned) {
			chomp($_);
            push( @SUMMARY, "\t\\_ " . $_ );
        }
    }
}

sub get_process_pid_hash ($) {
    my ($href) = @_;
    for ( split /\n/, timed_run( 0, 'ps', 'axwww', '-o', 'user,pid,ppid,cmd' ) ) {

        # nobody    5403  1666 /usr/local/apache/bin/httpd -k start -DSSL
        if (m{ ^ ([^\s]+) \s+ (\d+) \s+ (\d+) \s+ (.*?) \s* $ }xms) {
            ${$href}{$2}{USER} = $1;
            ${$href}{$2}{PPID} = $3;
            ${$href}{$2}{CMD}  = $4;
        }
    }
}

sub get_ipcs_hash ($) {
    my ($href) = @_;
    my $header = 0;
    for ( split /\n/, timed_run( 0, 'ipcs', '-m', '-p' ) ) {
        if ( $header == 0 ) {
            $header = 1 if m/^ shmid \s+ owner \s+ cpid \s+ lpid \s* $/ix;
            next;
        }
        my @ipcs = split( /\s+/, $_, 5 );
        push @{ ${$href}{ $ipcs[1] }{'mp'} }, {    # Key by owner, type 'mp' (-m -p output)
            'shmid' => $ipcs[0],
            'cpid'  => $ipcs[2],
            'lpid'  => $ipcs[3]
        };
    }
}

sub timed_run_trap_stderr {
    my ( $timer, @PROGA ) = @_;
    $timer = $timer ? $timer : 25;
    return if ( substr( $PROGA[0], 0, 1 ) eq '/' && !-x $PROGA[0] );
    open( my $save_stderr_fh, '>&STDERR' );
    open( STDERR, '>', '/dev/null' );
    my $output   = "";
    my $complete = 0;
    my $pid;
    my $fh;
    eval {
        local $SIG{'__DIE__'} = 'DEFAULT';
        local $SIG{'ALRM'} = sub { $output = ""; print RED ON_BLACK "Timeout while executing: " . join( ' ', @PROGA ) . "\n"; die; };
        alarm($timer);
        if ( $pid = open( $fh, '-|' ) ) {
            local $/;
            $output = readline($fh);
            close($fh);
        }
        elsif ( defined $pid ) {
            open( STDIN, '<', '/dev/null' );
            open( STDERR, '>&STDOUT' );
            exec(@PROGA) or exit 1;
        }
        else {
            warn 'Error while executing: [' . join( ' ', @PROGA ) . ']: ' . $!;
            alarm(0);
            open( STDERR, '>&=' . fileno($save_stderr_fh) );
            return "";
        }
        $complete = 1;
        alarm 0;
    };
    alarm 0;
    if ( !$complete && $pid && $pid > 0 ) {
        kill( 15, $pid );    #TERM
        sleep(2);            # Give the process a chance to die 'nicely'
        kill( 9, $pid );     #KILL
    }
    open( STDERR, '>&=' . fileno($save_stderr_fh) );
    return $output;
}

sub timed_run {
    my ( $timer, @PROGA ) = @_;
    $timer = $timer ? $timer : 25;
    return if ( substr( $PROGA[0], 0, 1 ) eq '/' && !-x $PROGA[0] );
    open( my $save_stderr_fh, '>&STDERR' );
    open( STDERR, '>', '/dev/null' );
    my $output   = "";
    my $complete = 0;
    my $pid;
    my $fh;
    eval {
        local $SIG{'__DIE__'} = 'DEFAULT';
        local $SIG{'ALRM'} = sub { $output = ""; print RED ON_BLACK "Timeout while executing: " . join( ' ', @PROGA ) . "\n"; die; };
        alarm($timer);
        if ( $pid = open( $fh, '-|' ) ) {
            local $/;
            $output = readline($fh);
            close($fh);
        }
        elsif ( defined $pid ) {
            open( STDIN, '<', '/dev/null' );
            exec(@PROGA) or exit 1;
        }
        else {
            warn 'Error while executing: [' . join( ' ', @PROGA ) . ']: ' . $!;
            alarm(0);
            open( STDERR, '>&=' . fileno($save_stderr_fh) );
            return "";
        }
        $complete = 1;
        alarm 0;
    };
    alarm 0;
    if ( !$complete && $pid && $pid > 0 ) {
        kill( 15, $pid );
        sleep(2);
        kill( 9, $pid );
    }
    open( STDERR, '>&=' . fileno($save_stderr_fh) );
    return $output;
}

sub check_preload {
    return unless ( -e ("/etc/ld.so.preload") );
    my $libcrypt_so = qx[ grep '/usr/lib64/libcrypt.so.1.1.0' /etc/ld.so.preload ];
    if ($libcrypt_so) {
        print_warn('Found /usr/lib64/libcrypt.so.1.1.0 in /etc/ld.so.preload - Root Compromised!');
    }
    my $libconv_so = qx[ grep 'libconv.so' /etc/ld.so.preload ];
    if ($libconv_so) {
        print_warn('Found libconv.so in /etc/ld.so.preload - Root Compromised!');
    }
}

sub create_summary {
    open( my $CSISUMMARY, '>', "$csidir/summary" )
      or die("Cannot create CSI summary file $csidir/summary: $!\n");
    foreach (@SUMMARY) {
        print $CSISUMMARY $_, "\n";
    }
    close($CSISUMMARY);
    my $clamlog = qx[ find $csidir -name '*_clamscan.log' ];
    if ($clamlog) {
        print_info("Don't forget to review $clamlog");
    }
}

sub dump_summary {
    if ( @SUMMARY == 0 ) {
        unlink("$csidir/summary");
    }
    else {
        create_summary();
        print_warn('The following negative items were found:');
        foreach (@SUMMARY) {
            print BOLD YELLOW $_ . "\n";
        }
        print_normal('');
        my $isCpanelSupport = get_login_ip();
        if ($isCpanelSupport) {
            print_separator('cPanel Analysts: If you believe there are negative items that warrant escalation, please read over https://cpanel.wiki/display/LS/CSIEscalations');
            print_separator('You need to understand exactly what the output is that you are seeing before escalating this ticket to L3.');
            print_normal('');
        }
        else {
            print_separator('If you believe there are negative items, you should consult with your system administrator or a security professional.');
            print_separator('If you need a system administrator, one can probably be found by going to https://go.cpanel.net/sysadmin');
            print_separator('Note: cPanel Support cannot assist you with any negative issues found.');
        }
        print_normal('');
    }
}

sub print_normal {
    my $text = shift;
    print "$text\n";
}

sub print_normal_chomped {
    my $text = shift;
    print "$text";
}

sub print_separator {
    my $text = shift;
    print BOLD BLUE "$text\n";
}

sub print_header {
    my $text = shift;
    print BOLD CYAN "$text\n";
}

sub print_status {
    my $text = shift;
    print YELLOW "$text\n";
}

sub print_summary {
    my $text = shift;
    print BOLD YELLOW "$text\n";
}

sub print_info {
    my $text = shift;
    print BOLD GREEN "[INFO]: $text\n";
}

sub print_warn {
    my $text = shift;
    print BOLD RED "[WARN]: $text\n";
}

sub print_error {
    my $text = shift;
    print BOLD MAGENTA "**[ERROR]**: $text\n";
}

# BEGIN MALWARE CHEKCS HERE

sub check_for_eggdrop { 
    my @dirs  = qw( /tmp );
    my @files = qw(
		.user
		.psy 
	);
    for my $dir (@dirs) {
		for my $file (@files) {
            if ( -f "${dir}/${file}" and not -z "${dir}/${file}" ) {
				push(@SUMMARY, "Possible eggdrop IRC Bot found\n\t\\_ ${dir}/${file}");
				vtlink("${dir}/${file}");
            }
        }
    }
}

sub check_for_korkerds {
    my @dirs  = qw( /bin /etc /usr/sbin /usr/local/lib /tmp /tmp/systemd-private-afjdhdicjijo473skiosoohxiskl573q-systemd-timesyncc.service-g1g5qf/cred/fghhhh/data );
    my @files = qw(
      httpdns
      netdns
      libdns.so
      kworkerds
      zigw
      gmbpr
      watchdog
      config.json
      config.txt
      cpu.txt
      pools.txt
      .tmpc
      .wwwwwwweeeeeeeeeeepaasss
    );
    my $bad_libs;

    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            if ( -f "${dir}/${file}" and not -z "${dir}/${file}" ) {
                $bad_libs .= "${dir}/${file}";
            }
        }
    }
    my $netstatcheck = qx[ netstat -nap | grep ':56415' ];
    if ($netstatcheck) {
        push( @SUMMARY, "> [Possible rootkit: KORKERDS] - " . CYAN "Evidence of the Coinminer.Linux.KORKERDS.AB Rootkit found.\nSuspicious socket listening on one or more of the following ports\n$netstatcheck" );
    }
    if ($bad_libs) {
        push( @SUMMARY, "> [Possible rootkit: KORKERDS] - " . CYAN "Evidence of the Coinminer.Linux.KORKERDS.AB Rootkit found.\n" );
        vtlink($bad_libs);
    }
}

sub check_for_kthrotlds { 
	if (-e("/usr/bin/\[kthrotlds\]")) {
		push( @SUMMARY, "> [Possible rootkit: Linux/CoinMiner.AP] - " . CYAN "Evidence of Linux/CoinMiner.AP rootkit found." );
   		vtlink("/usr/bin/\[kthrotlds\]");
	}
	else { 
		my @dirs  = qw( /root /root/.cache /etc/cron.d );
   		my @files = qw( .kswapd .a .favicon.ico .ntp .sysud .editorinfo .rm .cd root );
		my $fullpath;
   		for my $dir (@dirs) {
   			next if !-e $dir;
   			for my $file (@files) {
   				$fullpath = $dir . "/" . $file;
   				stat $fullpath;
   				if ( -f _ and not -z _ ) {
					push( @SUMMARY, "> Possible Rootkit found. - " . CYAN "Evidence of bitcoin miner found." );
					push( @SUMMARY, "\t \\_ " . $fullpath . " found" );
                    vtlink($fullpath);
   				}
   			}
		}
	}
}

sub check_for_cdorked_A {
    return unless defined $HTTPD_PATH;
    return unless -f $HTTPD_PATH;
    my $max_bin_size = 10_485_760;
	my $fStat=stat($HTTPD_PATH);
	my $FileSize=$fStat->size;
    return if ( $FileSize > $max_bin_size );
    my $has_cdorked = 0;
    my $signature;
    my @apache_bins = ();
    push @apache_bins, $HTTPD_PATH;

    for my $process (@process_list) {
        if ( $process =~ m{ \A root \s+ (\d+) [^\d]+ $HTTPD_PATH }xms ) {
            my $pid          = $1;
            my $proc_pid_exe = "/proc/" . $pid . "/exe";
            if ( -l $proc_pid_exe && readlink($proc_pid_exe) =~ m{ \(deleted\) }xms ) {
                next if ( ( stat($proc_pid_exe) )[7] > $max_bin_size );
                push @apache_bins, $proc_pid_exe;
            }
        }
    }
    for my $check_bin (@apache_bins) {
        my $httpd;
        if ( open my $fh, '<', $check_bin ) {
            local $/;
            $httpd = <$fh>;
            close $fh;
        }
        next if !$httpd;

        if ( $httpd =~ /(open_tty|hangout|ptsname|Qkkbal)/ ) {
            $signature   = $check_bin . ": \"" . $1 . "\"";
            $has_cdorked = 1;
            last;
        }
    }
    if ( $has_cdorked == 1 ) {
        push( @SUMMARY, "> [Possible rootkit: CDORKED A] - " . CYAN "Evidence of CDORKED A Rootkit found." );
    }
}

sub check_for_cdorked_B {
    my $has_cdorked_b = 0;
    my @files = ( '/usr/sbin/arpd ', '/usr/sbin/tunelp ', '/usr/bin/s2p ' );
    my $cdorked_files;
    for my $file (@files) {
        if ( -e $file ) {
            $has_cdorked_b = 1;
            $cdorked_files .= "[$file] ";
        }
    }
    if ( $has_cdorked_b == 1 ) {
        push( @SUMMARY, "> [Possible rootkit: CDORKED B] - " . CYAN "Evidence of CDORKED B Rootkit found.\n\t Found " . $cdorked_files . " [Note space at end of files]" );
    }
}

sub check_for_libkeyutils_filenames {
    my $bad_libs;
    my @dirs  = qw( /lib /lib64 /usr/include /usr/bin );
    my @files = qw(
      libkeyutils.so.1.9
      libkeyutils-1.2.so.0
      libkeyutils-1.2.so.2
      libkeyutils.so.1.3.0
      libkeyutils.so.1.3.2
      libns2.so
      libns5.so
      libpw3.so
      libpw5.so
      libsbr.so
      libslr.so
      libtsr.so
	  libhdx.so
      tls/libkeyutils.so.1
      tls/libkeyutils.so.1.5
	  ide.h
	  netda.h
	  pwd2.h
	  out.h
	  sys/record.h
	  ssd
    );

    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            if ( -f "${dir}/${file}" and not -z "${dir}/${file}" ) {
                $bad_libs .= "${dir}/${file}\n";
				chomp($bad_libs);
            }
        }
    }
    if ($bad_libs) {
        push( @SUMMARY, "> [Possible rootkit: Ebury/Libkeys] - " . CYAN "Evidence of Ebury/Libkeys Rootkit found" );
        vtlink($bad_libs);
    }
}

sub check_sha1_sigs_libkeyutils {
    return if !$LIBKEYUTILS_FILES_REF;
    my $trojaned_lib;
    my @checksums = qw(
      09c8af3be4327c83d4a7124a678bbc81e12a1de4
      1a9aff1c382a3b139b33eeccae954c2d65b64b90
      267d010201c9ff53f8dc3fb0a48145dc49f9de1e
      2e571993e30742ee04500fbe4a40ee1b14fa64d7
      2fc132440bafdbc72f4d4e8dcb2563cc0a6e096b
      39ec9e03edb25f1c316822605fe4df7a7b1ad94a
      3c5ec2ab2c34ab57cba69bb2dee70c980f26b1bf
      471ee431030332dd636b8af24a428556ee72df37
      58f185c3fe9ce0fb7cac9e433fb881effad31421
      5d3ec6c11c6b5e241df1cc19aa16d50652d6fac0
      74aa801c89d07fa5a9692f8b41cb8dd07e77e407
      7adb38bf14e6bf0d5b24fa3f3c9abed78c061ad1
      899b860ef9d23095edb6b941866ea841d64d1b26
      8daad0a043237c5e3c760133754528b97efad459
      8f75993437c7983ac35759fe9c5245295d411d35
      9bb6a2157c6a3df16c8d2ad107f957153cba4236
      9e2af0910676ec2d92a1cad1ab89029bc036f599
      a7b8d06e2c0124e6a0f9021c911b36166a8b62c5
      adfcd3e591330b8d84ab2ab1f7814d36e7b7e89f
      b8508fc2090ddee19a19659ea794f60f0c2c23ff
      bbce62fb1fc8bbed9b40cfb998822c266b95d148
      bf1466936e3bd882b47210c12bf06cb63f7624c0
      d552cbadee27423772a37c59cb830703b757f35e
      e14da493d70ea4dd43e772117a61f9dbcff2c41c
      e2a204636bda486c43d7929880eba6cb8e9de068
      f1ada064941f77929c49c8d773cbad9c15eba322
    );

    for my $lib (@$LIBKEYUTILS_FILES_REF) {
        next unless my $checksum = timed_run( 0, 'sha1sum', "$lib" );
        chomp $checksum;
        $checksum =~ s/\s.*//g;
        if ( grep { /$checksum/ } @checksums ) {
        	push( @SUMMARY, "> [Possible rootkit: Ebury/Libkeys] - " . CYAN "Evidence of Ebury/Libkeys Rootkit found." );
        	vtlink($lib);
            last;
        }
    }
}

sub check_for_evasive_libkey { 
	my $EvasiveLibKey=qx[ strings /etc/ld.so.cache |grep tls/ ];
	if ($EvasiveLibKey) { 
        push( @SUMMARY, "> [Possible rootkit: Ebury/Libkeys] - " . CYAN "Hidden/Evasive evidence of Ebury/Libkeys Rootkit found.\n\t \\_ TECH-759" );
	}
}

sub check_for_unowned_libkeyutils_files {
    return if !$LIBKEYUTILS_FILES_REF;
    my @unowned_libs;
    for my $lib (@$LIBKEYUTILS_FILES_REF) {
        chomp( my $rpm_check = timed_run( 0, 'rpm', '-qf', "$lib" ) );
        if ( $rpm_check =~ /owned/ ) {
            push @unowned_libs, $lib;
        }
    }
    if (@unowned_libs) {
        push( @SUMMARY, "> [Possible rootkit: Ebury/Libkeys] - " . CYAN "Evidence of Ebury/Libkeys Rootkit found." );
		for my $unowned_lib(@unowned_libs) { 
			vtlink($unowned_lib);
		}
    }
}

sub check_sha1_sigs_httpd {
    return unless defined $HTTPD_PATH;
    return if !-e $HTTPD_PATH;
    my $infected = 0;
    return unless my $sha1sum = timed_run( 0, 'sha1sum', $HTTPD_PATH );
    if ( $sha1sum =~ m{ \A (\S+) \s }xms ) {
        $sha1sum = $1;
    }
    my @sigs = qw(
      0004b44d110ad9bc48864da3aea9d80edfceed3f
      03592b8147e2c84233da47f6e957acd192b3796a
      0eb1108a9d2c9fe1af4f031c84e30dcb43610302
      10c6ce8ee3e5a7cb5eccf3dffd8f580e4fb49089
      149cf77d2c6db226e172390a9b80bc949149e1dc
      1972616a731c9e8a3dbda8ece1072bd16c44aa35
      24e3ebc0c5a28ba433dfa69c169a8dd90e05c429
      4f40bb464526964ba49ed3a3b2b2b74491ea89a4
      5b87807b4a1796cfb1843df03b3dca7b17995d20
      62c4b65e0c4f52c744b498b555c20f0e76363147
      78c63e9111a6701a8308ad7db193c6abb17c65c4
      858c612fe020fd5089a05a3ec24a6577cbeaf7eb
      9018377c0190392cc95631170efb7d688c4fd393
      a51b1835abee79959e1f8e9293a9dcd8d8e18977
      a53a30f8cdf116de1b41224763c243dae16417e4
      ac96adbe1b4e73c95c28d87fa46dcf55d4f8eea2
      dd7846b3ec2e88083cae353c02c559e79124a745
      ddb9a74cd91217cfcf8d4ecb77ae2ae11b707cd7
      ee679661829405d4a57dbea7f39efeb526681a7f
      fc39009542c62a93d472c32891b3811a4900628a
      fdf91a8c0ff72c9d02467881b7f3c44a8a3c707a
    );

    for my $sig (@sigs) {
        if ( $sha1sum eq $sig ) {
            $infected = 1;
            last;
        }
    }
    if ( $infected == 1 ) {
        push( @SUMMARY, "> [Possible rootkit: Apache Binary] - " . CYAN "Evidence of hacked Apache binary found.\n\t Found " . $sha1sum );
    }
}

sub check_sha1_sigs_named {
    my $named = '/usr/sbin/named';
    return if !-e $named;
    my $infected = 0;
    return unless my $sha1sum = timed_run( 0, 'sha1sum', $named );
    if ( $sha1sum =~ m{ \A (\S+) \s }xms ) {
        $sha1sum = $1;
    }
    my @sigs = qw(
      42123cbf9d51fb3dea312290920b57bd5646cefb
      ebc45dd1723178f50b6d6f1abfb0b5a728c01968
    );
    for my $sig (@sigs) {
        if ( $sha1sum eq $sig ) {
            $infected = 1;
            last;
        }
    }
    if ( $infected == 1 ) {
        push( @SUMMARY, "> [Possible rootkit: Named Binary] - " . CYAN "Evidence of hacked Named binary found.\n\t Found " . $sha1sum );
    }
}

sub check_sha1_sigs_ssh {
    my $ssh = '/usr/bin/ssh';
    return if !-e $ssh;
    my $infected = 0;
    return unless my $sha1sum = timed_run( 0, 'sha1sum', $ssh );
    if ( $sha1sum =~ m{ \A (\S+) \s }xms ) {
        $sha1sum = $1;
    }
    my @sigs = qw(
      c4c28d0372aee7001c44a1659097c948df91985d
      fa6707c7ef12ce9b0f7152ca300ebb2bc026ce0b
    );
    for my $sig (@sigs) {
        if ( $sha1sum eq $sig ) {
            $infected = 1;
            last;
        }
    }
    if ( $infected == 1 ) {
        push( @SUMMARY, "> [Possible rootkit: SSH Binary] - " . CYAN "Evidence of hacked SSH binary found.\n\t Found " . $sha1sum );
    }
}

sub check_sha1_sigs_ssh_add {
    my $ssh_add = '/usr/bin/ssh-add';
    return if !-e $ssh_add;
    my $infected = 0;
    return unless my $sha1sum = timed_run( 0, 'sha1sum', $ssh_add );
    if ( $sha1sum =~ m{ \A (\S+) \s }xms ) {
        $sha1sum = $1;
    }
    my @sigs = qw(
      575bb6e681b5f1e1b774fee0fa5c4fe538308814
    );
    for my $sig (@sigs) {
        if ( $sha1sum eq $sig ) {
            $infected = 1;
            last;
        }
    }
    if ( $infected == 1 ) {
        push( @SUMMARY, "> [Possible rootkit: SSH-ADD Binary] - " . CYAN "Evidence of hacked SSH-ADD binary found.\n\t Found " . $sha1sum );
    }
}

sub check_sha1_sigs_sshd {
    my $sshd = '/usr/sbin/sshd';
    return if !-e $sshd;
    my $infected = 0;
    return unless my $sha1sum = timed_run( 0, 'sha1sum', $sshd );
    if ( $sha1sum =~ m{ \A (\S+) \s }xms ) {
        $sha1sum = $1;
    }
    my @sigs = qw(
      0daa51519797cefedd52864be0da7fa1a93ca30b
      4d12f98fd49e58e0635c6adce292cc56a31da2a2
      7314eadbdf18da424c4d8510afcc9fe5fcb56b39
      98cdbf1e0d202f5948552cebaa9f0315b7a3731d
    );
    for my $sig (@sigs) {

        if ( $sha1sum eq $sig ) {
            $infected = 1;
            last;
        }
    }
    if ( $infected == 1 ) {
        push( @SUMMARY, "> [Possible rootkit: sshd Binary] - " . CYAN "Evidence of hacked sshd binary found.\n\t Found " . $sha1sum );
    }
}

sub check_for_ebury_ssh_G {
    my $ssh = '/usr/bin/ssh';
    return if !-e $ssh;
    return if !-f _;
    return if !-x _;
    return if -z _;
    my $ssh_version = timed_run_trap_stderr( 0, $ssh, '-V' );
    return if $ssh_version !~ m{ \A OpenSSH_5 }xms;
    my $ssh_G = timed_run_trap_stderr( 0, $ssh, '-G' );

    if ( $ssh_G !~ /illegal|unknown/ ) {
        push( @SUMMARY, "> [Possible rootkit: ssh Binary] - " . CYAN "Evidence of hacked ssh binary found.\n\t " . $ssh . " -G did not return either 'illegal' or 'unknown'" );
    }
}

sub check_for_ebury_ssh_banner {
    my ( $host, $port, $ssh_banner );
    my $ssh_connection = $ENV{'SSH_CONNECTION'};
    return if !$ssh_connection;
    if ( $ssh_connection =~ m{ \s (\d+\.\d+\.\d+\.\d+) \s (\d+) \z }xms ) {
        ( $host, $port ) = ( $1, $2 );
    }
    return if !$host;
    return if !$port;
    my $sock = IO::Socket::INET->new(
        PeerAddr => $host,
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    ) or return;
    $ssh_banner = readline $sock;
    close $sock;
    return if !$ssh_banner;
    chomp $ssh_banner;
    if ( $ssh_banner =~ m{ \A SSH-2\.0-[0-9a-f]{22,46} }xms ) {
        push( @SUMMARY, "> [Possible rootkit: ssh banner] - " . CYAN "Evidence of hacked ssh banner found.\n\t " . $ssh_banner . "." );
    }
}

sub check_for_ebury_ssh_shmem {
    return if !defined( $IPCS_REF->{root}{mp} );
    for my $href ( @{ $IPCS_REF->{root}{mp} } ) {
        my $shmid = $href->{shmid};
        my $cpid  = $href->{cpid};
        if ( $PROCESS_REF->{$cpid}{CMD} && $PROCESS_REF->{$cpid}{CMD} =~ m{ \A /usr/sbin/sshd \b }x ) {
            push( @SUMMARY, "> [Possible rootkit: SSHd Shared Memory] - " . CYAN "Evidence of hacked SSHd Shared Memory found.\n\t cpid: " . $cpid . " - shmid: " . $shmid . "." );
        }
    }
}

sub check_for_ebury_root_file {
    my $file = '/home/ ./root';
    if ( -e $file ) {
        push( @SUMMARY, "> [Possible rootkit: Ebury] - " . CYAN "Found hidden file: " . $file );
    }
}

sub check_for_ebury_3_digit_rpms {
    my $bad_rpms;
    for my $rpm (@RPM_LIST) {
        if ( $rpm =~ m{ \A openssh-(clients|server|\d)(.*)-(\d){3}\. }xms ) {
            $bad_rpms .= "\t$rpm\n";
        }
    }
    if ($bad_rpms) {
        push( @SUMMARY, "> [Possible rootkit: Ebury] - " . CYAN "3-digit RPM's: " . $bad_rpms );
    }
}

sub check_for_ebury_socket {
    return unless my $netstat_out = timed_run( 0, 'netstat', '-nap' );
    my $found = 0;
    for my $line ( split( '\n', $netstat_out ) ) {
        if ( $line =~ m{@/proc/udevd} ) {
            push( @SUMMARY, "> [Possible rootkit: Ebury] - " . CYAN "Ebury socket connection found: " . $line );
            $found = 1;
            last;
        }
    }
}

sub check_for_ncom_filenames {
    my @bad_libs;
    my @dirs  = qw( /lib /lib64 );
    my @files = qw(
      libnano.so.4
      libncom.so.4.0.1
      libselinux.so.4
    );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            my $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
                push @bad_libs, $fullpath;
            }
        }
    }
    if (@bad_libs) {
        push( @SUMMARY, "> [Possible rootkit: NCOM] - " . CYAN "Evidence of the NCOM Rootkit found: " );
        vtlink(@bad_libs);
    }
}

sub check_for_ELF_images { 
	my $ELFimages1 = File::Find::Rule->file()->name( '*.png' )->start( '/' );
	my $isELF="";
	my @ELFImages;
	while ( defined ( my $image = $ELFimages1->match ) ) { 
		$isELF = check_file_for_elf($image);
		if ($isELF) { 
			push(@ELFImages, "$image");
		}
	}
	my $ELFimages2 = File::Find::Rule->file()->name( '*.jpg' )->start( '/' );
	while ( defined ( my $image = $ELFimages2->match ) ) { 
		$isELF = check_file_for_elf($image);
		if ($isELF) { 
			push(@ELFImages, "$image");
		}
	}
	my $ELFimages3 = File::Find::Rule->file()->name( '*.gif' )->start( '/' );
	while ( defined ( my $image = $ELFimages3->match ) ) { 
		$isELF = check_file_for_elf($image);
		if ($isELF) { 
			push(@ELFImages, "$image");
		}
	}
	my $ELFimages4 = File::Find::Rule->file()->name( '*.jpeg' )->start( '/' );
	while ( defined ( my $image = $ELFimages4->match ) ) { 
		$isELF = check_file_for_elf($image);
		if ($isELF) { 
			push(@ELFImages, "$image");
		}
	}
	my $ELFImageCnt=@ELFImages;
	if ($ELFImageCnt > 0 ) { 
		push(@SUMMARY, "Found ELF binary file(s) masquerading as images:");
		my $ELFImage;
		foreach $ELFImage(@ELFImages) { 
			chomp($ELFImage);
			push @SUMMARY, CYAN "\t\\_ $ELFImage";
		}
	}
}

sub check_for_ngioweb { 
    return if (!-e "/etc/machine-id");
	return unless(  qx[ grep 'ddb0b49d10ec42c38b1093b8ce9ad12a' /etc/machine-id ] );
	push(@SUMMARY, "Found evidence of Linux.Ngioweb rootkit\n\t\\_ /etc/machine-id contains: ddb0b49d10ec42c38b1093b8ce9ad12a");
}

sub check_for_hiddenwasp { 
	my @bad_libs;
    my @dirs  = qw( /lib /sbin );
    my @files = qw(
      libselinux.so
      libselinux.a
      libselinux
	  .ifup-local
	);
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            my $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
                push @bad_libs, $fullpath;
            }
        }
    }
    if (@bad_libs) {
        push( @SUMMARY, "> [Possible rootkit: HiddenWasp] - " . CYAN "Evidence of the HiddenWasp Rootkit found: " );
        vtlink(@bad_libs);
    }
	if (-e ("/lib/libselinux.a")) {
		my $HIDESHELL=qx[ strings /lib/libselinux.a | grep 'HIDE_THIS_SHELL' ];
		if ($HIDESHELL) { 
        	push @SUMMARY, "> Found HIDE_THIS_SHELL in the /lib/libselinux.a file. Could indicate HiddenWasp rootkit";
		}
	}
    if ( -e ("/tmp/.bash") ) {
        push @SUMMARY, "> Found suspicious file '.bash' in /tmp directory. Could indicate HiddenWasp rootkit";
    }
    if ( qx[ env | grep 'I_AM_HIDDEN' ] ) {
        push @SUMMARY, "> Found I_AM_HIDDEN environment variable. Could indicate HiddenWasp rootkit";
    }
	if ( -e ("/var/sftp")) { 
        push @SUMMARY, "> Found /var/sftp directory. Could indicate HiddenWasp rootkit";
	}
    my $HWSocket = qx[ lsof -i tcp:61061 ];
    if ($HWSocket) {
        push @SUMMARY, "> Found socket listening on port 61061. Could indicate HiddenWasp rootkit";
	}
}

sub check_for_dirtycow_passwd {
    print_header("[ Checking for evidence of DirtyCow within /etc/passwd ]");
    return unless my $gecos = ( getpwuid(0) )[6];
    if ( $gecos eq "pwned" ) {
        push( @SUMMARY, "> [DirtyCow] - Evidence of FireFart/DirtyCow compromise found." );
        my $passwdBAK = qx[ stat -c "%n [Owned by %U]" /tmp/*passwd* ];
        push( @SUMMARY, "Possible backup of /etc/passwd found: $passwdBAK" ) unless ( !$passwdBAK );
    }
}

sub check_for_dirtycow_kernel {
    print_header("[ Checking if kernel is vulnerable to DirtyCow ]");
	logit("DirtyCow Kernel Check");
    if ( !("/usr/bin/rpm") ) {
        push( @SUMMARY, "RPM not installed - is this a CentOS server?" );
		logit("RPM not installed - is this a CentOS server?");
        return;
    }
    my $dc_kernel = qx[ uname -r ];
    chomp($dc_kernel);
    if ( $dc_kernel =~ m/stab/ ) {
        if ( $dc_kernel lt "2.6.32-042stab120.3" ) {
            push( @SUMMARY, "> Virtuozzo Kernel [$dc_kernel] is susceptible to DirtyCow [CVE-2016-5195]" );
            logit("Virtuozzo Kernel [$dc_kernel] is susceptible to DirtyCow");
        }
        else {
            logit("Virtuozzo Kernel version is greater than 2.6.32-042stab120.3 - Not susceptible to DirtyCow");
        }
        return;
    }
	if ( $dc_kernel =~ m/linode/ ) { 
        if ( $dc_kernel lt "4.8.3" ) {
            push( @SUMMARY, "> Linode Kernel [$dc_kernel] is susceptible to DirtyCow [CVE-2016-5195]" );
            logit("Linode Kernel [$dc_kernel] is susceptible to DirtyCow");
        }
        else {
            logit("Linode Kernel version is greater than 4.8.3 - Not susceptible to DirtyCow");
        }
        return;
	}
    if ( $dc_kernel =~ m/lve/ ) {
        my $KernelDate = qx[ uname -v ];
        chomp($KernelDate);
        my $KernelYear = substr( $KernelDate, -4 );
        if ( $KernelYear > 2016 ) {
            logit("CloudLinux Kernel [$dc_kernel] is patched against DirtyCow");
        }
        else {
            push( @SUMMARY, "> CloudLinux Kernel [$dc_kernel] is not patched against DirtyCow - Consider updating!" );
        }
        return;
    }
    my $RPMPATCH = qx[ rpm -q --changelog kernel | grep 'CVE-2016-5195' ];
    if ( $RPMPATCH =~ m/package kernel is not installed/ ) {
        my ($kernelver) = ( split( /-/, $dc_kernel ) )[0];
        chomp($kernelver);
        $kernelver =~ s/\.//g;
        if ( $kernelver < 4978 ) {
            push( @SUMMARY, "> This Kernel [$dc_kernel] is susceptible to DirtyCow [CVE-2016-5195]" );
        }
        else {
            logit("This Kernel version is greater than 4.9.77 - Not susceptible to DirtyCow");
        }
        return;
    }
    if ($RPMPATCH) {
        logit("Kernel [$dc_kernel] is patched against DirtyCow");
    }
    else {
        push( @SUMMARY, "> Kernel [$dc_kernel] is not patched against DirtyCow - Consider updating!" );
    }
}

sub check_for_dragnet {
    my $found = 0;
    if ( open my $fh, '<', '/proc/self/maps' ) {
        while (<$fh>) {
            if (m{ (\s|\/) libc\.so\.0 (\s|$) }x) {
                push( @SUMMARY, "> [Possible rootkit: Dragnet] - " . CYAN "Evidence of Dragnet Rootkit found.\n\t libc.so.0 was found in process maps." );
                $found = 1;
                last;
            }
        }
        close($fh);
    }
}

sub check_for_xor_ddos {
    my @libs = qw(
      /lib/libgcc.so
      /lib/libgcc.so.bak
      /lib/libgcc4.4.so
      /lib/libgcc4.so
      /lib/libudev.so
    );
    my @matched;

    for my $lib (@libs) {
        next if -l $lib;
        push @matched, $lib if -f $lib;
    }
    if (@matched) {
        push( @SUMMARY, "> [Possible rootkit: Linux/XoRDDoS] - " . CYAN "Evidence of the Linux/XoRDDoS Rootkit found: " );
        vtlink(@matched);
    }
}

sub check_for_abafar { 
	my @dirs = qw( /etc/X11 );
	my @files = qw(
		.pr
    );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            my $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
        		push( @SUMMARY, "> [Possible rootkit: Abafar] - " . CYAN "Evidence of the Linux/SSHDoor.AB Rootkit found: " );
        		vtlink($fullpath);
            }
        }
    }
}

sub check_for_akiva {
	my @dirs = qw( /usr/local/include );
	my @files = qw(
		uconf.h
    );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            my $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
        		push( @SUMMARY, "> [Possible rootkit: Akiva] - " . CYAN "Evidence of the Linux/SSHDoor.A Rootkit found." );
        		vtlink($fullpath);
            }
        }
    }
}

sub check_for_alderaan {
	my @dirs = qw( /etc );
	my @files = qw(
		gshadow--
    );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            my $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
        		push( @SUMMARY, "> [Possible rootkit: Alderaan] - " . CYAN "Evidence of the Linux/SSHDoor.AE Rootkit found." );
        		vtlink($fullpath);
            }
        }
    }
}

sub check_for_bashrootkit {
	my @dirs = qw( /tmp /etc/profile.d /usr/include );
	my @files = qw(
		.helpdd
		.h
		emacs.sh
		diskmanagerd
		kacpi_notify
    );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            my $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
        		push( @SUMMARY, "> [Possible rootkit: Bash Rootkit] - " . CYAN "Evidence of the Bash Rootkit found." );
        		vtlink($fullpath);
            }
        }
    }
}

sub check_for_anoat {
	my @dirs = qw( /usr/share/polkit-1 /usr/share/X11/sessmgr /usr/include/X11/sessmgr );
	my @files = qw(
		policy.in
		policy.out
		coredump.in
    );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            my $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
        		push( @SUMMARY, "> [Possible rootkit: Anoat] - " . CYAN "Evidence of the Linux/SSHDoor.AF Rootkit found." );
        		vtlink($fullpath);
            }
        }
    }
}

sub check_for_atollon {
	my @dirs = qw( /usr/share/man/hu /usr/share/man/man1 );
	my @files = qw(
		sd
    );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            my $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
        		push( @SUMMARY, "> [Possible rootkit: Atollon] - " . CYAN "Evidence of the Linux/SSHDoor.AT Rootkit found." );
        		vtlink($fullpath);
            }
        }
    }
}

sub check_for_bespin {
	my @dirs = qw( /var/tmp );
	my @files = qw(
		.pipe.sock
    );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            my $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
        		push( @SUMMARY, "> [Possible rootkit: Bespin] - " . CYAN "Evidence of the Linux/SSHDoor.BE Rootkit found." );
        		vtlink($fullpath);
            }
        }
    }
}

sub check_for_bonadan {
	my @dirs = qw( /usr/share/lsx );
	my @files = qw(
		.ig.swr
    );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            my $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
        		push( @SUMMARY, "> [Possible rootkit: Bonadan] - " . CYAN "Evidence of the Linux/SSHDoor.BO Rootkit found." );
        		vtlink($fullpath);
            }
        }
    }
}

sub check_for_kessel {
	my @dirs = qw( /tmp );
	my @files = qw(
		KCtbBo
    );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            my $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
        		push( @SUMMARY, "> [Possible rootkit: Kessel] - " . CYAN "Evidence of the Linux/SSHDoor.CK Rootkit found." );
        		vtlink($fullpath);
            }
        }
    }
}

sub check_for_quarren {
	my @dirs = qw( /usr/share/man/man5 );
	my @files = qw(
		tty1.5.gz
		ttyv.5.gz
    );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            my $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
        		push( @SUMMARY, "> [Possible rootkit: Quarren] - " . CYAN "Evidence of the Linux/SSHDoor.Q Rootkit found." );
        		vtlink($fullpath);
            }
        }
    }
}

sub check_for_polismassa {
	my @dirs = qw( /usr/share /usr/include /var/www/html /var/log );
	my @files = qw(
		boot.sync
		mbstring.h
		lol
		utmp
    );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            my $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
        		push( @SUMMARY, "> [Possible rootkit: Polis Massa] - " . CYAN "Evidence of the Linux/SSHDoor.P Rootkit found." );
        		vtlink($fullpath);
            }
        }
    }
}

sub check_for_onderon {
	my @dirs = qw( /usr/lib/mozilla/extensions /tmp /var/opt /usr/tmp /usr/local/share/man/man1 /etc/ssh /usr/share/man/man1 /usr/include /usr/lib/gcc/x86_64-redhat-linux );
	my @files = qw(
		mozzlia.ini
		zilog
		~tmp441
		power
		Openssh.1
		.0
		ssh_known_hosts
		.olog
		sn.h
    );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            my $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
        		push( @SUMMARY, "> [Possible rootkit: Onderon] - " . CYAN "Evidence of the Linux/SSHDoor.O Rootkit found." );
        		vtlink($fullpath);
            }
        }
    }
}

sub check_for_chandrila {
	my @dirs = qw( /usr/share/man );
	my @files = qw(
		.urandom
    );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            my $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
        		push( @SUMMARY, "> [Possible rootkit: Chandrila] - " . CYAN "Evidence of the Linux/SSHDoor.CH Rootkit found." );
        		vtlink($fullpath);
            }
        }
    }
}

sub check_for_coruscant {
	my @dirs = qw( /dev );
	my @files = qw(
		.ctrl
    );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            my $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
        		push( @SUMMARY, "> [Possible rootkit: Coruscant] - " . CYAN "Evidence of the Linux/SSHDoor.CD Rootkit found." );
        		vtlink($fullpath);
            }
        }
    }
}

sub check_for_crait {
	my @dirs = qw( /usr/share/man/man0 );
	my @files = qw(
		.cache
    );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            my $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
        		push( @SUMMARY, "> [Possible rootkit: Crait] - " . CYAN "Evidence of the Linux/SSHDoor.Cl Rootkit found." );
        		vtlink($fullpath);
            }
        }
    }
}

sub check_for_batuu {
	my @dirs = qw( /usr/lib );
	my @files = qw(
		libt1x.so.1.5
		libcurl.a.2.1
		libpanel.so.a.3
    );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            my $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
        		push( @SUMMARY, "> [Possible rootkit: Batuu] - " . CYAN "Evidence of the Linux/SSHDoor.BX Rootkit found." );
        		vtlink($fullpath);
            }
        }
    }
}

sub check_for_ando {
	my @dirs = qw( /usr/lib /etc/ssh );
	my @files = qw(
		libsoftokn3.so.0
		.sshd_auth
    );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            my $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
        		push( @SUMMARY, "> [Possible rootkit: Ando] - " . CYAN "Evidence of the Linux/SSHDoor.AN Rootkit found." );
        		vtlink($fullpath);
            }
        }
    }
}

sub check_for_bg_botnet {
    my @bg_files       = qw(
      /boot/pro
      /boot/proh
      /etc/atdd
      /etc/atddd
      /etc/cupsdd
      /etc/cupsddd
      /etc/dsfrefr
      /etc/fdsfsfvff
      /etc/ferwfrre
      /etc/gdmorpen
      /etc/gfhddsfew
      /etc/gfhjrtfyhuf
      /etc/ksapd
      /etc/ksapdd
      /etc/kysapd
      /etc/kysapdd
      /etc/rewgtf3er4t
      /etc/sdmfdsfhjfe
      /etc/sfewfesfs
      /etc/sfewfesfsh
      /etc/sksapd
      /etc/sksapdd
      /etc/skysapd
      /etc/skysapdd
      /etc/smarvtd
      /etc/whitptabil
      /etc/xfsdx
      /etc/xfsdxd
      /etc/rc.d/init.d/DbSecuritySpt
      /etc/rc.d/init.d/selinux
      /usr/bin/.sshd
      /usr/bin/bsd-port/getty
      /usr/bin/pojie
      /usr/lib/libamplify.so
      /var/.lug.txt
	  /lost+found/mimipenguin-master/kautomount--pid-file-var-run-au
    );
    my @root_bg_files = qw( /tmp/bill.lock /tmp/gates.lock /tmp/moni.lock /tmp/fdsfsfvff /tmp/gdmorpen /tmp/gfhjrtfyhuf /tmp/rewgtf3er4t /tmp/sfewfesfs /tmp/smarvtd /tmp/whitptabil );
	my @found_bg_files = grep { -e $_ } @bg_files;
    for my $file (@root_bg_files) {
        if ( -e $file && ( stat $file )[4] eq 0 ) {
            push( @found_bg_files, $file );
        }
    }
	return unless ( scalar @found_bg_files );
	push( @SUMMARY, "> [Possible rootkit: BG Botnet] - " . CYAN "Evidence of the BG Botnet Rootkit found." );
	vtlink(@found_bg_files);
}

sub check_for_elknot_rootkit { 
	my @elknot_files = qw (
		/tmp/tmpnam_[a-zA-Z]{5}
		/tmp/tmp.l
		/etc/init.d/upgrade
		/etc/init.d/python3.O
		/bin/update-rc.d
	);
	my @found_elknot_files = grep{ -e $_ } @elknot_files;
	push( @SUMMARY, "> [Possible rootkit: Elknot Rootkit] - " . CYAN "Evidence of the Elknot Rootkit found." );
	vtlink(@found_elknot_files);
}

sub check_for_UMBREON_rootkit {
    my $dir = '/usr/local/__UMBREON__';
    if ( chdir $dir ) {
        push( @SUMMARY, "> [Possible rootkit: UMBREON] - " . CYAN "Evidence of the UMBREON Rootkit found." );
		push( @SUMMARY, "\t \\_ " . $dir . "\n" );
    }
}

sub check_for_libms_rootkit {
    my $dir = '/lib/udev/x.modules';
    if ( chdir $dir ) {
        push( @SUMMARY, "> [Possible rootkit: LIBMS] - " . CYAN "Evidence of the LIBMS Rootkit found." );
		push( @SUMMARY, "\t \\_ " . $dir . "\n" );
    }
}

sub check_for_jynx2_rootkit {
    my @dirs = qw( /usr/bin64 /XxJynx );
	my @files = qw(
		3.so
		4.so
		reality.so
		jynx2.so
    );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            my $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
        		push( @SUMMARY, "> [Possible rootkit: Jynx2] - " . CYAN "Evidence of the Jynx2 Rootkit found." );
        		vtlink($fullpath);
            }
        }
    }
}

sub check_for_azazel_rootkit { 
    if ( qx[ env | grep 'HIDE_THIS_SHELL' ] ) {
        push @SUMMARY, "> Found HIDE_THIS_SHELL environment variable. Could indicate Azazel rootkit";
    }
}

sub check_for_shellbot {
    my @libs = qw(
      /lib/libgrubd.so
    );
    my @matched;
    for my $lib (@libs) {
        next if -l $lib;
        push @matched, $lib if -f $lib;
    }
    if (@matched) {
        push( @SUMMARY, "> [Possible rootkit: ShellBot] - " . CYAN "Evidence of the ShellBot Rootkit found." );
        vtlink(@matched);
    }
}

sub check_for_libkeyutils_symbols {
    local $ENV{'LD_DEBUG'} = 'symbols';
    my $output = timed_run_trap_stderr( 0, '/bin/true' );
    return unless $output;
    if ( $output =~ m{ /lib(keyutils|ns[25]|pw[35]|s[bl]r)\. }xms ) {
        push( @SUMMARY, "> [Possible rootkit: Ebury] - " . CYAN "Evidence of the Ebury Rootkit found in symbol table.\n\t\_ Run: LD_DEBUG=symbols /bin/true 2>&1 | egrep '/lib(keyutils|ns[25]|pw[35]|s[bl]r)\.' to confirm." );
    }
}

sub all_malware_checks {
    check_for_korkerds();
	check_for_kthrotlds();
    check_for_UMBREON_rootkit();
    check_for_libms_rootkit();
    check_for_jynx2_rootkit();
	check_for_azazel_rootkit();
    check_for_cdorked_A();
    check_for_cdorked_B();
    check_for_libkeyutils_symbols();
    check_for_libkeyutils_filenames();
	check_for_unowned_libkeyutils_files();
	check_for_evasive_libkey();
    check_sha1_sigs_libkeyutils();
    check_sha1_sigs_httpd();
    check_sha1_sigs_named();
    check_sha1_sigs_ssh();
    check_sha1_sigs_ssh_add();
    check_sha1_sigs_sshd();
    check_for_ebury_ssh_G();
    check_for_ebury_ssh_banner();
    check_for_ebury_ssh_shmem();
    check_for_ebury_root_file();
    check_for_ebury_socket();
    check_for_bg_botnet();
    check_for_dragnet();
    check_for_xor_ddos();
    check_for_shellbot();
	check_for_exim_vuln();
	check_for_eggdrop();
	check_for_abafar();
	check_for_akiva();
	check_for_alderaan();
	check_for_ando();
	check_for_anoat();
	check_for_atollon();
	check_for_batuu();
	check_for_bespin();
	check_for_bonadan();
	check_for_chandrila();
	check_for_coruscant();
	check_for_crait();
	check_for_kessel();
	check_for_onderon();
	check_for_polismassa();
	check_for_quarren();
    check_for_ncom_filenames();
	check_for_hiddenwasp();
	check_for_ngioweb();
    check_for_dirtycow_passwd();
    check_for_dirtycow_kernel();
}

sub get_httpd_path {
    if ( $EA4 && -x '/usr/sbin/httpd' ) {
        return '/usr/sbin/httpd';
    }
    if ( !$EA4 && -x '/usr/local/apache/bin/httpd' ) {
        return '/usr/local/apache/bin/httpd';
    }
    return;
}

sub check_for_touchfile {
    return if !-d $docdir;
    opendir( my $fh, $docdir ) or return;
    my @touchfiles = grep { /^\.cp\.([^\d]+)\.(\d{4}-\d{2}-\d{2})_([^_]+)_(\d+)$/ } readdir $fh;
    closedir $fh;
    return if ( scalar @touchfiles == 0 );
    for my $touchfile (@touchfiles) {
        if ( $touchfile =~ /^\.cp\.([^\d]+)\.(\d{4}-\d{2}-\d{2})_([^_]+)_(\d+)$/ ) {
            my ( $cptech, $date, $ipaddr, $ticket ) = ( $1, $2, $3, $4 );
            $date =~ s#-#/#g;
            $cptech = ucfirst $cptech;
            push( @SUMMARY, "> $cptech reported this server at $ipaddr as compromised on $date local server time in ticket $ticket" );
        }
    }
}

sub logit {
    my $Message2Log = $_[0];
    my $date        = `date`;
    chomp($Message2Log);
    chomp($date);
    open( CSILOG, ">>/root/CSI/csi.log" ) or die($!);
    print CSILOG "$date - $Message2Log\n";
    close(CSILOG);
}

sub uniq {
    my %seen;
    grep !$seen{$_}++, @_;
}

sub spin {
    my %spinner = ( '|' => '/', '/' => '-', '-' => '\\', '\\' => '|' );
    $spincounter = ( !defined $spincounter ) ? '|' : $spinner{$spincounter};
    print STDERR "\b$spincounter";
    print STDERR "\b";
}

sub alltrim() {
    my $string2trim = $_[0];
    $string2trim =~ s/^\s*(.*?)\s*$/$1/;
    return $string2trim;
}

sub userscan {
    my $lcUserToScan = $_[0];
	unlink("/root/CSI/csi_detections.txt") unless( ! -e "/root/CSI/csi_detections");
    logit("Running a user scan for $lcUserToScan");
    installClamAV() unless($skipClam);
    my $RealHome = Cpanel::PwCache::gethomedir($lcUserToScan);;
    if ( !( -e ("$RealHome") ) ) {
        print_warn("$lcUserToScan has no /home directory!");
        logit( $lcUserToScan . " has no /home directory!" );
        return;
    }
    my $isClamAVInstalled = qx[ whmapi1 servicestatus service=clamd | grep 'installed: 1' ];
    print_status("Checking for symlinks to other locations...");
    logit( "Checking for symlink hacks in " . $RealHome . "/public_html" );
    my @FINDSYMLINKHACKS = qx[ find $RealHome/public_html -type l -ls ];
    my $symlink;
    foreach $symlink (@FINDSYMLINKHACKS) {
        chomp($symlink);
        my ( $owner, $group, $path, $linkarrow, $symlinkedto ) = ( split( /\s+/, $symlink ) )[ 4, 5, 10, 11, 12 ];
        if ( $owner eq "root" or $group eq "root" ) {
            push( @SUMMARY, "> Found root owned symlink $path $linkarrow $symlinkedto\n" );
            logit("POSSIBLE ROOT LEVEL COMPROMISE!: $path $linkarrow $symlinkedto");
        }
        else {
            push( @SUMMARY, "> Found user owned symlink $path $linkarrow $symlinkedto\n" );
            logit("Found user owned symlink $path $linkarrow $symlinkedto");
        }
    }

    print_status( "Checking for deprecated .accesshash file in " . $RealHome . "..." );
    logit( "Checking for deprecated .accesshash file in " . $RealHome );
    if ( -e ("$RealHome/.accesshash") ) {
        push( @SUMMARY, "> Found $RealHome/.accesshash file! - Consider using API Tokens instead" );
        logit("Found $RealHome/.accesshash file! - Consider using API Tokens instead");
    }

    print_status( "Checking for deprecated .my.cnf file in " . $RealHome . "..." );
    logit( "Checking for deprecated .my.cnf file in " . $RealHome );
    if ( -e ("$RealHome/.my.cnf") ) {
        push( @SUMMARY, "> Found $RealHome/.my.cnf file! - Deprecated and no longer used or needed. Consider removing!" );
        logit("Found $RealHome/.my.cnf file! - Deprecated and no longer used or needed. Consider removing!");
    }

    print_status( "Checking for Troldesh Ransomware in " . $RealHome . "/public_html/.well-known/pki-validation and acme-challenge..." );
    logit( "Checking for for Troldesh Ransomware" );
	my $pkidir="$RealHome/public_html/.well-known/pki-validation";
	my $acmedir="$RealHome/public_html/.well-known/acme-challenge";
    my @files = qw( error_log ins.htm msg.jpg msges.jpg reso.zip rolf.zip stroi-invest.zip thn.htm );
	my $pkitroldesh_ransomware = 0;
	my $acmetroldesh_ransomware = 0;
	my $fullpath;
	if (-e $pkidir) { 
        for my $file (@files) {
            $fullpath = $pkidir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
				$pkitroldesh_ransomware = 1;
				last;
            }
        }
    }
	if ($pkitroldesh_ransomware) { 
        push( @SUMMARY, "> Found evidence of Troldesh Ransomware in $pkidir" );
	}
	if (-e $acmedir) { 
        for my $file (@files) {
            $fullpath = $acmedir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
				$acmetroldesh_ransomware = 1;
				last;
            }
        }
    }

	if ($acmetroldesh_ransomware) { 
        push( @SUMMARY, "> Found evidence of Troldesh Ransomware in $acmedir" );
	}

    if ( $isClamAVInstalled and !$skipClam ) {
        print_status( "Scanning $RealHome/public_html using clamscan [results will be in " . $csidir . "/" . ${lcUserToScan} . "_clamscan.log]" );
        logit("Beginning clamscan for $lcUserToScan");
        qx[ /usr/local/cpanel/3rdparty/bin/clamscan -i --quiet -o --log="$csidir/${lcUserToScan}_clamscan.log" -r -z --phishing-sigs=yes --phishing-scan-urls=yes --algorithmic-detection=yes $RealHome/public_html ];
    }
    my $URL         = "https://raw.githubusercontent.com/cPanelPeter/infection_scanner/master/strings.txt";
	my @DEFINITIONS     = qx[ curl -s $URL > "/root/CSI/csi_detections.txt" ];
    @DEFINITIONS = qx[ curl -s $URL ];
    my $StringCnt   = @DEFINITIONS;
    print_status("Scanning $RealHome/public_html for ($StringCnt) known phrases/strings");
    logit("Beginning known phrases/strings scan for $lcUserToScan");
	my $retval = qx[ LC_ALL=C grep -FsrIwf /root/CSI/csi_detections.txt $RealHome/public_html/* ];
	my @retval = split(/\n/,$retval);
    my $TotalFound=@retval;
    my $ItemFound;
    my $find=":";
    my $replace=YELLOW . " contains the phrase: " . MAGENTA;
    foreach $ItemFound(@retval) {
        chomp($ItemFound);
        $ItemFound =~ s/$find/$replace/;
        print CYAN "\t \\_ The file: " . WHITE "$ItemFound\n";
    }
    if ( $TotalFound == 0 ) {
        print_info("No suspicious phrases/strings were found!");
        logit("No suspicious phrases/strings were found!");
    }
	unlink("/root/CSI/csi_detections.txt") unless( ! -e "/root/CSI/csi_detections");
    print_header('[ cPanel Security Inspection Complete! ]');
    logit('[ cPanel Security Inspection Complete! ]');
    print_normal('');
    logit("Creating summary");
    dump_summary();
    return;
}


sub check_for_symlinks {
    my @FINDSYMLINKHACKS = qx[ find $HOMEDIR/*/public_html -type l -lname / -ls ];
    my $symlink;
    foreach $symlink (@FINDSYMLINKHACKS) {
        chomp($symlink);
        my ( $owner, $group, $path, $linkarrow, $symlinkedto ) = ( split( /\s+/, $symlink ) )[ 4, 5, 10, 11, 12 ];
        if ( $owner eq "root" or $group eq "root" ) {
            push( @SUMMARY, "> Found root owned symlink $path $linkarrow $symlinkedto\n" );
            print_warn("POSSIBLE ROOT LEVEL COMPROMISE!: $path $linkarrow $symlinkedto");
        }
        else {
            push( @SUMMARY, "> Found user owned symlink $path $linkarrow $symlinkedto\n" );
        }
    }
}

sub check_for_accesshash {
    if ($allow_accesshash) {
        push( @SUMMARY, "> allow deprecated accesshash set in Tweak Settings - Consider using API Tokens instead." );
    }
    if ( -e ("/root/.accesshash") ) {
        push( @SUMMARY, "> Found /root/.accesshash file! - Consider using API Tokens instead" );
    }
}

sub installClamAV {
    my $isClamAVInstalled = qx[ whmapi1 servicestatus service=clamd | grep 'installed: 1' ];
    if ($isClamAVInstalled) {
        print_info("ClamAV already installed!");
        logit("ClamAV already installed!");
        print_info("Updating ClamAV definitions/databases");
        logit("Updating ClamAV definitions/databases");
        qx[ /usr/local/cpanel/3rdparty/bin/freshclam &> /dev/null ];
        return 1;
    }
    else {
#        if ( -e ("/etc/eximdisable") ) {
#            print_warn("Exim disabled - Skipping clamd installation");
#            logit("Exim is disabled - Skipping clamd installation");
#            return;
#        }
        print_info("Installing ClamAV plugin...");
        logit("Installing ClamAV plugin");
        qx[ /usr/local/cpanel/scripts/update_local_rpm_versions --edit target_settings.clamav installed ];
        qx[ /usr/local/cpanel/scripts/check_cpanel_rpms --fix --targets=clamav ];
        my $ClamInstallChk = qx[ whmapi1 servicestatus service=clamd | grep 'installed: 1' ];
        if ($ClamInstallChk) {
            logit("Install completed");
            print_info("Updating ClamAV definitions/databases");
            logit("Updating ClamAV definitions/databases");
            qx[ /usr/local/cpanel/3rdparty/bin/freshclam &> /dev/null ];
            return 1;
        }
        else {
            print_warn("Failed!");
            logit("Install failed");
            return 0;
        }
    }
}

sub security_advisor {
    unlink("/var/cpanel/security_advisor_history.json") if ( -e ("/var/cpanel/security_advisor_history.json") );
    my $SecAdvLine;
    my @SecAdvisor = qx[ /usr/local/cpanel/scripts/check_security_advice_changes | egrep -v 'High|Info|Advice|Type|Module' 2>/dev/null  ];
    push( @SUMMARY, YELLOW "> " . MAGENTA "\t============== BEGIN SECURITY ADVISOR RESULTS ===============" );
    foreach $SecAdvLine (@SecAdvisor) {
        chomp($SecAdvLine);
        push( @SUMMARY, BOLD CYAN $SecAdvLine . "\n" ) unless ( $SecAdvLine eq "" );
    }
    push( @SUMMARY, YELLOW "> " . MAGENTA "\t============== END SECURITY ADVISOR RESULTS ===============\n" );
}

sub check_for_deprecated {
    my $deprecated;
    my @DEPRECATED = qw(
      /usr/local/cpanel/cgi-sys/formmail.pl
      /usr/local/cpanel/cgi-sys/FormMail.cgi
      /usr/local/cpanel/cgi-sys/formmail.cgi
      /usr/local/cpanel/cgi-sys/FormMail-clone.cgi
      /usr/local/cpanel/cgi-sys/FormMail.pl
      /usr/local/cpanel/base/cgi-sys/guestbook.cgi
      /usr/local/cpanel/base/cgi-sys/Count.cgi
      /usr/local/cpanel/cgi-sys/mchat.cgi
      /usr/local/cpanel/cgi-sys/cgiecho
      /usr/local/cpanel/cgi-sys/cgiemail
    );

    foreach $deprecated (@DEPRECATED) {
        if ( -e ("$deprecated") ) {
            push( @SUMMARY, "> Found deprecated software " . CYAN $deprecated);
        }
    }
}

sub check_sshd_config {
    my $PermitRootLogin = qx[ grep '^PermitRootLogin ' /etc/ssh/sshd_config ];
    if ( $PermitRootLogin =~ m/yes/i ) {
        push( @SUMMARY, "> PermitRootLogin is set to yes in /etc/ssh/sshd_config - consider setting to no or without-password instead!" );
    }
    my $PassAuth = qx[ grep '^PasswordAuthentication ' /etc/ssh/sshd_config ];
    if ( $PassAuth =~ m/yes/i ) {
        push( @SUMMARY, "> PasswordAuthentication is set to yes in /etc/ssh/sshd_config - consider using ssh keys instead!" );
    }
}

sub isEA4 {
    if ( -f "/etc/cpanel/ea4/is_ea4" ) {
        return 1;
    }
    return undef;
}

sub get_login_ip {
    my $who = '/usr/bin/who';
    if ( !-x $who ) {
        return 0;
    }
    my @tech_logins = ();
    my $header      = "";
    my $num_logins  = 0;
    for my $line ( split /\n/, timed_run( 0, $who, '-H' ) ) {
        if ( $line =~ m{ \A NAME\s+ }xms ) {
            $header = $line;
            next;
        }
        if ( $line =~ m{ \((.+)\)\Z }xms ) {
            if (   $1 =~ m{ \A (.*\.)?(cptxoffice\.net|cloudlinux\.com|litespeedtech.com)(:|$) }xms
                || $1 =~ m{ \A (208\.74\.12[0-7]\.\d+|69\.175\.92\.(4[89]|5[0-9]|6[0-4])|69\.10\.42\.69)(:|$) }xms ) {
                push( @tech_logins, $line );
                $num_logins++;
            }
        }
    }
    if ( $num_logins <= 1 ) {
        return 0;
    }
    else {
        return 0;
    }
}

sub misc_checks { 
	my @dirs = undef;
	my @files = undef; 
	my $fullpath = "";
	my $cron = "";
	# Xbash ransomware
	my $mysql_datadir = "/var/lib/mysql";
	opendir( my $dh, $mysql_datadir );
    my ($HasXbash) = grep { /PLEASE_READ/i } readdir $dh;
    closedir $dh;
    if ($HasXbash) {
        push( @SUMMARY, "> Possible Xbash ransomware detected. Database's missing? Database $HasXbash exists!" );
    }

	# coinminer
    @dirs  = qw( /root/non /root/non/non );
    @files = qw( 
        run
        sh
        miner
        miner.pid
    );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
        		push( @SUMMARY, "> Suspicious file found: possible bitcoin miner\n\t\\_ $fullpath" );
				vtlink($fullpath);
				last;
            }
        }
    }
	# check_tmp for suspicious bc.pl file
    if ( -e ("/tmp/bc.pl") ) {
        push @SUMMARY, "> Found suspicious file 'bc.pl' in /tmp directory";
    }

    if ( -e ("/tmp/.mysqli/mysqlc") ) {
        push @SUMMARY, "> Found suspicious file '.mysqli/mysqlc' in /tmp directory";
    }

    if ( -e ("/etc/.ip") ) {
        push @SUMMARY, "> Found suspicious file '.ip' in /etc directory";
		vtlink("/etc/.ip");
    }

    if ( -e ("/var/log/.log") ) {
        push @SUMMARY, "> Found suspicious file '.log' in /var/log directory";
		vtlink("/var/log/.log");
    }

	# spy_master
	my $spymaster = qx[ objdump -T /usr/bin/ssh /usr/sbin/sshd | grep spy_master ];
	if ($spymaster) { 
        push @SUMMARY, "> Suspicious file found: evidence of spy_master running in ssh/sshd [ $spymaster ]";
	}

	# bitcoin
    @dirs  = qw( /dev/shm/.X12-unix /dev/shm /usr/local/lib /dev/shm/.X0-locked /dev/shm/.X13-unix );
    @files = qw( 
		a
		bash.pid
		cron.d
		dir.dir
		e
		f
		httpd
		kthreadd
		md.so
		screen.so
		y.so
		kdevtmpfs
		r
		systemd
		upd
		x
		aPOg5A3
		de33f4f911f20761
		e6mAfed
		sem.Mvlg_ada_lock
		prot
	);
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
        		push( @SUMMARY, "> Suspicous file found: possible root level compromise\n\t\\_ $fullpath" );
				vtlink($fullpath);
            }
        }
    }
	
	# bitcoin miner with rootkit
	my %warning = ();
    return unless my @crons_aref = get_cron_files();
	my @cronContains = undef;
	my $isImmutable="";
    for my $cron (@crons_aref) {
        if ( open my $cron_fh, '<', $cron ) {
            while (<$cron_fh>) {
				chomp($_);
                if ( $_ =~ /tor2web|onion|yxarsh\.shop|\/u\/SYSTEM|\/root\/\.ttp\/a\/updl\/root\/\/b\/sync|\/tmp\/\.mountfs\/\.rsync\/c\/aptitude|cr2\sh|82\.146\.53\.166|oanacroane/ ) {
					$isImmutable="";
					my $attr = qx[ /usr/bin/lsattr $cron ];
					if ( $attr =~ m/^\s*\S*[ai]/ ) {
						$isImmutable=" [IMMUTABLE]";
					}
					push @cronContains, CYAN "\t \\_ " . $cron . " Contains: [ " . $_ . " ] $isImmutable";
                }
            }
            close $cron_fh;
        }
    }
	splice( @cronContains ,0,1);
	if (@cronContains) { 
        push( @SUMMARY, "> Possible malicious crons found:" );
		push( @SUMMARY, @cronContains );
	}
	if (-e ("/usr/local/bin/dns")) { 
        push( @SUMMARY, "> Suspicious file found: /usr/local/bin/dns exists. Possible bitcoin miner!" );
	}
    @dirs  = qw( /opt/yilu /tmp/thisxxs /usr/bin/.sshd );
    for my $dir (@dirs) {
        next if !-e $dir;
  		push( @SUMMARY, "> Suspicious directories found:" );
		push( @SUMMARY, CYAN "\t\\_ " . $dir );
	}
    @dirs  = qw( /root/.ssh/.dsa/a /bin );
    @files = qw( f f.good in.txt nohup.out ftpsdns httpntp watchdog );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
        		push( @SUMMARY, "> Suspicious files found: possible bitcoin miner." );
				push( @SUMMARY, CYAN "\t \\_ " . $fullpath . " exists" );
            }
        }
    }
}

sub vtlink {
    my @FileToChk=@_;
	foreach my $FileToChk(@FileToChk) { 
    	chomp($FileToChk);
		next if (! -e "$FileToChk" );
        my $isELF=qx[ file $FileToChk | grep 'ELF' ];
        next if (! $isELF );
		my $fStat=stat($FileToChk);
		my $FileSize=$fStat->size;
    	my $KFS = $FileSize/1024;
		my $ctime=$fStat->ctime;
    	my $isRPMowned = qx[ rpm -qf $FileToChk | grep 'not owned by' ];
    	chomp($isRPMowned);
    	my $RPMowned = "";
		my $RPMname = "";
    	if ($isRPMowned) {
        	$RPMowned = RED "No" . YELLOW "  [ Most system files should be owned by an RPM ]";
    	}
    	else {
        	$RPMname = qx[ rpm -qf $FileToChk 2>&1 ];
        	chomp($RPMname);
        	    $RPMowned = GREEN "Yes - " . YELLOW $RPMname . "\n\t\\_ Compare Size and Key ID against a clean server by running:\n\t\\_ rpm -qi $RPMname | egrep 'Size|Key ID'\n\t\\_ Notice the different Size and Key ID?";
    	}
    	my $sizeDesc = "";
    	if ( $KFS > 25 ) {
        	$sizeDesc = " [ Most system files/libraries are less than 25k. Anything larger should be considered suspicious. ]";
    	}
    	my $sha256 = qx[ sha256sum $FileToChk ];
    	chomp($sha256);
    	($sha256only) = ( split( /\s+/, $sha256 ) )[0];
    	push @SUMMARY, "  File: " . CYAN $FileToChk . GREEN " [ Not normally found on clean servers ]";
    	push @SUMMARY, "  Size: " . CYAN $FileSize . WHITE " (" . nearest(.1,$KFS) . "k)" . GREEN "  $sizeDesc ";
    	push @SUMMARY, "  Changed: " . CYAN scalar localtime($ctime) . GREEN " [ Approximate date the compromise may have occurred ]";
    	push @SUMMARY, "  RPM Owned: " . $RPMowned; 
    	push @SUMMARY, "  sha256sum: " . CYAN $sha256only . "\n";
    	push @SUMMARY, GREEN "  Taking the above sha256 hash of $FileToChk and plugging it into VirusTotal.com...";
    	push @SUMMARY, GREEN "  Check this link to see if it has already been detected:\n\t \\_ " . WHITE "https://www.virustotal.com/#/file/$sha256only/detection\n";
	}
}

sub rpm_yum_running_chk { 
	my $lcRunning = qx[ ps auxfwww | egrep -i '/usr/bin/rpm|/usr/bin/yum' | grep -v grep ];
	if ($lcRunning) { 
		logit("An rpm/yum process may be running");
        print_warn("An rpm/yum process may be running. Could cause some checks to hang waiting for process to complete.");
		exit;
	}
}

sub chk_shadow_hack { 
	my $shadow_roottn_baks=qx[ find $HOMEDIR/*/etc/* -name 'shadow\.*' -print ];	
	if ($shadow_roottn_baks) { 
		chomp($shadow_roottn_baks);
		push @SUMMARY, "> Found the following directories containing the shadow.roottn.bak hack:\n " . CYAN $shadow_roottn_baks;
		push @SUMMARY, MAGENTA "\t \\_ See: https://github.com/bksmile/WebApplication/blob/master/smtp_changer/wbf.php";
	}
}

sub check_for_exim_vuln {
	my $chk_eximlog=qx[ grep '\${run' /var/log/exim_mainlog* | head -1 ];
	if ($chk_eximlog) { 
		push @SUMMARY, "> Found the following string in /var/log/exim_mainlog file. Possible root level compromise:\n " . CYAN $chk_eximlog;
	}
    return unless(-e "/root/.ssh/authorized_keys");
	my $authkeysGID=(stat("/root/.ssh/authorized_keys")->gid);
	my $authkeysGname=getgrgid($authkeysGID);
	if ($authkeysGID > 0) { 
		push @SUMMARY, "> Found the /root/.ssh/authorized_keys file to have an invalid group name [$authkeysGname]. Indicates tampering at the root level.";
	}
}

sub spamscriptchk {
	opendir my $dh, "/tmp";
	my $totaltmpfiles = () = readdir($dh);
	closedir $dh;
	return if $totaltmpfiles > 1000;
	#  Check for obfuscated Perl spamming script - will be owned by user check ps for that user and /tmp/dd
	my @string = qx[ grep -srl '295c445c5f495f5f4548533c3c3c3d29' /tmp/* ];
    my $stringCnt=@string;
    my $stringLine="";
	if ($stringCnt > 0) { 
		push @SUMMARY, "> Found evidence of user spamming script in /tmp directory";
        foreach $stringLine(@string) { 
            chomp($stringLine);
            push @SUMMARY, "\t\\_ $stringLine";
        }
	}
}

sub spamscriptchk2 { 
	opendir my $dh, "/var/spool/cron";
	my @allcrons=readdir($dh);
	closedir $dh;
	my $usercron;
	my @crondata;
	my $cronline;
	foreach $usercron(@allcrons) { 
		open(USERCRON,"/var/spool/cron/$usercron");
		@crondata=<USERCRON>;
		close(USERCRON);
		foreach $cronline(@crondata) { 
			chomp($cronline);
			if ( $cronline =~ m{ perl \s (?:/var)?/tmp/[a-zA-Z]+ }xms ) { 
				push @SUMMARY, CYAN "> Found suspicious cron entry in the " . MAGENTA $usercron . CYAN " user account:" . YELLOW "\n\t\\_ $cronline";
			}
		}
	}
}

sub chkbinforhttp { 
	if (-e("/usr/bin/http")) { 
		push @SUMMARY, "> Found evidence of hacked http in /usr/bin directory.";
	}
}

sub check_for_Super_privs {
	return if ! -e "/var/lib/mysql/mysql.sock";
	my @MySQLSuperPriv=qx[ mysql -BNe "SELECT Host,User FROM mysql.user WHERE Super_priv='Y'" | egrep -v 'root|mysql.session' ];
	if (@MySQLSuperPriv) { 
		push @SUMMARY, "> The following MySQL users have the Super Privilege:";
		my $MySQLSuperPriv="";
		foreach $MySQLSuperPriv(@MySQLSuperPriv) { 
			chomp($MySQLSuperPriv);
			my ($MySQLHost,$MySQLUser)=(split(/\s+/,$MySQLSuperPriv));
			push @SUMMARY, CYAN "\t \\_ User: " . MAGENTA $MySQLUser . CYAN " on Host: " . MAGENTA $MySQLHost;
		}
	}
}

sub build_libkeyutils_file_list {
    my @dirs = qw( /lib /lib/tls /lib64 /lib64/tls );
    my @libkeyutils_files;
    for my $dir (@dirs) {
        next unless -e $dir;
        opendir( my $dir_fh, $dir );
        while ( my $file = readdir($dir_fh) ) {
            if ( $file =~ /^libkeyutils\.so\.(?:[\.\d]+)?$/ ) {
                push @libkeyutils_files, "$dir/$file\n";
            }
        }
        closedir $dir_fh;
    }
    chomp @libkeyutils_files;
    return \@libkeyutils_files;
}

sub get_cron_files {
	my @cronlist = glob( q{ /etc/cron.d/{.,}* /etc/cron.hourly/{.,}* /etc/cron.daily/{.,}* /etc/cron.weekly/{.,}* /etc/cron.monthly/{.,}* /etc/crontab /var/spool/cron/root } );
}

sub get_last_logins_WHM { 
	my @lastWHMRootLogins=qx[ grep 'root' /usr/local/cpanel/logs/access_log | grep '200' | grep 'post_login=' ];
	my $WHMLogins="";
	my @WHMIPs=undef;
	foreach $WHMLogins(@lastWHMRootLogins) { 
		my ($lastIP) = (split(/\s+/,$WHMLogins))[0];
		push @WHMIPs, $lastIP;
	}
	splice(@WHMIPs,0,1);
	my @sorted=uniq(@WHMIPs);
	#my @sortedIPs=sort(@sorted);
    push( @SUMMARY, "> The following IP address(es) logged on via WHM successfully as root:" );
	#foreach $WHMLogins(@sortedIPs) { 
	my $ipcnt=0;
	foreach $WHMLogins(@sorted) { 
		push( @SUMMARY, CYAN "\t\\_ IP: $WHMLogins" ) unless($WHMLogins =~ m/208.74.123.|184.94.197./);
		last if $ipcnt > 8;
		$ipcnt++;
	}
}

sub get_last_logins_SSH { 
	my @LastSSHRootLogins=qx[ last | grep 'root' | tail ];
	my $SSHLogins="";
	my @SSHIPs=undef;
	foreach $SSHLogins(@LastSSHRootLogins) { 
		my ($lastIP) = (split(/\s+/,$SSHLogins))[2];
		push @SSHIPs, $lastIP unless($lastIP =~ /[a-zA-Z]/);
	}
	splice(@SSHIPs,0,1);
	my @sortedIPs=uniq(@SSHIPs);
    push( @SUMMARY, "> The following IP address(es) logged on via SSH successfully as root:" );
	foreach $SSHLogins(@sortedIPs) { 
		push( @SUMMARY, CYAN "\t\\_ IP: $SSHLogins" ) unless($SSHLogins =~ m/208.74.123.|184.94.197./); 
	}
    push( @SUMMARY, CYAN "\nDo you recognize any of the above IP addresses?\nIf not, then further investigation should be performed." );
}

sub check_file_for_elf { 
	my $tcFile=$_[0];
	my $retval=0;
	if ($tcFile =~ /mynewdomain\/public_html\/png/) { 
		$retval = timed_run(0, 'file', "$tcFile", '|grep "ELF"') ? 1:0;
	}
	#my $retval = qx[ file \"$tcFile\" | grep ELF ];
	#my $retval = timed_run(0, 'file', "$tcFile", '|grep "ELF"');
	return $retval;
}

sub get_conf {
    my $conf = shift;
    my %cpconf;
    if ( open( my $cpconf_fh, '<', $conf ) ) {
        local $/ = undef;
        %cpconf = map { ( split( /=/, $_, 2 ) )[ 0, 1 ] } split( /\n/, readline($cpconf_fh) );
        close $cpconf_fh;
        return %cpconf;
    } else {
        print_warn("Could not open file: $conf\n");
    }
    return;
}

# EOF
