#!/usr/local/cpanel/3rdparty/bin/perl
# Copyright 2018, cPanel, L.L.C.
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

#use File::stat;
use Cpanel::Exception       ();
use Cpanel::Sys             ();
use Cpanel::Sys::OS         ();
use Cpanel::FindBin         ();
use Cpanel::Kernel          ();
use Cpanel::KernelCare      ();
use Cpanel::SafeRun::Object ();
use Math::Round;
use POSIX;
use Getopt::Long;
use IO::Socket::INET;
use Term::ANSIColor qw(:constants);
use Time::Piece;
use Time::Seconds;
$Term::ANSIColor::AUTORESET = 1;

my $version = "3.4.13";
my $rootdir = "/root";
my $csidir  = "$rootdir/CSI";
our $KernelChk;
our $spincounter;
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
my $help;
my $userscan;
my $scanmail;
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
our $LIBKEYUTILS_FILES_REF;
our $IPCS_REF;
our $PROCESS_REF;
our $EA4 = isEA4();
our @RPM_LIST;
our $OPT_TIMEOUT;
GetOptions(
    'bincheck'   => \$binscan,
    'userscan=s' => \$userscan,
    'scanmail'   => \$scanmail,
    'full'       => \$full,
    'skipClamAV' => \$skipClam,
    'help'       => \$help,
);
#######################################
# Set variables needed for later subs #
#######################################
chomp( my $wget = qx[which wget] );
chomp( my $tar  = qx[which tar] );
my $rkhunter_bin   = "$csidir/rkhunter/bin/rkhunter";
my $chkrootkit_bin = "$csidir/chkrootkit/chkrootkit";
our $CSISUMMARY;
our @SUMMARY;
our @LYNISWARNINGS;
our $LYNISWARN;
my $docdir = '/usr/share/doc';
check_for_touchfile();
my @logfiles = (
    '/var/log/apache2/access_log',
    '/var/log/apache2/error_log',
    '/var/log/messages',
    '/var/log/maillog',
    '/var/log/wtmp',
    '/root/.bash_history',
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
my $scanstarttime = Time::Piece->new;
print_header("Scan started on $scanstarttime");
logit("Scan started on $scanstarttime");
logit("Showing disclaimer");
print_info("Usage: /root/csi.pl [functions] [options]");
print_info("See --help for a full list of options");
print_normal('');
disclaimer();

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

#my $scanTotTime = $scantimediff->pretty, "\n";
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
    print_header("--full                     Installs chkrootkit, rkhunter, lynis 3rd party tools and does a full scan.");
    print_header("                           Includes symlink hack check for entire server, and RPM check for non-owned RPM's.");
    print_normal(" ");
    print_header("Available options for --userscan");
    print_header("=================");
    print_status("--scanmail                 Scans mail directory as well (can take longer).");
    print_status("--skipClam                 Skips ClamAV Scan.");
    print_normal(" ");
    print_header("Examples");
    print_header("=================");
    print_status("            /root/csi.pl [DEFAULT] quick scan");
    print_status("            /root/csi.pl --full");
    print_status("Bincheck: ");
    print_status("            /root/csi.pl --bincheck");
    print_status("Userscan ");
    print_status("            /root/csi.pl --userscan myuser [skips mail]");
    print_status("            /root/csi.pl --scanmail --userscan myuser [includes mail]");
    print_status("            /root/csi.pl --userscan myuser --skipClam [skips ClamAV Scan]");
    print_normal(" ");
}

sub bincheck {
    print_normal('');
    print_header('[ Starting cPanel Security Inspection: Bincheck Mode ]');
    logit("Starting bincheck");
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
    print_status('Done - Found: $RPMcnt RPMs to verify');
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
    print_header('### If it is suspected to be root compromised, only Level III Analysts #');
    print_header('### should be handling the issue. Account level compromises are        #');
    print_header('### investigated as a courtesy and carry no guarantees.                #');
    print_header('########################################################################');
    print_normal('');
}

sub scan {
    print_normal('');
    print_header('[ Starting cPanel Security Inspection: DEFAULT SCAN Mode ]');
    print_header("[ System: $OS_RELEASE ]");
    print_normal('');
    print_header("[ Available flags when running csi.pl scan ]");
    print_header('[     --full Performs a more compreshensive scan using 3rd party tools (chkrootkit, rkhunter)]');
    print_normal('');
    if ($full) {
        logit("Installing 3rd party tools");
        my $RKHUNTER   = install_rkhunter();
        my $CHKROOTKIT = install_chkrootkit();
        my $LYNIS      = install_lynis();
        print_header('[ Running 3rdparty rootkit and security checking programs ]');
        logit("Running 3rdparty rootkit and security checking programs");
        if ($RKHUNTER) {

            #            run_rkhunter();
        }
        else {
            print_warn("RKHunter may not have installed properly - skipping this check.");
            logit("RKHunter installation failed!");
        }
        if ($CHKROOTKIT) {

            #            run_chkrootkit();
        }
        else {
            print_warn("chkrootkit may not have installed properly - skipping this check.");
            logit("chkrootkit installation failed!");
        }
        if ($LYNIS) {

            #            run_lynis();
        }
        else {
            print_warn("Lynis may not have installed properly - skipping this check.");
            logit("Lynis installation failed!");
        }
    }
    else {
        print_header('[ Running without 3rdparty rootkit and security checking programs ]');
        logit("Running without 3rdparty tools [Limited Checks]");
        print_normal('');
    }
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
    print_header('[ Checking for mod_security ]');
    logit("Checking if ModSecurity is enabled");
    check_modsecurity();
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
    print_header('[ Checking for Xbash ransomware ]');
    logit("Checking for Xbash ransomware");
    check_for_Xbash();
    print_header('[ Checking for deprecated plugins/modules ]');
    logit("Checking for deprecated plugins");
    check_for_deprecated();
    print_header('[ Checking for sshd_config ]');
    logit("Checking sshd_config");
    check_sshd_config();
    print_header('[ Checking for modified/hacked SSH ]');
    logit("Checking for modified/hacked ssh");
    check_ssh();
    print_header('[ Checking kernel status ]');
    logit("Checking kernel status");
    check_kernel_updates();

    if ( !$full ) {
        print_info("full option not passed, skipping non-owned files/libraries check");
        logit("full option not passed - skipping lib check");
        print_info("full option not passed, skipping symlink hack check");
        logit("full option not passed - skipping symlink hack check");
    }
    else {
        print_header('[ Checking for files/libraries not owned by an RPM ]');
        logit("Checking for non-owned files/libraries");

        #        check_lib();
        print_header('[ Checking for symlink hacks ]');
        logit("Checking for symlink hacks");

        #        check_for_symlinks();
    }
    print_header('[ Checking for accesshash ]');
    logit("Checking for accesshash");
    check_for_accesshash();
    print_header('[ Gathering the last 10 IP addresses that logged on to WHM successfully as root ]');
    logit("Gathering last 10 IP address logged on as root");
    check_session_log(10);
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
    logit("Kernel status check started.");
    my $CanModify             = Cpanel::Kernel::can_modify_kernel();
    my $boot_kernelversion    = Cpanel::Kernel::get_default_boot_version();
    my $running_kernelversion = Cpanel::Kernel::get_running_version();
    my $custom_kernel         = 0;
    if ( $running_kernelversion !~ m/\.(?:noarch|x86_64|i[3-6]86)$/ ) {
        $custom_kernel = 1;
    }
    my $has_kernelcare = 0;
    if ( Cpanel::KernelCare::kernelcare_responsible_for_running_kernel_updates() ) {
        $has_kernelcare = 1;
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
                push @SUMMARY, "> KernelCare installed but running kernel version [ $running_kernelversion ] does not match boot version [ $boot_kernelversion] reboot may be required.";
            }
            else {
                push @SUMMARY, "> KernelCare installed but running kernel version [ $running_kernelversion ] does not match boot version [ $boot_kernelversion] please check with VM provider.";
            }
        }
    }
    else {
        if ($reboot_required) {
            if ($CanModify) {
                push @SUMMARY, "> Running kernel version [ $running_kernelversion ] does not match boot version [ $boot_kernelversion] reboot may be required.";
            }
            else {
                push @SUMMARY, "> Running kernel version [ $running_kernelversion ] does not match boot version [ $boot_kernelversion] please check with VM provider.";
            }
        }
    }
    logit("Kernel status check completed.");
}

sub run_rkhunter {
    print_status('Running rkhunter. This will take a few minutes.');
    logit("Running rkhunter");
    qx($rkhunter_bin --cronjob --rwo > $csidir/rkhunter.log 2>&1);
    if ( -s "$csidir/rkhunter.log" ) {
        open( my $LOG, '<', "$csidir/rkhunter.log" )
          or die("Cannot open logfile $csidir/rkhunter.log: $!");
        my @results = grep /Rootkit/, <$LOG>;
        close $LOG;
        if (@results) {
            push @SUMMARY, "> Rkhunter has found a suspected rootkit infection(s):";
            foreach (@results) {
                push @SUMMARY, $_;
            }
            push @SUMMARY, "> More information can be found in the log at $csidir/rkhunter.log";
        }
        else {
            logit("rkhunter found no evidence of rootkits.");
            open( my $LOG, '>', "$csidir/rkhunter.log" ) or die("Cannot open logfile $csidir/rkhunter.log ($!)");
            print $LOG "rkhunter found no evidence of rootkits.";
            close $LOG;
        }
    }
}

sub run_chkrootkit {
    print_status('Running chkrootkit. This will take a few minutes.');
    logit("Running chkrootkit");
    qx($chkrootkit_bin 2> /dev/null | egrep 'INFECTED|vulnerable' | grep -v "INFECTED PORTS: ( 465)" | grep -v "passwd" | tee "$csidir/chkrootkit.log" 2> /dev/null);
    if ( -s "$csidir/chkrootkit.log" ) {
        open( my $LOG, '<', "$csidir/chkrootkit.log" )
          or die("Cannot open logfile $csidir/chkrootkit.log: $!");
        my @results = <$LOG>;
        close $LOG;
        if (@results) {
            push @SUMMARY, '> Chkrootkit has found suspected rootkit or infection:';
            foreach (@results) {
                push @SUMMARY, $_;
            }
        }
    }
    else {
        logit("chkrootkit found no evidence of rootkits");
        open( my $LOG, '>', "$csidir/chkrootkit.log" ) or die("Cannot open logfile $csidir/chkrootkit.log ($!)");
        print $LOG "chkrootkit found no evidence of rootkits.";
        close $LOG;
    }
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

sub check_uids {
    my @baduids;
    while ( my ( $user, $pass, $uid, $gid, $group, $home, $shell ) = getpwent() ) {
        if ( $uid == 0 && $user ne 'root' ) {
            push( @baduids, $user );
        }
    }
    endpwent();
    if (@baduids) {
        push @SUMMARY, '> Users with UID of 0 detected:';
        foreach (@baduids) {
            push( @SUMMARY, $_ );
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
    chomp( my @ps_output = qx(ps aux) );
    foreach my $line (@ps_output) {
        if ( $line =~ 'sleep 7200' ) {
            push @SUMMARY, "> ps output contains 'sleep 7200' which is a known part of a hack process:";
            push @SUMMARY, "     $line";
        }
        if ( $line =~ / perl$/ ) {
            push @SUMMARY, "> ps output contains 'perl' without a command following, which could indicate a hack:";
            push @SUMMARY, "     $line";
        }
        if ( $line =~ /mine/ ) {
            push @SUMMARY, "> ps output contains 'mine' could indicate a bitcoin mining hack:";
            push @SUMMARY, "     $line";
        }
        if ( $line =~ /cryptonight/ ) {
            push @SUMMARY, "> ps output contains 'cryptonight' could indicate a bitcoin mining hack:";
            push @SUMMARY, "     $line";
        }
        if ( $line =~ /manero/ ) {
            push @SUMMARY, "> ps output contains 'manero' could indicate a bitcoin mining hack:";
            push @SUMMARY, "     $line";
        }
        if ( $line =~ /zcash/ ) {
            push @SUMMARY, "> ps output contains 'zcash' could indicate a bitcoin mining hack:";
            push @SUMMARY, "     $line";
        }
        if ( $line =~ /xmr-stak/ ) {
            push @SUMMARY, "> ps output contains 'xmr-stak' could indicate a bitcoin mining hack:";
            push @SUMMARY, "     $line";
        }
        if ( $line =~ /xmrig/ ) {
            push @SUMMARY, "> ps output contains 'xmrig' could indicate a bitcoin mining hack:";
            push @SUMMARY, "     $line";
        }
        if ( $line =~ /xm2sg/ ) {
            push @SUMMARY, "> ps output contains 'xm2sg' could indicate a bitcoin mining hack:";
            push @SUMMARY, "     $line";
        }
        if ( $line =~ /DSST/ ) {
            push @SUMMARY, "> ps output contains 'DSST' could indicate a bitcoin mining hack:";
            push @SUMMARY, "     $line";
        }
        if ( $line =~ /pty.spwan\(\"\/bin\/sh\"\)/ ) {
            push @SUMMARY, "> ps output contains 'pty.spwan(\"/bin/ssh\")' indicates potential compromise";
            push @SUMMARY, "     $line";
        }
    }
}

sub check_tmp {
    if ( !("/tmp/bc.pl") ) {
        push @SUMMARY, "> Found suspicious file 'bc.pl' in /tmp directory";
    }
}

sub bitcoin_chk {
    my $xmrig_cron = qx[ grep '.xmr' /var/spool/cron/* ];
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
    my $pastebinurl = qx[ grep 'https://pastebin.com/raw/1NtRkBc3%7C%7Cwget' /var/spool/cron/* ];
    if ($pastebinurl) {
        push @SUMMARY, "> Found evidence of possilbe bitcoin miner: " . CYAN $pastebinurl;
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
    my @process_list = qx(ps aux | grep "sshd: root@" | egrep -v 'pts|priv');
    if ( @process_list and $process_list[0] =~ 'root' ) {
        push( @ssh_errors, " Suspicious SSH process(es) found:\n" );
        push( @ssh_errors, " $process_list[0]" );
    }
    if (@ssh_errors) {
        push @SUMMARY, "> System has detected the presence of a *POSSIBLY* compromised SSH:\n";
        foreach (@ssh_errors) {
            push( @SUMMARY, $_ );
        }
    }
}

sub check_lib {
    my @lib_errors;
    my @lib_files = qx[ find {,/usr,/usr/local}/{include,lib}{,64} -path /lib/firmware -prune -o -path /lib/modules -prune -o -path /usr/lib/vmware-tools -prune -o -path /lib64/xtables\* -prune -o -path /usr/lib/ruby -prune -o -path /usr/lib/python\* -prune -o -type f -exec rpm -qf {} + 2>/dev/null ];
    foreach my $file (@lib_files) {
        chomp($file);
        if ( -f $file && -l $file ) {
            spin();
            $file = abs_path($file);
            next unless ( $file =~ m/not owned/ );
            push( @lib_errors, " Found $file which is not owned by any RPM.\n" );
        }
    }
    if (@lib_errors) {
        push @SUMMARY, "> Found library files not owned by an RPM, *MAY* indicate a compromise or could be custom installed by an administrator.\n";
        foreach (@lib_errors) {
            push( @SUMMARY, $_ );
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

            #print BOLD MAGENTA "> " . YELLOW $_ . "\n";
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
    if ( -e ("$csidir/warnings_from_lynis.txt") ) {
        print_info("Lynis found some warnings that should be looked into - See $csidir/warnings_from_lynis.txt");
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

sub check_for_korkerds {
    my @dirs  = qw( /bin /usr/sbin /usr/local/lib /tmp );
    my @files = qw(
      httpdns
      netdns
      libdns.so
      kworkerds
    );
    my $bad_libs;

    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            if ( -f "${dir}/${file}" and not -z "${dir}/${file}" ) {
                $bad_libs .= "${dir}/${file}\n";
            }
        }
    }
    my $netstatcheck = qx[ netstat -nap | grep '56415' ];
    if ($netstatcheck) {
        push( @SUMMARY, "> [ROOTKIT: KORKERDS] - " . CYAN "Evidence of the Coinminer.Linux.KORKERDS.AB Rootkit found.\nSuspicious socket listening on port 56415\n$netstatcheck" );
    }
    if ($bad_libs) {
        push( @SUMMARY, "> [ROOTKIT: KORKERDS] - " . CYAN "Evidence of the Coinminer.Linux.KORKERDS.AB Rootkit found.\n" );
        vtlink($bad_libs);
    }
}

sub check_for_cdorked_A {
    return unless defined $HTTPD_PATH;
    return unless -f $HTTPD_PATH;
    my $max_bin_size = 10_485_760;
    return if ( ( stat($HTTPD_PATH) )[7] > $max_bin_size );
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
        push( @SUMMARY, "> [ROOTKIT: CDORKED A] - " . CYAN "Evidence of CDORKED A Rootkit found." );
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
        push( @SUMMARY, "> [ROOTKIT: CDORKED B] - " . CYAN "Evidence of CDORKED B Rootkit found.\n\t Found " . $cdorked_files . " [Note space at end of files]" );
    }
}

sub check_for_libkeyutils_filenames {
    my $bad_libs;
    my @dirs  = qw( /lib /lib64 );
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
      tls/libkeyutils.so.1
      tls/libkeyutils.so.1.5
    );

    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            if ( -f "${dir}/${file}" and not -z "${dir}/${file}" ) {
                $bad_libs .= "${dir}/${file}\n";
            }
        }
    }
    if ($bad_libs) {
        push( @SUMMARY, "> [ROOTKIT: Ebury/Libkeys] - " . CYAN "Evidence of Ebury/Libkeys Rootkit found.\n" );
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
            $trojaned_lib = "$lib\n\tSHA-1 checksum: $checksum";
            last;
        }
    }
    if ($trojaned_lib) {
        push( @SUMMARY, "> [ROOTKIT: Ebury/Libkeys] - " . CYAN "Evidence of Ebury/Libkeys Rootkit found.\n\t Found " . $trojaned_lib );
        vtlink($trojaned_lib);
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
        push( @SUMMARY, "> [ROOTKIT: Ebury/Libkeys] - " . CYAN "Evidence of Ebury/Libkeys Rootkit found." );
        push( @SUMMARY, "Found: " . @unowned_libs );
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
        push( @SUMMARY, "> [ROOTKIT: Apache Binary] - " . CYAN "Evidence of hacked Apache binary found.\n\t Found " . $sha1sum );
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
        push( @SUMMARY, "> [ROOTKIT: Named Binary] - " . CYAN "Evidence of hacked Named binary found.\n\t Found " . $sha1sum );
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
        push( @SUMMARY, "> [ROOTKIT: SSH Binary] - " . CYAN "Evidence of hacked SSH binary found.\n\t Found " . $sha1sum );
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
        push( @SUMMARY, "> [ROOTKIT: SSH-ADD Binary] - " . CYAN "Evidence of hacked SSH-ADD binary found.\n\t Found " . $sha1sum );
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
        push( @SUMMARY, "> [ROOTKIT: sshd Binary] - " . CYAN "Evidence of hacked sshd binary found.\n\t Found " . $sha1sum );
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
        push( @SUMMARY, "> [ROOTKIT: ssh Binary] - " . CYAN "Evidence of hacked ssh binary found.\n\t " . $ssh . " -G did not return either 'illegal' or 'unknown'" );
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
        push( @SUMMARY, "> [ROOTKIT: ssh banner] - " . CYAN "Evidence of hacked ssh banner found.\n\t " . $ssh_banner . "." );
    }
}

sub check_for_ebury_ssh_shmem {
    return if !defined( $IPCS_REF->{root}{mp} );
    for my $href ( @{ $IPCS_REF->{root}{mp} } ) {
        my $shmid = $href->{shmid};
        my $cpid  = $href->{cpid};
        if ( $PROCESS_REF->{$cpid}{CMD} && $PROCESS_REF->{$cpid}{CMD} =~ m{ \A /usr/sbin/sshd \b }x ) {
            push( @SUMMARY, "> [ROOTKIT: SSHd Shared Memory] - " . CYAN "Evidence of hacked SSHd Shared Memory found.\n\t cpid: " . $cpid . " - shmid: " . $shmid . "." );
        }
    }
}

sub check_for_ebury_root_file {
    my $file = '/home/ ./root';
    if ( -e $file ) {
        push( @SUMMARY, "> [ROOTKIT: Ebury] - " . CYAN "Found hidden file: " . $file );
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
        push( @SUMMARY, "> [ROOTKIT: Ebury] - " . CYAN "3-digit RPM's: " . $bad_rpms );
    }
}

sub check_for_ebury_socket {
    return unless my $netstat_out = timed_run( 0, 'netstat', '-nap' );
    my $found = 0;
    for my $line ( split( '\n', $netstat_out ) ) {
        if ( $line =~ m{@/proc/udevd} ) {
            push( @SUMMARY, "> [ROOTKIT: Ebury] - " . CYAN "Ebury socket connection found: " . $line );
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
        push( @SUMMARY, "> [ROOTKIT: NCOM] - " . CYAN "Evidence of the NCOM Rootkit found: " );
        vtlink(@bad_libs);
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
    if ( !("/usr/bin/rpm") ) {
        print "RPM not installed - is this a CentOS server?\n";
        return;
    }
    my $dc_kernel = qx[ uname -r ];
    chomp($dc_kernel);
    if ( $dc_kernel =~ m/stab/ ) {
        print "Virtuozzo Kernel Detected\n";
        if ( $dc_kernel lt "2.6.32-042stab120.3" ) {
            push( @SUMMARY, "> Virtuozzo Kernel [$dc_kernel] is susceptible to DirtyCow [CVE-2016-5195]" );
            logit("Virtuozzo Kernel [$dc_kernel] is susceptible to DirtyCow");
        }
        else {
            logit("Virtuozzo Kernel version is greater than 2.6.32-042stab120.3 - Not susceptible to DirtyCow");
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
                push( @SUMMARY, "> [ROOTKIT: Dragnet] - " . CYAN "Evidence of Dragnet Rootkit found.\n\t libc.so.0 was found in process maps." );
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
        push( @SUMMARY, "> [ROOTKIT: Linux/XoRDDoS] - " . CYAN "Evidence of the Linux/XoRDDoS Rootkit found: " );
        vtlink(@matched);
    }
}

sub check_for_bg_botnet {
    my @found_bg_files = ();
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
    );
    my @root_bg_files = qw(
      /tmp/bill.lock
      /tmp/gates.lock
      /tmp/moni.lock
      /tmp/fdsfsfvff
      /tmp/gdmorpen
      /tmp/gfhjrtfyhuf
      /tmp/rewgtf3er4t
      /tmp/sfewfesfs
      /tmp/smarvtd
      /tmp/whitptabil
    );

    for my $file (@bg_files) {
        if ( -e $file ) {
            push( @found_bg_files, $file );
        }
    }
    for my $file (@root_bg_files) {
        if ( -e $file && ( stat $file )[4] eq 0 ) {
            push( @found_bg_files, $file );
        }
    }
    if ( scalar @found_bg_files ) {
        push( @SUMMARY, "> [ROOTKIT: BG Botnet] - " . CYAN "Evidence of the BG Botnet Rootkit found." );
        vtlink(@found_bg_files);
    }
}

sub check_for_UMBREON_rootkit {
    my $dir = '/usr/local/__UMBREON__';
    if ( chdir $dir ) {
        push( @SUMMARY, "> [ROOTKIT: UMBREON] - " . CYAN "Evidence of the UMBREON Rootkit found: " . $dir . "." );
    }
}

sub check_for_libms_rootkit {
    my $dir = '/lib/udev/x.modules';
    if ( chdir $dir ) {
        push( @SUMMARY, "> [ROOTKIT: LIBMS] - " . CYAN "Evidence of the LIBMS Rootkit found.\nFound the following: " . $dir . "." );
    }
}

sub check_for_jynx2_rootkit {
    my $dir = '/usr/bin64';
    if ( chdir $dir ) {
        my @found_jynx2_files = ();
        my @jynx2_files       = qw( 3.so 4.so );
        for (@jynx2_files) {
            my $file = $dir . "/" . $_;
            if ( -e $file ) {
                push( @found_jynx2_files, $file );
            }
        }
        if ( ( scalar @found_jynx2_files ) > 0 ) {
            push( @SUMMARY, "> [ROOTKIT: Jynx2] - " . CYAN "Evidence of the Jynx2 Rootkit found." );
            push( @SUMMARY, @found_jynx2_files );
        }
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
        push( @SUMMARY, "> [ROOTKIT: ShellBot] - " . CYAN "Evidence of the ShellBot Rootkit found." );
        vtlink(@matched);
    }
}

sub check_for_libkeyutils_symbols {
    local $ENV{'LD_DEBUG'} = 'symbols';
    my $output = timed_run_trap_stderr( 0, '/bin/true' );
    return unless $output;
    if ( $output =~ m{ /lib(keyutils|ns[25]|pw[35]|s[bl]r)\. }xms ) {
        push( @SUMMARY, "> [ROOTKIT: Ebury] - " . CYAN "Evidence of the Ebury Rootkit found in symbol table." );
    }
}

sub all_malware_checks {
    check_for_korkerds();
    check_for_UMBREON_rootkit();
    check_for_libms_rootkit();
    check_for_jynx2_rootkit();
    check_for_cdorked_A();
    check_for_cdorked_B();
    check_for_libkeyutils_symbols();
    check_for_libkeyutils_filenames();
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
    check_for_ncom_filenames();
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

sub run_lynis {
    print_status('Running lynis. This will take a few minutes.');
    logit("Running lynis");
    chdir("$csidir/lynis");
    qx[ ./lynis audit system --quiet --cronjob --logfile "$csidir/lynis.log" &> /dev/null ];
    if ( -s "$csidir/lynis.log" ) {
        my @results = qx[ grep 'Warning:' "$csidir/lynis.log" ];
        if (@results) {
            push @LYNISWARNINGS, "Lynis has found some Warnings that should be looked into: ";
            foreach (@results) {
                push @LYNISWARNINGS, $_;
            }
            push @LYNISWARNINGS, "More information can be found in the log at $csidir/lynis.log";
        }
        else {
            print_info('Good news! Lynis found no Warnings');
        }
    }
    if (@LYNISWARNINGS) {
        logit("Lynis completed - see $csidir/lynis.log file for full results");
        open( my $LYNISWARN, ">", "$csidir/warnings_from_lynis.txt" )
          or die("Can't create $csidir/warnings_from_lynis.txt file $!\n");
        foreach (@LYNISWARNINGS) {
            print $LYNISWARN $_, "\n";
        }
        close($LYNISWARN);
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

sub check_session_log {
    my $returnlines = $_[0];
    my @sessionlog;
    my $sessionlogline;
    my @rootlogins;
    open( SESSIONLOG, "/usr/local/cpanel/logs/session_log" );
    @sessionlog = <SESSIONLOG>;
    close(SESSIONLOG);
    foreach $sessionlogline (@sessionlog) {
        chomp($sessionlogline);
        if ( $sessionlogline =~ m/NEW root/ and ( $sessionlogline =~ m/handle_form_login/ or $sessionlogline =~ m/create_user_session/ ) ) {
            push( @rootlogins, $sessionlogline );
        }
    }
    my $myline;
    my $tstamp;
    my $tz;
    my $loginip;
    my $thedate;
    my @linesTOreturn = ( $returnlines >= @rootlogins ) ? @rootlogins : @rootlogins[ -$returnlines .. -1 ];
    @rootlogins = @linesTOreturn;
    push( @SUMMARY, "> The following $returnlines IP addresses logged on to WHM successfully as root:\n" );

    foreach $myline (@rootlogins) {
        chomp($myline);
        ( $thedate, $tstamp, $tz, $loginip ) = ( split( /\s+/, $myline ) )[ 0, 1, 2, 5 ];
        next if ( $loginip eq "internal" );
        push( @SUMMARY, CYAN "IP: $loginip logged on to WHM on $thedate $tstamp $tz" );
    }
    push( @SUMMARY, CYAN "\nDo you recognize any of the above IP addresses?\nIf not, then further investigation should be performed." );
}

sub install_lynis {
    logit("Installing latest lynis");
    print_header("[ Installing latest lynis ]");
    chdir("$csidir");
    qx[ /usr/local/cpanel/3rdparty/lib/path-bin/git clone https://github.com/CISOfy/lynis &> /dev/null ];
    if ( -e ("$csidir/lynis/lynis") ) {
        return 1;
    }
    else {
        return 0;
    }
}

sub install_rkhunter {
    logit("Installing latest rkhunter");
    my $RKHURL = "http://sourceforge.net/projects/rkhunter/files/latest/download";
    print_header("[ Installing latest rkhunter ]");
    chdir("$csidir");
    qx[ $wget -O rkhunter.tar.gz $RKHURL &> /dev/null ];
    qx[ $tar -xzf rkhunter.tar.gz &> /dev/null ];
    unlink("$csidir/rkhunter.tar.gz");
    opendir( CSIDIR, "$csidir" );
    my @CSIDIRFILES = readdir(CSIDIR);
    closedir(CSIDIR);
    my $csidirfile;
    my $rkhunterinstall;

    foreach $csidirfile (@CSIDIRFILES) {
        chomp($csidirfile);
        next unless ( $csidirfile =~ m/rkhunter/ );
        $rkhunterinstall = $csidirfile;
        last;
    }
    mkdir( "$csidir/rkhunter", 0755 );
    qx[ mv "$csidir/$rkhunterinstall" "$csidir/rkhunterinstall" ];
    chdir("$csidir/rkhunterinstall");
    system("sh installer.sh --layout custom '$csidir/rkhunter' --install &> /dev/null");
    if ( !( -e ("$csidir/rkhunter/bin/rkhunter") ) ) {
        print_warn("RKHunter installation failed!");
        return 0;
    }
    qx[ rm -rf "$csidir/rkhunterinstall" ];
    return 1;
}

sub install_chkrootkit {
    logit("Installing latest chkrootkit");
    my $CHKRKURL = "ftp://ftp.pangeia.com.br/pub/seg/pac/chkrootkit.tar.gz";
    print_header("[ Installing latest chkrootkit ]");
    chdir("$csidir");
    qx[ $wget -O chkrootkit.tar.gz $CHKRKURL &> /dev/null ];
    qx[ $tar -xzf chkrootkit.tar.gz &> /dev/null ];
    unlink("$csidir/chkrootkit.tar.gz");
    opendir( CSIDIR, "$csidir" );
    my @CSIDIRFILES = readdir(CSIDIR);
    closedir(CSIDIR);
    my $csidirfile;
    my $chkrootkitinstall;

    foreach $csidirfile (@CSIDIRFILES) {
        chomp($csidirfile);
        next unless ( $csidirfile =~ m/chkrootkit-/ );
        $chkrootkitinstall = $csidirfile;
        last;
    }
    qx[ mv "$csidir/$chkrootkitinstall" "$csidir/chkrootkit" ];
    if ( !( -e ("$csidir/chkrootkit/chkrootkit") ) ) {
        print_warn("Chkrootkit installation failed!");
    }
    return 1;
}

sub userscan {
    my $lcUserToScan = $_[0];
    my $skipmail     = "--exclude-dir=mail";
    if ($scanmail) {
        $skipmail = "";
        logit("Running a user scan for $lcUserToScan with mail directory scan");
    }
    else {
        logit("Running a user scan for $lcUserToScan skipping mail directory");
    }
    installClamAV();
    my $RealHome;
    my $etcpasswd = qx[ grep -w $lcUserToScan /etc/passwd ];
    if ($etcpasswd) {
        ($RealHome) = ( split( /:/, $etcpasswd ) )[5];
        chomp($RealHome);
    }
    else {
        print_warn("Sorry, $lcUserToScan not found in /etc/passwd file!");
        logit( $lcUserToScan . " not found in /etc/passwd file!" );
        return;
    }
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

    if ( $isClamAVInstalled and !$skipClam ) {
        print_status( "Scanning $RealHome/public_html using clamscan [results will be in " . $csidir . "/" . ${lcUserToScan} . "_clamscan.log]" );
        logit("Beginning clamscan for $lcUserToScan");
        qx[ /usr/local/cpanel/3rdparty/bin/clamscan -i --quiet -o --log="$csidir/${lcUserToScan}_clamscan.log" -r -z --phishing-sigs=yes --phishing-scan-urls=yes --algorithmic-detection=yes $RealHome/public_html ];
    }
    my $URL         = "https://raw.githubusercontent.com/cPanelPeter/infection_scanner/master/strings.txt";
    my @DEFINITIONS = qx[ curl -s $URL ];
    my $StringCnt   = @DEFINITIONS;
    print_status("Scanning $RealHome/public_html for ($StringCnt) known phrases/strings");
    logit("Beginning known phrases/strings scan for $lcUserToScan");
    my @SEARCHSTRING    = sort(@DEFINITIONS);
    my @FOUND           = undef;
    my $SOMETHING_FOUND = 0;
    my $SEARCHSTRING;

    foreach $SEARCHSTRING (@SEARCHSTRING) {
        chomp($SEARCHSTRING);
        my $SCAN = qx[ grep -srIl --exclude-dir=www --exclude-dir=mail --exclude-dir=tmp --exclude=*.png --exclude=*.svg --exclude-dir=access-logs -w "$SEARCHSTRING" $RealHome/public_html ];
        spin();
        chomp($SCAN);
        if ($SCAN) {
            $SOMETHING_FOUND = 1;
            $SEARCHSTRING =~ s/\\//g;
            push( @SUMMARY, GREEN "The phrase $SEARCHSTRING was found in $SCAN" );
        }
    }
    if ( !$SOMETHING_FOUND ) {
        print_info("No suspicious phrases/strings were found!");
        logit("No suspicious phrases/strings were found!");
    }
    print_header('[ cPanel Security Inspection Complete! ]');
    logit('[ cPanel Security Inspection Complete! ]');
    print_normal('');
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
        if ( -e ("/etc/eximdisable") ) {
            print_warn("Exim disabled - Skipping clamd installation");
            logit("Exim is disabled - Skipping clamd installation");
            return;
        }
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
    my @SecAdvisor = qx[ /usr/local/cpanel/scripts/check_security_advice_changes | egrep -v 'High|Info|Advice|Type|Module' ];
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

sub check_for_Xbash {
    my $HasXbash = qx[ mysql -BNe "SHOW DATABASES LIKE 'PLEASE_READ%';" ];
    chomp($HasXbash);
    if ($HasXbash) {
        push( @SUMMARY, "> Possible Xbash ransomware detected. Database's missing? Database $HasXbash exists!" );
    }
}

sub vtlink {
    my $FileToChk = $_[0];
    chomp($FileToChk);
    my ( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat($FileToChk);
    my $isRPMowned = qx[ /usr/bin/rpm -qf $FileToChk | grep 'not owned by any package' ];
    chomp($isRPMowned);
    my $RPMowned = "";
    if ($isRPMowned) {
        $RPMowned = RED "No - " . YELLOW "Most system files should be owned by an RPM";
    }
    else {
        $isRPMowned = qx[ rpm -qf $FileToChk ];
        chomp($isRPMowned);
        $RPMowned = GREEN "Yes - " . YELLOW $isRPMowned;
    }
    my $KFS      = ( $size / 1024 );
    my $sizeDesc = "";
    if ( $KFS > 25 ) {
        $sizeDesc = " - Most system files/libraries are less than 25k. Anything larger should be considered suspicious.";
    }
    my $FileNormal = "";
    if ( $RPMowned =~ m/Yes -/ ) {
        $FileNormal = " - Compare the Size and Key ID against a clean server.\n  See if they match [ " . CYAN "rpm -qil $isRPMowned | egrep 'Size|Key ID' ].";
    }
    else {
        $FileNormal = " - Not normally present on clean servers. Its presence should be considered suspicious.";
    }
    my $sha256 = qx[ sha256sum $FileToChk ];
    chomp($sha256);
    ($sha256only) = ( split( /\s+/, $sha256 ) )[0];
    push @SUMMARY, "  File     : " . CYAN $FileToChk . GREEN $FileNormal;
    push @SUMMARY, "  Size     : " . CYAN $size . WHITE " (" . $KFS . ")" . GREEN $sizeDesc;
    push @SUMMARY, "  Changed  : " . CYAN scalar localtime($ctime) . GREEN " [ Approximate date the compromise may have occurred ]";
    push @SUMMARY, "  RPM Owned: " . CYAN $RPMowned;
    push @SUMMARY, "  sha256sum: " . CYAN $sha256only . "\n";
    push @SUMMARY, GREEN "  Taking the above sha256 hash of $FileToChk and plugging it into VirusTotal.com...";
    push @SUMMARY, GREEN "  Check this link: " . WHITE "https://www.virustotal.com/#/file/$sha256only/detection\n";
    push @SUMMARY, GREEN "  See if it has already been detected.\n";
}

# EOF
