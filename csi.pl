#!/usr/local/cpanel/3rdparty/bin/perl
# Copyright 2020, cPanel, L.L.C.
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
#
# Current Maintainer: Peter Elsner

use strict;
my $version = "3.4.30";
use Cpanel::Config::LoadWwwAcctConf();
use Cpanel::Config::LoadCpConf();
use Text::Tabs;
$tabstop = 4;
use File::Basename;
use File::Path;
use File::stat;
use DateTime;
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
use List::MoreUtils qw(uniq);
use Math::Round;
use File::Find::Rule;
use POSIX;
use Getopt::Long;
use Path::Iterator::Rule;
use IO::Socket::INET;
use IO::Prompt;
use Term::ANSIColor qw(:constants);
use Time::Piece;
use Time::Seconds;
$Term::ANSIColor::AUTORESET = 1;

my $rootdir = "/root";
my $csidir  = "$rootdir/CSI";
our @HISTORY;
our $KernelChk;
our $spincounter;
our $CPANEL_CONFIG_FILE = q{/var/cpanel/cpanel.config};
my $conf             = Cpanel::Config::LoadWwwAcctConf::loadwwwacctconf();
my $cpconf           = Cpanel::Config::LoadCpConf::loadcpconf();
my $allow_accesshash = $cpconf->{'allow_deprecated_accesshash'};
my $sha256only;
our $HOMEDIR       = $conf->{'HOMEDIR'};
our @FILESTOSCAN   = undef;
our $rootkitsfound = 0;
my $Last10 = "-10";
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
my $libchk;
my $shadow;
my $symlink;
my $secadv;
my $help;
my $userscan;
my $binscan;
my $scan;
our @process_list = get_process_list();
my %process;
&get_process_pid_hash( \%process );
my %ipcs;
&get_ipcs_hash( \%ipcs );
my $distro         = Cpanel::Sys::OS::getos();
my $distro_version = Cpanel::Sys::OS::getreleaseversion();
our $OS_RELEASE            = ucfirst($distro) . " Linux release " . $distro_version;
our $HTTPD_PATH            = get_httpd_path();
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
    'libchk'     => \$libchk,
    'shadow'     => \$shadow,
    'symlink'    => \$symlink,
    'secadv'     => \$secadv,
    'help'       => \$help,
);

#######################################
# Set variables needed for later subs #
#######################################
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

my %cpconf = get_conf($CPANEL_CONFIG_FILE);
if ( Cpanel::IONice::ionice( 'best-effort', exists $cpconf{'ionice_import_exim_data'} ? $cpconf{'ionice_import_exim_data'} : 6 ) ) {
    print_info( "Setting I/O priority to reduce system load: " . Cpanel::IONice::get_ionice() . "\n" );
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
print_header("Checking for RPM database corruption and repairing as necessary...");
my $findRPMissues   = qx[ /usr/local/cpanel/scripts/find_and_fix_rpm_issues ];
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
my $scanTotTime  = $scantimediff->pretty;
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
    print_status("With no arguments, performs a quick scan looking for IoC's.");
    print_normal(" ");
    print_status("--bincheck  Performs RPM verification on core system binaries and prints active aliases.");
    print_normal(" ");
    print_status("--userscan cPanelUser  Performs YARA scan [using clamscan if ClamAV is installed] for a single cPanel User..");
    print_normal(" ");
    print_header("Additional scan options available");
    print_header("=================");
    print_header("--libchk	Performs a non-owned library/file check.");
    print_header("--shadow	Performs a check on all email accounts looking for variants of shadow.roottn hack.");
    print_header("--symlink	Performs a symlink hack check for all accounts.");
    print_header("--secadv	Runs Security Advisor");
    print_header("--full		Performs all of the above checks - very time consuming.");
    print_normal(" ");
    print_header("Examples");
    print_header("=================");
    print_status("            /root/csi.pl [DEFAULT] quick scan");
    print_status("            /root/csi.pl --libchk --shadow");
    print_status("            /root/csi.pl --symlink");
    print_status("            /root/csi.pl --full");
    print_status("Bincheck: ");
    print_status("            /root/csi.pl --bincheck");
    print_status("Userscan ");
    print_status("            /root/csi.pl --userscan myuser");
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
    print_status( 'Done - Found: ' . $RPMcnt . ' RPMs to verify' );
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
    print_header('[ Starting cPanel Security Inspection: SCAN Mode ]');
    print_header("[ System: $OS_RELEASE ]");
    print_normal('');
    print_header("[ Available flags when running csi.pl scan ]");
    print_header( MAGENTA '[     --full Performs a more compreshensive scan ]' );
    print_header( MAGENTA '[     --libchk Performs a non-owned library/file check ]' );
    print_header( MAGENTA '[     --shadow Scans all accounts for variants of shadow.roottn email hack ]' );
    print_header( MAGENTA '[     --symlink Scans for symlink hacks going back to / ]' );
    print_header( MAGENTA '[     --secadv Performs a Security Advisor run ]' );
    print_normal('');
    print_header('[ Checking logfiles ]');
    logit("Checking logfiles");
    check_logfiles();
    print_header('[ Checking for bad UIDs ]');
    logit("Checking for bad UIDs");
    check_uids();
    print_header('[ Checking for known Indicators of Compromise (IoC) ]');
    logit("Checking for known IoC's");
    all_malware_checks();
    print_header('[ Checking Apache configuration ]');
    logit("Checking Apache configuration");
    check_httpd_config();
    print_header('[ Checking if Use MD5 passwords with Apache is disabled ]');
    logit("Checking if Use MD5 passwords with Apache is disabled");
    chk_md5_htaccess();
    print_header('[ Checking for index.html in /tmp and /home ]');
    logit("Checking for index file in /tmp and $HOMEDIR");
    check_index();
    print_header('[ Checking for modified suspended page ]');
    logit("Checking web template [suspendedpage]");
    check_suspended();
    print_header('[ Checking for suspicious files ]');
    logit("Checking for suspicious files");
    look_for_suspicious_files();
    print_header('[ Checking if root bash history has been tampered with ]');
    logit("Checking roots bash_history for tampering");
    check_history();
    print_header('[ Checking /etc/ld.so.preload for compromised library ]');
    check_preload();
    print_header('[ Checking process list for suspicious processes ]');
    logit("Checking process list for suspicious processes");
    check_processes();
    check_for_stealth_in_ps();
    print_header('[ Checking for suspicious bitcoin miners ]');
    logit("Checking for suspicious bitcoin miners");
    bitcoin_chk();
    print_header('[ Checking for miscellaneous compromises ]');
    logit("Checking for miscellaneous compromises");
    misc_checks();
    check_changepasswd_modules();
    print_header('[ Checking Apache Modules ]');
    logit("Checking Apache Modules (owned by RPM)");
    check_apache_modules();
    print_header('[ Checking for deprecated plugins/modules ]');
    logit("Checking for deprecated plugins");
    check_for_deprecated();
    print_header('[ Checking for sshd_config ]');
    logit("Checking sshd_config");
    check_sshd_config();
    print_header('[ Checking vm.nr.hugepages in /proc/sys/vm ]');
    logit("Checking vm.nr.hugepages value");
    check_proc_sys_vm();
    print_header('[ Checking for modified/hacked SSH ]');
    logit("Checking for modified/hacked ssh");
    check_ssh();
    print_header('[ Checking /root/.bash_history for anomalies ]');
    logit("Checking /root/.bash_history");
    check_for_TTY_shell_spawns();
    check_roots_history();
    print_header('[ Checking for non-root users with ALL privileges in /etc/sudoers file ]');
    logit("Checking /etc/sudoers file");
    check_sudoers_file();
    print_header('[ Checking for spam sending script in /tmp ]');
    logit("Checking for spam sending script in /tmp");
    spamscriptchk();
    spamscriptchk2();

    if ( -e "/etc/grub.conf" ) {
        print_header('[ Checking kernel status ]');
        logit("Checking kernel status");
        check_kernel_updates();
    }
    print_header('[ Checking for MySQL users with Super privileges ]');
    logit("Checking for MySQL users with Super privileges");
    check_for_Super_privs();

    if ( $full or $libchk ) {
        print_header( YELLOW '[ Additional check for files/libraries not owned by an RPM ]' );
        logit("Checking for non-owned files/libraries");
        check_lib();
    }
    if ( $full or $symlink ) {
        print_header( YELLOW '[ Additional check for symlink hacks ]' );
        logit("Checking for symlink hacks");
        check_for_symlinks();
    }
    if ( $full or $shadow ) {
        print_header( YELLOW '[ Additional check for shadow.roottn.bak hacks ]' );
        logit("Checking for shadow.roottn.bak hacks");
        chk_shadow_hack();
    }

    # Checking for recommendations
    print_header('[ Checking if updates are enabled ]');
    logit("Checking if updates are enabled");
    check_cpupdate_conf();
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
    get_root_pass_changes();

    if ( $full or $secadv ) {
        print_header( YELLOW '[ Additional check Security Advisor ]' );
        logit("Running Security Advisor");
        security_advisor();
    }

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
    if ( Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '>', '11.68' ) ) {

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

        # Load /root/.bash_history into @HISTORY array
        open( HISTORY, "/root/.bash_history" );
        @HISTORY = <HISTORY>;
        close(HISTORY);
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
        if ( $user eq 'firefart' ) {
            push @SUMMARY, "> firefart user found [Possible DirtyCow root-level compromise].";
        }
        if ( $user eq 'sftp' ) {
            push @SUMMARY, "> sftp user found [Possible HiddenWasp root-level compromise].";
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

sub check_for_TTY_shell_spawns {
    my $histline;
    foreach $histline (@HISTORY) {
        chomp($histline);

        if ( $histline =~ m/python -c 'import pty; pty.spawn("\/bin\/sh");'|python -c 'import pty;pty.spawn("\/bin\/bash");'|echo os.system\('\/bin\/bash'\)|\/bin\/sh -i|\/bin\/bash -i/ ) {
            push( @SUMMARY, "> Evidence of in /root/.bash_history for possible TTY shell being spawned" );
            push( @SUMMARY, "\t \\_ $histline\n" );
        }
    }
}

sub check_roots_history {
    my $histline;
    foreach $histline (@HISTORY) {
        chomp($histline);
        if ( $histline =~ m/\etc\/cxs\/uninstall.sh|rm -rf \/etc\/apache2\/conf.d\/modsec|bash \/etc\/csf\/uninstall.sh|yum remove -y cpanel-clamav/ ) {
            push( @SUMMARY, "> Suspicious entries found in /root/.bash_history" );
            push( @SUMMARY, "\t\\_ $histline" );
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

    #chomp( my @ps_output = qx(ps auxf) );
    chomp( my @ps_output = qx(ps eo cmd) );
    foreach my $line (@ps_output) {
        if ( $line =~ 'sleep 7200' ) {
            push @SUMMARY, "> ps output contains 'sleep 7200' which is a known part of a hack process:";
            push @SUMMARY, "\t$line";
        }
        if ( $line =~ 'sleep 30' ) {
            push @SUMMARY, "> ps output contains 'sleep 30/300' which is a known part of a root-level infection";
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
        if ( $line =~ /watchdog/ ) {
            push @SUMMARY, "> ps output contains 'watchdog' indicates potential watchdog coin miner compromise";
            push @SUMMARY, "\t$line";
        }
        if ( $line =~ /watchbog/ ) {
            push @SUMMARY, "> ps output contains 'watchbog' indicates potential watchdog coin miner compromise";
            push @SUMMARY, "\t$line";
        }
        if ( $line =~ /bnrffa4/ ) {
            push @SUMMARY, "> ps output contains 'bnrffa4' indicates potential Linux/Lady Rootkit";
            push @SUMMARY, "\t$line";
        }
        if ( $line =~ /systemdo/ ) {
            push @SUMMARY, "> ps output contains 'systemdo' indicates potential cryptominer";
            push @SUMMARY, "\t$line";
        }
        if ( $line =~ /\[kworker\/u8:7-ev\]/ ) {
            push @SUMMARY, "> ps output contains '[kworker/u8:7ev]' indicates potential ACBackdoor rootkit";
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
    my @HasPastebinURL = qx[ grep -srl 'pastebin' /etc/cron* ];
    my $PastebinCnt    = @HasPastebinURL;
    my $PastebinLine   = "";
    if ( $PastebinCnt > 0 ) {
        push @SUMMARY, "> Found pastebin URL's in cron files: ";
        foreach $PastebinLine (@HasPastebinURL) {
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
    my @dirs    = qw( /lib /lib64 /usr/lib /usr/lib64 /usr/local/include /usr/local/include64 );
    my $dir     = "";
    my @AllDirs = undef;
    my @array   = undef;
    foreach $dir (@dirs) {
        chomp($dir);
        next unless -d $dir;
        @array = File::Find::Rule->directory->in($dir);
        push @AllDirs, @array;
    }
    my $line = "";
    splice( @AllDirs, 0, 1 );
    my @RPMNotOwned = undef;
    foreach $line (@AllDirs) {
        chomp($line);
        next unless ( !-d $line );
        next if $line =~ m{/usr/lib/systemd/system|/lib/modules|/lib/firmware|/usr/lib/vmware-tools|/lib64/xtables|jvm|php|perl5|/usr/lib/ruby|python|golang|fontconfig|/usr/lib/exim|/usr/lib/exim/bin|/usr/lib64/pkcs11|/usr/lib64/setools|/usr/lib64/dovecot/old-stats|/usr/lib64/libdb4};
        my $NotOwned = qx[ rpm -qf $line | grep 'not owned' ];
        next unless ($NotOwned);
        push @RPMNotOwned, $line . " is not owned by any RPM";
    }
    splice( @RPMNotOwned, 0, 1 );
    if (@RPMNotOwned) {
        push @SUMMARY, "> Found library files not owned by an RPM, *MAY* indicate a compromise or a custom install by an administrator.";
        foreach (@RPMNotOwned) {
            chomp($_);
            push( @SUMMARY, expand( CYAN "\t\\_ " . $_ ) );
        }
    }
}

sub get_process_pid_hash ($) {
    my ($href) = @_;
    for ( split /\n/, timed_run( 0, 'ps', 'axwww', '-o', 'user,pid,ppid,cmd' ) ) {
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
        local $SIG{'ALRM'}    = sub { $output = ""; print RED ON_BLACK "Timeout while executing: " . join( ' ', @PROGA ) . "\n"; die; };
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
        local $SIG{'ALRM'}    = sub { $output = ""; print RED ON_BLACK "Timeout while executing: " . join( ' ', @PROGA ) . "\n"; die; };
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
        print_warn('Found /usr/lib64/libcrypt.so.1.1.0 in /etc/ld.so.preload - Possible root-level compromise.');
    }
    my $libconv_so = qx[ grep 'libconv.so' /etc/ld.so.preload ];
    if ($libconv_so) {
        print_warn('Found libconv.so in /etc/ld.so.preload - Possible root-level compromise.');
    }
}

sub create_summary {
    open( my $CSISUMMARY, '>', "$csidir/summary" )
      or die("Cannot create CSI summary file $csidir/summary: $!\n");
    foreach (@SUMMARY) {
        print $CSISUMMARY $_, "\n";
    }
    close($CSISUMMARY);
}

sub dump_summary {
    if ( @SUMMARY == 0 ) {
        unlink("$csidir/summary");
    }
    else {
        create_summary();
        if (@SUMMARY) {
            print_warn('The following negative items were found:');
            foreach (@SUMMARY) {
                print BOLD YELLOW $_ . "\n";
            }
            print_normal('');
            print_separator('If you believe there are negative items, you should consult with your system administrator or a security professional.');
            print_separator('If you need a system administrator, one can probably be found by going to https://go.cpanel.net/sysadmin');
            print_separator('Note: cPanel Support cannot assist you with any negative issues found.');
            print_normal('');
        }
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

sub check_for_kthrotlds {
    if ( -e ("/usr/bin/\[kthrotlds\]") ) {
        push( @SUMMARY, "> [Possible rootkit: Linux/CoinMiner.AP] - " . CYAN "Evidence of Linux/CoinMiner.AP rootkit found." );
        vtlink("/usr/bin/\[kthrotlds\]");
    }
}

sub check_for_cdorked_A {
    return unless defined $HTTPD_PATH;
    return unless -f $HTTPD_PATH;
    my $max_bin_size = 10_485_760;
    my $fStat        = stat($HTTPD_PATH);
    my $FileSize     = $fStat->size;
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
        push( @SUMMARY, "> [Possible Rootkit: CDORKED A] - " . CYAN "Evidence of CDORKED A Rootkit found." );
    }
}

sub check_for_cdorked_B {
    my $has_cdorked_b = 0;
    my @files         = ( '/usr/sbin/arpd ', '/usr/sbin/tunelp ', '/usr/bin/s2p ' );
    my $cdorked_files;
    for my $file (@files) {
        if ( -e $file ) {
            $has_cdorked_b = 1;
            $cdorked_files .= "[$file] ";
        }
    }
    if ( $has_cdorked_b == 1 ) {
        push( @SUMMARY, "> [Possible Rootkit: CDORKED B] - " . CYAN "Evidence of CDORKED B Rootkit found.\n\t Found " . $cdorked_files . " [Note space at end of files]" );
    }
}

sub check_for_libkeyutils_filenames {
    my $bad_libs;
    my @bad_libs;
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
      libtsq.so
      libhdx.so
      tls/libkeyutils.so.1
      tls/libkeyutils.so.1.5
    );

    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            if ( -f "${dir}/${file}" and not -z "${dir}/${file}" ) {
                push( @bad_libs, "${dir}/${file}" );
            }
        }
    }
    return if ( @bad_libs == 0 );
    push( @SUMMARY, "> [Possible Rootkit: Ebury/Libkeys]" );
    foreach $bad_libs (@bad_libs) {
        vtlink($bad_libs);
    }
    $rootkitsfound = 1;
}

sub check_sha1_sigs_libkeyutils {
    return if !$LIBKEYUTILS_FILES_REF;
    my $trojaned_lib;
    my @checksums = qw(
      09c8af3be4327c83d4a7124a678bbc81e12a1de4
      17c40a5858a960afd19cc02e07d3a5e47b2ab97a
      1a9aff1c382a3b139b33eeccae954c2d65b64b90
      1d3aafce8cd33cf51b70558f33ec93c431a982ef
      267d010201c9ff53f8dc3fb0a48145dc49f9de1e
      27ed035556abeeb98bc305930403a977b3cc2909
      2e571993e30742ee04500fbe4a40ee1b14fa64d7
      2f382e31f9ef3d418d31653ee124c0831b6c2273
      2fc132440bafdbc72f4d4e8dcb2563cc0a6e096b
      39ec9e03edb25f1c316822605fe4df7a7b1ad94a
      3c5ec2ab2c34ab57cba69bb2dee70c980f26b1bf
      44b340e90edba5b9f8cf7c2c01cb4d45dd25189e
      471ee431030332dd636b8af24a428556ee72df37
      58f185c3fe9ce0fb7cac9e433fb881effad31421
      5c796dc566647dd0db74d5934e768f4dfafec0e5
      5d3ec6c11c6b5e241df1cc19aa16d50652d6fac0
      615c6b022b0fac1ff55c25b0b16eb734aed02734
      7248e6eada8c70e7a468c0b6df2b50cf8c562bc9
      74aa801c89d07fa5a9692f8b41cb8dd07e77e407
      7adb38bf14e6bf0d5b24fa3f3c9abed78c061ad1
      899b860ef9d23095edb6b941866ea841d64d1b26
      8daad0a043237c5e3c760133754528b97efad459
      8f75993437c7983ac35759fe9c5245295d411d35
      9bb6a2157c6a3df16c8d2ad107f957153cba4236
      9e2af0910676ec2d92a1cad1ab89029bc036f599
      a559ee8c2662ee8f3c73428eaf07d4359958cae1
      a7b8d06e2c0124e6a0f9021c911b36166a8b62c5
      adfcd3e591330b8d84ab2ab1f7814d36e7b7e89f
      b58725399531d38ca11d8651213b4483130c98e2
      b8508fc2090ddee19a19659ea794f60f0c2c23ff
      bbce62fb1fc8bbed9b40cfb998822c266b95d148
      bf1466936e3bd882b47210c12bf06cb63f7624c0
      d4eeada3d10e76a5755c6913267135a925e195c6
      d552cbadee27423772a37c59cb830703b757f35e
      e14da493d70ea4dd43e772117a61f9dbcff2c41c
      e2a204636bda486c43d7929880eba6cb8e9de068
      e8d392ae654f62c6d44c00da517f6f4f33fe7fed
      e8d3c369a231552081b14076cf3eaa8901e6a1cd
      eb352686d1050b4ab289fe8f5b78f39e9c85fb55
      f1ada064941f77929c49c8d773cbad9c15eba322
    );

    for my $lib (@$LIBKEYUTILS_FILES_REF) {
        next unless my $checksum = timed_run( 0, 'sha1sum', "$lib" );
        chomp $checksum;
        $checksum =~ s/\s.*//g;
        if ( grep { /$checksum/ } @checksums ) {
            push( @SUMMARY, "> [Possible Rootkit: Ebury/Libkeys] - " . CYAN "Evidence of Ebury/Libkeys Rootkit found." );
            vtlink($lib);
            last;
        }
    }
}

sub check_for_evasive_libkey {
    my $EvasiveLibKey = qx[ strings /etc/ld.so.cache |grep tls/ ];
    if ($EvasiveLibKey) {
        push( @SUMMARY, "> [Possible Rootkit: Ebury/Libkeys] - " . CYAN "Hidden/Evasive evidence of Ebury/Libkeys Rootkit found.\n\t \\_ TECH-759" );
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
        return if ($rootkitsfound);
        push( @SUMMARY, "> [Possible Rootkit: Ebury/Libkeys] - " . CYAN "Library/file not owned by an RPM" );
        for my $unowned_lib (@unowned_libs) {
            push( @SUMMARY, CYAN "\t\\_ $unowned_lib is not owned by any RPM" );
            vtlink($unowned_lib);
        }
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
        push( @SUMMARY, "> [Possible Rootkit: ssh Binary] - " . CYAN "Evidence of hacked ssh binary found.\n\t " . $ssh . " -G did not return either 'illegal' or 'unknown'" );
    }
}

sub check_for_ebury_ssh_shmem {
    return if !defined( $IPCS_REF->{root}{mp} );
    for my $href ( @{ $IPCS_REF->{root}{mp} } ) {
        my $shmid = $href->{shmid};
        my $cpid  = $href->{cpid};
        if ( $PROCESS_REF->{$cpid}{CMD} && $PROCESS_REF->{$cpid}{CMD} =~ m{ \A /usr/sbin/sshd \b }x ) {
            push( @SUMMARY, "> [Possible Rootkit: SSHd Shared Memory] - " . CYAN "Evidence of hacked SSHd Shared Memory found.\n\t cpid: " . $cpid . " - shmid: " . $shmid . "." );
        }
    }
}

sub check_for_ebury_root_file {
    my $file = '/home/ ./root';
    if ( -e $file ) {
        push( @SUMMARY, "> [Possible Rootkit: Ebury] - " . CYAN "Found hidden file: " . $file );
    }
}

sub check_for_ebury_socket {
    return unless my $netstat_out = timed_run( 0, 'netstat', '-nap' );
    my $found = 0;
    for my $line ( split( '\n', $netstat_out ) ) {
        if ( $line =~ m{@/proc/udevd} ) {
            push( @SUMMARY, "> [Possible Rootkit: Ebury] - " . CYAN "Ebury socket connection found: " . $line );
            $found = 1;
            last;
        }
    }
}

sub check_for_ngioweb {
    return if ( !-e "/etc/machine-id" );
    return unless (qx[ grep 'ddb0b49d10ec42c38b1093b8ce9ad12a' /etc/machine-id ]);
    push( @SUMMARY, "Found evidence of Linux.Ngioweb Rootkit\n\t\\_ /etc/machine-id contains: ddb0b49d10ec42c38b1093b8ce9ad12a" );
}

sub check_for_hiddenwasp {
    if ( -e ("/lib/libselinux.a") ) {
        my $HIDESHELL = qx[ strings /lib/libselinux.a | grep 'HIDE_THIS_SHELL' ];
        if ($HIDESHELL) {
            push @SUMMARY, "> Found HIDE_THIS_SHELL in the /lib/libselinux.a file. Could indicate HiddenWasp Rootkit";
        }
    }
    if (qx[ env | grep 'I_AM_HIDDEN' ]) {
        push @SUMMARY, "> Found I_AM_HIDDEN environment variable. Could indicate HiddenWasp Rootkit";
    }
    my $HWSocket = qx[ lsof -i tcp:61061 ];
    if ($HWSocket) {
        push @SUMMARY, "> Found socket listening on port 61061. Could indicate HiddenWasp Rootkit";
    }
}

sub check_for_dirtycow_passwd {
    print_header("[ Checking for evidence of DirtyCow within /etc/passwd ]");
    return unless my $gecos = ( getpwuid(0) )[6];
    if ( $gecos eq "pwned" ) {
        push( @SUMMARY, "> [DirtyCow] - Evidence of FireFart/DirtyCow compromise found." );
        my @passwdBAK    = qx[ stat -c "%n [Owned by %U]" /tmp/*passwd* 2> /dev/null ];
        my $passwdBAKcnt = @passwdBAK;
        my $passwdBAK;
        if ( $passwdBAKcnt > 0 ) {
            push( @SUMMARY, MAGENTA "\t\\_ Possible backup of /etc/passwd found:" );
            foreach $passwdBAK (@passwdBAK) {
                chomp($passwdBAK);
                push( @SUMMARY, CYAN "\t\t\\_ " . $passwdBAK );
            }
        }
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
    if ( $dc_kernel =~ m/amzn1|Amazon Linux AMI/ ) {
        if ( $dc_kernel lt "4.4.23" ) {
            push( @SUMMARY, "> Amazon Linux AMI Kernel [$dc_kernel] is susceptible to DirtyCow [CVE-2016-5195]" );
            logit("Amazon Linux AMI Kernel [$dc_kernel] is susceptible to DirtyCow");
        }
        else {
            logit("Amazon Linux AMI Kernel version is greater than 4.4.23 - Not susceptible to DirtyCow");
        }
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
                push( @SUMMARY, "> [Possible Rootkit: Dragnet] - " . CYAN "Evidence of Dragnet Rootkit found.\n\t libc.so.0 was found in process maps." );
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
        push( @SUMMARY, "> [Possible Rootkit: Linux/XoRDDoS] - " . CYAN "Evidence of the Linux/XoRDDoS Rootkit found: " );
        vtlink(@matched);
    }
}

sub check_for_suckit {
    my $SuckItCount = 0;
    my @dirs        = qw( /sbin /etc/rc.d/rc0.d /etc/rc.d/rc1.d /etc/rc.d/rc2.d /etc/rc.d/rc3.d /etc/rc.d/rc4.d /etc/rc.d/rc5.d /etc/rc.d/rc6.d /etc/.MG /usr/share/locale/sk/.sk12 /dev/sdhu0/tehdrakg /usr/lib/perl5/site_perl/i386-linux/auto/TimeDate/.packlist /dev/.golf /lib );
    my @files       = qw( sk S23kmdac .x );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            my $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
                $SuckItCount++;
            }
        }
    }
    if ( -e "/sbin/init" ) {
        my ($SuckItHomeVal) = ( split( /=/, qx[ strings /sbin/init | grep 'HOME=' ] ) )[1];
        if ( $SuckItHomeVal and $SuckItHomeVal =~ m/[a-zA-z0-9]/ ) {
            $SuckItCount++;
        }
        my $SuckItFound = qx[ strings -an4 /sbin/init | egrep -ie "(fuck|backdoor|bin/rcpc|bin/login)" ];
        if ($SuckItFound) {
            $SuckItCount++;
        }
    }
    my $HasSuckIt = qx[ cat /proc/1/maps | egrep "init." | grep -v '(deleted)' ];
    if ($HasSuckIt) {
        $SuckItCount++;
    }
    my $initSymLink    = qx[ ls -li /sbin/init ];
    my $telinitSymLink = qx[ ls -li /sbin/telinit ];
    my ( $SLInode1, $isLink1 ) = ( split( /\s+/, $initSymLink ) )[ 0, 1 ];
    my ( $SLInode2, $isLink2 ) = ( split( /\s+/, $telinitSymLink ) )[ 0, 1 ];
    if ( $SLInode1 == $SLInode2 and substr( $isLink1, 0, 1 ) ne "l" or substr( $isLink2, 0, 1 ) ne "l" ) {
        $SuckItCount++;
    }
    my $SuckItHidden = qx[ touch "$csidir/suckittest.mem" "$csidir/suckittest.xrk" ];
    if ( !-e "$csidir/suckittest.mem" or !-e "$csidir/suckittest.mem" ) {
        $SuckItCount++;
    }
    if ( $SuckItCount > 1 ) {
        push( @SUMMARY, "> [Possible Rootkit: SuckIt] - " . CYAN "$SuckItCount out of 6 checks used have detected evidence of the SuckIt Rootkit." );
        if ( $SuckItCount > 2 ) {
            push( @SUMMARY, "  (More than 3 checks being positive, should be investigated)" );
        }
    }
}

sub check_for_redisHack {
    return unless ( -e "/root/.ssh/authorized_keys" );
    my $RedisHack = qx[ grep 'REDIS0006 crackitA' /root/.ssh/authorized_keys ];
    if ($RedisHack) {
        push( @SUMMARY, "> [Possible Rootkit: Redis Hack] - " . CYAN "Evidence of the Redis Hack compromise found in /root/.ssh/authorized_keys." );
    }
}

sub check_for_linux_lady {
    my $LLSocket1 = qx[ lsof -i tcp:6379 ];

    # NOTE: redis server software runs on port 6379.  Hopefully it's not running as root :)
    if ( $LLSocket1 =~ m/root/ ) {
        push @SUMMARY, "> Found socket listening on port 6379 (Redis server?). Running as root - VERY DANGEROUS!";
    }
}

sub check_for_bg_botnet {
    my @bg_files = qw(
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
      /usr/bin/pojie
      /usr/lib/libamplify.so
      /etc/pprt
      /etc/ssh.tar
      /var/.lug.txt
      /lost+found/mimipenguin-master/kautomount--pid-file-var-run-au
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
      /tmp/tmpnam_[a-zA-Z]{5}
      /tmp/tmp.l
      /etc/init.d/upgrade
      /etc/init.d/python3.O
      /bin/update-rc.d
    );
    my @found_bg_files = grep { -e $_ } @bg_files;
    return unless ( scalar @found_bg_files );
    push( @SUMMARY, "> [Possible Rootkit: Elknot/BG Botnet] - " . CYAN "Evidence of the Elknot (BG Botnet) Rootkit found." );
    my $elknot_file;

    for $elknot_file (@found_bg_files) {
        chomp($elknot_file);
        push( @SUMMARY, expand( CYAN " \t\\_ " . $elknot_file ) );
        vtlink($elknot_file);
    }
}

sub check_for_jynx2_rootkit {
    my @dirs  = qw( /usr/bin64 /XxJynx );
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
                push( @SUMMARY, "> [Possible Rootkit: Jynx2] - " . CYAN "Evidence of the Jynx2 Rootkit found." );
                vtlink($fullpath);
            }
        }
    }
}

sub check_for_azazel_rootkit {
    if (qx[ env | grep 'HIDE_THIS_SHELL' ]) {
        push @SUMMARY, "> Found HIDE_THIS_SHELL environment variable. Could indicate Azazel Rootkit";
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
        push( @SUMMARY, "> [Possible Rootkit: ShellBot] - " . CYAN "Evidence of the ShellBot Rootkit found." );
        vtlink(@matched);
    }
    if ( -e "/tmp/s.pl" ) {
        my $funcarg = qx[ grep funcarg /tmp/s.pl ];
        if ($funcarg) {
            push( @SUMMARY, "> [Possible Rootkit: ShellBot] - " . CYAN "Evidence of the ShellBot Rootkit found." );
        }
    }
}

sub check_for_libkeyutils_symbols {
    local $ENV{'LD_DEBUG'} = 'symbols';
    my $output = timed_run_trap_stderr( 0, '/bin/true' );
    return unless $output;
    if ( $output =~ m{ /lib(keyutils|ns[25]|pw[35]|s[bl]r)\. }xms ) {
        push( @SUMMARY, "> [Possible Rootkit: Ebury] - " . CYAN "Evidence of the Ebury Rootkit found in symbol table.\n\t\_ Run: LD_DEBUG=symbols /bin/true 2>&1 | egrep '/lib(keyutils|ns[25]|pw[35]|s[bl]r)\.' to confirm." );
    }
}

sub all_malware_checks {
    check_for_kthrotlds();
    check_for_linux_lady();
    check_for_ncom_rootkit();
    check_for_jynx2_rootkit();
    check_for_azazel_rootkit();
    check_for_cdorked_A();
    check_for_cdorked_B();
    check_for_suckit();
    check_for_libkeyutils_symbols();
    check_for_libkeyutils_filenames();
    check_for_unowned_libkeyutils_files();
    check_for_evasive_libkey();
    check_sha1_sigs_libkeyutils();
    check_for_ebury_ssh_G();
    check_for_ebury_ssh_shmem();
    check_for_ebury_root_file();
    check_for_ebury_socket();
    check_for_bg_botnet();
    check_for_dragnet();
    check_for_xor_ddos();
    check_for_shellbot();
    check_for_exim_vuln();
    check_for_hiddenwasp();
    check_for_ngioweb();
    check_for_dirtycow_passwd();
    check_for_dirtycow_kernel();
    check_for_lilocked_ransomware();
    check_for_junglesec();
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
    my $RealHome     = Cpanel::PwCache::gethomedir($lcUserToScan);
    if ( !( -e ("$RealHome") ) ) {
        print_warn("$lcUserToScan has no /home directory!");
        logit( $lcUserToScan . " has no /home directory!" );
        return;
    }
    print_status("Checking for symlinks to other locations...");
    logit( "Checking for symlink hacks in " . $RealHome . "/public_html" );
    my @symlinks;
    my @conffiles = qw( / wp-config.php configuration.php conf_global.php Settings.php config.php settings.php root );
    my $conffile;
    foreach $conffile (@conffiles) {
        chomp($conffile);
        push( @symlinks, qx[ find "$RealHome/public_html" -type l -lname "$HOMEDIR/*/public_html/$conffile" -ls ] );
    }
    my $headerprinted = 0;
    my $hp1           = 0;
    my $hp2           = 0;
    my $symlink;
    foreach $symlink (@symlinks) {
        my ( $symUID, $symGID, $link, $pointer, $realpath ) = ( split( /\s+/, $symlink ) )[ 4, 5, 10, 11, 12 ];
        my ( $SLfilename, $SLdir ) = fileparse($link);
        if ( $headerprinted == 0 ) {
            push( @SUMMARY, YELLOW "> Found symlink hacks under $SLdir" );
            $headerprinted = 1;
        }
        else {
            my $fStat = stat($realpath);
            if ( -e _ ) {
                if ( $symUID eq "root" or $symGID eq "root" ) {
                    if ( $hp1 == 0 ) {
                        push( @SUMMARY, expand( CYAN "\t\\_ root owned symlinks " . BOLD RED "(should be considered root compromised!): " ) );
                        $hp1 = 1;
                    }
                    push( @SUMMARY, expand( "\t\t\\_ " . MAGENTA $link . " " . $pointer . " " . $realpath ) );
                }
                else {
                    if ( $hp2 == 0 ) {
                        push( @SUMMARY, expand( CYAN "\t\\_ User owned ($symUID) symlinks: " ) );
                        $hp2 = 1;
                    }
                    push( @SUMMARY, expand( "\t\t\\_ " . MAGENTA $link . " " . $pointer . " " . $realpath ) );
                }
            }
        }
    }

    print_status("Checking for shadow.roottn.bak hack variants...");
    my $shadow_roottn_baks = qx[ find $RealHome/etc/* -name 'shadow\.*' -print ];
    if ($shadow_roottn_baks) {
        my @shadow_roottn_baks = split "\n", $shadow_roottn_baks;
        push @SUMMARY, "> Found the following directories containing possible variant of the shadow.roottn.bak hack:";
        push @SUMMARY, expand( MAGENTA "\t \\_ See: https://github.com/bksmile/WebApplication/blob/master/smtp_changer/wbf.php" );
        foreach $shadow_roottn_baks (@shadow_roottn_baks) {
            chomp($shadow_roottn_baks);
            next if ( $shadow_roottn_baks =~ m/shadow.lock/ );
            push @SUMMARY, expand( CYAN "\t\t\\_ " . $shadow_roottn_baks );
        }
    }

    print_status("Checking cgi-bin directory for suspicious bash script");
    my $suspBash = qx [ find $RealHome/public_html/cgi-bin/jarrewrite.sh ];
    if ($suspBash) {
        chomp($suspBash);
        push @SUMMARY, "> Found suspicious bash script $suspBash";
    }

    print_status("Checking for php scripts in $RealHome/public_html/.well-known");
    use Path::Iterator::Rule;
    my $rule          = Path::Iterator::Rule->new;
    my $it            = $rule->iter("$RealHome/public_html/.well-known");
    my $headerprinted = 0;
    while ( my $file = $it->() ) {
        next if ( $file eq "." or $file eq ".." );
        next unless ( "$file" =~ m/\.php$/ );
        if ( $headerprinted == 0 ) {
            push( @SUMMARY, YELLOW "> Found php script under $RealHome/public_html/.well-known" );
            $headerprinted = 1;
        }
        push( @SUMMARY, CYAN "\t\\_ $file" );
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

    if ( -e ("$RealHome/.env") ) {
        push( @SUMMARY, "> Found $RealHome/.env file! - May contain passwords for MySQL. Consider removing!" );
        logit("Found $RealHome/.env file! - May contain passwords for MySQL. Consider removing!");
    }

    print_status( "Checking for Troldesh Ransomware in " . $RealHome . "/public_html/.well-known/pki-validation and acme-challenge..." );
    logit("Checking for for Troldesh Ransomware");
    my $pkidir                  = "$RealHome/public_html/.well-known/pki-validation";
    my $acmedir                 = "$RealHome/public_html/.well-known/acme-challenge";
    my @files                   = qw( error_log ins.htm msg.jpg msges.jpg reso.zip rolf.zip stroi-invest.zip thn.htm freshtools.net.php );
    my $pkitroldesh_ransomware  = 0;
    my $acmetroldesh_ransomware = 0;
    my $fullpath;

    if ( -e $pkidir ) {
        for my $file (@files) {
            $fullpath = $pkidir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
                spin();
                $pkitroldesh_ransomware = 1;
                last;
            }
        }
    }
    if ($pkitroldesh_ransomware) {
        push( @SUMMARY, "> Found evidence of Troldesh Ransomware in $pkidir" );
    }
    if ( -e $acmedir ) {
        for my $file (@files) {
            $fullpath = $acmedir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
                spin();
                $acmetroldesh_ransomware = 1;
                last;
            }
        }
    }
    if ($acmetroldesh_ransomware) {
        push( @SUMMARY, "> Found evidence of Troldesh Ransomware in $acmedir" );
    }

    # stealrat botnet
    print_status( "Checking for Stealrat botnet in " . $RealHome . "/public_html/..." );
    logit("Checking for Stealrat botnet");
    @files = qw( sm13e.php sm14e.php ch13e.php Up.php Del.php Copy.php Patch.php Bak.php );
    for my $file (@files) {
        $fullpath = "$RealHome/public_html/" . $file;
        stat $fullpath;
        if ( -f _ and not -z _ ) {
            spin();
            push( @SUMMARY, "> Found evidence of stealrat botnet" );
            push( @SUMMARY, CYAN "\t\\_ $fullpath" );
        }
    }

    # Malicious WP Plugins - https://blog.sucuri.net/2020/01/malicious-javascript-used-in-wp-site-home-url-redirects.html
    print_status("Checking for malicious WordPress plugins");
    logit("Checking for malicious WordPress plugins");
    if ( -e "$RealHome/public_html/wp-content/plugins/supersociall" ) {
        push( @SUMMARY, "> Found possible malicious WordPress plugin in $RealHome/public_html/wp-content/plugins/supercociall/" );
    }
    if ( -e "$RealHome/public_html/wp-content/plugins/blockspluginn" ) {
        push( @SUMMARY, "> Found possible malicious WordPress plugin in $RealHome/public_html/wp-content/plugins/blockpluginn/" );
    }

    # MageCart Hack checks
    print_status( "Checking for MageCart hacks in any JavaScript files under" . $RealHome . "/public_html/" );
    logit("Checking for for MageCart hacks");
    use Path::Iterator::Rule;
    my $rule = Path::Iterator::Rule->new;
    my $it   = $rule->iter("$RealHome/public_html");
    while ( my $file = $it->() ) {
        next if ( $file eq "." or $file eq ".." );
        next unless ( "$file" =~ m/\.js$/ );
        spin();
        my $MageCartStringFound = qx[ egrep 'EventsListenerPool|OpenDoorCDN.com|TopLevelStatic.com|ATMZOW|zdsassets.com|aHR0cHM6Ly9jb250ZW50LW|_0x8205=|_0xdb2b=|z0ogkswp6146oodog3d9jb|YUhSMGNITTZN|fca9c64fe59ea2f|h545f985|Ly90TXRRTS9rUGk0SHV5d|givemejs.cc|content-delivery.cc|cdn-content.cc|deliveryjs.cc|darvishkhan.net' $file ];
        if ($MageCartStringFound) {
            push( @SUMMARY, "> Found evidence of possible MageCart hack in" );
            push( @SUMMARY, expand( CYAN "\t\\_ $file" ) );
        }
    }

    logit("Running a user scan for $lcUserToScan");
    unlink("/root/CSI/csi_detections.txt")      unless ( !-e "/root/CSI/csi_detections" );
    unlink("/root/CSI/suspicious_strings.yara") unless ( !-e "/root/CSI/suspicious_strings.yara" );
    if ( -e "/usr/local/cpanel/3rdparty/bin/clamscan" ) {
        my $URL         = "https://raw.githubusercontent.com/cPanelPeter/infection_scanner/master/suspicious_strings.yara";
        my @DEFINITIONS = qx[ curl -s $URL > "/root/suspicious_strings.yara" ];
        print CYAN "Scanning " . WHITE $RealHome . "/public_html... (Using YARA rules)\n";
        open( RULES, "/root/suspicious_strings.yara" );
        my @RULEDATA = <RULES>;
        close(RULES);
        my $resultLine;
        my @FOUND = undef;
        my @results =
          qx[ /usr/local/cpanel/3rdparty/bin/clamscan --no-summary --infected --suppress-ok-results --log=/root/suspicious_strings_scan_results.log --recursive --exclude=".psd" --exclude=".dat" --exclude=".bz2" --exclude=".crt" --exclude=".mp4" --exclude=".mp3" --exclude=".zip" --exclude=".webm" --exclude=".json" --exclude=".pdf"  --exclude=".png" --exclude=".css" --exclude=".svg" --include=".php" --include=".*htm*" --include=".t*t" --database /root/suspicious_strings.yara "$RealHome/public_html" ];

        if ( @results > 0 ) {
            push( @SUMMARY, "> A general scan of the $lcUserToScan account found the following suspicous items" );
        }
        foreach $resultLine (@results) {
            chomp($resultLine);
            my ( $scannedFile, $foundRule ) =
              ( split( /\s+/, $resultLine ) )[ 0, 1 ];
            chomp($scannedFile);
            chomp($foundRule);
            $scannedFile =~ s/://g;
            $foundRule   =~ s/YARA.//g;
            $foundRule   =~ s/.UNOFFICIAL//g;
            my $resultCnt = 1;
            my $ruleData;

            foreach $ruleData (@RULEDATA) {
                chomp($ruleData);
                $resultCnt++;
                spin();
                if ( $ruleData eq "rule $foundRule {" ) {
                    $ruleData = $RULEDATA[$resultCnt];
                    my ($string) = ( split( /\"/, $ruleData ) )[1];
                    my $ChangeDate = timed_run( 3, "stat $scannedFile | grep -i change" );
                    ($ChangeDate) = ( split( /\./, $ChangeDate ) );
                    $ChangeDate =~ s/Change: //;
                    push( @FOUND, expand( CYAN "\t \\_ File: " . MAGENTA $scannedFile . YELLOW " contains the string: " . WHITE $string . BOLD MAGENTA . " [ Modified: " . BOLD BLUE $ChangeDate . MAGENTA " ]" ) );
                    last;
                }
            }
        }
        splice( @FOUND, 0, 1 );
        my $cntFOUND = @FOUND;
        my $foundLine;
        if ( $cntFOUND == 0 ) {
            push( @SUMMARY, GREEN "Result: No suspicious strings/phrases were found!" );
        }
        else {
            foreach $foundLine (@FOUND) {
                chomp($foundLine);
                push( @SUMMARY, "$foundLine" );
            }
            push( @SUMMARY, RED "Result: " . WHITE $cntFOUND . RED " suspicious items found. " );
            push( @SUMMARY, YELLOW "These should be investigated.\n" );
        }
    }
    else {
        print YELLOW "ClamAV is not installed - skipping suspicious strings YARA scan...\n";
        my $URL         = "https://raw.githubusercontent.com/cPanelPeter/infection_scanner/master/strings.txt";
        my @DEFINITIONS = qx[ curl -s $URL > "/root/ai_detections.txt" ];
        @DEFINITIONS = qx[ curl -s $URL ];
        my $StringCnt = @DEFINITIONS;
        print "Scanning $RealHome/public_html for ($StringCnt) known phrases/strings\n";
        my $retval     = qx[ LC_ALL=C grep -srIwf /root/ai_detections.txt $RealHome/public_html/* ];
        my @retval     = split( /\n/, $retval );
        my $TotalFound = @retval;
        my $ItemFound;
        my @FileNamesOnly;
        my $FileOnly;

        foreach $ItemFound (@retval) {
            chomp($ItemFound);
            ($FileOnly) = ( split( /:/, $ItemFound ) );
            push( @FileNamesOnly, $FileOnly );
        }
        my @newRetVal       = uniq(@FileNamesOnly);
        my $TotalFilesFound = @newRetVal;
        foreach $FileOnly (@newRetVal) {
            my $ChangeDate = timed_run( 3, "stat $FileOnly | grep -i change" );
            ($ChangeDate) = ( split( /\./, $ChangeDate ) );
            $ChangeDate =~ s/Change: //;
            push( @SUMMARY, expand( CYAN "\t \\_ File: " . WHITE "$FileOnly " . BOLD RED . "looks suspicious " . BOLD MAGENTA . " [ Modified: " . BOLD BLUE $ChangeDate . MAGENTA " ]\n" ) );
        }
        if ( $TotalFound == 0 ) {
            push( @SUMMARY, GREEN "Result: Nothing suspicious found!\n" );
        }
        else {
            push( @SUMMARY, RED "Result: " . WHITE $TotalFound . RED " suspicious items found in " . WHITE $TotalFilesFound . RED " files. " );
            push( @SUMMARY, YELLOW "These should be investigated.\n" );
        }
    }
    unlink("/root/CSI/csi_detections.txt")      unless ( !-e "/root/CSI/csi_detections" );
    unlink("/root/CSI/suspicious_strings.yara") unless ( !-e "/root/CSI/suspicious_strings.yara" );

    print_header('[ cPanel Security Inspection Complete! ]');
    logit('[ cPanel Security Inspection Complete! ]');
    print_normal('');
    logit("Creating summary");
    dump_summary();
    return;
}

sub check_for_symlinks {
    my @symlinks;
    my @conffiles = qw( / wp-config.php configuration.php conf_global.php Settings.php config.php settings.php );
    my $conffile;
    foreach $conffile (@conffiles) {
        chomp($conffile);
        push( @symlinks, qx[ find /home/*/public_html -type l -lname "/home/*/$conffile" -ls ] );
    }
    my $headerprinted = 0;
    my $hp1           = 0;
    my $hp2           = 0;
    my $symlink;
    foreach $symlink (@symlinks) {
        my ( $symUID, $symGID, $link, $pointer, $realpath ) = ( split( /\s+/, $symlink ) )[ 4, 5, 10, 11, 12 ];
        my ( $SLfilename, $SLdir ) = fileparse($link);
        if ( $headerprinted == 0 ) {
            push( @SUMMARY, YELLOW "> Found symlink hacks under $SLdir" );
            $headerprinted = 1;
        }
        else {
            my $fStat = stat($realpath);
            if ( -e _ ) {
                if ( $symUID eq "root" or $symGID eq "root" ) {
                    if ( $hp1 == 0 ) {
                        push( @SUMMARY, expand( CYAN "\t\\_ root owned symlink " . BOLD RED "(should be considered root compromised!): " ) );
                        $hp1 = 1;
                    }
                    push( @SUMMARY, expand( "\t\t\\_ " . MAGENTA $link . " " . $pointer . " " . $realpath ) );

                }
                else {
                    if ( $hp2 == 0 ) {
                        push( @SUMMARY, expand( CYAN "\t\\_ User owned ($symUID) symlink: " ) );
                        $hp2 = 1;
                    }
                    push( @SUMMARY, expand( "\t\t\\_ " . MAGENTA $link . " " . $pointer . " " . $realpath ) );
                }
            }
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
    my $attr = isImmutable("/etc/ssh/sshd_config");
    if ($attr) {
        push( @SUMMARY, "> The /etc/ssh/sshd_config file is " . MAGENTA "[IMMUTABLE]" . CYAN " indicates possible root-level compromise" );
    }
    return unless ( -e "/root/.ssh/authorized_keys" );
    my $authkeysGID   = ( stat("/root/.ssh/authorized_keys")->gid );
    my $authkeysGname = getgrgid($authkeysGID);
    if ( $authkeysGID > 0 ) {
        push @SUMMARY, "> Found the /root/.ssh/authorized_keys file to have an invalid group name [" . MAGENTA $authkeysGname . YELLOW "] - " . CYAN "Indicates tampering at the root-level.";
    }
}

sub isEA4 {
    return 1 if ( -f "/etc/cpanel/ea4/is_ea4" );
    return undef;
}

sub misc_checks {
    my @dirs     = undef;
    my @files    = undef;
    my $fullpath = "";
    my $cron     = "";

    # Xbash ransomware
    # Fix this so that it looks in the correct place for the mysql_datadir.
    my $mysql_datadir = "/var/lib/mysql";
    opendir( my $dh, $mysql_datadir );
    my ($HasXbash) = grep { /PLEASE_READ/i } readdir $dh;
    closedir $dh;
    if ($HasXbash) {
        push( @SUMMARY, "> Possible Xbash ransomware detected. Database's missing? Database $HasXbash exists!" );
    }

    # Add additional xbash checks here

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

    # spy_master
    my $spymaster = qx[ objdump -T /usr/bin/ssh /usr/sbin/sshd | grep spy_master ];
    if ($spymaster) {
        push @SUMMARY, "> Suspicious file found: evidence of spy_master running in ssh/sshd [ $spymaster ]";
    }

    # bitcoin
    @dirs  = qw( /dev/shm/.X12-unix /dev/shm /usr/local/lib /dev/shm/.X0-locked /dev/shm/.X13-unix /tmp/.X19-unix/.rsync/a );
    @files = qw( a bash.pid cron.d dir.dir e f httpd kthreadd md.so screen.so y.so kdevtmpfs r systemd upd x aPOg5A3 de33f4f911f20761 e6mAfed sem.Mvlg_ada_lock prot);

    my $headerprinted = 0;
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ or -d _ and not -z _ ) {
                if ( $headerprinted == 0 ) {
                    push( @SUMMARY, "> Suspicous file found (possible bitcoin miner?)" );
                    $headerprinted = 1;
                }
                push( @SUMMARY, CYAN "\t\\_ $fullpath" );
                vtlink($fullpath);
            }
        }
    }

    my %warning = ();
    return unless my @crons_aref = get_cron_files();
    my @cronContains = undef;
    my $isImmutable  = "";
    for my $cron (@crons_aref) {
        $isImmutable = isImmutable($cron);
        if ( open my $cron_fh, '<', $cron ) {
            while (<$cron_fh>) {
                chomp($_);
                if ( $_ =~ /tor2web|onion|yxarsh\.shop|cr2\.sh|82\.146\.53\.166|oanacroane|bnrffa4|ipfswallet|pastebin|R9T8kK9w|iamhex|watchd0g\.sh|\/tmp\/\.\/xL|\/dev\/shm\/\.kauditd\/\[kauditd\]/ ) {
                    $isImmutable = "";
                    my $attr = isImmutable($cron);
                    if ($attr) {
                        $isImmutable = MAGENTA " [IMMUTABLE]";
                    }
                    push @cronContains, CYAN "\t \\_ " . $cron . " Contains: [ " . RED $_ . CYAN " ] $isImmutable";
                }
            }
            close $cron_fh;
        }
    }
    splice( @cronContains, 0, 1 );
    if (@cronContains) {
        push( @SUMMARY, "> Possible malicious crons found:" );
        push( @SUMMARY, @cronContains );
    }

    @dirs  = qw( /root/.ssh/.dsa/a /bin /etc/rc.local );
    @files = qw( f f.good in.txt nohup.out ftpsdns httpntp watchdog watchd0g.sh );
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
    my @FileToChk = @_;
    foreach my $FileToChk (@FileToChk) {
        chomp($FileToChk);
        next if ( !-e "$FileToChk" );
        my $isELF = qx[ file $FileToChk | grep 'ELF' ];
        next if ( !$isELF );
        my $fStat = stat($FileToChk);
        if ( -f _ or -d _ and not -z _ ) {
            my $FileU = qx[ stat -c "%U" $FileToChk ];
            chomp($FileU);
            my $FileG = qx[ stat -c "%G" $FileToChk ];
            chomp($FileG);
            my $FileSize      = $fStat->size;
            my $ctime         = $fStat->ctime;
            my $isNOTRPMowned = qx[ rpm -qf $FileToChk | grep 'not owned by' ];
            chomp($isNOTRPMowned);
            my $RPMowned = "Yes";

            if ($isNOTRPMowned) {
                $RPMowned = "No";
            }
            my $sha256 = qx[ sha256sum $FileToChk ];
            chomp($sha256);
            ($sha256only) = ( split( /\s+/, $sha256 ) )[0];
            my $knownHash = known_sha256_hashes($sha256only);
            push @SUMMARY, expand( "> Suspicious binary file found: " . CYAN $FileToChk . YELLOW "\n\t\\_ Size: " . CYAN $FileSize . YELLOW " Date Changed: " . CYAN scalar localtime($ctime) . YELLOW " RPM Owned: " . CYAN $RPMowned . YELLOW " Owned by UID/GID: " . CYAN $FileU . "/" . $FileG );
            push @SUMMARY, expand( GREEN "\t \\_ " . WHITE "https://www.virustotal.com/#/file/$sha256only/detection" );
            if ($knownHash) {
                push @SUMMARY, MAGENTA "> The hash " . GREEN . $sha256only . MAGENTA " is known to be suspicious!";
            }
        }
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
    my $shadow_roottn_baks = qx[ find $HOMEDIR/*/etc/* -name 'shadow\.*' -print ];
    if ($shadow_roottn_baks) {
        my @shadow_roottn_baks = split "\n", $shadow_roottn_baks;
        push @SUMMARY, "> Found the following directories containing the shadow.roottn.bak hack:";
        push @SUMMARY, expand( MAGENTA "\t \\_ See: https://github.com/bksmile/WebApplication/blob/master/smtp_changer/wbf.php" );
        foreach $shadow_roottn_baks (@shadow_roottn_baks) {
            chomp($shadow_roottn_baks);
            next if ( $shadow_roottn_baks =~ m/shadow.lock/ );
            push @SUMMARY, expand( CYAN "\t\t\\_ " . $shadow_roottn_baks );
        }
    }
}

sub check_for_exim_vuln {
    my $chk_eximlog = qx[ grep '\${run' /var/log/exim_mainlog* | head -1 ];
    if ($chk_eximlog) {
        push @SUMMARY, "> Found the following string in /var/log/exim_mainlog file. Possible root-level compromise:\n " . CYAN $chk_eximlog;
    }
}

sub spamscriptchk {
    opendir my $dh, "/tmp";
    my $totaltmpfiles = () = readdir($dh);
    closedir $dh;
    return if $totaltmpfiles > 1000;

    #  Check for obfuscated Perl spamming script - will be owned by user check ps for that user and /tmp/dd
    my @string     = qx[ grep -srl '295c445c5f495f5f4548533c3c3c3d29' /tmp/* ];
    my $stringCnt  = @string;
    my $stringLine = "";
    if ( $stringCnt > 0 ) {
        push @SUMMARY, "> Found evidence of user spamming script in /tmp directory";
        foreach $stringLine (@string) {
            chomp($stringLine);
            push @SUMMARY, "\t\\_ $stringLine";
        }
    }
}

sub spamscriptchk2 {
    opendir my $dh, "/var/spool/cron";
    my @allcrons = readdir($dh);
    closedir $dh;
    my $usercron;
    my @crondata;
    my $cronline;
    foreach $usercron (@allcrons) {
        open( USERCRON, "/var/spool/cron/$usercron" );
        @crondata = <USERCRON>;
        close(USERCRON);
        foreach $cronline (@crondata) {
            chomp($cronline);
            if ( $cronline =~ m{ perl \s (?:/var)?/tmp/[a-zA-Z]+ }xms ) {
                push @SUMMARY, CYAN "> Found suspicious cron entry in the " . MAGENTA $usercron . CYAN " user account:" . YELLOW "\n\t\\_ $cronline";
            }
        }
    }
}

sub check_for_Super_privs {
    return if !-e "/var/lib/mysql/mysql.sock";
    my @MySQLSuperPriv = qx[ mysql -BNe "SELECT Host,User FROM mysql.user WHERE Super_priv='Y'" | egrep -v 'root|mysql.session' ];
    if (@MySQLSuperPriv) {
        push @SUMMARY, "> The following MySQL users have the Super Privilege:";
        my $MySQLSuperPriv = "";
        foreach $MySQLSuperPriv (@MySQLSuperPriv) {
            chomp($MySQLSuperPriv);
            my ( $MySQLHost, $MySQLUser ) = ( split( /\s+/, $MySQLSuperPriv ) );
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
    my @cronlist = glob(q{ /etc/cron.d/{.,}* /etc/cron.hourly/{.,}* /etc/cron.daily/{.,}* /etc/cron.weekly/{.,}* /etc/cron.monthly/{.,}* /etc/crontab /var/spool/cron/root });
}

sub get_last_logins_WHM {
    my $dt   = DateTime->now;
    my $year = $dt->year;
    open( ACCESSLOG, "/usr/local/cpanel/logs/access_log" );
    my @ACCESSLOG = <ACCESSLOG>;
    close(ACCESSLOG);
    my $accessline;
    my @Success;
    foreach $accessline (@ACCESSLOG) {
        chomp($accessline);
        my ( $ipaddr, $user, $date, $haslogin, $status ) = ( split( /\s+/, $accessline ) )[ 0, 2, 3, 6, 8 ];
        if ( $user eq "root" and $status eq "200" and $haslogin =~ m/post_login/ and $date =~ m/$year/ ) {
            push( @Success, "$ipaddr" );
        }
    }
    my @unique_ips = uniq @Success;
    my $num;
    my $success;
    my $times;
    push( @SUMMARY, "> The following IP address(es) logged on via WHM successfully as root:" );
    foreach $success (@unique_ips) {
        chomp($success);
        $num   = grep { $_ eq $success } @Success;
        $times = "time";
        if ( $num > 1 ) { $times = "times"; }
        push( @SUMMARY, CYAN "\t\\_ $success ($num $times)" ) unless ( $success =~ m/208\.74\.123\.|184\.94\.197\./ );
    }
}

sub get_last_logins_SSH {
    my $dt                = DateTime->now;
    my $mon               = $dt->month_abbr;
    my @LastSSHRootLogins = qx[ last | grep 'root' ];
    my $SSHLogins         = "";
    my @SSHIPs            = undef;
    foreach $SSHLogins (@LastSSHRootLogins) {
        my ( $lastIP, $cMonth ) = ( split( /\s+/, $SSHLogins ) )[ 2, 4 ];
        next unless ( $cMonth eq $mon );
        push @SSHIPs, $lastIP unless ( $lastIP =~ /[a-zA-Z]/ );
    }
    splice( @SSHIPs, 0, 1 );
    my @sortedIPs = uniq(@SSHIPs);
    push( @SUMMARY, "> The following IP address(es) logged on via SSH successfully as root (in $mon):" );
    foreach $SSHLogins (@sortedIPs) {
        push( @SUMMARY, CYAN "\t\\_ IP: $SSHLogins" ) unless ( $SSHLogins =~ m/208.74.12|184.94.197./ );
    }
    push( @SUMMARY, CYAN "\nDo you recognize any of the above IP addresses?\nIf not, then further investigation should be performed." );
}

sub get_root_pass_changes {
    my $dt   = DateTime->now;
    my $year = $dt->year;
    open( ACCESSLOG, "/usr/local/cpanel/logs/access_log" );
    my @ACCESSLOG = <ACCESSLOG>;
    close(ACCESSLOG);
    my $accessline;
    my @Success;
    foreach $accessline (@ACCESSLOG) {
        chomp($accessline);
        my ( $ipaddr, $user, $date, $chpass, $status ) = ( split( /\s+/, $accessline ) )[ 0, 2, 3, 6, 8 ];
        if ( $user eq "root" and $status eq "200" and $chpass =~ m/chrootpass/ and $date =~ m/$year/ ) {
            push( @Success, "$ipaddr" );
        }
    }
    my @unique_ips = uniq @Success;
    my $num;
    my $success;
    my $times;
    push( @SUMMARY, "> The following IP address(es) changed roots password via WHM (in $year):" );
    foreach $success (@unique_ips) {
        chomp($success);
        $num   = grep { $_ eq $success } @Success;
        $times = "time";
        if ( $num > 1 ) { $times = "times"; }
        push( @SUMMARY, CYAN "\t\\_ $success ($num $times)" ) unless ( $success =~ m/208\.74\.123\.|184\.94\.197\./ );
    }
}

sub check_file_for_elf {
    my $tcFile  = $_[0];
    my $retval  = 0;
    my $ELFfile = 0;
    if ( $tcFile =~ /\.jpg|\.gif|\.png|\.jpeg/ ) {
        $ELFfile = timed_run( 0, 'file', "$tcFile" );
        if ( $ELFfile =~ m/ ELF / ) {
            $retval = 1;
        }
    }
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
    }
    else {
        print_warn("Could not open file: $conf\n");
    }
    return;
}

sub check_for_lilocked_ransomware {
    my $lilockedFound = qx[ find / -xdev -maxdepth 3 -name '*.lilocked' -print ];
    if ($lilockedFound) {
        my @lilockedFound = split "\n", $lilockedFound;
        push( @SUMMARY, "> Evidence of lilocked ransomware detected." );
        foreach $lilockedFound (@lilockedFound) {
            chomp($lilockedFound);
            push( @SUMMARY, CYAN "\t \\_ $lilockedFound" );
        }
    }
}

sub check_sudoers_file {
    return if !-e ("/etc/sudoers");
    open( SUDOERS, "/etc/sudoers" );
    my @SUDOERS = <SUDOERS>;
    close(SUDOERS);
    my $sudoerLine;
    my $showHeader = 0;
    foreach $sudoerLine (@SUDOERS) {
        chomp($sudoerLine);
        next if ( $sudoerLine eq "" );
        next if ( substr( $sudoerLine, 0, 1 ) eq "#" );
        next if ( substr( $sudoerLine, 0, 4 ) eq 'root' );
        next if ( substr( $sudoerLine, 0, 8 ) eq 'Defaults' );
        next if ( $sudoerLine =~ m/\wheel/ );
        next unless ( $sudoerLine =~ m/ALL$/ );
        if ( $showHeader == 0 ) {
            push( @SUMMARY, "> Found non-root users with insecure privileges in /etc/sudoers file." );
            $showHeader++;
        }
        if ( $sudoerLine =~ m/ALL, !root/ ) {
            push( @SUMMARY, CYAN "\t\\_ $sudoerLine" . RED " (HAS !root - might be susceptible to CVE-2019-14287" );
        }
        else {
            push( @SUMMARY, CYAN "\t\\_ $sudoerLine" );
        }
    }
}

sub look_for_suspicious_files {
    my @files = qw(
      /bin/config.json
      /bin/config.txt
      /bin/cpu.txt
      /bin/ftpsdns
      /bin/gmbpr
      /bin/home
      /bin/host.ph1
      /bin/httpdns
      /bin/httpntp
      /bin/.ilog
      /bin/imin
      /bin/imout
      /bin/in.telnetd
      /bin/kworkerds
      /bin/ldu
      /bin/.lib
      /bin/lkillall
      /bin/lnetstat
      /bin/.login
      /bin/.lpstree
      /bin/mjy
      /bin/netdns
      /bin/.olog
      /bin/pools.txt
      /bin/.ps
      /bin/rtty
      /bin/squit
      /bin/.tmpc
      /bin/watchbog
      /bin/watchdog
      /bin/.wwwwwwweeeeeeeeeeepaasss
      /bin/zigw
      /boot/.IptabLes
      /boot/.IptabLex
      /boot/.stabip
      /boot/IptabLes
      /boot/grub/deamon
      /boot/grub/disk_genius
      /dev/...
      /dev/.arctic
      /dev/chr
      /dev/.ctrl
      /dev/cuc
      /dev/devno
      /dev/grid-hide-pid-
      /dev/grid-hide-port-
      /dev/grid-show-pids
      /dev/grid-unhide-pid-
      /dev/grid-unhide-port-
      /dev/hd7
      /dev/hda06
      /dev/hdx1
      /dev/hdx2
      /dev/ida/.inet
      /dev/.kork
      /dev/.lib
      /dev/.lib/1iOn.sh
      /dev/.pizda
      /dev/ptyp
      /dev/ptyr
      /dev/ptyxx
      /dev/ptyzg
      /dev/ptyzx
      /dev/.pula
      /dev/.rd/
      /dev/rd/cdb
      /dev/saux
      /dev/.shit/red.tgz
      /dev/shm/cfgas
      /dev/shm/.kauditd
      /dev/shm/.ssh/./x86_64
      /dev/srd0
      /dev/ttyof
      /dev/ttyop
      /dev/tux
      /dev/tux/.file
      /dev/tux/.proc
      /dev/wd4
      /dev/xdf1
      /dev/xdf2
      /dev/.xman
      /etc/gshadow--
      /etc/httpdns
      /etc/netdns
      /etc/libdns.so
      /etc/kworkerds
      /etc/zigw
      /etc/gmbpr
      /etc/config.json
      /etc/config.txt
      /etc/cpu.txt
      /etc/pools.txt
      /etc/.tmpc
      /etc/.wwwwwwweeeeeeeeeeepaasss
      /etc/1ssue.net
      /etc/bin/ava
      /etc/.bmbl
      /etc/.bmbl/sk
      /etc/cron.d/.a
      /etc/cron.d/.cd
      /etc/cron.d/.editorinfo
      /etc/cron.d/.favicon.ico
      /etc/cron.d/.kswapd
      /etc/cron.d/.ntp
      /etc/cron.d/.rm
      /etc/cron.d/root
      /etc/cron.d/.sysud
      /etc/cron.d/rootcat
      /etc/cron.d/apache
      /etc/cron.d/apache.bak
      /etc/cron.d/apachecat
      /etc/cron.d/system
      /etc/cron.d/system.bak
      /etc/cron.d/systemcat
      /etc/.enyelkmHIDE^IT.ko
      /etc/gpufd
      /etc/host.ph1
      /etc/init.d/kworker
      /etc/.ip
      /etc/ld.so.hash
      /etc/listpr
      /etc/profile.d/.helpdd
      /etc/profile.d/.h
      /etc/profile.d/emacs.sh
      /etc/profile.d/diskmanagerd
      /etc/profile.d/kacpi_notify
      /etc/rc.d/init.d/.IptabLes
      /etc/rc.d/init.d/.IptabLex
      /etc/rc.d/init.d/.stabip
      /etc/rc.d/init.d/IptabLes
      /etc/rc.d/init.d/rc.modules
      /etc/rc.d/rsha
      /etc/sbin/ava
      /etc/security/pam_env
      /etc/ssh/ssh_known_hosts
      /etc/ssh/.sshd_auth
      /etc/sysconfig/console/load.zk
      /etc/systemd/system/ntp.service
      /etc/ttyhash
      /etc/xinetd.d/asp
      /etc/xmrig
      /etc/X11/.pr
      /lib/defs
      /lib/file.h
      /lib/hosts.h
      /lib/libnano.so.4
      /lib/libncom.so.4.0.1
      /lib/libselinux.so.4
      /lib/libselinux.so
      /lib/libselinux.a
      /lib/libselinux
      /lib/.ifup-local
      /lib/.fx
      /lib/initr
      /lib/lblip.tk
      /lib/ldd.so
      /lib/ldlib.tk
      /lib/.libgh-gh
      /lib/.libgh.gh
      /lib/libproc.a
      /lib/libproc.so.2.0.6
      /lib/libsh.so
      /lib/lidps1.so
      /lib/.ligh.gh
      /lib/log.h
      /lib/proc.h
      /lib/security/.config
      /lib/.so
      /lib/udev/ssd_control/cryptov2.ko
      /lib/udev/ssd_control/iproute.ko
      /lib/udev/ssd_control/kauditd
      /lib/udev/ssd_control/miner2
      /lib/udev/ssd_control/netlink.ko
      /lib/udev/ssd_control/pamdicks
      /lib/udev/ssd_control/pc
      /lib/udev/ssd_control/t
      /lib/udev/x.modules
      /lib64/libnano.so.4
      /lib64/libncom.so.4.0.1
      /lib64/libselinux.so.4
      /opt/KHK75NEOiq33
      /opt/yilu/mservice
      /opt/yilu/work/xig/xig
      /opt/yilu/work/xige/xige
      /opt/yilu/work/xig
      /opt/yilu/work/xige
      /proc/knark
      /proc/kset
      /rescue/mount_fs
      /root/README_DECRYPT
      /root/READ_TO_DECRYPT
      /root/READ_ME.txt
      /root/README_DECRYPT.html
      /root/.a
      /root/.cd
      /root/.ddg/bnrffa4
      /root/.ddg/4004.db
      /root/.editorinfo
      /root/.favicon.ico
      /root/.kswapd
      /root/.ntp
      /root/.rm
      /root/root
      /root/.sysud
      /root/watchd0g.sh
      /root/.ssh/KHK75NEOiq
      /root/.cache/.a
      /root/.cache/.cd
      /root/.cache/.editorinfo
      /root/.cache/.favicon.ico
      /root/.cache/.kswapd
      /root/.cache/.ntp
      /root/.cache/.rm
      /root/.cache/root
      /root/.cache/.sysud
      /root//dev/shm/./sshd
      /root/.ssh/./xL
      /root/.ssh/./sshd
      /sbin/home
      /sbin/libselinux.so
      /sbin/libselinux.a
      /sbin/libselinux
      /sbin/.ifup-local
      /sbin/pback
      /sbin/vobiscum
      /sbin/xc
      /sbin/xlogin
      /tmp/2t3ik
      /tmp/4004.db
      /tmp/a7b104c270
      /tmp/.a
      /tmp/.../a
      /tmp/.b
      /tmp/baby
      /tmp/.bash
      /tmp/bashf
      /tmp/bashg
      /tmp/bc.pl
      /tmp/.bkp
      /tmp/bnrffa4
      /tmp/.bugtraq
      /tmp/.bugtraq.c
      /tmp/cback
      /tmp/.cheese
      /tmp/.cinik
      /tmp/conn
      /tmp/conns
      /tmp/.cron
      /tmp/config.json
      /tmp/crun
      /tmp/cryptov2.ko
      /tmp/.datass
      /tmp/ddgs.3012
      /tmp/ddgs.3013
      /tmp/derfiq
      /tmp/diskmanagerd
      /tmp/.dump
      /tmp/emacs.sh
      /tmp/.font-unix/.cinik
      /tmp/.h
      /tmp/.helpdd
      /tmp/./xL
      /tmp/./xL.1
      /tmp/./xL.2
      /tmp/httpd
      /tmp/httpd.conf
      /tmp/.IptabLes
      /tmp/.IptabLex
      /tmp/IptabLes
      /tmp/.ICE-unix/error.log
      /tmp/iproute.ko
      /tmp/irq
      /tmp/irq.sh
      /tmp/irqbalanc1
      /tmp/kacpi_notify
      /tmp/kauditd
      /tmp/KCtbBo
      /tmp/kidd0
      /tmp/kidd0.c
      /tmp/libapache
      /tmp/.lost+found
      /tmp/.main
      /tmp/mcliZokhb
      /tmp/mclzaKmfa
      /tmp/miner2
      /tmp/.mysqli/mysqlc
      /tmp/netlink.ko
      /tmp/pamdicks
      /tmp/pc
      /tmp/.pfile
      /tmp/pools.txt
      /tmp/.psy
      /tmp/qW3xT.2
      /tmp/.../r
      /tmp/ramen.tgz
      /tmp/.rewt
      /tmp/root.sh
      /tmp/sess.rotat
      /tmp/.stabip
      /tmp/systemd-private-afjdhdicjijo473skiosoohxiskl573q-systemd-timesyncc.service-g1g5qf/cred/fghhhh/data
      /tmp/systemdo
      /tmp/t
      /tmp/.tmpcelse
      /tmp/.tmpcfi
      /tmp/.tmpdropoff
      /tmp/thisxxs
      /tmp/.unlock
      /tmp/.user
      /tmp./update
      /tmp/.uua
      /tmp/watchbog.txt.sh
      /tmp/wnTKYg
      /tmp/xp
      /tmp/zilog
      /tmp/zolog
      /usr/bin/_-config
      /usr/bin/_-pud
      /usr/bin/_-minerd
      /usr/bin/4004.db
      /usr/bin/adore
      /usr/bin/atm
      /usr/bin/bnrffa4
      /usr/bin/bsd-port
      /usr/bin/bsd-port/knerl
      /usr/bin/bsd-port/getty
      /usr/bin/chsh2
      /usr/bin/cleaner
      /usr/bin/ddc
      /usr/bin/.etc
      /usr/bin/gib
      /usr/bin/http
      /usr/bin/ishit
      /usr/bin/jdc
      /usr/bin/kfl
      /usr/bin/kr4p
      /usr/bin/ldu
      /usr/bin/lkillall
      /usr/bin/lnetstat
      /usr/bin/.lpstree
      /usr/bin/mailrc
      /usr/bin/n3tstat
      /usr/bin/ntpsx
      /usr/bin/pc
      /usr/bin/t
      /usr/bin/miner2
      /usr/bin/kauditd
      /usr/bin/iproute.ko
      /usr/bin/netlink.ko
      /usr/bin/cryptov2.ko
      /usr/bin/pamdicks
      /usr/bin/.ps
      /usr/bin/ras2xm
      /usr/bin/.sshd
      /usr/bin/sia
      /usr/bin/slice
      /usr/bin/slice2
      /usr/bin/snick
      /usr/bin/soucemask
      /usr/bin/sourcemask
      /usr/bin/ssd
      /usr/bin/util
      /usr/bin/vadim
      /usr/bin/volc
      /usr/bin/xchk
      /usr/bin/xsf
      /usr/bin/xstat
      /usr/doc/.dnif
      /usr/doc/.dpct
      /usr/doc/.gifnocfi
      /usr/doc/.logdsys
      /usr/doc/.nigol
      /usr/doc/.sl
      /usr/doc/.sp
      /usr/doc/.statnet
      /usr/games/.blane
      /usr/games/.lost+found
      /usr/.IptabLes
      /usr/.IptabLex
      /usr/IptabLes
      /usr/include/addr.h
      /usr/include/boot.h
      /usr/include/chk.h
      /usr/include/client.h
      /usr/include/cron.h
      /usr/include/emacs.sh
      /usr/include/diskmanagerd
      /usr/include/filearch.h
      /usr/include/file.h
      /usr/include/gpm2.h
      /usr/include/.h
      /usr/include/.helpdd
      /usr/include/hosts.h
      /usr/include/.i
      /usr/include/iceconf.h
      /usr/include/icekey.h
      /usr/include/iceseed.h
      /usr/include/ide.h
      /usr/include/ivtype.h
      /usr/include/kacpi_notify
      /usr/include/kix.h
      /usr/include/libproc.a
      /usr/include/libproc.so.2.0.6
      /usr/include/libssh.h
      /usr/include/lidps1.so
      /usr/include/linux/arp.h
      /usr/include/linux/boot.h
      /usr/include/linux/byteorder/ssh.h
      /usr/include/linux/netfilter/ssh.h
      /usr/include/linux/sys/sysp2.h
      /usr/include/log.h
      /usr/include/lwpin.h
      /usr/include/mbstring.h
      /usr/include/ncurse.h
      /usr/include/netda.h
      /usr/include/proc.h
      /usr/include/out.h
      /usr/include/.o
      /usr/include/proc.h
      /usr/include/pthread2x.h
      /usr/include/pwd2.h
      /usr/include/rpc/../kit
      /usr/include/rpc/../kit2
      /usr/include/rpcsvc/du
      /usr/include/salt.h
      /usr/include/sn.h
      /usr/include/symc.h
      /usr/include/sys/record.h
      /usr/include/syslog2.h
      /usr/include/syslogs.h
      /usr/include/true.h
      /usr/include/usr.h
      /usr/include/X11/sessmgr/coredump.in
      /usr/include/zaux.h
      /usr/include/zconf2.h
      /usr/info/libc1.so
      /usr/info/.t0rn
      /usr/info/.tc2k
      /usr/info/torn
      /usr/lib/.../
      /usr/lib/.bkit-
      /usr/lib/.egcs
      /usr/lib/elm/arobia
      /usr/libexec/ssh-keysign
      /usr/lib/.fx
      /usr/lib/gcc/x86_64-redhat-linux/.0
      /usr/lib/jlib.h
      /usr/lib/.kinetic
      /usr/lib/ldliblogin.so
      /usr/lib/ldlibns.so
      /usr/lib/ldlibps.so
      /usr/lib/libgssapi_krb5.so.9.9
      /usr/lib/libtix.so.1.5
      /usr/lib/libcurl.a.2.1
      /usr/lib/libpanel.so.a.3
      /usr/lib/libiconv.so.0
      /usr/lib/liblog.o
      /usr/lib/libm.c
      /usr/lib/libpikapp.a
      /usr/lib/libQtNetwork.so.4.0.1
      /usr/lib/libsoftokn3.so.0
      /usr/lib/libsh
      /usr/lib/libsplug.2.so
      /usr/lib/libsplug.4.so
      /usr/lib/libt
      /usr/lib/libtools.x
      /usr/lib/locale/uboot
      /usr/lib/mozilla/extensions/mozzlia.ini
      /usr/lib/pt07
      /usr/lib/rpm/rpm.cx
      /usr/lib/.sshd.h
      /usr/lib/tcl5.3
      /usr/lib/volc
      /usr/lib/.wormie
      /usr/local/__UMBREON__
      /usr/local/bin/4004.db
      /usr/local/bin/bin
      /usr/local/bin/.../bktd
      /usr/local/bin/bnrffa4
      /usr/local/bin/curl
      /usr/local/bin/dns
      /usr/local/bin/xmrig
      /usr/local/cpanel/backup/dnsadmin
      /usr/local/cpanel/backup/run
      /usr/local/cpanel/backup/xh
      /usr/local/include/uconf.h
      /usr/local/lib/libjdk.so
      /usr/local/sbin/bin/bash.pid
      /usr/local/sbin/bin/config.json
      /usr/local/sbin/bin/cron.d
      /usr/local/sbin/bin/crv
      /usr/local/sbin/bin/dir.dir
      /usr/local/sbin/bin/g.js
      /usr/local/sbin/bin/.n
      /usr/local/sbin/bin/run
      /usr/local/sbin/bin/sh
      /usr/local/sbin/bin/start
      /usr/local/sbin/bin/t
      /usr/local/sbin/bin/upd
      /usr/local/share/man/man1/Openssh.1
      /usr/man/.man10
      /usr/man/man1/lib/.lib
      /usr/man/man2/.man8
      /usr/man/man3/psid
      /usr/man/muie
      /usr/ofed/bin/bin
      /usr/ofed/bin/ssh
      /usr/sbin/.../
      /usr/sbin/arobia
      /usr/sbin/atd2
      /usr/sbin/httpdns
      /usr/sbin/initcheck
      /usr/sbin/initdl
      /usr/sbin/in.slogind
      /usr/sbin/in.telnet
      /usr/sbin/jcd
      /usr/sbin/kswapd
      /usr/sbin/ldb
      /usr/sbin/libdns.so
      /usr/sbin/mech
      /usr/sbin/minerd
      /usr/sbin/netdns
      /usr/sbin/ntp
      /usr/sbin/xntps
      /usr/share/.aPa
      /usr/share/boot.sync
      /usr/share/core.h
      /usr/share/.home
      /usr/share/lsx/.ig.swr
      /usr/share/man/mann/options
      /usr/share/man/hu/sd
      /usr/share/man/hu/dd
      /usr/share/man/hu/aa
      /usr/share/man/hu/cc
      /usr/share/man/.urandom
      /usr/share/man/man0/.cache
      /usr/share/man/man1/sd
      /usr/share/man/man1/aa
      /usr/share/man/man1/cc
      /usr/share/man/man1/dd
      /usr/share/man/man1/.olog
      /usr/share/man/man5/tty1.5.gz
      /usr/share/man/man5/ttyv.5.gz
      /usr/share/polkit-1/policy.in
      /usr/share/polkit-1/policy.out
      /usr/share/sshd.sync
      /usr/share/X11/sessmgr/coredump.in
      /usr/share/.zk
      /usr/share/.zk/zk
      /usr/src/linux/modules/autod.o
      /usr/src/linux/modules/soundx.o
      /usr/src/.poop
      /usr/src/.puta
      /usr/.stabip
      /usr/tmp/~tmp441
      /usr/X11R6/include/pain
      /usr/X11R6/.zk
      /usr/X11R6/.zk/echo
      /usr/X11R6/.zk/xfs
      /var/adm/.profile
      /var/adm/sa/.adm
      /var/html/lol
      /var/lib/cryptov2.ko
      /var/lib/kauditd
      /var/lib/games/.k
      /var/lib/iproute.ko
      /var/lib/miner2
      /var/lib/netlink.ko
      /var/lib/nfs/gpm2.h
      /var/lib/pamdicks
      /var/lib/pc
      /var/lib/t
      /var/local/.lpd
      /var/log/.log
      /var/log/.login
      /var/log/utmp
      /var/log/xmrig
      /var/opt/power
      /var/run/lvm//lvm.pid
      /var/run/npss.state
      /var/run/.options
      /var/run/+++php.run
      /var/run/.pid
      /var/run/proc.pid
      /var/run/+++screen.run
      /var/run/.ssh.pid
      /var/run/.tmp
      /var/sftp
      /var/spool/cron/crontabs
      /var/spool/cron/crontabs/rootcat
      /var/spool/cron/root.bak
      /var/spool/cron/rootkey
      /var/spool/lp/admins/.lp
      /var/spool/lp/.profile
      /var/tmp/kworkerds
      /var/tmp/config.json
      /var/tmp/.pipe.sock
      /var/www/html/Index.php
      /var/.x
      /var/.x/psotnic
      /watchd0g.sh
    );

    for my $file (@files) {
        my $fStat = stat($file);
        if ( -f _ or -d _ and not -z _ ) {
            my $FileU = qx[ stat -c "%U" $file ];
            chomp($FileU);
            my $FileG = qx[ stat -c "%G" $file ];
            chomp($FileG);
            my $FileSize      = $fStat->size;
            my $ctime         = $fStat->ctime;
            my $isNOTRPMowned = qx[ rpm -qf $file | grep 'not owned by' ];
            chomp($isNOTRPMowned);
            my $RPMowned = "Yes";

            if ($isNOTRPMowned) {
                $RPMowned = "No";
            }
            my $isImmutable = isImmutable($file);
            if ($isImmutable) {
                $isImmutable = MAGENTA " [IMMUTABLE]";
            }
            else {
                $isImmutable = "";
            }
            push @SUMMARY, expand( "> Suspicious directory/file found: " . CYAN $file . $isImmutable . YELLOW "\n\t\\_ Size: " . CYAN $FileSize . YELLOW " Date Changed: " . CYAN scalar localtime($ctime) . YELLOW " RPM Owned: " . CYAN $RPMowned . YELLOW " Owned by UID/GID: " . CYAN $FileU . "/" . $FileG );
        }
    }
}

sub check_proc_sys_vm {
    my $sysctl = { map { split( /\s=\s/, $_, 2 ) } split( /\n/, timed_run( 0, 'sysctl', '-a' ) ) };
    if ( defined( $sysctl->{'vm.nr.hugepages'} && $sysctl->{'vm.nr.hugepages'} > '0' ) ) {
        push( @SUMMARY, "> Found suspicious value for vm.nr.hugepages [" . CYAN $sysctl->{'vm.nr.hugepages'} . YELLOW "] - Possible cryptominer?" );
    }
}

sub known_sha256_hashes {
    my $checksum    = $_[0];
    my @knownhashes = qw(
      0adadc3799d06b35465107f98c07bd7eef5cb842b2cf09ebaeaa3773c1f02343
      d814bf38f5cf7a58c3469d530d83106c4fc7653b6be079fc2a6f73a36b1b35c6
      7f30ea52b09d6d9298f4f30b8045b77c2e422aeeb84541bb583118be2425d335
      690aea53dae908c9afa933d60f467a17ec5f72463988eb5af5956c6cb301455b
      1155fae112da3072d116f39e90f6af5430f44f78638db3f43a62a9037baa8333
      2c7b1707564fb4b228558526163249a059cf5e90a6e946be152089f0b69e4025
      48cf0f374bc3add6e3f73f6db466f9b62556b49a9f7abbcce068ea6fb79baa04
      0b9c54692d25f68ede1de47d4206ec3cd2e5836e368794eccb3daa632334c641
      7bef63fa84a17ab5ed0848b44e5e42570cb35160571be904b55f6f3c1b91af3b
      15ee5b44947271e6bd15e18b45e04219859dc5cb0800063519a4a8273291c57e
      03179a152a0ee80814ec62c91f8e7f0d0d6902bf190d2af1ecb6f17a0c0b8095
      e1268b45a93ea4ec27bf3e0fa3bfade49b4bd9464c1a08c5fe628341526d687f
      f808a42b10cf55603389945a549ce45edc6a04562196d14f7489af04688f12bc
      dbc380cbfb1536dfb24ef460ce18bccdae549b4585ba713b5228c23924385e54
      dcd37e5b266cc0cd3fab73caa63b218f5b92e9bd5b25cf1cacf1afdb0d8e76ff
      de63ce4a42f06a5903b9daa62b67fcfbdeca05beb574f966370a6ae7fd21190d
      09968c4573580398b3269577ced28090eae4a7c326c1a0ec546761c623625885
      5b790f02bdb26b6b6b270a5669311b4f231d17872aafb237b7e87b6bbb57426d
      e59be6eec9629d376a8a4a70fe9f8f3eec7b0919019f819d44b9bdd1c429277c
      7a18c7bdf0c504832c8552766dcfe0ba33dd5493daa3d9dbe9c985c1ce36e5aa
      a27acc07844bb751ac33f5df569fd949d8b61dba26eb5447482d90243fc739af
      33128713bbcd191ef14e6f3e32015da9953813baa689b220303cd56eb0c1cdf1
      c64a24c0373afb7ac72b24bc775e4aa4c738dd6fa5a4e533c39a89fe2cf65190
      559a828af0ff4fc964c7e2dbbfcf01a094fbdf152a9a36af875311cb71f1e167
      5d51dbf649d34cd6927efdb6ef082f27a6ccb25a92e892800c583a881bbf9415
      56cca56e39431187a2bd95e53eece8f11d3cbe2ea7ee692fa891875f40f233f5
      f1f905558c1546cd6df67504462f0171f9fca1cfe8b0348940aad78265a5ef73
      87ee0ae3abcd8b4880bf48781eba16135ba03392079a8d78a663274fde4060cd
      80e40051baae72b37fee49ecc43e8dded645b1baf5ce6166c96a3bcf0c3582ce
      31AC68194FA993214E18AA2483B7187AAD0CB482667EC14A7E9A0A37F8ED7534
      8B30223133EFAA61DDABF629E3FD1753B51DDB1E5E3459F82A72BA31F78BD490
      06305ACBF12150DCC8DAE68E1F7A326558661F1EDC9F49149D38C7450DC37654
      2f7ff54b631dd0af3a3d44f9f916dbde5b30cdbd2ad2a5a049bc8f2d38ae2ab6
      d9390bbbc6e399a388ac6ed601db4406eeb708f3893a40f88346ee002398955c
      0179fd8449095ac2968d50c23d37f11498cc7b5b66b94c03b7671109f78e5772
      023c1094fb0e46d13e4b1f81f1b80354daa0762640cb73b5fdf5d35fcc697960
      baf93d22c9d1ae6954942704928aeeacbf55f22c800501abcdbacfbb3b2ddedf
      cdd921a5de5d5fffc51f8c9140afa9d23f3736e591fce3f2a1b959d02ab4275e
      3764270bf9fb85f45486643681644574dabfd2a34b68df5ce45e3e0c43a9e3e7
      7989bb311baa38ef545250282aa065d23281c46dfb8faabe4c653487bdbded5c
      a4e8bcd615ecd02a0cbfe7c538c0821c2f912b8934a662df6dbc753eca412825
      537d62df67401a43f98c421a48e657c045256922d639d4d03cdfb67753bdab6f
      c09620afb90dcb1055b7c23dad622994e9bf455afe7e5683eca987a20e1dbbcb
      604f505cad0981bc098d3526e43ecb3fc87f0fc3bf5081ab97ed893ac34dbc31
      98006732eb2cfaea212447b882a43397a99e4a1c1bcf0ee0cd3e87b569c3a2a3
      5287d7948bc61aa7d4531a46c57c1e4fce682435e6a56b4189e86b24a73e917e
      dcae3867e2baa178416e409b2f6c2ee3902829e004aadbd3c7ed8bafd80d0e9a
      3592a5ba7bfd95b12cfd85c71b8f4d9f6559f6a5fad5a58e2b79ae8c1bff42a8
      64af1473f3a5ff49be1b5e6ffd09e5e8b9bab2c7201104f25e67eea3efdc34aa
      e7d92f67a07c77f2c5202429d61581d47287a031b784b83dddfc4bbd16b0a184
      5c7d2a17ad519f8504aed9e15cc2e4e8b9e2d971d6229fa7f7c2be44346f9eee
      c07fe8abf4f8ba83fb95d44730efc601ba9a7fc340b3bb5b4b2b2741b5e31042
      3ae9b7ca11f6292ef38bd0198d7e7d0bbb14edb509fdeee34167c5194fa63462
      e6eb4093f7d958a56a5cd9252a4b529efba147c0e089567f95838067790789ee
      240ad49b6fe4f47e7bbd54530772e5d26a695ebae154e1d8771983d9dce0e452
      945d6bd233a4e5e9bfb2d17ddace46f2b223555f60f230be668ee8f20ba8c33c
      913208a1a4843a5341231771b66bb400390bd7a96a5ce3af95ce0b80d4ed879e
      bf88572ce96677afea10f4c7968b3e144b8cc53250d1dc69f8d7916943e8ce68
      48c4891ba19a3998b8828543dec53488e8fe8f1d0b0ff47b124392d1a8894cb0
      d8189f4ab2bbe8dbd92391ebc83985fae7ce8cb1377ad54205adeabadb0fb9c3
      c0165ad421a8421ddad2e625e509be90f515cb8cd0519431ddabf273ffd2a589
      9f22b453d5a5acbb465380a78349fca81fd4900f6ab13fa235f0275f82e9ba89
      99783b36b8779334e308ce5a9d9d79fa6039b17716c5ce93146849509052b6a2
      5f1402a6dc4885cb5d2f3a34a6cdfe91b7fab4f1174047f18578e166ea57ac8e
      4c3e505da13bc6d52af09bfcda88cdeb3ebabe0051969f8d87a34c8474d5f4ac
    );

    if ( grep { /$checksum/ } @knownhashes ) {
        return 1;
    }
    else {
        return 0;
    }
}

sub check_for_junglesec {
    my $IPRule = qx[ iptables -L -n | grep 'dport 64321' | grep 'j ACCEPT' ];
    if ($IPRule) {
        push( @SUMMARY, "> Port 64321 set to ACCEPT in firewall - evidence of backdoor created by JungleSec Ransomware" );
    }
    my $SearchJungleSec = qx[ find / -xdev -maxdepth 3 -name '*junglesec*' ];
    if ($SearchJungleSec) {
        push( @SUMMARY, "> Found possible JungleSec Ransomware - found several encrypted files with the junglesec extension." );
        push( @SUMMARY, CYAN "\t\\_ Run: " . MAGENTA "find / -xdev -maxdepth 3 -name '*junglesec*'" );
    }
}

sub isImmutable {
    my $FileToCheck = $_[0];
    return if !-e $FileToCheck;
    my $attr = qx[ /usr/bin/lsattr $FileToCheck 2> /dev/null ];
    if ( $attr =~ m/^\s*\S*[ai]/ ) {
        return 1;
    }
    else {
        return 0;
    }
}

sub chk_md5_htaccess {
    my $use_apache_md5_for_htaccess = qx[ grep 'use_apache_md5_for_htaccess=0' /var/cpanel/cpanel.config ];
    if ($use_apache_md5_for_htaccess) {
        push @SUMMARY, "> Use MD5 passwords with Apache is disabled in Tweak Settings (limits max characters for htpasswd passwords to 8)";
    }
}

sub get_cpupdate_conf {
    my $conf = '/etc/cpupdate.conf';
    my %conf;
    if ( open( my $conf_fh, '<', $conf ) ) {
        local $/ = undef;
        %conf = map { ( split( /=/, $_, 2 ) )[ 0, 1 ] } split( /\n/, readline($conf_fh) );
        close $conf_fh;
    }
    return \%conf;
}

sub check_cpupdate_conf {
    return unless my $cpupdate_conf = get_cpupdate_conf();
    my $_is_allowed = sub {
        my ($type) = @_;
        return 0 if ( defined $cpupdate_conf->{$type} and ( $cpupdate_conf->{$type} eq "never" or $cpupdate_conf->{$type} eq "manual" ) );
        return 1;
    };
    unless ( $_is_allowed->('UPDATES') ) {
        push( @SUMMARY, "> UPDATES set to never or manual. Please consider enabling cPanel Software automatic updates." );
    }
    unless ( $_is_allowed->('RPMUP') ) {
        push( @SUMMARY, "> RPMUP set to never or manual. Please consider enabling RPM automatic updates." );
    }
    unless ( $_is_allowed->('SARULESUP') ) {
        push( @SUMMARY, "> SARULESUP set to never or manual. Please consider enabling SpamAssassin Rule updates." );
    }
}

sub check_apache_modules {
    return if ( !-d "/etc/apache2/modules" );
    my $ApacheMod;
    opendir( APACHEMODS, "/etc/apache2/modules" );
    my @ApacheMods = readdir(APACHEMODS);
    closedir(APACHEMODS);
    my $FoundOne = 0;
    my $FoundMod = "";
    foreach $ApacheMod (@ApacheMods) {
        my $NotOwned = qx[ rpm -qf "/etc/apache2/modules/$ApacheMod" | grep 'not owned' ];
        next unless ($NotOwned);
        $FoundMod .= $ApacheMod . " ";
        $FoundOne = 1;
    }
    if ($FoundOne) {
        push( @SUMMARY, expand( "> Found at least one Apache module in /etc/apache/modules that is not owned by an RPM!\n\t\\_ " . CYAN "Should be investigated " . MAGENTA $FoundMod ) );
    }
}

sub check_for_stealth_in_ps {
    chomp( my @ps_output = qx(ps auxfwww) );
    foreach my $line (@ps_output) {
        if ( $line =~ /\[stealth\]/ ) {
            push @SUMMARY, "> ps output contains '[stealth]' should be investigated";
            push @SUMMARY, CYAN "\t$line";
            my ( $stealthUser, $stealthPid ) = ( split( /\s+/, $line ) )[ 0, 1 ];
            my $stealthExe = qx[ ls -al /proc/$stealthPid/exe ];
            chomp($stealthExe);
            push( @SUMMARY, CYAN "\tPid: $stealthPid | User: $stealthUser | Exe: $stealthExe" );
        }
    }
}

sub check_changepasswd_modules {
    my $dir = '/usr/local/cpanel/Cpanel/ChangePasswd/';
    return unless ( -d $dir );
    return unless opendir( my $dh, $dir );
    my @dir_contents = grep { /\.pm\Z/ } readdir $dh;
    close $dh;
    return unless @dir_contents;
    my @suspicious;
    foreach my $module (@dir_contents) {
        next if ( $module eq 'DigestAuth.pm' );
        push @suspicious, $module if ( -s $dir . $module );
    }
    if (@suspicious) {
        push @SUMMARY, "> Found custom ChangePasswd module(s) in " . GREEN "/usr/local/cpanel/Cpanel/ChangePasswd/" . YELLOW " directory";
        push @SUMMARY, CYAN "\t\\_ " . join( ' ', @suspicious );
    }
}

sub check_for_ncom_rootkit {
    return if !-e "/etc/ld.so.preload";
    my $HasNCOM = qx[ strings $(cat /etc/ld.so.preload) | egrep 'libncom|libselinux|drop_suidshell_if_env_is_set|shall_stat_return_error|is_readdir64_result_invisible|is_readdir_result_invisible|drop_dupshell|is_file_invisible' ];
    if ($HasNCOM) {
        push( @SUMMARY, "> [Possible Rootkit: NCOM/iDRAC]" );
        push( @SUMMARY, "\t\\_ /etc/ld.so.preload contains evidence of the following:" );
        push( @SUMMARY, "\t\\_ $HasNCOM" );
    }
}

# EOF
