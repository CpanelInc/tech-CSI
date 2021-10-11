#!/usr/local/cpanel/3rdparty/bin/perl
# Copyright 2021, cPanel, L.L.C.
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
my $version = "3.4.46";
use Cpanel::Config::LoadWwwAcctConf();
use Cpanel::Config::LoadCpConf();
use Cpanel::Config::LoadUserDomains();
use Text::Tabs;
$tabstop = 4;
use File::Basename;
use File::Path;
use File::stat;
use IO::Prompt;
use DateTime;
use HTTP::Tiny;
use Cpanel::Exception       ();
use Cpanel::FindBin         ();
use Cpanel::Version         ();
use Cpanel::Kernel          ();
use Cpanel::KernelCare      ();
use Cpanel::IONice          ();
use Cpanel::PwCache         ();
use Cpanel::PwCache::Get    ();
use Cpanel::SafeRun::Timed  ();
use List::MoreUtils qw(uniq);
use Math::Round;
use File::Find::Rule;
use POSIX;
use Getopt::Long;
use Path::Iterator::Rule;
use IO::Socket::INET;
use IO::Prompt;
use JSON::MaybeXS qw(encode_json decode_json);
use Term::ANSIColor qw(:constants);
use Time::Piece;
use Time::Seconds;
$Term::ANSIColor::AUTORESET = 1;
our $RUN_STATE;

_init_run_state();
if ( exists $ENV{'PACHA_AUTOFIXER'} ) {
    _set_run_type('cptech');
}
elsif ( defined $ENV{'HISTFILE'} and index( $ENV{'HISTFILE'}, 'cpanel_ticket' ) != -1 ) {
    _set_run_type('cptech');
}
else {
    foreach ( @ENV{ 'SSH_CLIENT', 'SSH_CONNECTION' } ) {
        next unless defined $_;

        next unless m{\A (184\.94\.197\.[2-6]|208\.74\.123\.98)}xms;
        _set_run_type('cptech');
        last;
    }
}

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
my ( $full, $shadow, $symlink, $yarascan, $secadv, $help, $debug, $userscan, $customdir, $binscan, $scan, %process, %ipcs, $distro, $distro_version, $distro_major, $distro_minor, $ignoreload );
&get_process_pid_hash( \%process );
&get_ipcs_hash( \%ipcs );
if ( -e '/usr/local/cpanel/Cpanel/Sys.pm' ) {
    # up to 94
    eval("use Cpanel::Sys");
    eval("use Cpanel::Sys::OS");
    $distro         = Cpanel::Sys::OS::getos();
    $distro_version = Cpanel::Sys::OS::getreleaseversion();
}
if ( -e '/usr/local/cpanel/Cpanel/OS.pm' ) {

    if ( Cpanel::OS->can('instance') ) {
        # 96 and 98
        $distro       = Cpanel::OS->instance->distro;
        $distro_major = Cpanel::OS->instance->major;
        $distro_minor = Cpanel::OS->instance->minor;
    }
    elsif ( Cpanel::OS->can('supported_methods') ) {
        # 100+
        $distro       = Cpanel::OS->_instance->distro;
        $distro_major = Cpanel::OS->_instance->major;
        $distro_minor = Cpanel::OS->_instance->minor;
    }
    $distro_version = $distro_major . "." . $distro_minor;
}
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
    'customdir=s' => \$customdir,
    'full'       => \$full,
    'shadow'     => \$shadow,
    'symlink'    => \$symlink,
    'yarascan'   => \$yarascan,
    'secadv'     => \$secadv,
    'ignoreload' => \$ignoreload,
    'help'       => \$help,
    'debug'      => \$debug,
);


#######################################
# Set variables needed for later subs #
#######################################
our $CSISUMMARY;
our @SUMMARY;
our @RECOMMENDATIONS;
our @INFO;
my $docdir = '/usr/share/doc';
check_for_touchfile();
my @logfiles = ( '/var/log/apache2/access_log', '/var/log/apache2/error_log', '/var/log/wtmp' );
if ( $distro eq "ubuntu" ) {
    push @logfiles, '/var/log/syslog';
    push @logfiles, '/var/log/auth.log';
    push @logfiles, '/var/log/mail.log';
}
else {
    push @logfiles, '/var/log/messages';
    push @logfiles, '/var/log/maillog';
    push @logfiles, '/var/log/secure';
    push @logfiles, '/var/log/cron';
}

######################
# Run code main body #
######################
if ($help) {
    show_help();
    exit;
}
check_previous_scans();
logit("=== STARTING CSI ===");

sub get_loadavg {
    my ($load_avg) = (split(/\s+/,qx[ cat /proc/loadavg ]))[0];
    chomp($load_avg);
    return $load_avg;
}

my $corecnt = qx[ nproc ];
chomp($corecnt);
my $loadavg = get_loadavg();

if ($loadavg > ($corecnt * 3) && !$ignoreload ) {
    print RED "Load Average is too high ($loadavg) which is > than 3 times the number of cores\n";
    print WHITE "If you really want to continue, pass --ignoreload\n";
    exit;
}

my %cpconf = get_conf($CPANEL_CONFIG_FILE);
if (
    Cpanel::IONice::ionice(
        'best-effort',
        exists $cpconf{'ionice_import_exim_data'}
        ? $cpconf{'ionice_import_exim_data'}
        : 6
    )
  )
{
    print_info( "Setting I/O priority to reduce system load: "
          . Cpanel::IONice::get_ionice()
          . "\n" );
    setpriority( 0, 0, 19 );
}
my $scanstarttime = Time::Piece->new;
print_header( YELLOW "Scan started on $scanstarttime");
logit("Scan started on $scanstarttime");
logit("Showing disclaimer");
print_info("Usage: /root/csi.pl [functions] [options]");
print_info("See --help for a full list of options");
print_normal('');
disclaimer();
print_header(
    "Checking for RPM database corruption and repairing as necessary...") unless($distro eq "ubuntu");
my $findRPMissues   = qx[ /usr/local/cpanel/scripts/find_and_fix_rpm_issues ] unless($distro eq "ubuntu");
my $isRPMYUMrunning = rpm_yum_running_chk() unless($distro eq "ubuntu");

if ($binscan) {
    bincheck();
    if ( $distro eq "ubuntu") { print "The bincheck option not available on Ubuntu!\n"; }
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
print_header( YELLOW "\nScan completed on $scanendtime");
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
    print_header("\ncPanel Security Investigator Version $version");
    print_header(
"Usage: /usr/local/cpanel/3rdparty/bin/perl csi.pl [options] [function]\n"
    );
    print_header("Functions");
    print_header("=================");
    print_status("With no arguments, performs a quick scan looking for IoC's.");
    print_normal(" ");
    print_status(
"--bincheck  Performs RPM verification on core system binaries and prints active aliases."
    );
    print_normal(" ");
    print_status(
"--userscan cPanelUser  Asks to install Yara if not already installed and performs a Yara scan for a single cPanel User.."
    );
    print_normal(" ");
    print_header("Additional scan options available");
    print_header("=================");
    print_header(
"--shadow	Performs a check on all email accounts looking for variants of shadow.roottn hack."
    );
    print_header("--symlink	Performs a symlink hack check for all accounts.");
    print_header("--secadv	Runs Security Advisor");
    print_header("--yarascan	Performs a yara scan. CAUTION - Can cause very high load and take a very long time!");
    print_header(
        "--full		Performs all of the above checks - very time consuming.");
    print_normal(" ");
    print_header("Examples");
    print_header("=================");
    print_status("            /root/csi.pl [DEFAULT] quick scan");
    print_status("            /root/csi.pl --symlink");
    print_status("            /root/csi.pl --secadv");
    print_status("            /root/csi.pl --yarascan");
    print_status("            /root/csi.pl --full");
    print_status("Bincheck: ");
    print_status("            /root/csi.pl --bincheck");
    print_status("Userscan ");
    print_status("            /root/csi.pl --userscan myuser");
    print_status("            /root/csi.pl --userscan myuser --customdir mycustomdir");
    print_status("            (must be relative to the myuser homedir and defaults to public_html if non-existent!");
    print_normal(" ");
}

sub bincheck {
    return if ( $distro eq "ubuntu" );
    logit("Starting bincheck");
    print_normal('');
    print_header('[ Starting cPanel Security Investigator Bincheck Mode ]');
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
# CentOS 6 apparently installs RPM in /bin/rpm (why this hasn't failed on a C6 server before now is a mystery)
    my $whichRPM = qx[ which rpm ];
    chomp($whichRPM);
    my @RPMS =
qx[ $whichRPM -qa --qf "%{NAME}\n" | egrep -v "^(ea-|cpanel|kernel)" | sort -n | uniq ];
    my $RPMcnt = @RPMS;
    print_status( 'Done - Found: ' . $RPMcnt . ' RPMs to verify' );
    print_header('[ Verifying RPM binaries - This may take some time... ]');
    logit("Verifying RPM binaries");

    foreach $rpmline (@RPMS) {
        chomp($rpmline);
        $verify = qx[ $whichRPM -V $rpmline | egrep "/(s)?bin" ];
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
                push( @SUMMARY,
                    "> Modified Attribute: $binary [$verify_string]" );
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
    print_header(
'########################################################################'
    );
    print_header(
'### DISCLAIMER! cPanel\'s Technical Support does not provide            #'
    );
    print_header(
'### security consultation services. The only support services we       #'
    );
    print_header(
'### can provide at this time is to perform a minimal analysis of the   #'
    );
    print_header(
'### possible security breach solely for the purpose of determining if  #'
    );
    print_header(
'### cPanel\'s software was involved or used in the security breach.     #'
    );
    print_header(
'########################################################################'
    );
    print_header(
'### As with any anti-malware scanning system false positives may occur #'
    );
    print_header(
'### If anything suspicious is found, it should be investigated by a    #'
    );
    print_header(
'### professional security consultant. There are never any guarantees   #'
    );
    print_header(
'########################################################################'
    );
    print_normal('');
}

sub scan {
    print_normal('');
    print_header('[ Starting cPanel Security Investigator SCAN Mode ]');
    print_header("[ System: $OS_RELEASE ]");
    print_normal('');
    print_header("[ Available flags when running csi.pl scan ]");
    print_header(
        MAGENTA '[     --full Performs a more compreshensive scan ]' );
    print_header( MAGENTA
'[     --shadow Scans all accounts for variants of shadow.roottn email hack ]'
    );
    print_header(
        MAGENTA '[     --symlink Scans for symlink hacks going back to / ]' );
    print_header( MAGENTA '[     --secadv Performs a Security Advisor run ]' );
    print_normal('');
    print_header('[ Checking logfiles ]');
    logit("Checking logfiles");
    check_logfiles();
    print_header('[ Checking for bad UIDs ]');
    logit("Checking for bad UIDs");
    check_uids();
    print_header('[ Checking /etc/passwd file for suspicious users ]');
    logit("Checking /etc/passwd for suspicious users");
    check_for_suspicious_user('ferrum');
    print_header('[ Checking /etc/hosts file for suspicious entries ]');
    logit("Checking /etc/hosts for suspicious entries");
    check_hosts_file();
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
    print_header('[ Checking for suspicious bitcoin miners ]');
    logit("Checking for suspicious bitcoin miners");
    bitcoin_chk();
    print_header(
        '[ Checking cPanel access_log for anonymousF0x/smtpF0x entries ]');
    logit("Checking cPanel access_log for smtpF0x");
    check_for_smtpF0x_access_log();
    print_header('[ Checking reseller ACLs ]');
    logit("Checking reseller ACLs");
    check_resellers_for_all_ACL();
    print_header(
'[ Checking if /var/cpanel/authn/api_tokens_v2/whostmgr/root.json is IMMUTABLE ]'
    );
    logit(
"Checking if /var/cpanel/authn/api_tokens_v2/whostmgr/root.json is IMMUTABLE"
    );
    check_apitokens_json();
    print_header( '[ Checking /usr/local/cpanel/logs/api_tokens_log for passwd changes ]');
    logit( "Checking api_tokens_log for passwd changes");
    check_api_tokens_log();

    print_header('[ Checking for PHP backdoors in unprotected path ]');
    logit("Checking /usr/local/cpanel/base/unprotected for PHP backdoors");
    check_for_unprotected_backdoors();
    print_header('[ Checking for miscellaneous compromises ]');
    logit("Checking for miscellaneous compromises");
    misc_checks();
    check_changepasswd_modules();
    print_header('[ Checking Apache Modules ]');
    logit("Checking Apache Modules (owned by RPM)");
    check_apache_modules();
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
    print_header(
'[ Checking for non-root users with ALL privileges in /etc/sudoers file ]'
    );
    logit("Checking /etc/sudoers file");
    check_sudoers_file();
    print_header('[ Checking for spam sending script in /tmp ]');
    logit("Checking for spam sending script in /tmp");
    spamscriptchk();
    spamscriptchk2();
    check_for_ransomwareEXX();

    if ( -e "/etc/grub.conf" ) {
        print_header('[ Checking kernel status ]');
        logit("Checking kernel status");
        check_kernel_updates();
    }
    print_header('[ Checking for suspicious MySQL users (Including Super privileges) ]');
    logit("Checking for suspicious MySQL users including Super privileges");
    check_for_Super_privs();
    check_for_mysqlbackups_user();

    print_header('[ Checking for unowned files/libraries ]');
    logit("Checking for non-owned files/libraries");
    check_lib();

    print_header('[ Checking for fileless malware in memfd_create ]');
    logit("Checking for fileless malware");
    check_for_fileless_malware();

    print_header('[ Checking /etc/group for suspicious users ]');
    logit("Checking /etc/group for suspicious users");
    check_etc_group();

    if ( $full or $symlink ) {
        print_header( YELLOW '[ Additional check for symlink hacks ]' );
        logit("Checking for symlink hacks");
        check_for_symlinks();
    }
    if ( $full or $shadow ) {
        print_header(
            YELLOW '[ Additional check for shadow.roottn.bak hacks ]' );
        logit("Checking for shadow.roottn.bak hacks");
        chk_shadow_hack();
    }

    if ( $full or $yarascan ) {
        print_header( YELLOW "Checking for and downloading Yara and additional Yara Rules!" );
        my $yara_available = check_for_yara();
        if ( $yara_available ) {
            print_warn( "This process can cause very high loads and take a long time!!!\nWaiting 10 seconds [Press CTRL+C To Abort]" );
            sleep(10);
            my @yara_urls = qw( 
                https://raw.githubusercontent.com/reversinglabs/reversinglabs-yara-rules/develop/yara/ransomware/Linux.Ransomware.LuckyJoe.yara 
                https://raw.githubusercontent.com/reversinglabs/reversinglabs-yara-rules/develop/yara/virus/Linux.Virus.Vit.yara 
                https://raw.githubusercontent.com/CpanelInc/tech-CSI/master/csi_rules.yara 
            );

            print_header("Downloading additional yara rules to $csidir");

            my @data;
            for my $URL(@yara_urls) {
                chomp($URL);
                my $response = HTTP::Tiny->new->get( $URL );
                if ( $response->{success} ) {
                    my $yara_filename = basename($URL);
                    chomp($yara_filename);
                    open(YARAFILE, ">$csidir/$yara_filename" );
                    print YARAFILE $response->{content};
                    close(YARAFILE);
                    push @data, "$csidir/$yara_filename" if ( -e "$csidir/$yara_filename" );
                }
                else {
                    print_status( "Failed to download $URL" );
                }
            }
            my @dirs = qw( /bin /sbin /root /boot /etc /lib /lib64 /var /usr /tmp );
            my (@results, $results);
            for my $dir(@dirs) { 
                chomp($dir);
                next unless -d $dir;
                print_status("\tScanning $dir directory");
                foreach my $file(@data) {
                    chomp($file);
                    my $loadavg = get_loadavg();
                    print_status( "\t\t\\_ Yara file: $file [ Load: $loadavg ]");
                    $results = Cpanel::SafeRun::Timed::timedsaferun( 0, 'yara', '-fwNr', "$file", "$dir" );
                }
                my @results = split /\n/, $results;
                my $resultcnt=@results;
                if ( $resultcnt > 0 ) {
                    my $showHeader = 0;
                    foreach my $yara_result(@results) {
                        chomp($yara_result);
                        my ( $triggered_rule, $triggered_file ) = (split( '\s+', $yara_result ) );
                        push @SUMMARY, "> A Yara scan found some suspicious files..." unless( $triggered_file =~ m/\.yar|\.yara|CSI|rfxn|\.hdb|\.ndb/ or $showHeader );
                        $showHeader = 1;
                        push @SUMMARY, "\t\\_ Rule Triggered: " . CYAN $triggered_rule . YELLOW " in the file: " . MAGENTA $triggered_file unless( $triggered_file =~ m/\.yar|\.yara|CSI|rfxn|\.hdb|\.ndb/ );
                    }
                }
            }
        }
    }

    print_normal( ' ' );
    print_header( GREEN 'Looking for recommendations' );
    print_normal( ' ' );
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
    print_header('[ Checking setting of Cookie IP Validation ]');
    logit("Checking setting of Cookie IP Validation");
    check_cookieipvalidation();
    print_header('[ Checking setting of X-Frame/X-Content Type headers with cpsrvd ]');
    logit("Checking setting of X-Frame/X-Content Type headers with cpsrvd");
    check_xframe_content_headers();
    print_header('[ Checking for deprecated plugins/modules ]');
    logit("Checking for deprecated plugins");
    check_for_deprecated();
    print_header(
        '[ Gathering the IP addresses that logged on successfully as root ]');
    logit("Gathering IP address that logged on as root successfully");
    get_last_logins_WHM("root");
    get_last_logins_SSH("root");
    get_root_pass_changes("root");
    push( @INFO,
        CYAN
"\nDo you recognize the above IP addresses? If not, then further investigation should be performed\nby a qualified security specialist."
    );

    if ( $full or $secadv ) {
        print_header( YELLOW '[ Additional check Security Advisor ]' );
        logit("Running Security Advisor");
        security_advisor();
    }

    print_header('[ cPanel Security Investigator Complete! ]');
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
    return if ( Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '<', '11.68'));
    my $CanModify             = Cpanel::Kernel::can_modify_kernel();
    my $boot_kernelversion;
    if ( Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '>', '11.96')) {
        eval("use Cpanel::Kernel::GetDefault");
        $boot_kernelversion = Cpanel::Kernel::GetDefault::get();
    }
    else {
        $boot_kernelversion    = Cpanel::Kernel::get_default_boot_version();
    }
    my $running_kernelversion = Cpanel::Kernel::get_running_version();
    my $custom_kernel         = 0;
    if ( $running_kernelversion !~ m/\.(?:noarch|x86_64|i[3-6]86)$/ ) {
        $custom_kernel = 1;
    }
    my $has_kernelcare = 0;
    if ( Cpanel::KernelCare::kernelcare_responsible_for_running_kernel_updates()) {
        $has_kernelcare = 1;
    }
    my $reboot_required = 0;
    if ( $running_kernelversion ne $boot_kernelversion ) {
        $reboot_required = 1;
    }
    if ($custom_kernel) {
        push @SUMMARY,
          "> You have a custom kernel installed [ $running_kernelversion ]";
        return;
    }
    if ($has_kernelcare) {
        if ($reboot_required) {
            if ($CanModify) {
                push @SUMMARY,
"> KernelCare installed but running kernel version does not match boot version (run kcarectl --update or reboot):";
                push @SUMMARY, CYAN "\t \\_ Running Version: [ "
                  . $running_kernelversion . " ]";
                push @SUMMARY,
                  CYAN "\t \\_ Boot Version: [ " . $boot_kernelversion . " ]";
            }
            else {
                push @SUMMARY,
"> KernelCare installed but running kernel version does not match boot version (contact provider):";
                push @SUMMARY, CYAN "\t \\_ Running Version: [ "
                  . $running_kernelversion . " ]";
                push @SUMMARY,
                  CYAN "\t \\_ Boot Version: [ " . $boot_kernelversion . " ]";
                push @SUMMARY,
                  CYAN "\t \\_ Please check with your VM provider.";
            }
        }
    }
    else {
        if ($reboot_required) {
            if ($CanModify) {
                push @SUMMARY,
"> KernelCare not installed and running kernel version does not match boot version (reboot required):";
                push @SUMMARY, CYAN "\t \\_ Running Version: [ "
                  . $running_kernelversion . " ]";
                push @SUMMARY,
                  CYAN "\t \\_ Boot Version: [ " . $boot_kernelversion . " ]";
            }
            else {
                push @SUMMARY,
"> KernelCare not installed and running kernel version does not match boot version (contact provider):";
                push @SUMMARY, CYAN "\t \\_ Running Version: [ "
                  . $running_kernelversion . " ]";
                push @SUMMARY,
                  CYAN "\t \\_ Boot Version: [ " . $boot_kernelversion . " ]";
                push @SUMMARY,
                  CYAN "\t \\_ Please check with your VM provider.";
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

   # Check if journal logging is enabled.  If so, these may be empty on purpose.
            my $HasJournalLogging = "";
            if ( -e "/run/systemd/journal/syslog" ) {
                $HasJournalLogging =
                  " [ Might be configured to use imJournal ]";
            }
            push @SUMMARY,
              "> Log file $log exists, but is empty $HasJournalLogging";
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
        push @SUMMARY,
'> Custom account suspended template found at /var/cpanel/webtemplates/root/english/suspended.tmpl';
        push @SUMMARY,
'     This could mean the admin just created a custom template or that an attacker gained access';
        push @SUMMARY, '     and created it (hack page)';
    }
}

sub check_history {
    if ( -e '/root/.bash_history' ) {
        if ( -l '/root/.bash_history' ) {
            my $result = qx(ls -la /root/.bash_history);
            push @SUMMARY, "> /root/.bash_history is a symlink, $result";
        }

        my $attr          = isImmutable("/root/.bash_history");
        my $lcisImmutable = "";
        if ($attr) {
            $lcisImmutable = " [ IMMUTABLE ] ";
        }
        if ( !-s '/root/.bash_history' and !-l '/root/.bash_history' ) {
            push @SUMMARY,
              "> /root/.bash_history is a 0 byte file $lcisImmutable";
        }

        # Load /root/.bash_history into @HISTORY array
        open( HISTORY, "/root/.bash_history" );
        @HISTORY = <HISTORY>;
        close(HISTORY);
    }
    else {
        push @SUMMARY,
"> /root/.bash_history is not present, this indicates possible root-level compromise";
    }
}

sub check_modsecurity {
    my $result =
      qx[ /usr/sbin/whmapi1 modsec_is_installed | grep 'installed: 1' ];
    if ( !$result ) {

        push @RECOMMENDATIONS, "> Mod Security is disabled";
        return;
    }
    my $modsec_vendorsJSON = get_whmapi1( 'modsec_get_vendors' );
    my $rules_found=0;
    for my $modsec_vendor ( @{ $modsec_vendorsJSON->{data}->{vendors} } ) {
        if ( $modsec_vendor->{cpanel_provided} ) {
            if ( ! defined ( $modsec_vendor->{is_rpm} ) ) {
                push @RECOMMENDATIONS, "> Using $modsec_vendor->{description} YAML rules - Please consider using the RPM\n" . CYAN "\t\\_ yum install ea-modsec2-rules-owasp-crs" unless ( $distro eq "ubuntu" );
            }
            if ( $modsec_vendor->{enabled} == 0 ) {
                push @RECOMMENDATIONS, "> The $modsec_vendor->{description} is installed but not enabled\n\t\\_ Please consider running " . CYAN "/usr/local/cpanel/scripts/modsec_vendor enable OWASP3";
            }
        }
        $rules_found=1;
    }
    if ( ! $rules_found ) {
        push @RECOMMENDATIONS, "> Mod Security is installed but there were no active Mod Security vendor rules found.";
    }
}

sub check_2FA_enabled {
    my $result =
qx[ /usr/sbin/whmapi1 twofactorauth_policy_status | grep 'is_enabled: 1' ];
    if ( !$result ) {

        push @RECOMMENDATIONS,
"> Two-Factor Authentication Policy is disabled - Consider enabling this.";
        return;
    }
}

sub check_account_login_access {
    my $result =
qx[ /usr/sbin/whmapi1 get_tweaksetting key=account_login_access | grep 'value: ' ];
    if ( $result =~ m/owner|owner_root/ ) {
        push @RECOMMENDATIONS,
"> Consider changing Accounts that can access cPanel user account to cPanel User Only.";
    }
}

sub check_uids {
    my @baduids;
    while ( my ( $user, $pass, $uid, $gid, $group, $home, $shell ) =
        getpwent() )
    {
        if ( $uid == 0 && $user ne 'root' ) {
            push( @baduids, $user );
        }
        if ( $user eq 'firefart' ) {
            push @SUMMARY,
"> firefart user found [Possible DirtyCow root-level compromise].";
        }
        if ( $user eq 'sftp' ) {
            push @SUMMARY,
              "> sftp user found [Possible HiddenWasp root-level compromise].";
        }
    }
    endpwent();
    if (@baduids) {
        push @SUMMARY, '> Users with UID of 0 detected:';
        foreach (@baduids) {
            push( @SUMMARY, CYAN "\t \\_ " . $_ );
            get_last_logins_WHM($_);
            get_last_logins_SSH($_);
            get_root_pass_changes($_);
        }
    }
}

sub check_for_TTY_shell_spawns {
    my $histline;
    foreach $histline (@HISTORY) {
        chomp($histline);
        if ( $histline =~
m/pty.spawn("\/bin\/sh")|pty.spawn\("\/bin\/bash"\)|os.system\('\/bin\/bash'\)|os.system\('\/bin\/sh'\)|\/bin\/sh -i|\/bin\/bash -i/
          )
        {
            push( @SUMMARY,
"> Evidence of in /root/.bash_history for possible TTY shell being spawned"
            );
            push( @SUMMARY, "\t \\_ $histline\n" );
        }
    }
}

sub check_roots_history {
    my $histline;
    foreach $histline (@HISTORY) {
        chomp($histline);
        if ( $histline =~
m/\etc\/cxs\/uninstall.sh|rm -rf \/etc\/apache2\/conf.d\/modsec|bash \/etc\/csf\/uninstall.sh|yum remove -y cpanel-clamav/
          )
        {
            push( @SUMMARY,
                "> Suspicious entries found in /root/.bash_history" );
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
            and $apache_options !~ 'SymLinksIfOwnerMatch' )
        {
            push @SUMMARY,
              '> Apache configuration allows symlinks without owner match';
        }
    }
    else {
        push @SUMMARY, '> Apache configuration file is missing';
    }
}

sub check_processes {
    my $URL = "https://raw.githubusercontent.com/CpanelInc/tech-CSI/master/suspicious_procs.txt";
    my $susp_procs = timed_run( 6, 'curl', '-s', "$URL" );
    my @susp_procs = split /\n/, $susp_procs;
    my $headerPrint=0;
    foreach my $suspicious_process(@susp_procs) { 
        chomp($suspicious_process);
        if ( my %procs = grep_process_cmd( $suspicious_process, 'root' ) ) {
            next if ( $suspicious_process eq "sleep 30" && -e "/usr/local/sbin/maldet" );
            push @SUMMARY, "> The following suspicious process was found (please verify)" unless( $headerPrint == 1 );
            $headerPrint=1;
            push @SUMMARY, CYAN "\t\\_ " . join( "\t\\_ ", map { my ( $u, $c, $a ) = @{ $procs{$_} }{ 'USER', 'COMM', 'ARGS' }; "[pid: $_] [user: $u] [cmd: $c] [args: $a]" } keys %procs );
        }
    }
}

sub bitcoin_chk {
    my $xmrig_cron = qx[ grep -srl '\.xmr' /var/spool/cron/* ];
    if ($xmrig_cron) {
        push @SUMMARY,
          "> Found evidence of possilbe bitcoin miner: " . CYAN $xmrig_cron;
    }
    my $xm2sg_socket = qx[ netstat -plant | grep xm2sg ];
    if ($xm2sg_socket) {
        push @SUMMARY,
          "> Found evidence of possible bitcoin miner: " . CYAN $xm2sg_socket;
    }
}

sub get_process_list {
    my $continue = has_ps_command();
    return unless( $continue );
    return split /\n/, timed_run( 0, 'ps', 'axwwwf', '-o', 'user,pid,cmd' );
}

sub check_ssh {
    my @ssh_errors;
    my $ssh_verify;
    if ($distro eq "ubuntu" ) {
        my $Package;
        foreach my $rpm (qx(dpkg-query -Wf '${Package}\n' | grep '^openssh*')) {
            $ssh_verify = qx[ dpkg -V $rpm ];
            if ( $ssh_verify ne '' ) {
                push( @ssh_errors, " package verification on $rpm failed:\n" );
                push( @ssh_errors, " $ssh_verify" );
            }
        }
    }
    else {
        foreach my $rpm (qx(rpm -qa openssh*)) {
            chomp($rpm);
            $ssh_verify = qx(rpm --verify $rpm | egrep -v 'ssh_config|sshd_config|pam.d|/usr/libexec/openssh/ssh-keysign|/usr/bin/ssh-agent|\.build-id');
            if ( $ssh_verify ne '' ) {
                push( @ssh_errors, " RPM verification on $rpm failed:\n" );
                push( @ssh_errors, " $ssh_verify" );
            }
        }
    }
    if ($distro ne "ubuntu") {
        my $keyutils_verify = qx(rpm -V keyutils-libs | egrep -v '\.build-id');
        if ( $keyutils_verify ne "" ) {
            push( @ssh_errors, " RPM verification on keyutils-libs failed:\n" );
            push( @ssh_errors, " $keyutils_verify" );
            if ( -e '/var/log/prelink/prelink.log' ) { 
                push( @SUMMARY, "Note: /var/log/prelink/prelink.log file found. Might be OK if the keyutils-libs RPM was prelinked." );
                push( @SUMMARY, "If in doubt, this should be thoroughly checked by a security professional.");
            }
        }
    }
    my $continue = has_ps_command();
    if ( $continue ) {
        my @sshd_process_found = qx(ps aux | grep "sshd: root@");
        my $sshd_process_found;
        my $showHeaders = 0;
        foreach $sshd_process_found (@sshd_process_found) {
            chomp($sshd_process_found);
            next unless ( substr( $sshd_process_found, 0, 4 ) eq "root" );
            next if ( $sshd_process_found =~ m/pts|priv/ );
            if ( $showHeaders == 0 ) {
                push( @ssh_errors,
" Suspicious SSH process(es) found [could be sftpd which would be OK]:"
                );
                $showHeaders++;
            }
            push( @ssh_errors, " $sshd_process_found" );
        }
    }
    my @SSHRPMs;
    if ($distro eq "ubuntu") {
        @SSHRPMs = qw( openssh-server openssh-clients );
    }
    else {
        @SSHRPMs = qw( openssh-server openssh-clients openssh );
    }
    my $SSHRPM;
    my $ssh_error_cnt = 0;
    my ($rpmVendor, $rpmBuildHost, $rpmSignature);
    foreach $SSHRPM (@SSHRPMs) {
        chomp($SSHRPM);
        if ($distro eq "ubuntu" ) {
            # Vendor/Maintainer
            my $Maintainer;
            $rpmVendor = qx[ dpkg-query -W -f='${Maintainer}\n' | grep $SSHRPM ];
            chomp($rpmVendor);
            $ssh_error_cnt++ unless( $rpmVendor =~ (m/ubuntu|Ubuntu Developers/) );
            $ssh_error_cnt++ if ( $rpmVendor =~ (m/none/) );
            # dpkg-query on Ubuntu does not store Build Host
            # Signature
            open( my $fh, "<", "/varlib/dpkg/info/$SSHRPM.md5sums");
            while (<$fh>) {
                next unless($_ =~ m/\/bin\// );
                my ($md5hash,$filename1)=(split(/\s+/,$_));
                my $filename = "/" . $filename1;
                my ($md5syshash) = (split(/\s+/,qx[ md5sum $filename ]))[0];
                next unless( $md5syshash ne $md5hash );
                $ssh_error_cnt++;
            }
        }
        else {      ## CentOS/CloudLinux/AlmaLinux
            # Vendor/Maintainer
            $rpmVendor = qx[ rpm -qi $SSHRPM | grep 'Vendor' ];
            # Build Host
            $rpmBuildHost = qx[ rpm -qi $SSHRPM | grep 'Build Host' ];
            # Signature
            $rpmSignature = qx[ rpm -qi $SSHRPM | grep 'Signature' ];
            chomp($rpmVendor);
            chomp($rpmBuildHost);
            chomp($rpmSignature);
            $ssh_error_cnt++ unless( $rpmVendor =~ (m/CloudLinux|AlmaLinux|CentOS|Red Hat, Inc./) );
            $ssh_error_cnt++ if ( $rpmVendor =~ (m/none/) );
            $ssh_error_cnt++ unless( $rpmBuildHost =~ (m/cloudlinux.com|buildfarm01|buildfarm02|buildfarm03|centos.org|redhat.com/) );
            $ssh_error_cnt++ if ( $rpmBuildHost =~ (m/none/) ); 
            $ssh_error_cnt++ unless( $rpmSignature =~
                (m/24c6a8a7f4a80eb5|8c55a6628608cb71|199e2f91fd431d51|51d6647ec21ad6ea/) );
            $ssh_error_cnt++ if ( $rpmSignature =~ (m/none/) ); 
        }
    }
    if ( $ssh_error_cnt > 3 ) {
        push( @ssh_errors,
"Either the Vendor, Build Host, or Signature for one of the openssh RPM's does not match a known and suspected value"
        );
        push(
            @ssh_errors,
            expand(
                    MAGENTA "Check by running: "
                  . WHITE
"rpm -qi openssh-server openssh-clients openssh | egrep 'Vendor|Build Host|Signature'"
            )
        );
    }

    if (@ssh_errors) {
        push @SUMMARY,
          "> Detected presence of *POSSIBLY* compromised openssh RPM's";
        foreach (@ssh_errors) {
            chomp($_);
            push( @SUMMARY, expand( CYAN "\t\\_ " . $_ ) );
        }
    }
}

sub check_lib {
    my @dirs;
    if ( $distro eq "ubuntu" ) {
        @dirs = qw( /lib64 /usr/lib64 /usr/local/include );
    }
    else {
        @dirs = qw( /lib /lib64 /usr/lib /usr/lib64 /usr/local/include );
    }
    my $dir;
    my @notOwned;
    my $notOwned;
    my $filename;
    my @dumped;
    foreach $dir (@dirs) {
        chomp($dir);
        lstat $dir;
        next if -l $dir;
        opendir( DIR, $dir );
        my @DirFiles = readdir(DIR);
        closedir(DIR);
        if ( $distro eq "ubuntu" ) {
            @dumped = qx[ apt-cache dump ];
        }
        foreach $filename (@DirFiles) {
            next if $filename eq "." or $filename eq "..";
            lstat "$dir/$filename";
            next if -d "$dir/$filename" or -l "$dir/$filename";
            if ( $distro eq "ubuntu" ) {
                $notOwned = grep { /$filename/ } @dumped;
                if (! $notOwned) {
                    push @notOwned, "$dir/$filename" unless( $filename eq "yara.h" );
                }
            }
            else {
                $notOwned = qx[ rpm -qf "$dir/$filename" | grep 'not owned' ];
                if ($notOwned) {
                    push @notOwned, "$dir/$filename" unless( $filename eq "yara.h" );
                }
            }
        }
    }
    my $rpmcnt = @notOwned;
    if ( $rpmcnt > 0 ) {
        push @SUMMARY, "> Found library files that are not owned";
    }
    my $file;
    foreach $file (@notOwned) {
        chomp($file);
        next
          if $file =~
m{/usr/lib/systemd/system|/lib/modules|/lib/firmware|/usr/lib/vmware-tools|/lib64/xtables|jvm|php|perl5|/usr/lib/ruby|python|golang|fontconfig|/usr/lib/exim|/usr/lib/exim/bin|/usr/lib64/pkcs11|/usr/lib64/setools|/usr/lib64/dovecot/old-stats|/usr/lib64/libdb4};
        push( @SUMMARY, expand( CYAN "\t\\_ " . $file ) );
    }
}

sub get_process_pid_hash () {
    my $continue = has_ps_command();
    return unless( $continue );
    my $field_separator = '#^#';
    my $ps_format_opt   = join( $field_separator, qw( %p %P %U %t %n %c %a ) );
    my %hash            = map {
        my ( $pid, $ppid, $user, $etime, $nice, $comm, $args ) = split /\s*\Q$field_separator\E\s*/, $_;
        $pid  =~ s/^\s+//;
        $args =~ s/\s+$//;
        my ( $sec, $min, $hou, $day ) = reverse split( /[:-]/, $etime );
        $day += 0;
        $hou += 0;
        $min += 0;
        $sec += $day * 86400 + $hou * 3600 + $min * 60;
        $pid => {
            'PPID'   => defined $ppid  ? $ppid  : '',
            'USER'   => defined $user  ? $user  : '',
            'ETIME'  => defined $etime ? $etime : '',
            'NICE'   => defined $nice  ? $nice  : '0',
            'COMM'   => defined $comm  ? $comm  : '',
            'ARGS'   => defined $args  ? $args  : '',
            'ETIMES' => $sec,
        }
    } split /\n/, timed_run( 0, 'ps', '--no-headers', '--width=1000', '-eo', $ps_format_opt );
    return \%hash;
}

sub grep_process_cmd {
    my ( $pattern, $user ) = @_;
    my $procs = get_process_pid_hash();
    my %result;
    for my $pid ( keys %{$procs} ) {
        next                           if defined $user ? $procs->{$pid}->{'USER'} ne $user : 0;
        $result{$pid} = $procs->{$pid} if grep { /$pattern/ } @{ $procs->{$pid} }{ 'COMM', 'ARGS' };
    }
    return %result;
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
        push @{ ${$href}{ $ipcs[1] }{'mp'} },
          {    # Key by owner, type 'mp' (-m -p output)
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
        local $SIG{'ALRM'}    = sub {
            $output = "";
            print RED ON_BLACK "Timeout while executing: "
              . join( ' ', @PROGA ) . "\n";
            die;
        };
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
        local $SIG{'ALRM'}    = sub {
            $output = "";
            print RED ON_BLACK "Timeout while executing: "
              . join( ' ', @PROGA ) . "\n";
            die;
        };
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
    my $libcrypt_so =
      qx[ grep '/usr/lib64/libcrypt.so.1.1.0' /etc/ld.so.preload ];
    if ($libcrypt_so) {
        push( @SUMMARY,
"> Found /usr/lib64/libcrypt.so.1.1.0 in /etc/ld.so.preload - Possible root-level compromise."
        );
    }
    my $libconv_so = qx[ grep 'libconv.so' /etc/ld.so.preload ];
    if ($libconv_so) {
        push( @SUMMARY,
"> Found libconv.so in /etc/ld.so.preload - Possible root-level compromise."
        );
    }
    my $libs_so = qx[ grep '/lib64/libs.so' /etc/ld.so.preload ];
    if ($libs_so) {
        push( @SUMMARY,
"> Found /lib64/libs.so in /etc/ld.so.preload - Possible root-level compromise."
        );
    }
}

sub create_summary {
    open( my $CSISUMMARY, '>', "$csidir/summary" )
      or die("Cannot create CSI summary file $csidir/summary: $!\n");
    print $CSISUMMARY BOLD RED "\nWARNINGS\n";
    print $CSISUMMARY
"=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
    if (@SUMMARY) {
        foreach (@SUMMARY) {
            print $CSISUMMARY $_, "\n";
        }
    }
    else {
        print $CSISUMMARY BOLD GREEN
          "> Congratulations, no negative items found!\n\n";
    }
    print $CSISUMMARY
"=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
    print $CSISUMMARY BOLD CYAN "\nINFORMATIONAL\n";
    if (@INFO) {
        foreach (@INFO) {
            print $CSISUMMARY $_, "\n";
        }
    }
    else {
        print $CSISUMMARY BOLD CYAN "Nothing to report.\n\n";
    }
    print $CSISUMMARY
"=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
    print $CSISUMMARY "\nRECOMMENDATIONS\n";
    if (@RECOMMENDATIONS) {
        foreach (@RECOMMENDATIONS) {
            print $CSISUMMARY BOLD GREEN $_, "\n";
        }
    }
    else {
        print $CSISUMMARY BOLD CYAN "No recommendations to make.\n\n";
    }
    close($CSISUMMARY);
}

sub dump_summary {
    if ( @SUMMARY == 0 ) {
        print BOLD GREEN "> Congratulations, no negative items found!\n\n";
    }

    create_summary();
    if (@SUMMARY) {
        my @UniqSummary = uniq(@SUMMARY);
        @SUMMARY = @UniqSummary;
        print_warn('The following negative items were found:');
        foreach (@SUMMARY) {
            print BOLD YELLOW $_ . "\n";
        }
        print_normal('');
        print_normal(
'Any negative items should be investigated by your system administrator or a security professional.'
        );
        print_normal(
'If you need a system administrator, one can probably be found by going to https://go.cpanel.net/sysadmin'
        );
        print_normal(
'Note: cPanel, L.L.C. Support cannot assist you with any negative issues found.'
        );
        print_normal('');
    }
    print_separator(
'=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-='
    );
    if (@INFO) {
        print_info('The following is just informational');
        foreach (@INFO) {
            print BOLD YELLOW $_ . "\n";
        }
    }
    print_separator(
'=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-='
    );
    if (@RECOMMENDATIONS) {
        print_recommendations(
            'You should consider making the following recommendations:');
        foreach (@RECOMMENDATIONS) {
            print BOLD YELLOW $_ . "\n";
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
    print BOLD CYAN "[INFORMATIONAL]: $text\n";
}

sub print_warn {
    my $text = shift;
    print BOLD RED "[WARNING]: $text\n";
}

sub print_recommendations {
    my $text = shift;
    print BOLD GREEN "[RECOMMENDATIONS]: $text\n";
}

# BEGIN MALWARE CHEKCS HERE

sub check_for_kthrotlds {
    if ( -e ("/usr/bin/\[kthrotlds\]") ) {
        push( @SUMMARY,
            "> [Possible rootkit: Linux/CoinMiner.AP] - "
              . CYAN "Evidence of Linux/CoinMiner.AP rootkit found." );
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

    my @process_list = get_process_list();
    for my $process (@process_list) {
        if ( $process =~ m{ \A root \s+ (\d+) [^\d]+ $HTTPD_PATH }xms ) {
            my $pid          = $1;
            my $proc_pid_exe = "/proc/" . $pid . "/exe";
            if ( -l $proc_pid_exe
                && readlink($proc_pid_exe) =~ m{ \(deleted\) }xms )
            {
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
        push( @SUMMARY,
            "> [Possible Rootkit: CDORKED A] - "
              . CYAN "Evidence of CDORKED A Rootkit found." );
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
        push( @SUMMARY,
                "> [Possible Rootkit: CDORKED B] - "
              . CYAN "Evidence of CDORKED B Rootkit found.\n\t Found "
              . $cdorked_files
              . " [Note space at end of files]" );
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
      libkeystats.so
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
            push( @SUMMARY,
                "> [Possible Rootkit: Ebury/Libkeys] - "
                  . CYAN "Evidence of Ebury/Libkeys Rootkit found." );
            vtlink($lib);
            last;
        }
    }
}

sub check_for_evasive_libkey {
    my $EvasiveLibKey = qx[ strings /etc/ld.so.cache |grep tls/ ];
    if ($EvasiveLibKey) {
        push( @SUMMARY,
            "> [Possible Rootkit: Ebury/Libkeys] - "
              . CYAN
"Hidden/Evasive evidence of Ebury/Libkeys Rootkit found.\n\t \\_ TECH-759"
        );
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
        push( @SUMMARY,
            "> [Possible Rootkit: Ebury/Libkeys] - "
              . CYAN "Library/file is unowned" );
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
        push( @SUMMARY,
                "> [Possible Rootkit: ssh Binary] - "
              . CYAN "Evidence of hacked ssh binary found.\n\t "
              . $ssh
              . " -G did not return either 'illegal' or 'unknown'" );
    }
}

sub check_for_ebury_ssh_shmem {
    return if !defined( $IPCS_REF->{root}{mp} );
    for my $href ( @{ $IPCS_REF->{root}{mp} } ) {
        my $shmid = $href->{shmid};
        my $cpid  = $href->{cpid};
        if (   $PROCESS_REF->{$cpid}{CMD}
            && $PROCESS_REF->{$cpid}{CMD} =~ m{ \A /usr/sbin/sshd \b }x )
        {
            push( @SUMMARY,
                "> [Possible Rootkit: SSHd Shared Memory] - "
                  . CYAN
                  "Evidence of hacked SSHd Shared Memory found.\n\t cpid: "
                  . $cpid
                  . " - shmid: "
                  . $shmid
                  . "." );
        }
    }
}

sub check_for_ebury_root_file {
    my $file = '/home/ ./root';
    if ( -e $file ) {
        push( @SUMMARY,
                "> [Possible Rootkit: Ebury] - "
              . CYAN "Found hidden file: "
              . $file );
    }
}

sub check_for_ebury_socket {
    return unless my $netstat_out = timed_run( 0, 'netstat', '-nap' );
    my $found = 0;
    for my $line ( split( '\n', $netstat_out ) ) {
        if ( $line =~ m{@/proc/udevd} ) {
            push( @SUMMARY,
                    "> [Possible Rootkit: Ebury] - "
                  . CYAN "Ebury socket connection found: "
                  . $line );
            $found = 1;
            last;
        }
    }
}

sub check_for_ngioweb {
    return if ( !-e "/etc/machine-id" );
    return
      unless (qx[ grep 'ddb0b49d10ec42c38b1093b8ce9ad12a' /etc/machine-id ]);
    push( @SUMMARY,
"Found evidence of Linux.Ngioweb Rootkit\n\t\\_ /etc/machine-id contains: ddb0b49d10ec42c38b1093b8ce9ad12a"
    );
}

sub check_for_hiddenwasp {
    if ( -e ("/lib/libselinux.a") ) {
        my $HIDESHELL =
          qx[ strings /lib/libselinux.a | grep 'HIDE_THIS_SHELL' ];
        if ($HIDESHELL) {
            push @SUMMARY,
"> Found HIDE_THIS_SHELL in the /lib/libselinux.a file. Could indicate HiddenWasp Rootkit";
        }
    }
    if (qx[ env | grep 'I_AM_HIDDEN' ]) {
        push @SUMMARY,
"> Found I_AM_HIDDEN environment variable. Could indicate HiddenWasp Rootkit";
    }
    my $HWSocket = qx[ lsof -i tcp:61061 ];
    if ($HWSocket) {
        push @SUMMARY,
"> Found socket listening on port 61061. Could indicate HiddenWasp Rootkit";
    }
    my $HWSocket = qx[ lsof -i tcp:65130 ];
    if ($HWSocket) {
        push @SUMMARY,
"> Found socket listening on port 65130. Could indicate Sutsersu Rootkit";
    }
    my $HWSocket = qx[ lsof -i tcp:65439 ];
    if ($HWSocket) {
        push @SUMMARY,
"> Found socket listening on port 65439. Could indicate Sutsersu Rootkit";
    }
}

sub check_for_dirtycow_passwd {
    print_header("[ Checking for evidence of DirtyCow within /etc/passwd ]");
    return unless my $gecos = ( getpwuid(0) )[6];
    if ( $gecos eq "pwned" ) {
        push( @SUMMARY,
            "> [DirtyCow] - Evidence of FireFart/DirtyCow compromise found." );
        push( @SUMMARY,
            CYAN
"\t \\_ Run: getent passwd 0 and notice the 5th field says 'pwned'"
        );
        my $HasPwnd = timed_run( 4, 'getent passwd 0' );
        chomp($HasPwnd);
        push( @SUMMARY, MAGENTA "\t \\_ $HasPwnd" );
        my @passwdBAK =
          qx[ stat -c "%n [Owned by %U]" /tmp/*passwd* 2> /dev/null ];
        my $passwdBAKcnt = @passwdBAK;
        my $passwdBAK;

        if ( $passwdBAKcnt > 0 ) {
            push( @SUMMARY,
                MAGENTA "\t\\_ Possible backup of /etc/passwd found:" );
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
    return if ( $distro eq "ubuntu" );
    if ( ! -e "/usr/bin/rpm" ) {
        push( @SUMMARY, "RPM not installed - is this a CentOS server?" );
        logit("RPM not installed - is this a CentOS server?");
        return;
    }
    my $kernelVersion = qx[ uname -v ];
    my $kernelRelease = qx[ uname -r ];
    my $MinKernVer    = "2.6.32.642.6.2";
    chomp($kernelVersion);
    chomp($kernelRelease);

    if ( $kernelRelease =~ m/stab|vz7/ ) {
        if ( $kernelRelease lt "2.6.32-042stab120.3" ) {
            push( @SUMMARY,
"> Virtuozzo Kernel [$kernelRelease] might be susceptible to DirtyCow [CVE-2016-5195]"
            );
            logit(
"Virtuozzo Kernel [$kernelRelease] might be susceptible to DirtyCow"
            );
        }
        else {
            logit(
"Virtuozzo Kernel version is greater than 2.6.32-042stab120.3 - Not susceptible to DirtyCow"
            );
        }
        return;
    }
    if ( $kernelRelease =~ m/linode/ ) {
        if ( $kernelRelease lt "4.8.3" ) {
            push( @SUMMARY,
"> Linode Kernel [$kernelRelease] might be susceptible to DirtyCow [CVE-2016-5195]"
            );
            logit(
"Linode Kernel [$kernelRelease] might be susceptible to DirtyCow"
            );
        }
        else {
            logit(
"Linode Kernel version is greater than 4.8.3 - Not susceptible to DirtyCow"
            );
        }
        return;
    }
    if ( $kernelRelease =~ m/lve/ ) {
        my $KernYear = substr( $kernelVersion, -5 );
        if ( $KernYear > 2016 ) {
            logit(
                "CloudLinux Kernel [$kernelRelease] is patched against DirtyCow"
            );
        }
        else {
            push( @SUMMARY,
"> CloudLinux Kernel [$kernelRelease] might be susceptible to DirtyCow [CVE-2016-5192]"
            );
        }
        return;
    }
    if ( $kernelRelease =~ m/amzn1|Amazon Linux AMI/ ) {
        if ( $kernelRelease lt "4.4.23" ) {
            push( @SUMMARY,
"> Amazon Linux AMI Kernel [$kernelRelease] might be susceptible to DirtyCow [CVE-2016-5195]"
            );
            logit(
"Amazon Linux AMI Kernel [$kernelRelease] might be susceptible to DirtyCow"
            );
        }
        else {
            logit(
"Amazon Linux AMI Kernel version is greater than 4.4.23 - Not susceptible to DirtyCow"
            );
        }
        return;
    }

    my $RPMPATCH = qx[ rpm -q --changelog kernel | grep 'CVE-2016-5195' ];
    if ($RPMPATCH) {
        logit("Kernel [$kernelRelease] is patched against DirtyCow");
        return;
    }
    if ( $kernelRelease lt $MinKernVer ) {
        push( @SUMMARY,
"> This Kernel [$kernelRelease] might be susceptible to DirtyCow [CVE-2016-5195]"
        );
    }
    else {
        logit(
"This Kernel version is greater than 4.9.77 - Not susceptible to DirtyCow"
        );
    }
    return;
}

sub check_for_dragnet {
    my $found = 0;
    if ( open my $fh, '<', '/proc/self/maps' ) {
        while (<$fh>) {
            if (m{ (\s|\/) libc\.so\.0 (\s|$) }x) {
                push( @SUMMARY,
                    "> [Possible Rootkit: Dragnet] - "
                      . CYAN
"Evidence of Dragnet Rootkit found.\n\t libc.so.0 was found in process maps."
                );
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
      /etc/cron.hourly/udev.sh
      /etc/cron.hourly/gcc.sh
    );
    my @matched;

    for my $lib (@libs) {
        next if -l $lib;
        push @matched, $lib if -f $lib;
    }
    if (@matched) {
        push( @SUMMARY,
            "> [Possible Rootkit: Linux/XoRDDoS] - "
              . CYAN "Evidence of the Linux/XoRDDoS Rootkit found: " );
        vtlink(@matched);
    }
}

sub check_for_suckit {
    my $SuckItCount = 0;
    my @dirs =
      qw( /sbin /etc/rc.d/rc0.d /etc/rc.d/rc1.d /etc/rc.d/rc2.d /etc/rc.d/rc3.d /etc/rc.d/rc4.d /etc/rc.d/rc5.d /etc/rc.d/rc6.d /etc/.MG /usr/share/locale/sk/.sk12 /dev/sdhu0/tehdrakg /usr/lib/perl5/site_perl/i386-linux/auto/TimeDate/.packlist /dev/.golf /lib );
    my @files = qw( sk S23kmdac .x );
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
        my ($SuckItHomeVal) =
          ( split( /=/, qx[ strings /sbin/init | grep 'HOME=' ] ) )[1];
        if ( $SuckItHomeVal and $SuckItHomeVal =~ m/[a-zA-z0-9]/ ) {
            $SuckItCount++;
        }
        my $SuckItFound =
qx[ strings -an4 /sbin/init | egrep -ie "(fuck|backdoor|bin/rcpc|bin/login)" ];
        if ($SuckItFound) {
            $SuckItCount++;
        }
    }
    my $HasSuckIt =
      qx[ cat /proc/1/maps | egrep "init." | grep -v '(deleted)' ];
    if ($HasSuckIt) {
        $SuckItCount++;
    }
    my $initSymLink    = qx[ ls -li /sbin/init ];
    my $telinitSymLink = qx[ ls -li /sbin/telinit ];
    my ( $SLInode1, $isLink1 ) = ( split( /\s+/, $initSymLink ) )[ 0, 1 ];
    my ( $SLInode2, $isLink2 ) = ( split( /\s+/, $telinitSymLink ) )[ 0, 1 ];
    if ( $SLInode1 == $SLInode2 and substr( $isLink1, 0, 1 ) ne "l"
        or substr( $isLink2, 0, 1 ) ne "l" )
    {
        $SuckItCount++;
    }
    my $SuckItHidden =
      qx[ touch "$csidir/suckittest.mem" "$csidir/suckittest.xrk" ];
    if ( !-e "$csidir/suckittest.mem" or !-e "$csidir/suckittest.xrk" ) {
        $SuckItCount++;
    }
    if ( $SuckItCount > 1 ) {
        push( @SUMMARY,
            "> [Possible Rootkit: SuckIt] - "
              . CYAN
"$SuckItCount out of 6 checks used have detected evidence of the SuckIt Rootkit."
        );
        if ( $SuckItCount > 2 ) {
            push( @SUMMARY,
                "  (More than 3 checks being positive, should be investigated)"
            );
        }
    }
    if ( -e "$csidir/suckittest.mem" ) { unlink( "$csidir/suckittest.mem"); }
    if ( -e "$csidir/suckittest.xrk" ) { unlink( "$csidir/suckittest.xrk"); }
}

sub check_for_redisHack {
    return unless ( -e "/root/.ssh/authorized_keys" );
    my $RedisHack = qx[ grep 'REDIS0006 crackitA' /root/.ssh/authorized_keys ];
    if ($RedisHack) {
        push( @SUMMARY,
            "> [Possible Rootkit: Redis Hack] - "
              . CYAN
"Evidence of the Redis Hack compromise found in /root/.ssh/authorized_keys."
        );
    }
}

sub check_for_linux_lady {
    my $LLSocket1 = qx[ lsof -i tcp:6379 ];

# NOTE: redis server software runs on port 6379.  Hopefully it's not running as root :)
    if ( $LLSocket1 =~ m/root/ ) {
        push @SUMMARY,
"> Found socket listening on port 6379 (Redis server?). Running as root - VERY DANGEROUS!";
    }
}

sub check_for_twink {
    my $TwinkSSHPort = qx[ lsof -i tcp:322 | grep sshd ];
    my $InRootsCron  = qx[ egrep '/tmp/twink' /var/spool/cron/root ]
      unless ( !-e "/var/spool/cron/root" );
    if ( $TwinkSSHPort and $InRootsCron ) {
        push @SUMMARY,
            "> Found sshd listening on "
          . CYAN "port 322"
          . YELLOW " and "
          . RED "/tmp/twink"
          . YELLOW " in roots crontab. Indicates a possible rootkit";
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
    push( @SUMMARY,
        "> [Possible Rootkit: Elknot/BG Botnet] - "
          . CYAN "Evidence of the Elknot (BG Botnet) Rootkit found." );
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
                push( @SUMMARY,
                    "> [Possible Rootkit: Jynx2] - "
                      . CYAN "Evidence of the Jynx2 Rootkit found." );
                vtlink($fullpath);
            }
        }
    }
}

sub check_for_azazel_rootkit {
    if (qx[ env | grep 'HIDE_THIS_SHELL' ]) {
        push @SUMMARY,
"> Found HIDE_THIS_SHELL environment variable. Could indicate Azazel Rootkit";
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
        push( @SUMMARY,
            "> [Possible Rootkit: ShellBot] - "
              . CYAN "Evidence of the ShellBot Rootkit found." );
        vtlink(@matched);
    }
    if ( -e "/tmp/s.pl" ) {
        my $funcarg = qx[ grep funcarg /tmp/s.pl ];
        if ($funcarg) {
            push( @SUMMARY,
                "> [Possible Rootkit: ShellBot] - "
                  . CYAN "Evidence of the ShellBot Rootkit found." );
        }
    }
}

sub check_for_libkeyutils_symbols {
    local $ENV{'LD_DEBUG'} = 'symbols';
    my $output = timed_run_trap_stderr( 0, '/bin/true' );
    return unless $output;
    if ( $output =~ m{ /lib(keyutils|ns[25]|pw[35]|s[bl]r)\. }xms ) {
        push( @SUMMARY,
            "> [Possible Rootkit: Ebury] - "
              . CYAN
"Evidence of the Ebury Rootkit found in symbol table.\n\t\_ Run: LD_DEBUG=symbols /bin/true 2>&1 | egrep '/lib(keyutils|ns[25]|pw[35]|s[bl]r)\.' to confirm."
        );
    }
}

sub all_malware_checks {
    check_for_kthrotlds();
    check_for_linux_lady();
    check_for_twink();
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
    my @touchfiles =
      grep { /^\.cp\.([^\d]+)\.(\d{4}-\d{2}-\d{2})_([^_]+)_(\d+)$/ }
      readdir $fh;
    closedir $fh;
    return if ( scalar @touchfiles == 0 );
    for my $touchfile (@touchfiles) {
        if ( $touchfile =~
            /^\.cp\.([^\d]+)\.(\d{4}-\d{2}-\d{2})_([^_]+)_(\d+)$/ )
        {
            my ( $cptech, $date, $ipaddr, $ticket ) = ( $1, $2, $3, $4 );
            $date =~ s#-#/#g;
            $cptech = ucfirst $cptech;
            push( @SUMMARY,
"> $cptech reported this server at $ipaddr as compromised on $date local server time in ticket $ticket"
            );
        }
    }
}

sub logit {
    my $Message2Log = $_[0];
    my $date        = `date`;
    chomp($Message2Log);
    chomp($date);
    open( CSILOG, ">>$csidir/csi.log" ) or die($!);
    print CSILOG "$date - $Message2Log\n";
    close(CSILOG);
}

sub spin {
    my %spinner = ( '|' => '/', '/' => '-', '-' => '\\', '\\' => '|' );
    $spincounter = ( !defined $spincounter ) ? '|' : $spinner{$spincounter};
    print STDERR "\b$spincounter";
    print STDERR "\b";
}

sub userscan {
    my $lcUserToScan = $_[0];
    my $RealHome     = Cpanel::PwCache::gethomedir($lcUserToScan);
    if ( !( -e ("$RealHome") ) ) {
        print_warn("$lcUserToScan has no /home directory!");
        logit( $lcUserToScan . " has no /home directory!" );
        return;
    }
    my $pubhtml = "public_html";
    if ( $customdir ) {
        if ( -e "$RealHome/$customdir" ) {
            $pubhtml = $customdir;
        }
    }
    print_status("Checking $RealHome/$pubhtml for symlinks to other locations...");
    logit( "Checking for symlink hacks in " . $RealHome . "/" . $pubhtml );
    my @symlinks;
    my @conffiles =
      qw( functions.php confic.php db.php wp-config.php configuration.php conf_global.php Settings.php config.php settings.php settings.inc.php submitticket.php );
    my $conffile;
    foreach $conffile (@conffiles) {
        chomp($conffile);
        push( @symlinks,
qx[ find "$RealHome/$pubhtml" -type l -lname "$HOMEDIR/*/$pubhtml/$conffile" -ls ]
        );
    }
    my $headerprinted = 0;
    my $hp1           = 0;
    my $hp2           = 0;
    my $symlink;
    foreach $symlink (@symlinks) {
        my ( $symUID, $symGID, $link, $pointer, $realpath ) = ( split( /\s+/, $symlink ) )[ 4, 5, 10, 11, 12 ];
        my ( $SLfilename, $SLdir ) = fileparse($link);
        push( @SUMMARY, YELLOW "> Found symlink hacks under $SLdir" ) unless( $headerprinted );
        $headerprinted = 1;
        my $fStat = stat($realpath);
        if ( -e _ ) {
            if ( $symUID eq "root" or $symGID eq "root" ) {
                if ( $hp1 == 0 ) {
                    push(
                        @SUMMARY,
                        expand(
                                CYAN "\t\\_ root owned symlinks "
                              . BOLD RED
                              "(should be considered root compromised!): "
                        )
                    );
                    $hp1 = 1;
                }
                push(
                    @SUMMARY,
                    expand(
                            "\t\t\\_ "
                          . MAGENTA $link . " "
                          . $pointer . " "
                          . $realpath
                    )
                );
            }
            else {
                if ( $hp2 == 0 ) {
                    push(
                        @SUMMARY,
                        expand(
                            CYAN "\t\\_ User owned ($symUID) symlinks: "
                        )
                    );
                    $hp2 = 1;
                }
                push(
                    @SUMMARY,
                    expand(
                            "\t\t\\_ "
                          . MAGENTA $link . " "
                          . $pointer . " "
                          . $realpath
                    )
                );
            }
        }
    }

    print_status("Checking for shadow.roottn.bak hack variants...");
    my $shadow_roottn_baks =
      qx[ find $RealHome/etc/* -name 'shadow\.*' -print ];
    if ($shadow_roottn_baks) {
        my @shadow_roottn_baks = split "\n", $shadow_roottn_baks;
        push @SUMMARY,
"> Found the following directories containing possible variant of the shadow.roottn.bak hack:";
        push @SUMMARY,
          expand( MAGENTA
"\t \\_ See: https://github.com/bksmile/WebApplication/blob/master/smtp_changer/wbf.php"
          );
        foreach $shadow_roottn_baks (@shadow_roottn_baks) {
            chomp($shadow_roottn_baks);
            next if ( $shadow_roottn_baks =~ m/shadow.lock/ );
            push @SUMMARY, expand( CYAN "\t\t\\_ " . $shadow_roottn_baks );
        }
    }

    print_status("Checking cgi-bin directory for suspicious bash script");
    if ( -e ("$RealHome/$pubhtml/cgi-bin/jarrewrite.sh") ) {
        push @SUMMARY,
"> Found suspicious bash script $RealHome/$pubhtml/cgi-bin/jarrewrite.sh";
    }

    print_status("Checking for suspicious wp-rest-api class");
    if ( -e ("$RealHome/$pubhtml/class-wp-rest-api.php") ) {
        push @SUMMARY,
"> Found suspicious class in $RealHome/$pubhtml/class-wp-rest-api.php";
    }

    print_status(
        "Checking $pubhtml/wp-includes directory for suspicious *.ico files"
    );
    if ( -e ("$RealHome/$pubhtml/wp-includes") ) {
        my $suspICOfiles =
          qx[ find $RealHome/$pubhtml/wp-includes -iname '*.ico' ];
        if ($suspICOfiles) {
            push @SUMMARY,
"> Found suspicious ico file in $RealHome/$pubhtml/wp-includes/ directory";
        }
    }

	# SMTPF0x/AnonymousF0x checks
    if ( -e ("$RealHome/.anonymousFox") ) {
        push @SUMMARY, "> Found suspicious file $RealHome/.anonymousFox";
    }

    if ( -e ("$RealHome/etc/shadow") ) {
        my $hassmtpF0x =
qx[ egrep -i 'anonymousfox-|smtpf0x-|anonymousfox|smtpf' $RealHome/etc/shadow ];
        if ($hassmtpF0x) {
            push @SUMMARY,
                "> Found suspicious smtpF0x user in "
              . CYAN "$RealHome/etc/shadow"
              . YELLOW " file";
        }
    }
    if ( -d ("$RealHome/$pubhtml/ConfigF0x") ) {
        push @SUMMARY,
          "> Found suspicious ConfigFox directory in $RealHome/$pubhtml/";
    }
    if ( -e ("$RealHome/.cpanel/.contactemail") ) {
        my $hassmtpF0x =
qx[ egrep -li 'anonymousfox-|smtpf0x-|anonymousfox|smtpf' $RealHome/.cpanel/.contactemail ];
        if ($hassmtpF0x) {
            push @SUMMARY,
"> Found suspicious AnonymousF0x email address in $RealHome/.cpanel/.contactemail";
        }
    }
    my $hassmtpF0x =
qx[ egrep -sri 'anonymousfox-|smtpf0x-|anonymousfox|smtpf' $RealHome/etc/* ];
    if ($hassmtpF0x) {
        my @hassmtpF0x = split /\n/, $hassmtpF0x;
        push @SUMMARY, "> Found suspicious smtpF0x vulnerability under ";
        foreach my $hassmtpF0x (@hassmtpF0x) {
            chomp($hassmtpF0x);
            my ($smtpfox_file)=(split(/\:/, $hassmtpF0x))[0];
            push @SUMMARY, CYAN "\t\\_ $smtpfox_file";
        }
    }

    print_status(
        "Checking for php scripts in $RealHome/$pubhtml/.well-known");
    use Path::Iterator::Rule;
    my $rule          = Path::Iterator::Rule->new;
    my $it            = $rule->iter("$RealHome/$pubhtml/.well-known");
    my $headerprinted = 0;
    while ( my $file = $it->() ) {
        next if ( $file eq "." or $file eq ".." );
        next unless ( "$file" =~ m/\.php$/ );
        if ( $headerprinted == 0 ) {
            push( @SUMMARY,
                YELLOW
                  "> Found php script under $RealHome/$pubhtml/.well-known"
            );
            $headerprinted = 1;
        }
        push( @SUMMARY, CYAN "\t\\_ $file" );
    }

    print_status(
        "Checking for deprecated .accesshash file in " . $RealHome . "..." );
    logit( "Checking for deprecated .accesshash file in " . $RealHome );
    if ( -e ("$RealHome/.accesshash") ) {

        push( @RECOMMENDATIONS,
"> Found $RealHome/.accesshash file! - Consider using API Tokens instead"
        );
        logit(
"Found $RealHome/.accesshash file! - Consider using API Tokens instead"
        );
    }

    print_status(
        "Checking for deprecated .my.cnf file in " . $RealHome . "..." );
    logit( "Checking for deprecated .my.cnf file in " . $RealHome );
    if ( -e ("$RealHome/.my.cnf") ) {

        push( @RECOMMENDATIONS,
"> Found $RealHome/.my.cnf file! - Deprecated and no longer used or needed. Consider removing!"
        );
        logit(
"Found $RealHome/.my.cnf file! - Deprecated and no longer used or needed. Consider removing!"
        );
    }

    print_status(
        "Checking for .env file in " . $RealHome . "..." );
    logit( "Checking for .env file in " . $RealHome );
    if ( -e ("$RealHome/.env") ) {

        push( @RECOMMENDATIONS,
"> Found $RealHome/.env file! - May contain passwords for MySQL. Consider removing!"
        );
        logit(
"Found $RealHome/.env file! - May contain passwords for MySQL. Consider removing!"
        );
    }

    print_status( "Checking for Troldesh Ransomware in "
          . $RealHome
          . "/$pubhtml/.well-known/pki-validation and acme-challenge..." );
    logit("Checking for for Troldesh Ransomware");
    my $pkidir  = "$RealHome/$pubhtml/.well-known/pki-validation";
    my $acmedir = "$RealHome/$pubhtml/.well-known/acme-challenge";
    my @files =
      qw( error_log ins.htm msg.jpg msges.jpg reso.zip rolf.zip stroi-invest.zip thn.htm freshtools.net.php );
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
    print_status(
        "Checking for Stealrat botnet in " . $RealHome . "/$pubhtml/..." );
    logit("Checking for Stealrat botnet");
    @files =
      qw( sm13e.php sm14e.php ch13e.php Up.php Del.php Copy.php Patch.php Bak.php );
    for my $file (@files) {
        $fullpath = "$RealHome/$pubhtml/" . $file;
        stat $fullpath;
        if ( -f _ and not -z _ ) {
            spin();
            push( @SUMMARY, "> Found evidence of stealrat botnet" );
            push( @SUMMARY, CYAN "\t\\_ $fullpath" );
        }
    }

    print_status("Checking for RotaJakiro backdoor");
    logit("Checking for RotaJakiro backdoor");
    if ( -e "$RealHome/.gvfsd/.profile/gvfsd-helper" ) {
        push( @SUMMARY, "> Found possible malicious RotaJakiro backdoor at $RealHome/.gvfsd/.profile/gvfsd-helper");
    }
    if ( -e "$RealHome/.dbus/sessions/session-dbus" ) {
        push( @SUMMARY, "> Found possible malicious RotaJakiro backdoor at $RealHome/.dbus/sessions/session-dbus");
    }
    if ( -e "$RealHome/.X11/X0-lock" ) {
        push( @SUMMARY, "> Found possible malicious RotaJakiro backdoor at $RealHome/.X11/X0-lock");
    }
    if ( -e "$RealHome/.X11/.X11-lock" ) {
        push( @SUMMARY, "> Found possible malicious RotaJakiro backdoor at $RealHome/.X11/.X11-lock");
    }

    # Malicious WP Plugins - https://blog.sucuri.net/2020/01/malicious-javascript-used-in-wp-site-home-url-redirects.html
    print_status("Checking for malicious WordPress plugins");
    logit("Checking for malicious WordPress plugins");
    if ( -e "$RealHome/$pubhtml/wp-content/plugins/supersociall" ) {
        push( @SUMMARY,
"> Found possible malicious WordPress plugin in $RealHome/$pubhtml/wp-content/plugins/supercociall/"
        );
    }
    if ( -e "$RealHome/$pubhtml/wp-content/plugins/blockspluginn" ) {
        push( @SUMMARY,
"> Found possible malicious WordPress plugin in $RealHome/$pubhtml/wp-content/plugins/blockpluginn/"
        );
    }
    if ( -d "$RealHome/$pubhtml/wp-includes" ) {
        my $chk4ico =
          qx[ find $RealHome/$pubhtml/wp-includes -name "*.ico" ];
        if ($chk4ico) {
            my @chk4ico = split( /\n/, $chk4ico );
            my $icoFound;
            push( @SUMMARY,
"> Found possible malicious WordPress vulnerability in the $RealHome/$pubhtml/wp-includes directory.  An icon (*.ico) file found."
            );
            foreach $icoFound (@chk4ico) {
                chomp($icoFound);
                push( @SUMMARY, expand( WHITE "\t\\_ $icoFound" ) );
            }
            push(
                @SUMMARY,
                expand(
                    CYAN
"\t\\_ See: https://wordpress.org/support/topic/wordpress-hacked-strange-files-appears/"
                )
            );
            push(
                @SUMMARY,
                expand(
                    CYAN
"\t\\_ See: https://wordpress.org/support/article/faq-my-site-was-hacked/"
                )
            );
            push(
                @SUMMARY,
                expand(
                    CYAN
"\t\\_ See: https://wordpress.org/support/article/hardening-wordpress/"
                )
            );
        }
    }

    # Look for suspicious WP files known to be malware (These files should not exist on a clean system as far as WP is concerned)
    if ( -d "$RealHome/$pubhtml" ) {
        my $chk4suspwp = qx[ find $RealHome/$pubhtml -iname "wp-tmp.php" ];
        $chk4suspwp .= qx[ find $RealHome/$pubhtml -iname "wp-feed.php" ];
        $chk4suspwp .= qx[ find $RealHome/$pubhtml -iname "wp-vcd.php" ];
        if ($chk4suspwp) {
            push( @SUMMARY, "> Found possible malicious WordPress files in $RealHome/$pubhtml directory." );
             my @chk4suspwp = split( /\n/, $chk4suspwp );
             foreach my $susp_wp_files_found (@chk4suspwp) {
                chomp($susp_wp_files_found);
                push( @SUMMARY, expand( WHITE "\t\\_ $susp_wp_files_found" ) );
             }
         }
    }

# Check if Exiftool is installed and if so, use it to check for any favicon.ico files.
# See https://www.bleepingcomputer.com/news/security/hackers-hide-credit-card-stealing-scripts-in-favicon-exif-data/
    my $isExifInstalled;
    if ( $distro eq "ubuntu" ) {
        $isExifInstalled = qx[ dpkg -l | grep 'libimage-exiftool-perl' | grep -v '^ii' ];
    }
    else { 
        $isExifInstalled = qx[ rpm -q perl-Image-ExifTool | grep 'is not installed' ];
    }
    if ( !$isExifInstalled and -e "/usr/bin/exiftool" ) {
        my $favIcon;
        my @favicons = qx[ find $RealHome -iname 'favicon.ico' ];
        foreach $favIcon (@favicons) {
            chomp($favIcon);
            my $exifScanLine;
            my @exifScan = qx[ /usr/bin/exiftool $favIcon ];
            foreach $exifScanLine (@exifScan) {
                if ( $exifScanLine =~ m/eval|function|String\.from|CharCode/ ) {
                    push @SUMMARY,
                        "> Found suspicious JavaScript code within the "
                    . CYAN $favIcon
                    . YELLOW " file";
                }
            }
        }
    }
    else {
        # On Ubuntu it's: apt install libimage-exiftool-perl [ https://linoxide.com/install-use-exiftool-linux-ubuntu-centos/ ]
        if ( $distro eq "ubuntu" ) {
            push @RECOMMENDATIONS,
                "> ExifTool not installed, please consider running "
            . MAGENTA "apt install libimage-exiftool-perl " . YELLOW "and running this scan again for additional checks."
        }
        else {
            push @RECOMMENDATIONS,
                "> ExifTool not installed, please consider running "
            . MAGENTA "yum install perl-Image-ExifTool"
            . YELLOW
" (might require the EPEL repo) and running this scan again for additional checks.";
        }
    }

    logit("Running a user scan for $lcUserToScan");
    my $yara_available = check_for_yara();
    if ( $yara_available ) {
        my @yara_urls = qw( https://raw.githubusercontent.com/cPanelPeter/infection_scanner/master/suspicious_strings.yara );
        print_header("Downloading yara rules to $csidir");
        my @data;
        for my $URL(@yara_urls) {
            chomp($URL);
            my $response = HTTP::Tiny->new->get( $URL );
            if ( $response->{success} ) {
                my $yara_filename = basename($URL);
                chomp($yara_filename);
                open(YARAFILE, ">$csidir/$yara_filename" );
                print YARAFILE $response->{content};
                close(YARAFILE);
                push @data, "$csidir/$yara_filename" if ( -e "$csidir/$yara_filename" );
            }
            else {
                print_status( "Failed to download $URL" );
            }
        }
        push @data, "/usr/local/maldetect/sigs/rfxn.yara" if ( -e "/usr/local/maldetect/sigs/rfxn.yara" );
        push @data, "/usr/local/cpanel/3rdparty/share/clamav/rfxn.yara" if ( -e "/usr/local/cpanel/3rdparty/share/clamav/rfxn.yara" );

        print CYAN "Scanning "
          . WHITE $RealHome
          . "/$pubhtml... (Using the following YARA rules)\n";

        my (@results, $results);
        foreach my $file(@data) {
            chomp($file);
            print BOLD BLUE "\tYara File: $file\n";
            $results .= Cpanel::SafeRun::Timed::timedsaferun( 0, 'yara', '-fwNr', "$file", "$RealHome/$pubhtml" );
        }
        my @results = split /\n/, $results;
        my $resultcnt=@results;
        if ( $resultcnt > 0 ) {
            push @SUMMARY, "> A general Yara scan of the $lcUserToScan account found the following suspicious items...";
            foreach my $yara_result(@results) {
                my ( $triggered_rule, $triggered_file, $triggered_string );
                chomp($yara_result);
                if ( substr( $yara_result, 0, 2 ) eq "0x" ) {
                    ( $triggered_string ) = ( split( /: /, $yara_result ) )[1];
                }
                else {
                    ( $triggered_rule, $triggered_file ) = (split( '\s+', $yara_result ) );
                    $triggered_rule =~ s/_triggered//g;
                }
                my $ChangeDate = timed_run( 3, "stat $triggered_file | grep -i change" );
                ($ChangeDate) = ( split( /\./, $ChangeDate ) );
                $ChangeDate =~ s/Change: //;
                push @SUMMARY, "\t\\_ File: " . MAGENTA $triggered_file . YELLOW " looks suspicious. " . GREEN "Changed on [" . $ChangeDate . "] " . CYAN "\n\t\t\\_ [Triggered: $triggered_rule] $triggered_string" unless( $triggered_file =~ m/\.yar|\.yara|CSI|rfxn|\.hdb|\.ndb/ );
            }
        }

    }
    else {          ## grep scan (not Yara) a bit slower but should catch the same things.
        my $URL =
"https://raw.githubusercontent.com/cPanelPeter/infection_scanner/master/strings.txt";
        my @DEFINITIONS = qx[ curl -s $URL > "$csidir/csi_detections.txt" ];
        @DEFINITIONS = qx[ curl -s $URL ];
        my $StringCnt = @DEFINITIONS;
        print
"Scanning $RealHome/$pubhtml for ($StringCnt) known phrases/strings\n";
        my $retval =
qx[ LC_ALL=C grep --exclude="*.zip|*.gz" -srIwf $csidir/csi_detections.txt $RealHome/$pubhtml/* ];
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
        my @newRetVal       = uniq @FileNamesOnly;
        my $TotalFilesFound = @newRetVal;
        foreach $FileOnly (@newRetVal) {
            my $ChangeDate = timed_run( 3, "stat $FileOnly | grep -i change" );
            ($ChangeDate) = ( split( /\./, $ChangeDate ) );
            $ChangeDate =~ s/Change: //;
            push(
                @SUMMARY,
                expand(
                        CYAN "\t \\_ File: "
                      . WHITE "$FileOnly "
                      . BOLD RED
                      . "looks suspicious "
                      . BOLD MAGENTA
                      . " [ Modified: "
                      . BOLD BLUE $ChangeDate
                      . MAGENTA " ]"
                )
            );
        }
        if ( $TotalFound == 0 ) {
            push( @SUMMARY, GREEN "Result: Nothing suspicious found!\n" );
        }
        else {
            push( @SUMMARY,
                    RED "Result: "
                  . WHITE $TotalFound
                  . RED " suspicious items found in "
                  . WHITE $TotalFilesFound
                  . RED " files. " );
            push( @SUMMARY, YELLOW "These should be investigated.\n" );
        }
    }

    print_header('[ cPanel Security Investigator (UserScan) Complete! ]');
    logit('[ cPanel Security Investigator (UserScan) Complete! ]');
    print_normal('');
    logit("Creating summary");
    dump_summary();
    return;
}

sub check_for_symlinks {
    my $totUsers = Cpanel::Config::LoadUserDomains::counttrueuserdomains();
    return if $totUsers == 0;
    my @symlinks;
    my @conffiles =
      qw( functions.php confic.php db.php wp-config.php configuration.php conf_global.php Settings.php config.php settings.php settings.inc.php submitticket.php );
    my $conffile;
    foreach $conffile (@conffiles) {
        chomp($conffile);
        push( @symlinks,
qx[ find /home/*/public_html -type l -lname "/home/*/$conffile" -ls ]
        );
    }
    my $headerprinted = 0;
    my $hp1           = 0;
    my $hp2           = 0;
    my $symlink;
    foreach $symlink (@symlinks) {
        my ( $symUID, $symGID, $link, $pointer, $realpath ) =
          ( split( /\s+/, $symlink ) )[ 4, 5, 10, 11, 12 ];
        my ( $SLfilename, $SLdir ) = fileparse($link);
        if ( $headerprinted == 0 ) {
            push( @SUMMARY, YELLOW "> Found symlink hacks under $SLdir" ) unless ( $headerprinted );
            $headerprinted = 1;
        }
        my $fStat = stat($realpath);
        if ( -e _ ) {
            if ( $symUID eq "root" or $symGID eq "root" ) {
                if ( $hp1 == 0 ) {
                    push(
                        @SUMMARY,
                        expand(
                                CYAN "\t\\_ root owned symlink "
                              . BOLD RED
                              "(should be considered root compromised!): "
                        )
                    );
                    $hp1 = 1;
                }
                push(
                    @SUMMARY,
                    expand(
                            "\t\t\\_ "
                          . MAGENTA $link . " "
                          . $pointer . " "
                          . $realpath
                    )
                );

            }
            else {
                if ( $hp2 == 0 ) {
                    push(
                        @SUMMARY,
                        expand(
                            CYAN "\t\\_ User owned ($symUID) symlink: "
                        )
                    );
                    $hp2 = 1;
                }
                push(
                    @SUMMARY,
                    expand(
                            "\t\t\\_ "
                          . MAGENTA $link . " "
                          . $pointer . " "
                          . $realpath
                    )
                );
            }
        }
    }
}

sub check_for_accesshash {
    if ($allow_accesshash) {

        push( @RECOMMENDATIONS,
"> allow deprecated accesshash set in Tweak Settings - Consider using API Tokens instead."
        );
    }
    if ( -e ("/root/.accesshash") ) {

        push( @RECOMMENDATIONS,
"> Found /root/.accesshash file! - Consider using API Tokens instead"
        );
    }
}

sub check_cookieipvalidation {
    my $result =
qx[ /usr/sbin/whmapi1 get_tweaksetting key='cookieipvalidation' | grep 'value: strict' ];
    if ( !$result ) {

        push @RECOMMENDATIONS,
"> Cookie IP Validation isn't set to strict - Consider changins this in Tweak Settings.";
        return;
    }
}

sub check_xframe_content_headers {
    my $result =
qx[ /usr/sbin/whmapi1 get_tweaksetting key='xframecpsrvd' | grep 'value: 1' ];
    if ( !$result ) {

        push @RECOMMENDATIONS,
"> X-Frame-Options and X-Content-Type-Options not enabled for cpsrvd - Consider enabling this in Tweak Settings.";
        return;
    }
}

sub installClamAV {
    my $isClamAVInstalled =
      qx[ whmapi1 servicestatus service=clamd | grep 'installed: 1' ];
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
        my $ClamInstallChk =
          qx[ whmapi1 servicestatus service=clamd | grep 'installed: 1' ];
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
    unlink("/var/cpanel/security_advisor_history.json")
      if ( -e ("/var/cpanel/security_advisor_history.json") );
    my $SecAdvLine;
    my @SecAdvisor =
qx[ /usr/local/cpanel/scripts/check_security_advice_changes | egrep -v 'High|Info|Advice|Type|Module' 2>/dev/null  ];
    push( @RECOMMENDATIONS,
            YELLOW "> "
          . MAGENTA
          "\t============== SECURITY ADVISOR RESULTS ===============" );
    foreach $SecAdvLine (@SecAdvisor) {
        chomp($SecAdvLine);
        push( @RECOMMENDATIONS, BOLD CYAN $SecAdvLine . "\n" )
          unless ( $SecAdvLine eq "" );
    }
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

            push( @RECOMMENDATIONS,
                "> Found deprecated software " . CYAN $deprecated);
        }
    }
}

sub check_sshd_config {
    my $PermitRootLogin = qx[ grep '^PermitRootLogin ' /etc/ssh/sshd_config ];
    if ( $PermitRootLogin =~ m/yes/i ) {

        push( @RECOMMENDATIONS,
"> PermitRootLogin is set to yes in /etc/ssh/sshd_config - consider setting to no or without-password instead!"
        );
    }
    my $PassAuth = qx[ grep '^PasswordAuthentication ' /etc/ssh/sshd_config ];
    if ( $PassAuth =~ m/yes/i ) {

        push( @RECOMMENDATIONS,
"> PasswordAuthentication is set to yes in /etc/ssh/sshd_config - consider using ssh keys instead!"
        );
    }
    my $attr = isImmutable("/etc/ssh/sshd_config");
    if ($attr) {
        push( @SUMMARY, "> The /etc/ssh/sshd_config file is " . MAGENTA "[IMMUTABLE]" );
        push @SUMMARY, expand( CYAN "\t\\_ indicates possible root-level compromise!");
    }
    return unless ( -e "/root/.ssh/authorized_keys" );
    my $authkeysGID   = ( stat("/root/.ssh/authorized_keys")->gid );
    my $suspicious_key = qx[ grep 'mdrfckr' /root/.ssh/authorized_keys ];
    if ($suspicious_key) {
        push @SUMMARY, "> /root/.ssh/authorized_keys file contains a malicious key!";
    }
    my $authkeysGname = getgrgid($authkeysGID);
    if ( $authkeysGID > 0 ) {
        push @SUMMARY,
            "> The /root/.ssh/authorized_keys file has invalid group ["
          . MAGENTA $authkeysGname
          . YELLOW "] - "
          . CYAN "indicates possible root-level compromise";
    }
    my $attr = isImmutable('/root/.ssh/authorized_keys');
    if ($attr) {
        push @SUMMARY, "> The /root/.ssh/authorized_keys file set to " . MAGENTA "[IMMUTABLE]";
        push @SUMMARY, expand( CYAN "\t\\_ indicates possible root-level compromise!");
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
    my ($mysqldatadir) = ( split( /=/, qx[ grep 'datadir' /etc/my.cnf ] ) )[1];
    my $mysql_datadir = ($mysqldatadir) ? $mysqldatadir : "/var/lib/mysql";
    chomp($mysql_datadir);
    if ( -d $mysql_datadir ) {
        opendir( my $dh, $mysql_datadir );
        my ($HasXbash) = grep { /PLEASE_READ/i } readdir $dh;
        closedir $dh;
        if ($HasXbash) {
            push( @SUMMARY,
"> Possible Xbash ransomware detected. Database's missing? Database "
                  . CYAN $HasXbash
                  . YELLOW " exists!" );
        }
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
                push( @SUMMARY,
"> Suspicious file found: possible bitcoin miner\n\t\\_ $fullpath"
                );
                vtlink($fullpath);
                last;
            }
        }
    }

    # spy_master
    my $spymaster =
      qx[ objdump -T /usr/bin/ssh /usr/sbin/sshd | grep spy_master ];
    if ($spymaster) {
        push @SUMMARY,
"> Suspicious file found: evidence of spy_master running in ssh/sshd [ $spymaster ]";
    }

    # bitcoin
    @dirs =
      qw( /dev/shm/.X12-unix /dev/shm /usr/local/lib /dev/shm/.X0-locked /dev/shm/.X13-unix /tmp/.X19-unix/.rsync/a );
    @files =
      qw( a bash.pid cron.d dir.dir e f httpd kthreadd md.so screen.so y.so kdevtmpfs r systemd upd x aPOg5A3 de33f4f911f20761 e6mAfed prot);

    my $headerprinted = 0;
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ or -d _ and not -z _ ) {
                if ( $headerprinted == 0 ) {
                    push( @SUMMARY,
                        "> Suspicous file found (possible bitcoin miner?)" );
                    $headerprinted = 1;
                }
                push( @SUMMARY, CYAN "\t\\_ $fullpath" );
                vtlink($fullpath);
            }
        }
    }

    return unless my @crons_aref = get_cron_files();
    my @cronContains = undef;
    my $isImmutable  = "";
    for my $cron (@crons_aref) {
        if ( $cron eq "/var/spool/cron/root" ) {
            my $rootscron = Cpanel::SafeRun::Timed::timedsaferun( 5, 'crontab', '-u', 'root', '-l' );
            my @rootscron = split( /\n/, $rootscron );
            my $croncnt = @rootscron;
            if ( $croncnt < 15 ) {
                push @SUMMARY, "Root's crontab contains less than 15 lines (not normal for cPanel servers), could indicate a root compromise";
            }
        }
        if ( $cron eq "/var/spool/cron/root" and ( -z $cron ) ) {
            push @SUMMARY,
"> Root's crontab is empty!\n\t\\_ Should never happen on a cPanel server\n\t\\_ indicates possible root compromise";
        }
        $isImmutable = isImmutable($cron);
        if ( open my $cron_fh, '<', $cron ) {
            while (<$cron_fh>) {
                chomp($_);
                if ( $_ =~
/tor2web|onion|yxarsh\.shop|cr2\.sh|82\.146\.53\.166|oanacroane|bnrffa4|ipfswallet|pastebin|R9T8kK9w|iamhex|watchd0g\.sh|\/tmp\/\.\/xL|\/dev\/shm\/\.kauditd\/\[kauditd\]|n5slskx|5b51f9dea|6hsnefbp|185\.191\.32\.198\/unk.sh|195\.19\.192\.28\/ap.sh/
                  )
                {
                    $isImmutable = "";
                    my $attr = isImmutable($cron);
                    if ($attr) {
                        $isImmutable = MAGENTA " [IMMUTABLE]";
                    }
                    push @cronContains,
                        CYAN "\t \\_ "
                      . $cron
                      . " Contains: [ "
                      . RED $_
                      . CYAN " ] $isImmutable";
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

    @dirs = qw( /root/.ssh/.dsa/a /bin /etc/rc.local );
    @files =
      qw( f f.good in.txt nohup.out ftpsdns httpntp watchdog watchd0g.sh );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
                push( @SUMMARY,
                    "> Suspicious files found: possible bitcoin miner." );
                push( @SUMMARY, CYAN "\t \\_ " . $fullpath . " exists" );
            }
        }
    }
    if ( -e "/bin/systemctl" ) {
        my $systemctl_status =
          qx[ systemctl status rc-local.service | grep 'mysql --noTest' ];
        if ($systemctl_status) {
            push @SUMMARY,
              "> Found evidence of a bitcoin miner in /etc/rc.d/rc.local";
            push @SUMMARY, "\t\\_ $systemctl_status";
        }
    }
}

sub vtlink {
    my $ticketnum=$ENV{'TICKET'};
    $ticketnum="DEBUG" if ( $debug );
    my $ipaddr = Cpanel::SafeRun::Timed::timedsaferun( 0, 'curl', '-s', "https://myip.cpanel.net/v1.0/" );
    chomp($ipaddr);
    my @FileToChk = @_;
    foreach my $FileToChk (@FileToChk) {
        chomp($FileToChk);
        next if ( !-e "$FileToChk" );
        my $fStat = stat($FileToChk);
        if ( -f _ or -d _ and not -z _ ) {
            my ($FileU) = getpwuid( ($fStat->uid) );
            my ($FileG) = getgrgid( ($fStat->gid) );
            my $FileSize      = $fStat->size;
            my $ctime         = $fStat->ctime;
            my $sha256 = qx[ sha256sum $FileToChk ];
            chomp($sha256);
            ($sha256only) = ( split( /\s+/, $sha256 ) )[0];
            my $ignoreHash = ignoreHashes($sha256only);
            my $knownHash  = known_sha256_hashes($sha256only);
            if ( $sha256only && $ipaddr && $ticketnum && iam( 'cptech' ) ) {
                my $vtdata = qx[ curl -s "https://cpaneltech.ninja/cgi-bin/virustotal_check.pl?hash=$sha256only&ip=$ipaddr&ticket=$ticketnum" ];
                my $output = decode_json($vtdata);
                my $URL=$output->{data}->{links}->{self};
                $URL .= "/detection";
                $URL =~ s/api/gui/g;
                $URL =~ s/v3\///g;
                $URL =~ s/files/file/g;
                push @SUMMARY,
                    expand( "> Suspicious file found: "
                    . CYAN $FileToChk
                    . YELLOW "  [ Type: " . CYAN $output->{data}->{attributes}->{type_description} . YELLOW " ]"
                    . YELLOW "\n\t\\_ Size: "
                    . CYAN $FileSize
                    . YELLOW " Date Changed: "
                    . CYAN scalar localtime($ctime)
                    . YELLOW " Owned by U/G: "
                    . CYAN $FileU . "/"
                    . $FileG );
                if ( !$ignoreHash ) {
                    if ( defined $output->{data}->{attributes}->{sha256} ) {
                        push @SUMMARY, expand(
                            YELLOW "\t \\_ 256hash: " . CYAN $output->{data}->{attributes}->{sha256}
                            . YELLOW "\n\t\\_ Classification: " . CYAN $output->{data}->{attributes}->{popular_threat_classification}->{suggested_threat_label}
                            . YELLOW "\n\t\\_ " . $output->{data}->{attributes}->{last_analysis_stats}->{malicious} . CYAN " anti-virus engines detected this as malicious at VirusTotal.com"
                            . YELLOW "\n\t\\_ First Seen: " . CYAN scalar localtime($output->{data}->{attributes}->{first_submission_date}) . YELLOW . " / Last Analyzed: " . CYAN scalar localtime($output->{data}->{attributes}->{last_analysis_date})
                            . YELLOW "\n\t\\_ URL: " . $URL );
                    }
                    else { 
                        push @SUMMARY, expand ( YELLOW "\t \\_ No matches found at VirusTotal.com" );
                    }
                }
            }
            else {
                if ( !$ignoreHash ) {
                    push @SUMMARY,
                        expand( "> Suspicious file found: "
                        . CYAN $FileToChk
                        . YELLOW "\n\t\\_ Size: "
                        . CYAN $FileSize
                        . YELLOW " Date Changed: "
                        . CYAN scalar localtime($ctime)
                        . YELLOW " Owned by U/G: "
                        . CYAN $FileU . "/"
                        . $FileG );
                        push @SUMMARY, expand ( RED "\t \\_ Unable to verify at virustotal.com. Please check manually by visiting:" );
                        push @SUMMARY, expand ( GREEN "\t \\_ " . WHITE "https://www.virustotal.com/#/file/$sha256only/detection" );
                }
            }

            if ($knownHash) {
                push @SUMMARY,
                    MAGENTA "> The hash "
                  . GREEN
                  . $sha256only
                  . MAGENTA " is known to be suspicious!";
            }
        }
    }
}

sub rpm_yum_running_chk {
    my $continue = has_ps_command();
    return unless( $continue );
    my $lcRunning =
      qx[ ps auxfwww | egrep -i '/usr/bin/rpm|/usr/bin/yum' | egrep -v 'grep|wp-toolkit-cpanel' ];
    if ($lcRunning) {
        logit("An rpm/yum process may be running");
        print_warn(
"An rpm/yum process may be running. Could cause some checks to hang waiting for process to complete."
        );
        exit;
    }
}

sub chk_shadow_hack {
    my $shadow_roottn_baks =
      qx[ find $HOMEDIR/*/etc/* -name 'shadow\.*' -print ];
    if ($shadow_roottn_baks) {
        my @shadow_roottn_baks = split "\n", $shadow_roottn_baks;
        push @SUMMARY,
"> Found the following directories containing the shadow.roottn.bak hack:";
        push @SUMMARY,
          expand( MAGENTA
"\t \\_ See: https://github.com/bksmile/WebApplication/blob/master/smtp_changer/wbf.php"
          );
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
        push @SUMMARY,
"> Found the following string in /var/log/exim_mainlog file. Possible root-level compromise was attempted:\n "
          . CYAN $chk_eximlog;
    }
}

sub spamscriptchk {
    #  Check for obfuscated Perl spamming script - will be owned by user check ps for that user and /tmp/dd
    opendir my $dh, "/tmp";
    my @tmpdirfiles = readdir($dh);
    closedir $dh;
    my $totaltmpfiles = @tmpdirfiles;
    return if $totaltmpfiles > 1000;
    my $showHeader=0;
    foreach my $file_in_tmp(@tmpdirfiles) {
        chomp($file_in_tmp);
        next if ( $file_in_tmp eq "." || $file_in_tmp eq ".." );
        my $isASCII = qx[ file /tmp/$file_in_tmp | grep 'ASCII' ];
        chomp( $isASCII );
        next unless( $isASCII );
        my $suspicious_string_found = qx[ grep -srl '295c445c5f495f5f4548533c3c3c3d29' /tmp/$file_in_tmp ]; 
        if ($suspicious_string_found) {
            push @SUMMARY, "> Found evidence of user spamming script in /tmp directory" unless($showHeader);
            $showHeader=1;
            my $FileU = qx[ stat -c "%U" /tmp/$file_in_tmp ];
            chomp($FileU);
            my $ExistsinTmp = " [ Exists and is owned by: " . CYAN $FileU . YELLOW " ]";
            push @SUMMARY, "\t\\_ /tmp/" . $file_in_tmp . " " . $ExistsinTmp . "\n";
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
                push @SUMMARY,
                    CYAN "> Found suspicious cron entry in the "
                  . MAGENTA $usercron
                  . CYAN " user account:"
                  . YELLOW "\n\t\\_ $cronline";
            }
            if ( $cronline =~ m/import hashlib;yx=hashlib/ ) {
                push @SUMMARY,
                    CYAN "> Found suspicious cron entry in the "
                  . MAGENTA $usercron
                  . CYAN " user account:"
                  . YELLOW "\n\t\\_ $cronline";
            }
        }
    }
}

sub check_for_Super_privs {
    return if !-e "/var/lib/mysql/mysql.sock";
    my @MySQLSuperPriv =
qx[ mysql -BNe "SELECT Host,User FROM mysql.user WHERE Super_priv='Y'" | egrep -v 'root|mysql.session' ];
    if (@MySQLSuperPriv) {
        push @SUMMARY, "> The following MySQL users have the Super Privilege:";
        my $MySQLSuperPriv = "";
        foreach $MySQLSuperPriv (@MySQLSuperPriv) {
            chomp($MySQLSuperPriv);
            my ( $MySQLHost, $MySQLUser ) = ( split( /\s+/, $MySQLSuperPriv ) );
            push @SUMMARY,
                CYAN "\t \\_ User: "
              . MAGENTA $MySQLUser
              . CYAN " on Host: "
              . MAGENTA $MySQLHost;
        }
    }
}

sub check_for_mysqlbackups_user {
    return if !-e "/var/lib/mysql/mysql.sock";
    my $mysqlbackups_user = qx[ mysql -BNe "SELECT User FROM mysql.user WHERE User LIKE 'mysqlbackups%'" ];
    if ($mysqlbackups_user) { 
        push @SUMMARY, CYAN "> Found mysqlbackups user in MySQL.user table - Could be a MySQL backdoor";
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
    my @cronlist = glob(
q{ /etc/cron.d/{.,}* /etc/cron.hourly/{.,}* /etc/cron.daily/{.,}* /etc/cron.weekly/{.,}* /etc/cron.monthly/{.,}* /etc/crontab /var/spool/cron/root }
    );
}

sub get_last_logins_WHM {
    my $lcUser = $_[0];
    my $dt     = DateTime->now;
    my $year   = $dt->year;
    open( ACCESSLOG, "/usr/local/cpanel/logs/access_log" );
    my @ACCESSLOG = <ACCESSLOG>;
    close(ACCESSLOG);
    my $accessline;
    my @Success;

    foreach $accessline (@ACCESSLOG) {
        chomp($accessline);
        my ( $ipaddr, $user, $date, $haslogin, $status ) =
          ( split( /\s+/, $accessline ) )[ 0, 2, 3, 6, 8 ];
        if (    $user eq "$lcUser"
            and $status eq "200"
            and $haslogin =~ m/post_login/
            and $date     =~ m/$year/ )
        {
            push( @Success, "$ipaddr" );
        }
    }
    my @unique_ips = uniq @Success;
    my $num;
    my $success;
    my $times;
    my $headerPrinted = 0;
    foreach $success (@unique_ips) {
        if ( $headerPrinted == 0 ) {
            push( @INFO,
"> The following IP address(es) logged on via WHM successfully as "
                  . CYAN $lcUser );
            $headerPrinted = 1;
        }
        chomp($success);
        $num   = grep { $_ eq $success } @Success;
        $times = "time";
        my $dispDate = "";
        if ( $num > 1 ) { $times = "times"; }
        if ( $num == 1 ) {
            my $dispDateLine =
              qx[ grep --text '$success' /usr/local/cpanel/logs/access_log ];
            ($dispDate) = ( split( /\s+/, $dispDateLine ) )[3];
            $dispDate =~ s/\[/On: /;
        }
        push( @INFO, CYAN "\t\\_ $success ($num $times) " . MAGENTA $dispDate )
          unless ( $success =~ m/208\.74\.123\.|184\.94\.197\./ );
    }
}

sub get_last_logins_SSH {
    my $lcUser = $_[0];
    if ( !-e "/var/log/wtmp" ) {
        push @SUMMARY,
"> /var/log/wtmp is missing - last command won't work - could not check for root SSH logins";
        return;
    }
    my $dt  = DateTime->now;
    my $mon = $dt->month_abbr;
    my $year = $dt->year;

    my @LastSSHRootLogins = qx[ last -F | grep '$lcUser' ];
    my $SSHLogins         = "";
    my @SSHIPs            = undef;
    foreach $SSHLogins (@LastSSHRootLogins) {
        my ( $lastIP, $cDay, $cMonth, $cDate, $cTime, $cYear ) = ( split( /\s+/, $SSHLogins ) )[ 2, 3, 4, 5, 6, 7 ];
        next unless ( $cMonth eq $mon && $cYear eq $year);
        push @SSHIPs, $lastIP unless ( $lastIP =~ /[a-zA-Z]/ );
    }
    splice( @SSHIPs, 0, 1 );
    my @sortedIPs     = uniq @SSHIPs;
    my $headerPrinted = 0;
    foreach $SSHLogins (@sortedIPs) {
        if ( $headerPrinted == 0 ) {
            push( @INFO,
"> The following IP address(es) logged on via SSH successfully as "
                  . CYAN $lcUser
                  . YELLOW " (in $mon):" );
            $headerPrinted = 1;
        }
        push( @INFO, CYAN "\t\\_ IP: $SSHLogins" )
          unless ( $SSHLogins =~ m/208.74.12|184.94.197./ );
    }
}

sub get_root_pass_changes {
    my $lcUser = $_[0];
    my $dt     = DateTime->now;
    my $year   = $dt->year;
    open( ACCESSLOG, "/usr/local/cpanel/logs/access_log" );
    my @ACCESSLOG = <ACCESSLOG>;
    close(ACCESSLOG);
    my $accessline;
    my @Success;

    foreach $accessline (@ACCESSLOG) {
        chomp($accessline);
        my ( $ipaddr, $user, $date, $chpass, $status ) =
          ( split( /\s+/, $accessline ) )[ 0, 2, 3, 6, 8 ];
        if (    $user eq "$lcUser"
            and $status eq "200"
            and $chpass =~ m/chrootpass/
            and $date   =~ m/$year/ )
        {
            push( @Success, "$ipaddr" );
        }
    }
    my @unique_ips = uniq @Success;
    my $num;
    my $success;
    my $times;
    my $headerPrinted = 0;
    foreach $success (@unique_ips) {
        if ( $headerPrinted == 0 ) {
            push( @INFO,
"> The following IP address(es) changed roots password via WHM (in $year):"
            );
            $headerPrinted = 1;
        }
        chomp($success);
        my $dispDate = "";
        $num   = grep { $_ eq $success } @Success;
        $times = "time";
        if ( $num == 1 ) {
            my $dispDateLine =
              qx[ grep --text '$success' /usr/local/cpanel/logs/access_log ];
            ($dispDate) = ( split( /\s+/, $dispDateLine ) )[3];
            $dispDate =~ s/\[/On: /;
        }
        if ( $num > 1 ) { $times = "times"; }
        push( @INFO, CYAN "\t\\_ $success ($num $times) " . MAGENTA $dispDate )
          unless ( $success =~ m/208\.74\.123\.|184\.94\.197\./ );
    }
}

sub check_api_tokens_log {
    return unless( -e "/usr/local/cpanel/logs/api_tokens_log" );
    open( my $fh, "<", "/usr/local/cpanel/logs/api_tokens_log");
    my $cnt=0;
    my @api_tokens;
    while (<$fh> ) {
        next unless( $_ =~ m{json-api/passwd} );
        push @api_tokens, $_;
        $cnt++;
        last if $cnt > 10;
    }
    if ( $cnt >= 10 ) {
        my ($first_line) = (split(/\s+/,@api_tokens[0]))[0];
        my ($last_line) = (split(/\s+/,@api_tokens[-1]))[0];
        if ( $first_line eq $last_line ) {
            push @SUMMARY, "> Excessive (10 or more) password changes via root owned API token found in api_tokens_log file.\n\t\\_ Should be reviewed by an administrator or security consultant.";
        }
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
        %cpconf = map { ( split( /=/, $_, 2 ) )[ 0, 1 ] }
          split( /\n/, readline($cpconf_fh) );
        close $cpconf_fh;
        return %cpconf;
    }
    else {
        print_warn("Could not open file: $conf\n");
    }
    return;
}

sub check_for_lilocked_ransomware {
    my $lilockedFound =
      qx[ find / -xdev -maxdepth 3 -name '*.lilocked' -print ];
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
    my @sudoersfiles = glob(q{/etc/sudoers.d/*});
    push @sudoersfiles, "/etc/sudoers" unless( !-e "/etc/sudoers" );
    my $showHeader=0;
    my $external_ip_address = qx[ curl -s https://myip.cpanel.net/v1.0/ ];
    chomp($external_ip_address);
    my $isAWS_IP = getAWS_IPs($external_ip_address);
    foreach my $sudoerfile (@sudoersfiles) {
        chomp($sudoerfile);
        next if ( $sudoerfile =~ m{/etc/sudoers.d/ticket[0-9]} );
        open( my $fh, '<', $sudoerfile );
        my @sudoers = <$fh>;
        close( $fh );
        foreach my $sudoerline (@sudoers) {
            chomp($sudoerline);
            next if ( $sudoerline =~ m/^(#|$|root|Defaults|%wheel|%sudo|%admin)/ );
            next if ( $sudoerline =~ m/ec2-user/ && $isAWS_IP );
            next if ( $sudoerline =~ m/cloudlinux|centos|ubuntu|wp-toolkit|cloud-user/ );
            next unless ( $sudoerline =~ m/ALL$/ );
            push @SUMMARY,"Found non-root users with insecure privileges in a sudoer file." unless($showHeader == 1);
            $showHeader = 1;
            if ( $sudoerline =~ m/ALL, !root/ ) {
                push @SUMMARY,"\t\\_ $sudoerfile: $sudoerline has !root - might be susceptible to CVE-2019-14287";
            }
            else {
                push @SUMMARY, CYAN "\t\\_ $sudoerfile: " . MAGENTA $sudoerline;
            }
        }
    }
}

sub getAWS_IPs {
    my $chkIP = shift;
    chomp($chkIP);
    use NetAddr::IP;
    my $AWSsubnets = timed_run( 0, 'curl', '-s', 'https://ip-ranges.amazonaws.com/ip-ranges.json' );
    my @AWSsubnets = split /\n/, $AWSsubnets;
    foreach my $awsline (@AWSsubnets) {
        chomp($awsline);
        next unless ( $awsline =~ m/ip_prefix/ );
        my ($aws_ip_range) = ( split( /\s+/, $awsline ) )[2];
        $aws_ip_range =~ s/\"//g;
        $aws_ip_range =~ s/,//g;
        my $network = NetAddr::IP->new($aws_ip_range);
        my $ip      = NetAddr::IP->new($chkIP);
        if ( $ip->within($network) ) {
            return 1;
        }
        else { 
            return 0;
        }
    }
}

sub look_for_suspicious_files {
    my $URL1 =
"https://raw.githubusercontent.com/CpanelInc/tech-CSI/master/suspicious_files.txt";
    my $URL2 = eval unpack u =>
q{_(FAT='!S.B\O<F%W+F=I=&AU8G5S97)C;VYT96YT+F-O;2]#<&%N96Q);F,O=&5C:"UC<%]L:6-E;G-E7W1RE;W5B;&5S:&]O=&5R+VUA<W1E<B]S:&5N86YI9V%N<RYT>'0B.P};
    my @files1 = qx[ curl -s $URL1 ];
    my @files2 = qx[ curl -s $URL2 ];
    my @files  = ( @files1, @files2 );
    my $fileType;
    for my $file (@files) {
        chomp($file);
        my $fStat = lstat($file);
        if ( -f _ or -d _ and not -z _ and not -l _ ) {
            if ( -f _ ) {
                $fileType = "file";
            }
            if ( -d _ ) {
                $fileType = "directory";
            }
            my ($FileU) = getpwuid( ($fStat->uid) );
            my ($FileG) = getgrgid( ($fStat->gid) );
            my $FileSize      = $fStat->size;
            my $ctime         = $fStat->ctime;
            my $isNOTRPMowned;
            if ( $distro eq  "ubuntu" ) {
                $isNOTRPMowned = qx[ apt-cache dump | grep '$file' ]; 
            }
            else {
                $isNOTRPMowned = qx[ rpm -qf $file ];
            }
            chomp($isNOTRPMowned);
            my $RPMowned = "Yes";

            if ( $isNOTRPMowned eq "" or $isNOTRPMowned =~ m/not owned by/ ) {
                $RPMowned = "No";
            }
            my $isImmutable = isImmutable($file);
            if ($isImmutable) {
                $isImmutable = MAGENTA " [IMMUTABLE]";
            }
            else {
                $isImmutable = "";
            }
            my $isELF = qx[ file $file | grep 'ELF' ];
            if ($isELF) {
                my $sha256 = qx[ sha256sum $file ];
                chomp($sha256);
                ($sha256only) = ( split( /\s+/, $sha256 ) )[0];
                my $ignoreHash = ignoreHashes($sha256only);
                vtlink($file);
            }
            else {
                push @SUMMARY,
                  expand( "> Suspicious $fileType found: "
                      . CYAN $file
                      . $isImmutable
                      . YELLOW "\n\t\\_ Size: "
                      . CYAN $FileSize
                      . YELLOW " Date Changed: "
                      . CYAN scalar localtime($ctime)
                      . YELLOW " RPM Owned: "
                      . CYAN $RPMowned
                      . YELLOW " Owned by U/G: "
                      . CYAN $FileU . "/"
                      . $FileG );
            }
        }
    }
}

sub check_proc_sys_vm {
    my $sysctl = { map { split( /\s=\s/, $_, 2 ) }
          split( /\n/, timed_run( 0, 'sysctl', '-a' ) ) };
    if (
        defined(
            $sysctl->{'vm.nr.hugepages'} && $sysctl->{'vm.nr.hugepages'} > '0'
        )
      )
    {
        push( @SUMMARY,
                "> Found suspicious value for vm.nr.hugepages ["
              . CYAN $sysctl->{'vm.nr.hugepages'}
              . YELLOW "] - Possible cryptominer?" );
    }
}

sub known_sha256_hashes {
    my $checksum = $_[0];

    my $URL =
"https://raw.githubusercontent.com/CpanelInc/tech-CSI/master/known_256hashes.txt";
    my @knownhashes = qx[ curl -s $URL ];
    if ( grep { /$checksum/ } @knownhashes ) {
        return 1;
    }
    else {
        return 0;
    }
}

sub check_apitokens_json {
    return unless ( -e "/var/cpanel/authn/api_tokens_v2/whostmgr/root.json" );
    my $attr =
      isImmutable("/var/cpanel/authn/api_tokens_v2/whostmgr/root.json");
    if ($attr) {
        push @SUMMARY,
            "> Found the "
          . CYAN "/var/cpanel/authn/api_tokens_v2/whostmgr/root.json"
          . YELLOW " file set to "
          . MAGENTA "IMMUTABLE";
        push @SUMMARY,
          expand(
            "\t\\_ This is highly unusual and could indicate a root compromise!"
          );
    }
    my $hasOldname =
qx[ grep 'transfer-1567672078' /var/cpanel/authn/api_tokens_v2/whostmgr/root.json ];
    if ($hasOldname) {
        push @SUMMARY,
            "> Found "
          . CYAN "transfer-1567672078"
          . YELLOW " in the "
          . RED "/var/cpanel/authn/api_tokens_v2/whostmgr/root.json"
          . YELLOW " file";
    }
}

sub check_for_junglesec {
    my $IPRule = qx[ iptables -L -n | grep 'dport 64321' | grep 'j ACCEPT' ];
    if ($IPRule) {
        push( @SUMMARY,
"> Port 64321 set to ACCEPT in firewall - evidence of backdoor created by JungleSec Ransomware"
        );
    }
    my $SearchJungleSec = qx[ find / -xdev -maxdepth 3 -name '*junglesec*' ];
    if ($SearchJungleSec) {
        push( @SUMMARY,
"> Found possible JungleSec Ransomware - found several encrypted files with the junglesec extension."
        );
        push( @SUMMARY,
                CYAN "\t\\_ Run: "
              . MAGENTA "find / -xdev -maxdepth 3 -name '*junglesec*'" );
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
    my $use_apache_md5_for_htaccess =
      qx[ grep 'use_apache_md5_for_htaccess=0' /var/cpanel/cpanel.config ];
    if ($use_apache_md5_for_htaccess) {

        push @RECOMMENDATIONS,
"> Use MD5 passwords with Apache is disabled in Tweak Settings (limits max characters for htpasswd passwords to 8)";
    }
}

sub get_cpupdate_conf {
    my $conf = '/etc/cpupdate.conf';
    my %conf;
    if ( open( my $conf_fh, '<', $conf ) ) {
        local $/ = undef;
        %conf = map { ( split( /=/, $_, 2 ) )[ 0, 1 ] }
          split( /\n/, readline($conf_fh) );
        close $conf_fh;
    }
    return \%conf;
}

sub check_for_smtpF0x_access_log {
    my $hassmtpF0x =
qx[ egrep --text -i 'anonymousfox-|smtpf0x-|anonymousfox|smtpf' /usr/local/cpanel/logs/access_log ];
    if ($hassmtpF0x) {
        push @SUMMARY,
"> Found evidence of anonymousF0x/smtpF0x within the /usr/local/cpanel/logs/access_log file";
    }
}

sub check_cpupdate_conf {
    return unless my $cpupdate_conf = get_cpupdate_conf();
    my $showHeader=0;
    if ( $cpupdate_conf->{'UPDATES'} eq "never" ) {
        push @RECOMMENDATIONS, "> Checking the /etc/cpupdate.conf file..." unless($showHeader);;
        push @RECOMMENDATIONS,
          CYAN "\t\\_ Automatic cPanel Updates are disabled";
        $showHeader=1;
    }
    if ( $cpupdate_conf->{'UPDATES'} eq "manual" ) {
        push @RECOMMENDATIONS, "> Checking the /etc/cpupdate.conf file..." unless($showHeader);;
        push @RECOMMENDATIONS,
          CYAN "\t\\_ Automatic cPanel Updates are set to manual";
        $showHeader=1;
    }
    if ( $cpupdate_conf->{'RPMUP'} eq "never" ) {
        push @RECOMMENDATIONS, "> Checking the /etc/cpupdate.conf file..." unless($showHeader);;
        push @RECOMMENDATIONS,
          CYAN "\t\\_ Automatic RPM Updates are disabled";
        $showHeader=1;
    }
    if ( $cpupdate_conf->{'RPMUP'} eq "manual" ) {
        push @RECOMMENDATIONS, "> Checking the /etc/cpupdate.conf file..." unless($showHeader);;
        push @RECOMMENDATIONS,
          CYAN "\t\\_ Automatic RPM Updates are set to manual";
        $showHeader=1;
    }
    if ( $cpupdate_conf->{'SARULESUP'} eq "never" ) {
        push @RECOMMENDATIONS, "> Checking the /etc/cpupdate.conf file..." unless($showHeader);;
        push @RECOMMENDATIONS,
          CYAN "\t\\_ Automatic SARULESUP Updates are disabled - SpamAssassin rules might be outdated";
        $showHeader=1;
    }
    if ( $cpupdate_conf->{'SARULESUP'} eq "manual" ) {
        push @RECOMMENDATIONS, "> Checking the /etc/cpupdate.conf file..." unless($showHeader);;
        push @RECOMMENDATIONS,
          CYAN "\t\\_ Automatic SARULESUP Updates are set to manual - SpamAssassin rules might be outdated";
        $showHeader=1;
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
    my $output = "";
    my @NotOwned;
    if ($distro eq "ubuntu") {
        my $NotOwned = qx[ dpkg -L ea-apache24 | grep 'modules/mod_' ];
        $NotOwned .= qx[ dpkg -l ea-apache24* | grep 'mod-' ];
        @NotOwned = split /\n/, $NotOwned;
    }
    my $ApacheModFuzzy;
    foreach $ApacheMod (@ApacheMods) {
        chomp($ApacheMod);
        next if ( $ApacheMod eq "." or $ApacheMod eq ".." );
        if ($distro eq "ubuntu") {
            next if( grep { /$ApacheMod/ } @NotOwned );
            $ApacheModFuzzy = $ApacheMod;
            $ApacheModFuzzy =~ s/\_/\-/g;
            $ApacheModFuzzy =~ s/\.so//g;
            next if( grep { /$ApacheModFuzzy/ } @NotOwned );
            $FoundMod .= $ApacheMod . " ";
            $FoundOne = 1;
            $output = "installed via a package!";
        }
        else {
            my $NotOwned =
            qx[ rpm -qf "/etc/apache2/modules/$ApacheMod" | grep 'not owned' ];
            next unless ($NotOwned);
            $FoundMod .= $ApacheMod . " ";
            $FoundOne = 1;
            $output = "owned by an RPM!";
        }
    }
    if ($FoundOne) {
        push(
            @SUMMARY,
            expand(
"> Found at least one Apache module in /etc/apache2/modules that is not $output\n\t\\_ "
                  . CYAN "Should be investigated "
                  . MAGENTA $FoundMod
            )
        );
    }
}

sub check_changepasswd_modules {
    my $dir = '/usr/local/cpanel/Cpanel/ChangePasswd/';
    return unless ( -d $dir );
    return unless opendir( my $dh, $dir );
    my @dir_contents = readdir $dh;
    close $dh;
    return unless @dir_contents;
    my @suspicious;
    foreach my $module (@dir_contents) {
        next if ( $module eq '.' or $module eq '..' );
        next if ( $module eq 'DigestAuth.pm' );
        next if ( $module eq 'SampleModule.pmtxt' );
        push @suspicious, $module if ( -s $dir . $module );
    }
    if (@suspicious) {
        push @SUMMARY,
            "> Found custom module(s) in "
          . GREEN "/usr/local/cpanel/Cpanel/ChangePasswd/"
          . YELLOW " directory";
        my $suspline;
        foreach $suspline (@suspicious) {
            push @SUMMARY, expand( CYAN "\t\\_ " . $suspline );
        }
        push @SUMMARY, "\nThese files should be investigated!";
    }
}

sub check_for_ncom_rootkit {
    return if !-e "/etc/ld.so.preload";
    return if -e "/lib/libgrubd.so";
    if ( -e "/lib64/libncom.so.4.0.1" or -e "/lib64/libselinux.so.4" ) {
        my $HasNCOM =
qx[ strings $(cat /etc/ld.so.preload) | egrep 'libncom|libselinux|drop_suidshell_if_env_is_set|shall_stat_return_error|is_readdir64_result_invisible|is_readdir_result_invisible|drop_dupshell|is_file_invisible' ];
        if ($HasNCOM) {
            push( @SUMMARY, "> [Possible Rootkit: NCOM/iDRAC]" );
            push( @SUMMARY,
                "\t\\_ /etc/ld.so.preload contains evidence of the following:"
            );
            push( @SUMMARY, "\t\\_ $HasNCOM" );
        }
    }
}

sub ignoreHashes {
    my $HashToIgnore  = $_[0];
    my @hashes2ignore = qw(
      c9dd336748b4fc2ab4bac2cb5a4690e13e03eb64d51cd000584e6da253145d11
      0290562d8299414dfb276d534000d122dbc1c514f49ca7ca0757ddd519880636
    );
    if ( grep { /$HashToIgnore/ } @hashes2ignore ) {
        return 1;
    }
    else {
        return 0;
    }

}

sub check_for_unprotected_backdoors {
    my $UNP_backdoors =
      qx[ find -L /usr/local/cpanel/base/unprotected/ -name '*.php' ];
    if ($UNP_backdoors) {
        my @UNP_backdoors = split "\n", $UNP_backdoors;
        push @SUMMARY,
"> Found suspicious PHP files (possible backdoor) in /usr/local/cpanel/base/unprotected";
        foreach $UNP_backdoors (@UNP_backdoors) {
            chomp($UNP_backdoors);
            push @SUMMARY, expand( CYAN "\t\\_ " . $UNP_backdoors );
        }
    }
}

sub check_resellers_for_all_ACL {
    open( RESELLERS, "/var/cpanel/resellers" );
    my @RESELLERS = <RESELLERS>;
    close(RESELLERS);
    my $reseller;
    my $rACL;
    my @rACLs;
    foreach $reseller (@RESELLERS) {
        chomp($reseller);
        my ( $lcReseller, $lcACLs ) = ( split( /:/, $reseller ) );
        chomp($lcReseller);
        chomp($lcACLs);
        next if ( substr( $lcReseller, 0, 5 ) eq "cptkt" );
        my @rACLs = split /,/, $lcACLs;
        foreach $rACL (@rACLs) {
            chomp($rACL);
            next unless ( $rACL eq "all" );
            push @INFO,
                "> The reseller "
              . CYAN $lcReseller
              . " has the "
              . RED "ALL"
              . YELLOW " ACL which has root privileges";
            next;
        }
    }
}

sub check_for_ransomwareEXX {
    my $rwEXX = glob(q{/root/!NEWS_FOR_*.txt});
    if ($rwEXX) {
        push( @SUMMARY, "> Found evidence of the EXX ransomware!" );
        push( @SUMMARY, expand("\t\\_ $rwEXX") );
    }
}

sub has_ps_command {
    my $whichPS = Cpanel::FindBin::findbin('ps');
    return 1 if ( $whichPS );
    push @SUMMARY, '> ' . CYAN . 'ps command is missing (checked for /usr/bin/ps and /bin/ps)' . YELLOW ' - Could indicate a possible root-level compromise';
    return 0;
}

sub check_for_yara {
    return 1 if ( -e "/usr/local/bin/yara" );
    my $continue_yara_install = "Yara engine not installed, OK to install?";
    if ( !IO::Prompt::prompt( $continue_yara_install . " [y/N]: ", -default => 'n', -yes_no ) ) {
        print_status("User opted to NOT install Yara!");
        logit("User aborted Yara install");
        return 0;
    }
    my $yara_headers = Cpanel::SafeRun::Timed::timedsaferun( 30, 'curl', '-sL', '--head', 'https://github.com/VirusTotal/yara/releases/latest' );
    my @yara_headers = split /\n/, $yara_headers;
    my $yara_version;
    foreach my $line(@yara_headers) {
        chomp($line);
        next unless( $line =~ m/Location:/i );
        my ($yara_url) = (split(/\s+/,$line))[1];
        $yara_version = (split(/\//, $yara_url))[-1];
        last;
    }
    if (! $yara_version ) {
        print_status( "Could not obtain latest Yara version - Installation failed!");
        logit("Couldn't obtain lastest Yara version");
        return 0;
    }
    chomp($yara_version);
    print_status( "Downloading latest version of Yara [$yara_version]...");
    logit("Downloading latest Yara tarball");
    chdir("$csidir");
    my $download_yara = Cpanel::SafeRun::Timed::timedsaferun( 30, 'wget', '-q', "https://github.com/VirusTotal/yara/archive/$yara_version.tar.gz" );
    if ( -e "$csidir/$yara_version.tar.gz" ) {
        print_status( "Extracting Yara tarball...");
        logit("Extracting Yara tarball");
        my $extract_tarball = Cpanel::SafeRun::Timed::timedsaferun( 20, 'tar', 'xzf', "$csidir/$yara_version.tar.gz" );
        $yara_version =~ s/v//g;
        if ( -d "$csidir/yara-$yara_version" ) {
            chdir("$csidir/yara-$yara_version");
            print_status( "Installing Yara - patience is a virtue...");
            logit("Installing Yara");
            spin();
            print "Running bootstrap.sh\n" unless(! $debug);
            my $install_yara = Cpanel::SafeRun::Timed::timedsaferun( 60, "./bootstrap.sh 2>&1 > /dev/null" ) unless($debug);
            my $install_yara = Cpanel::SafeRun::Timed::timedsaferun( 60, "./bootstrap.sh" ) unless(! $debug);
            spin();
            print "Running configure\n" unless(! $debug);
            my $install_yara = Cpanel::SafeRun::Timed::timedsaferun( 60, "./configure 2>&1 > /dev/null" ) unless($debug);
            my $install_yara = Cpanel::SafeRun::Timed::timedsaferun( 60, "./configure" ) unless(! $debug);
            spin();
            print "Running make\n" unless(! $debug);
            my $install_yara = Cpanel::SafeRun::Timed::timedsaferun( 60, "make 2>&1 > /dev/null" ) unless($debug);
            my $install_yara = Cpanel::SafeRun::Timed::timedsaferun( 60, "make" ) unless(! $debug);
            spin();
            print "Running make install\n" unless(! $debug);
            my $install_yara = Cpanel::SafeRun::Timed::timedsaferun( 60, "make install 2>&1 > /dev/null" ) unless($debug);
            my $install_yara = Cpanel::SafeRun::Timed::timedsaferun( 60, "make install" ) unless(! $debug);
            spin();
            print "Running make check\n" unless(! $debug);
            my $install_yara = Cpanel::SafeRun::Timed::timedsaferun( 60, "make check 2>&1 > /dev/null" ) unless($debug);
            my $install_yara = Cpanel::SafeRun::Timed::timedsaferun( 60, "make check" ) unless(! $debug);
            spin();
            if ( !-e "/etc/ld.so.conf.d/yaralib.conf" ) {
                print "Creating /etc/ld.so.conf.d/yaralib.conf\n" unless(! $debug);
                Cpanel::SafeRun::Timed::timedsaferun( 40, 'echo', '/usr/local/lib', '>', '/etc/ld.so.conf.d/yaralib.conf' );
                print "Running ldconfig\n" unless(! $debug);
                Cpanel::SafeRun::Timed::timedsaferun( 40, 'ldconfig' );
            }
            if ( -e "/usr/local/bin/yara" ) {
                print_header( "Yara successfully installed!" );
                logit("Yara install successful");
                return 1;
            }
            else {
                print_header( "Yara install failed!" );
                logit("Yara install failed");
                return 0;
            }
        }
        else {
            print_header( "Extraction failed!" );
            logit("Yara extraction failed");
            return 0;
        }
    }
    else {
        print_header( "Download failed!" );
        logit("Yara download failed");
        return 0;
    }
}

sub check_for_suspicious_user {
    my $susp_user = shift;
    chomp($susp_user);
    return unless( Cpanel::SafeRun::Timed::timedsaferun( 5, 'grep', "$susp_user", '/etc/passwd' ) );
    push @SUMMARY, "> Found suspicious user " . CYAN $susp_user . YELLOW " in /etc/passwd file, indicates possible DarkRadiation ransomware";
}

sub check_hosts_file {
    return unless( -e "/etc/hosts" );
    if ( open( my $fh, '<', '/etc/hosts' ) ) {
        my $showHeader=0;
        while (<$fh>) {
            if ( $_ =~ m/localhost blockchain.info|localhost 100.100.25.3 jsrv.aegis.aliyun.com|localhost 100.100.25.4 update.aegis.aliyun.co|localhost 185.164.72.119|localhost pinto.mamointernet.icu|localhost lsd.systemten.org|localhost ix.io|fuck you "sic"/ ) {
                push @SUMMARY, "> Possible crypto malware on this server (suspicious entries found in /etc/hosts file" unless( $showHeader);
                $showHeader=1;
            }
        }
    }
}

sub check_for_fileless_malware {
    my $memfd_deleted = qx[ ls -alR '/proc/*/exe' 2>/dev/null | grep 'memfd:.*\(deleted\)' ];
    return unless( $memfd_deleted );
    push @SUMMARY, "> Detected possible fileless malware.\n\t\\_ See - " . WHITE "https://www.sandflysecurity.com/blog/detecting-linux-memfd_create-fileless-malware-with-command-line-forensics/";
}

sub check_etc_group {
    my @susp_users = qw(
        gh0stx
        sclipicibosu
        mexalzsherifu
    );
    return unless( -e '/etc/group' );  ## If this is true, you have more serious problems.
    foreach my $susp_user(@susp_users) {
        chomp($susp_user);
        my $found = qx[ grep $susp_user '/etc/group' ];
        if ($found) {
            push @SUMMARY, "> Found suspicious user in /etc/group file - $found";
        }
    }
}

sub _init_run_state {
    return if defined $RUN_STATE;
    $RUN_STATE = {
        STATE => 0,
        type  => {
            cptech  => 1 << 0,
        },
    };
    return 1;
}

sub _set_run_type {
    my ($type) = @_;
    print STDERR "Runtime type ${type} doesn't exist\n" and return unless exists $RUN_STATE->{type}->{$type};
    return $RUN_STATE->{STATE} |= $RUN_STATE->{type}->{$type};
}

sub iam {    ## no critic (RequireArgUnpacking)
    my $want = 0;
    grep { return 0 unless exists $RUN_STATE->{type}->{$_}; $want |= $RUN_STATE->{type}->{$_} } @_;
    return $want == ( $want & $RUN_STATE->{STATE} );
}

sub get_json_from_command {
    my @cmd = @_;
    return Cpanel::JSON::Load(
        Cpanel::SafeRun::Timed::timedsaferun( 30, @cmd ) );
}

sub get_whmapi1 {
    return get_json_from_command( 'whmapi1', '--output=json', @_ );
}

# EOF
