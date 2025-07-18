#!/usr/local/cpanel/3rdparty/bin/perl
# CSI - cPanel Security Investigator
# Current Maintainer: Peter Elsner

use strict;
my $version = "3.5.47";
use Cpanel::Config::LoadWwwAcctConf();
use Cpanel::Config::LoadCpConf();
use Cpanel::Config::LoadUserDomains();
use Text::Tabs;
$tabstop = 4;
use File::Basename;
use File::Path;
use File::Find;
use File::stat;
use File::Slurp;
use IO::Prompt;
use LWP::UserAgent;
use DateTime;
use HTTP::Tiny;
use Cpanel::Exception      ();
use Cpanel::FindBin        ();
use Cpanel::Version        ();
use Cpanel::Kernel::Status ();
use Cpanel::IONice         ();
use Cpanel::OSSys::Env;    ();
use Cpanel::PwCache        ();
use Cpanel::PwCache::Get   ();
use Cpanel::SafeRun::Timed ();
use Cpanel::SafeRun::Errors();
use Cpanel::Validate::IP   ();
use utf8;
use JSON::PP;
use List::MoreUtils qw(uniq);
use Math::Round;
use POSIX;
use Getopt::Long;
use Path::Iterator::Rule;
use IO::Socket::INET;
use IO::Prompt;
use Term::ANSIColor qw(:constants);
use Time::Piece;
use Time::Seconds;
$Term::ANSIColor::AUTORESET = 1;
our $RUN_STATE;
our $gl_is_kernel=0;

###################################################
# Check to see if the calling user is root or not #
###################################################
if ( $> != 0 ) {
    print "This script must be run as root\n";
    exit;
}

_init_run_state();
if ( exists $ENV{'PACHA_AUTOFIXER'} ) {
    _set_run_type('cptech');
}
elsif ( defined $ENV{'HISTFILE'}
    and index( $ENV{'HISTFILE'}, 'cpanel_ticket' ) != -1 )
{
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
our $spincounter;
our $CPANEL_CONFIG_FILE = q{/var/cpanel/cpanel.config};
my $conf             = Cpanel::Config::LoadWwwAcctConf::loadwwwacctconf();
my $cpconf           = Cpanel::Config::LoadCpConf::loadcpconf();
my $allow_accesshash = $cpconf->{'allow_deprecated_accesshash'};
my $sha256only;
our $HOMEDIR       = $conf->{'HOMEDIR'};
our @FILESTOSCAN   = undef;
our $rootkitsfound = 0;
our @process_list = get_process_list();
my $hostname = Cpanel::SafeRun::Timed::timedsaferun( 10, 'hostname', '-f' );
chomp $hostname if defined $hostname;
if ( not length($hostname) ) {
    $hostname = hostname();
}

###########################################################
# Parse positional parameters for flags and set variables #
###########################################################
# Set defaults for positional parameters
my (
    $full,         $shadow,  $symlink,        $yarascan,
    $secadv,       $help,    $debug,          $userscan,
    $customdir,    $scan,    $skipkernel,     %process,
    %ipcs,         $distro,  $distro_version, $distro_major,
    $distro_minor, $ignoreload, $overwrite,   $cron,
    $skipauthchk
);
get_ipcs_hash( \%ipcs );

$distro       = Cpanel::OS->_instance->distro;
$distro_major = Cpanel::OS->_instance->major;
$distro_minor = Cpanel::OS->_instance->minor;
$distro_version = $distro_major . "." . $distro_minor;

our $OS_RELEASE = ucfirst($distro) . " Linux release " . $distro_version;
our $HTTPD_PATH = get_httpd_path();
our $LIBKEYUTILS_FILES_REF = build_libkeyutils_file_list();
our $IPCS_REF;
our $PROCESS_REF;
our @RPM_LIST;
our $OPT_TIMEOUT;
GetOptions(
    'userscan=s'  => \$userscan,
    'customdir=s' => \$customdir,
    'full'        => \$full,
    'skipauthchk' => \$skipauthchk,
    'shadow'      => \$shadow,
    'symlink'     => \$symlink,
    'yarascan'    => \$yarascan,
    'secadv'      => \$secadv,
    'ignoreload'  => \$ignoreload,
    'help'        => \$help,
    'debug'       => \$debug,
    'overwrite'   => \$overwrite,
    'cron'        => \$cron,
    'skipkernel'  => \$skipkernel,
);

#######################################
# Set variables needed for later subs #
#######################################
our $CSISUMMARY;
our @SUMMARY;
our @RECOMMENDATIONS;
our @INFO;
my $content=get_hashes();
our @knownhashes = split /\n/, $content;
my $docdir = '/usr/share/doc';
check_for_touchfile();

my @logfiles = ( '/var/log/wtmp' );
if ( ! -e '/var/cpanel/dnsonly' ) {
    push @logfiles, '/var/log/apache2/access_log';
    push @logfiles, '/var/log/apache2/error_log';
}

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

if ( $cron ) {
    $overwrite=1;
    $full=1;
    $yarascan=1;
    logit("Running with cron switch (full, yarascan and overwrite are automatically added)");
}
check_previous_scans();
logit("=== STARTING CSI on $hostname ===");

sub get_loadavg {
    my ($load_avg) = (
        split(
            /\s+/,
            Cpanel::SafeRun::Timed::timedsaferun( 0, 'cat', '/proc/loadavg' )
        )
    )[0];
    chomp($load_avg);
    return $load_avg;
}

my $corecnt = Cpanel::SafeRun::Timed::timedsaferun( 0, 'nproc' );
chomp($corecnt);
my $loadavg = get_loadavg();

if ( $loadavg > ( $corecnt * 3 ) && !$ignoreload ) {
    print RED
"Load Average is too high ($loadavg) which is greater than 3 times the number of cores\n";
    print WHITE "If you really want to continue, pass --ignoreload\n";
    logit( 'Load average too high: ' . $loadavg );
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
print_header( YELLOW "Scan started on $scanstarttime" );
logit("Scan started on $scanstarttime");
logit("Showing disclaimer");
print_info("Usage: /root/csi.pl [functions] [options]");
print_info("See --help for a full list of options");
print_normal('');
disclaimer();
print_header(
    "Checking for RPM database corruption and repairing as necessary...")
  unless ( $distro eq "ubuntu" );

my $findRPMissues =
  Cpanel::SafeRun::Timed::timedsaferun( 0,
    '/usr/local/cpanel/scripts/find_and_fix_rpm_issues' )
  unless ( $distro eq "ubuntu" );
my $isRPMYUMrunning = rpm_yum_running_chk();

if ($userscan) {
    my $usertoscan = $userscan;
    chomp($usertoscan);
    userscan($usertoscan);
    exit;
}

logit("Running default scan");
scan();
my $scanendtime = Time::Piece->new;
print_header( YELLOW "\nScan completed on $scanendtime" );
logit("Scan completed on $scanendtime");
my $scantimediff = ( $scanendtime - $scanstarttime );
my $scanTotTime  = $scantimediff->pretty;
$scanTotTime = $scanTotTime . "\n";
print_header("Elapsed Time: $scanTotTime");
logit("Elapsed Time: $scanTotTime");
logit("=== COMPLETED CSI ===");
if ( $cron ) {
    send_email();
}
exit;

########
# Subs #
########

sub show_help {
    print_header("\ncPanel Security Investigator Version $version");
    print_header(
"Usage: /usr/local/cpanel/3rdparty/bin/perl csi.pl [options]\n"
    );
    print_header("Functions");
    print_header("=================");
    print_status("With no arguments [WHICH IS THE DEFAULT] a quick scan is performed.");
    print_normal(" ");
    print_status( "--userscan cPanelUser  Installs Yara if not already installed & performs a Yara scan for a single cPanel User.");
    print_normal(" ");
    print_header("Additional scan options available");
    print_header("=================");
    print_header( "--shadow     Performs a check on all email accounts looking for variants of shadow.roottn hack.");
    print_header( "--symlink    Performs a symlink hack check for all accounts.");
    print_header( "--secadv     Runs Security Advisor");
    print_header( "--skipkernel Skip kernel update checks. Useful if a custom kernel is installed and kernel checking fails.");
    print_header( "--yarascan   Skips confirmation during --full scan. CAUTION - Can cause very high load and take a very long time!");
    print_header( "--full       Performs all of the above checks - very time consuming. Can cause HIGH LOAD DURING YARA SCANS!!!");
    print_header( "--skipauthchk - Skip check for infected openssh backdoors");
    print_header( "--overwrite  Overwrite last summary and skip creation of new CSI directory under root.");
    print_header( "--cron       Run via cron. Note: --full, --overwrite and --yarascan options will also be passed.");
    print_header( "--debug      Shows additional extrenuous info including errors if any. Use only at direction of cPanel Support.");
    print_normal(" ");
    print_header("Examples");
    print_header("=================");
    print_status("            /root/csi.pl with no arguments does a quick scan [DEFAULT]");
    print_status("            /root/csi.pl --symlink");
    print_status("            /root/csi.pl --secadv");
    print_status("            /root/csi.pl --skipkernel");
    print_status("            /root/csi.pl --full [--yarascan] [--skipauthchk]");
    print_status("            /root/csi.pl --overwrite");
    print_status("            /root/csi.pl --cron [ add this to roots crontab or to a file in /etc/cron.d or /etc/cron.daily ]");
    print_status("Userscan ");
    print_status("            /root/csi.pl --userscan myuser");
    print_status(
        "            /root/csi.pl --userscan myuser --customdir mycustomdir");
    print_status(
"            (must be relative to the myuser homedir and defaults to public_html if non-existent!"
    );
    print_normal(" ");
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

# BEGIN DEFAULT SCAN HERE!

sub scan {
    print_normal('');
    print_header('[ Starting cPanel Security Investigator SCAN Mode ]');
    print_header("[ System: $OS_RELEASE ]");
    print_normal('');
    print_header("[ Available flags when running csi.pl scan ]");
    print_header(
        MAGENTA '[     --full Performs a more compreshensive scan (includes the options below)]' );
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
    check_for_suspicious_user();
    print_header('[ Checking /etc/hosts file for suspicious entries ]');
    logit("Checking /etc/hosts for suspicious entries");
    check_hosts_file();
    print_header('[ Checking for known Indicators of Compromise (IoC) ]');
    logit("Checking for known IoC's");
    all_malware_checks();
    print_header('[ Checking installed packages for CVEs ]');
    logit("Checking installed packages for CVEs");
    check_for_cve_vulnerabilities();
    print_header('[ Checking if polkit/policykit has been exploited by CVE-2021-4034 ]');
    logit("Checking if polkit/policykit has been exploited by CVE-2021-4034");
    check_for_cve_2021_4034();
    print_header('[ Checking for BPFDoor ]');
    logit("Checking for BPFDoor");
    check_for_bpfdoor();
    print_header('[ Checking for suspicious /etc/rc.modules file ]');
    logit("Checking for suspicious /etc/rc.modules file");
    check_for_susp_rc_modules();
    print_header('[ Checking for Free Download Manager Malware ]');
    logit("Checking for Free Download Manager Malware");
    check_for_freedownloadmanager_malware();
    print_header('[ Checking if Use MD5 passwords with Apache is disabled ]');
    logit("Checking if Use MD5 passwords with Apache is disabled");
    chk_md5_htaccess();
    print_header('[ Checking for index.html in /tmp and /home ]');
    logit("Checking for index file in /tmp and $HOMEDIR");
    check_index();
    print_header('[ Checking for suspicious files ]');
    logit("Checking for suspicious files");
    look_for_suspicious_files();
    print_header('[ Checking if root bash history has been tampered with ]');
    logit("Checking roots bash_history for tampering");
    check_history();
    print_header('[ Checking for open files that have been deleted ]');
    logit("Checking for open files that have been deleted");
    check_lsof_deleted();
    print_header('[ Checking /etc/ld.so.preload for compromised library ]');
    logit("Checking /etc/ld.so.preload for compromised library");
    check_preload();
    print_header('[ Checking for LKM rootkits ]');
    logit("Checking for Loadable Kernel Module rootkits");
    check_for_lkm_rootkits();
    print_header('[ Checking /dev/shm for binaries that are scripts or ELF fileyptes ]');
    logit("Checking /dev/shm for scripts and ELF file types");
    check_dev_shm_for_elf();
    print_header('[ Checking process list for suspicious processes ]');
    logit("Checking process list for suspicious processes");
    check_processes();
    print_header('[ Checking for suspicious bitcoin miners ]');
    logit("Checking for suspicious bitcoin miners");
    bitcoin_chk();
    print_header('[ Checking for suspicious mount points ]') if iam('cptech');
    logit("Checking for suspicious mount points") if iam('cptech');;
    check_mounts() if iam('cptech');
    print_header('[ Checking reseller ACLs ]');
    logit("Checking reseller ACLs");
    check_resellers_for_all_ACL();
    print_header( '[ Checking if /var/cpanel/authn/api_tokens_v2/whostmgr/root.json is IMMUTABLE ]');
    logit( "Checking if /var/cpanel/authn/api_tokens_v2/whostmgr/root.json is IMMUTABLE");
    check_apitokens_json();
    print_header( '[ Checking for root user as a cpanelid user ]');
    logit( "Checking authn paths for cpanelid user belonging to root" );
    check_authn_cpanelid();
    print_header( '[ Checking /usr/local/cpanel/logs/api_tokens_log for passwd changes ]');
    logit("Checking api_tokens_log for passwd changes");
    check_api_tokens_log();
    print_header( '[ Obtaining API Tokens ]');
    logit("Obtaining api tokens");
    get_api_tokens();
    print_header('[ Checking for PHP backdoors in unprotected path ]');
    logit("Checking /usr/local/cpanel/base/unprotected for PHP backdoors");
    check_for_unprotected_backdoors();
    print_header('[ Checking for miscellaneous compromises ]');
    logit("Checking for miscellaneous compromises");
    misc_checks();
    check_changepasswd_modules();
    print_header('[ Checking Binary Headers ]');
    logit("Checking Binary Headers (using hexdump -C)");
    check_binaries_for_shell();
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
    print_header( '[ Checking for non-root users with ALL privileges in /etc/sudoers file ]');
    logit("Checking /etc/sudoers file");
    check_sudoers_file();
    print_header('[ Checking for spam sending script in /tmp ]');
    logit("Checking for spam sending script in /tmp");
    spamscriptchk();
    print_header('[ Checking for root owned spam sending directory under /usr/local/share/. /ita/ ]');
    logit("Checking for root owned spam sending directory under /usr/local/share/. /ita/");
    check_for_ita_perl_hack();
    print_header('[ Checking user level crons for suspicious entries ]');
    logit("Checking user level crons");
    user_crons();
    print_header('[ Checking for ransomwareEXX ]');
    logit("Checking for ransomwareEXX");
    check_for_ransomwareEXX();
    print_header('[ Checking kernel status ]') unless( $skipkernel );
    logit("Checking kernel status") unless( $skipkernel );
    check_kernel_updates() unless( $skipkernel );
    print_header( '[ Checking for suspicious MySQL users (Including Super privileges) ]');
    logit("Checking for suspicious MySQL users including Super privileges");
    check_for_Super_privs();
    check_for_mysqlbackups_user();
    print_header('[ Checking for unowned files/libraries ]');
    logit("Checking for non-owned files/libraries");
    check_lib();
    print_header('[ Checking for suspicious users under /etc ]');
    logit("Checking for suspicious users under /etc");
    check_etc_files();
    print_header('[ Checking for suspicious Email Filters ]');
    logit("Checking for suspicious Email Filters");
    check_email_filters();
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
    if ( $full ) {
        unless( $skipauthchk ) {
            print_header( YELLOW '[ Additional check for infected openssh backdoors ]' );
            logit("Checking for infected openssh config files");
            check_auth_keys_for_commands();
        }
    }
    if ( $full ) {
        print_header( YELLOW '[ Additional check for Log4JShell hack attempts in log files ]' );
        logit("Additional check for Log4JShell hack attempts in log files");
        check_for_log4JShell_attempts();
    }

    if ( $full ) {
        print_header( YELLOW '[ Additional check for infections using YARA rules ]' );
        my $yara_available = check_for_yara();
        if ($yara_available) {
            my $abort_scan=0;
            if ( ! $yarascan ) {
                my $continue_yara_scan = "This process can cause very high loads and may take a long time!!!";
                if ( !IO::Prompt::prompt( $continue_yara_scan . " [y/N]: ", -default => 'n', -yes_no)) {
                    print_status("User opted to NOT continue with Yara scan!");
                    logit("User aborted Yara scan");
                    $abort_scan=1;
                }
            }
            if ( $abort_scan == 0 ) {
                my $url = URI->new( 'https://raw.githubusercontent.com/CpanelInc/tech-CSI/master/csi_rules.yara');
                my $ua = LWP::UserAgent->new( ssl_opts => { verify_hostname => 0 } );
                my $res       = $ua->get($url);
                my $yara_data = $res->decoded_content;
                my @yara_data = split /\n/, $yara_data;
                print_header("Downloading csi_rules.yara file to $csidir");
                open( YARAFILE, ">$csidir/csi_rules.yara" );
                foreach my $yara_line (@yara_data) {
                    chomp($yara_line);
                    print YARAFILE $yara_line . "\n";
                }
                close(YARAFILE);
                my @dirs = qw( /bin /boot /etc /lib /lib64 /opt /root /sbin /tmp /usr );
                for my $dir (@dirs) {
                    chomp($dir);
                    next unless -d $dir;
                    print_status("\tScanning $dir directory");
                    my $loadavg = get_loadavg();
                    print_status( expand( "\t\t\\_ Yara file: csi_rules.yara [ Load: $loadavg ]") );
                    my $results = Cpanel::SafeRun::Timed::timedsaferun( 0, 'yara', '-fwNr', "$csidir/csi_rules.yara", "$dir" );
                    my @results   = split /\n/, $results;
                    my $resultcnt = @results;
                    if ( $resultcnt > 0 ) {
                        my $showHeader = 0;
                        foreach my $yara_result (@results) {
                            chomp($yara_result);
                            next if ( $yara_result =~ m{.yar|.yara|CSI|rfxn|.hdb|.ndb|csi.pl|modsec_vendor_configs|access_log|swpDSK} );
                            my ( $triggered_rule, $triggered_file ) = ( split( '\s+', $yara_result ) );
                            my $ignore = _ignore( $triggered_rule, $triggered_file );
                            next unless( $ignore );
                            push @SUMMARY, "> A Yara scan found some suspicious files..." unless ( $showHeader );
                            $showHeader = 1;
                            push @SUMMARY, expand( "\t\\_ Rule Triggered: " . CYAN $triggered_rule . YELLOW " in the file: " . MAGENTA $triggered_file ) unless ( $triggered_file =~ m/\.yar|\.yara|CSI|rfxn|\.hdb|\.ndb|\/usr\/swpDSK|csi.pl/ );
                        }
                    }
                }
                sub _ignore {
                    my $rule2ignore = shift;
                    my $file2ignore = shift;
                    if ( $rule2ignore =~ m{} ) {
                        return 0;
                    }
                    if ( $file2ignore =~ m{/usr/local/cpanel/logs/access_log|/root/.bash_history} ) {
                        return 0;
                    }
                    return 1;
                }
            }
        }
    }

    print_normal(' ');
    print_header( GREEN 'Looking for recommendations' );
    print_normal(' ');

    # Checking for recommendations
    print_header('[ Checking for obsolete password hashes in /etc/shadow ]');
    logit("Checking for obsolete password hashes");
    check_for_obsolete_shadow_hashes();
    print_header('[ Comparing hashes in /etc/shells to /sbin/nologin ]');
    logit("Comparing hashes in /etc/shells to /sbin/nologin");
    compare_hash_of_shells();
    print_header('[ Checking if updates are enabled ]');
    logit("Checking if updates are enabled");
    check_cpupdate_conf();
    print_header('[ Checking for Two-Factor Authentication ]');
    logit("Checking if Two-Factor Authentication is enabled");
    check_2FA_enabled();
    print_header('[ Checking login_access Tweak Setting ]');
    logit("Checking login_access Tweak Setting");
    check_account_login_access();
    print_header('[ Checking for accesshash ]');
    logit("Checking for accesshash");
    check_for_accesshash();
    print_header('[ Checking if SymLinkProtection is enabled ]');
    logit("Checking if SymLinkProtection is enabled");
    check_if_symlink_protect_on();
    print_header('[ Checking setting of Cookie IP Validation ]');
    logit("Checking setting of Cookie IP Validation");
    check_cookieipvalidation();
    print_header( '[ Checking setting of X-Frame/X-Content Type headers with cpsrvd ]');
    logit("Checking setting of X-Frame/X-Content Type headers with cpsrvd");
    check_xframe_content_headers();
    print_header('[ Checking for deprecated plugins/modules ]');
    logit("Checking for deprecated plugins");
    check_for_deprecated();
    print_header( '[ Gathering the IP addresses that logged on successfully as root ]');
    logit("Gathering IP address that logged on as root successfully");
    get_last_logins_WHM("root");
    get_session_logins("root:");
    get_whm_terminal_logins("root");
    get_last_logins_SSH("root");
    check_secure_log("root");
    get_root_pass_changes("root");
    push( @INFO, CYAN "\nDo you recognize the above IP addresses? If not, then further investigation should be performed\nby a qualified security specialist.");

    if ( $full or $secadv ) {
        print_header( YELLOW '[ Additional check Security Advisor ]' );
        logit("Running Security Advisor");
        security_advisor();
    }

    print_header('[ cPanel Security Investigator Complete! ]');
    logit( 'cPanel Security Investigator Complete!' );
    print_header('[ CSI Summary ]');
    print_normal('');
    dump_summary();
}

sub check_previous_scans {
    print_info("CSI version: $version");
    print_status('Running in debug mode - Extrenuous output will be present') if ( $debug );
    logit('Running in debug mode') if ( $debug );
    if ( $overwrite ) {
       	unlink( "$csidir/csi.log" );
      	return;
    }
    print_status('Checking for a previous run of CSI');
    if ( -d $csidir ) {
        logit( 'Previous CSI directory found, backing up and creating a new one' );
        chomp( my $date = Cpanel::SafeRun::Timed::timedsaferun( 0, 'date', "+%Y-%m-%d-%H:%M:%S" ) );
        print_info("Existing $csidir is present, moving to $csidir-$date");
        rename "$csidir", "$csidir-$date";
        mkdir( "$csidir", 0755 );
    }
    return;
}

sub check_webtemplates_for_hack_page {
    my $dir='/var/cpanel/webtemplates/root/english';
    return unless( -d $dir );
    opendir my $dh, $dir;
    my @templatefiles = readdir($dh);
    closedir $dh;
    my $showHeader=0;
    foreach my $file(@templatefiles) {
        chomp($file);
        next if $file eq "." or $file eq "..";
        my $isHacked=Cpanel::SafeRun::Timed::timedsaferun( 0, 'grep', '-i', 'hack', "$dir/$file" );
        if ( $isHacked ) {
            push @SUMMARY, "> Web template file under: " . CYAN "$dir" . YELLOW " might contain a hack page." unless( $showHeader );
            $showHeader=1;
            push @SUMMARY, MAGENTA "\t\\_ $file";
        }
    }
}

sub check_kernel_updates {
    my $envtype = Cpanel::OSSys::Env::get_envtype();
    return if ( $envtype =~ m/lxc|viruozzo|vzcontainer/ );
    if ( Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '<', '11.102.0.0')) {
        use Cpanel::Kernel::GetDefault;
        my $boot_kernelversion = Cpanel::Kernel::GetDefault::get();
        my $running_kernelversion = Cpanel::Kernel::get_running_version();
        my $has_kernelcare=0;
        my $reboot_required=0;
        $has_kernelcare if ( Cpanel::KernelCare::kernelcare_responsible_for_running_kernel_updates() );
        if ( $running_kernelversion ne $boot_kernelversion ) {
            $reboot_required=1;
            if ($has_kernelcare) {
                if ($reboot_required) {
                    push @SUMMARY, "> KernelCare installed but running kernel version does not match boot version (contact provider):";
                    push @SUMMARY, expand( CYAN "\t \\_ Running Version: [ " . $running_kernelversion . " ]" );
                    push @SUMMARY, expand( CYAN "\t \\_ Boot Version: [ " . $boot_kernelversion . " ]" );
                }
            }
            else {
                push @RECOMMENDATIONS, "> Running kernel version does not match boot version (a reboot should be scheduled)";
                push @RECOMMENDATIONS, expand( CYAN "\t \\_ Running Version: [ " . $running_kernelversion . " ]" );
                push @RECOMMENDATIONS, expand( CYAN "\t \\_ Boot Version: [ " . $boot_kernelversion . " ]" );
            }
        }
    }
    else {      ## 102+
        my $KernelStatus = Cpanel::Kernel::Status::kernel_status();
        if ( $KernelStatus->{has_kernelcare} ) {
            if ( $KernelStatus->{running_version} ne $KernelStatus->{boot_version} ) {
                push @SUMMARY, "> KernelCare installed but running kernel version does not match boot version (contact provider):";
                push @SUMMARY, expand( CYAN "\t \\_ Running Version: [ " . $KernelStatus->{running_version} . " ]" );
                push @SUMMARY, expand( CYAN "\t \\_ Boot Version: [ " . $KernelStatus->{boot_version} . " ]" );
            }
        }
        else {
            if ( $KernelStatus->{reboot_required} ) {
                push @RECOMMENDATIONS, "> Running kernel version does not match boot version (a reboot is required)";
                push @RECOMMENDATIONS, expand( CYAN "\t \\_ Running Version: [ " . $KernelStatus->{running_version} . " ]" );
                push @RECOMMENDATIONS, expand( CYAN "\t \\_ Boot Version: [ " . $KernelStatus->{boot_version} . " ]" );
            }
        }
    }
}

sub check_logfiles {
    my $apachelogpath;
    #$apachelogpath = "/etc/apache2/logs";
    $apachelogpath = "/var/log/apache2";
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

sub check_history {
    if ( -e '/root/.bash_history' ) {
        if ( -l '/root/.bash_history' ) {
            my $result = Cpanel::SafeRun::Timed::timedsaferun( 0, 'ls', '-la', '/root/.bash_history' );
            push @SUMMARY, "> /root/.bash_history is a symlink, $result";
        }

        my $attr          = isImmutable("/root/.bash_history");
        my $lcisImmutable = "";
        if ($attr) {
            push @SUMMARY, "> /root/.bash_history is set to " . CYAN "[ IMMUTABLE ]";
        }
        if ( !-s '/root/.bash_history' and !-l '/root/.bash_history' ) {
            push @SUMMARY, "> /root/.bash_history is a 0 byte file";
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

sub check_2FA_enabled {
    my $resultJSON = get_whmapi1('twofactorauth_policy_status');
    if ( !$resultJSON->{data}->{is_enabled} ) {

        push @RECOMMENDATIONS,
"> Two-Factor Authentication Policy is disabled - Consider enabling this.";
        return;
    }
}

sub check_account_login_access {
    my $resultJSON =
      get_whmapi1( 'get_tweaksetting', 'key=account_login_access' );
    if ( $resultJSON->{data}->{tweaksetting}->{value} =~ m/owner|owner_root/ ) {
        push @RECOMMENDATIONS,
          "> Consider changing Accounts that can access cPanel user account to "
          . CYAN "cPanel User Only.";
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
            push( @SUMMARY, expand( CYAN "\t \\_ " . $_ ) );
            get_last_logins_WHM($_);
            get_session_logins($_ . ':');
            get_whm_terminal_logins($_);
            get_last_logins_SSH($_);
            check_secure_log($_);
            get_root_pass_changes($_);
        }
    }
}

sub check_for_TTY_shell_spawns {
    my $histline;
    foreach $histline (@HISTORY) {
        chomp($histline);
        if ( $histline =~
m/pty.spawn("\/bin\/sh")|pty.spawn\("\/bin\/bash"\)|os.system\('\/bin\/bash'\)|os.system\('\/bin\/sh'\)|\/bin\/sh -i|\/bin\/bash -i|cpuminer-gr-avx2/
          )
        {
            push( @SUMMARY,
"> Found evidence in /root/.bash_history of a possible TTY shell being spawned"
            );
            push( @SUMMARY, expand( "\t \\_ $histline\n" ) );
        }
    }
}

sub check_roots_history {
    my $histline;
    foreach $histline (@HISTORY) {
        chomp($histline);
        if ( $histline =~ m{/etc/cxs/uninstall.sh|rm -rf /etc/apache2/conf.d/modsec|bash /etc/csf/uninstall.sh|yum remove -y cpanel-clamav|remove bcm-agent|mdkri|unaem 0a|cd /ev/network/|unset HISTFILE|grep -c ^processor /proc/cpuinfo|/usr/bin/tactu_cpanel|wget http://www.curl.by|cbrute.tgz|cbrute}) {
            push( @SUMMARY,
                "> Suspicious entries found in /root/.bash_history" );
            push( @SUMMARY, expand( "\t\\_ $histline" ) );
        }
    }
}

sub check_processes {
    my $url = URI->new( 'https://raw.githubusercontent.com/CpanelInc/tech-CSI/master/suspicious_procs.txt');
    my $ua  = LWP::UserAgent->new( ssl_opts => { verify_hostname => 0 } );
    my $res = $ua->get($url);
    my $susp_procs  = $res->decoded_content;
    my @susp_procs  = split /\n/, $susp_procs;
    my $headerPrint = 0;
    foreach my $suspicious_process (@susp_procs) {
        chomp($suspicious_process);
        next if ( _ignore_susp_proc( $suspicious_process ) );
        foreach my $line(@process_list) {
            chomp($line);
            if ( $line =~ m/\b$suspicious_process\b/ ) {
                my ( $u, $p, $c ) = (split /\s+/, $line );
                my ( $a1,$a2,$a3,$a4,$a5,$a6,$a7 ) = (split( /\s+/, $line ))[3,4,5,6,7,8,9];
                my $a = $a1 . " " . $a2 . " " . $a3 . " " . $a4 . " " . $a5 . " " . $a6 . " " . $a7;
                push @SUMMARY, "> The following suspicious process was found (please verify)" unless ( $headerPrint == 1 );
                $headerPrint = 1;
                push @SUMMARY, CYAN expand( "\t\\_ Found suspicious process " . YELLOW $suspicious_process . CYAN " running" );
                push @SUMMARY, "\t\\_ " . MAGENTA "User: " . YELLOW $u . MAGENTA " / Pid: " . YELLOW $p . MAGENTA " / Command: " . YELLOW $c . MAGENTA " / Arguments: " . YELLOW $a;
                my $proclink = '/proc/' . $p . '/exe';
                if ( -l $proclink && readlink( $proclink ) ) {
                    push @SUMMARY, "\t\\_ " . YELLOW $proclink . " -> " . RED readlink($proclink) . CYAN "  - Checking this binary at VirusTotal.com";
                    vtlink(readlink( $proclink ));
                }
            }
        }
    }
    return;
}

sub _ignore_susp_proc {
    my $tcProc = shift;
    return 1 if ( $tcProc =~ m{log4j} && -e '/usr/bin/log4j-cve-2021-44228-hotpatch' );
    return 1 if ( $tcProc =~ m{log4j} && -d '/home/cpanelsolr/server/lib/ext/' );
    return 0;
}

sub bitcoin_chk {
    my @cronlist = glob(q{ /var/spool/cron/* /var/spool/cron/crontabs/* });
    my $xmrig_cron;
    foreach my $cronfile (@cronlist) {
        chomp($cronfile);
        $xmrig_cron =
          Cpanel::SafeRun::Timed::timedsaferun( 0, 'grep', '-srl', '.xmr',
            $cronfile );
        chomp($xmrig_cron);
        if ($xmrig_cron) {
            push @SUMMARY, "> Found suspicious data in: "
              . CYAN $xmrig_cron;
        }
    }
    my $xm2sg_socket = Cpanel::SafeRun::Timed::timedsaferun( 0, 'netstat', '-plant' );
    my @xm2sg_socket = split /\n/, $xm2sg_socket;
    if ( grep { /xm2sg/ } @xm2sg_socket ) {
        push @SUMMARY,
          "> Found evidence of possible bitcoin miner via "
          . CYAN "netstat -plant | grep 'xm2sg'";
    }
}

sub get_process_list {
    my $continue = has_ps_command();
    return unless ($continue);
    return split /\n/,
      Cpanel::SafeRun::Timed::timedsaferun( 0, 'ps', '--no-header', '--width=1000', 'axwwwf', '-o', 'user,pid,args' );
}

sub check_ssh {
    my @ssh_errors;
    my $ssh_verify;
    my $keyutils_verify;
    my $name;
    return unless my $rpms = get_rpm_href();
    my @openssh_pkgs = grep { /^openssh*/ } keys(%{$rpms} );
    my @keyutillibs_pkgs = grep { /^(libkeyutils1|keyutils-libs)/ } keys(%{$rpms} );
    foreach my $rpm (@openssh_pkgs) {
        chomp($rpm);
        $ssh_verify = Cpanel::SafeRun::Timed::timedsaferun( 0, 'dpkg', '--verify', $rpm ) unless( $distro ne 'ubuntu' );
        $ssh_verify = Cpanel::SafeRun::Timed::timedsaferun( 0, 'rpm', '--verify', $rpm ) unless( $distro eq 'ubuntu' );
        my @ssh_verify = split /\n/, $ssh_verify;
        my $showHeader = 0;
        foreach my $ssh_verify( @ssh_verify ) {
            next if( grep { m{ssh_config|sshd_config|pam.d|/usr/libexec/openssh/ssh-keysign|/usr/bin/ssh-agent|.build-id} } $ssh_verify );
            push( @ssh_errors, MAGENTA "RPM verification on $rpm failed for the following:" ) unless( $showHeader );;
            $showHeader = 1;
            push( @ssh_errors, expand( $ssh_verify ) ) unless( $distro eq 'ubuntu');
        }
    }
    foreach my $rpm (@keyutillibs_pkgs) {
        chomp($rpm);
        $keyutils_verify = Cpanel::SafeRun::Timed::timedsaferun( 0, 'dpkg', '--verify', $rpm ) unless( $distro ne 'ubuntu' );
        $keyutils_verify = Cpanel::SafeRun::Timed::timedsaferun( 0, 'rpm', '--verify', $rpm ) unless( $distro eq 'ubuntu' );
        my @keyutils_verify = split /\n/, $keyutils_verify;
        my $showHeader = 0;
        foreach my $keyutils_verify( @keyutils_verify ) {
            next if( grep { m{.build-id} } $keyutils_verify );
            push( @ssh_errors, " RPM verification on keyutils-libs failed:\n" ) unless( $showHeader );
            $showHeader = 1;
            push( @ssh_errors, " $keyutils_verify" ) unless( $distro eq 'ubuntu');
            if ( -e '/var/log/prelink/prelink.log' ) {
                push( @SUMMARY, "Note: /var/log/prelink/prelink.log file found. Might be OK if the keyutils-libs RPM was prelinked.");
                push( @SUMMARY, "If in doubt, this should be thoroughly checked by a security professional.");
            }
        }
    }
    my $sshd_process_found = 0;
    for my $process (@process_list) {
        next unless( $process =~ m{sshd: root@} );
        next unless( ! $process =~ m{pts|priv} );
        push( @ssh_errors, " Suspicious SSH process(es) found [could be sftpd which would be OK]:");
    }

    my @SSHRPMs;
    @SSHRPMs = qw( openssh-server openssh-client ) unless( $distro ne 'ubuntu' );
    @SSHRPMs = qw( openssh-server openssh-clients openssh ) unless( $distro eq 'ubuntu' );
    my $SSHRPM;
    my $ssh_error_cnt = 0;
    my ( $rpmVendor, $rpmBuildHost, $rpmSignature );
    foreach $SSHRPM (@SSHRPMs) {
        if ( $distro eq "ubuntu" ) {
            for my $name ( keys %{$rpms} ) {
                foreach my $rpm_ref ( @{ $rpms->{$name} } ) {
                    next unless( $name eq $SSHRPM );
                    $ssh_error_cnt++ unless ( $rpm_ref->{maintainer} =~ (m/ubuntu|Ubuntu Developers/) );
                    $ssh_error_cnt++ if ( $rpm_ref->{maintainer} =~ (m/none/) );
                }
            }
            # dpkg-query on Ubuntu does not store Build Host
            # Signature
            open( my $fh, "<", "/varlib/dpkg/info/$SSHRPM.md5sums" );
            while (<$fh>) {
                next unless ( $_ =~ m/\/bin\// );
                my ( $md5hash, $filename1 ) = ( split( /\s+/, $_ ) );
                my $filename = "/" . $filename1;
                my ($md5syshash) = ( split( /\s+/, Cpanel::SafeRun::Timed::timedsaferun( 2, 'md5sum', $filename ) ) )[0];
                next unless ( $md5syshash ne $md5hash );
                $ssh_error_cnt++;
            }
        }
        else {    ## CentOS/CloudLinux/AlmaLinux
            # Vendor/Maintainer, Build Host, Signature
            my $rpmInfo = Cpanel::SafeRun::Timed::timedsaferun( 0, 'rpm', '-qi', $SSHRPM );
            my @rpmInfo = split /\n/, $rpmInfo;
            foreach my $rpmLine(@rpmInfo) {
                chomp($rpmLine);
                next unless( $rpmLine =~ m{Vendor|Build Host|Signature} );
                $rpmVendor = $rpmLine if( $rpmLine =~ m/Vendor/ );
                $rpmBuildHost = $rpmLine if( $rpmLine =~ m/Build Host/ );
                $rpmSignature = $rpmLine if( $rpmLine =~ m/Signature/ );
            }
            $ssh_error_cnt++ unless ( $rpmVendor =~ (m/CloudLinux|AlmaLinux|CentOS|Red Hat, Inc.|Rocky/) );
            $ssh_error_cnt++ if ( $rpmVendor =~ (m/none/) );
            $ssh_error_cnt++ unless ( $rpmBuildHost =~ ( m/cloudlinux.com|buildfarm0|centos.org|redhat.com|rockylinux.org|almalinux.org/));
            $ssh_error_cnt++ if ( $rpmBuildHost =~ (m/none/) );
            $ssh_error_cnt++ unless ( $rpmSignature =~ ( m/24c6a8a7f4a80eb5|8c55a6628608cb71|199e2f91fd431d51|51d6647ec21ad6ea|15af5dac6d745a60|d36cb86cb86b3716|702d426d350d275d|2ae81e8aced7258b/));
            $ssh_error_cnt++ if ( $rpmSignature =~ (m/none/) );
        }
    }
    if ( $ssh_error_cnt > 3 ) {
        push( @ssh_errors, "Either the Vendor, Build Host, or Signature for one of the openssh RPM's does not match a known and suspected value");
        push( @ssh_errors, expand( MAGENTA "Check by running: " . WHITE "rpm -qi openssh-server openssh-clients openssh | egrep 'Vendor|Build Host|Signature'"));
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
            my $dumped = Cpanel::SafeRun::Timed::timedsaferun( 0, 'apt-cache', 'dump' );
            @dumped = split /\n/, $dumped;
        }
        foreach $filename (@DirFiles) {
            next if $filename eq "." or $filename eq "..";
            lstat "$dir/$filename";
            next if -d "$dir/$filename" or -l "$dir/$filename";
            my $isELF = check_file_for_elf("$dir/$filename");
            next unless( $isELF );
            if ( $distro eq "ubuntu" ) {
                $notOwned = grep { /$filename/ } @dumped;
                if ( !$notOwned ) {
                    push @notOwned, "$dir/$filename";
                }
            }
            else {
                $notOwned = Cpanel::SafeRun::Timed::timedsaferun( 0, 'rpm', '-qf', "$dir/$filename" );
                next unless( $notOwned =~ m/not owned/ );
                push @notOwned, "$dir/$filename";
            }
        }
    }
    my $rpmcnt = @notOwned;
    if ( $rpmcnt > 0 ) {
        push @SUMMARY, "> Found library files that are not owned by any package manager";
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

sub get_ipcs_hash ($) {
    my ($href) = @_;
    my $header = 0;
    for ( split /\n/,
        Cpanel::SafeRun::Timed::timedsaferun( 0, 'ipcs', '-m', '-p' ) )
    {
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
    my $preload_env = Cpanel::SafeRun::Timed::timedsaferun( 5, 'strings', "/proc/$$/environ | grep _PRELOAD" );
    push( @SUMMARY, "> Found _PRELOAD within the environment - Possible root-level compromise.") if( $preload_env );
    return unless ( -e ("/etc/ld.so.preload") );
    my $libcrypt_so = Cpanel::SafeRun::Timed::timedsaferun( 5, 'grep', '/usr/lib64/libcrypt.so.1.1.0', '/etc/ld.so.preload' );
    my $libconv_so = Cpanel::SafeRun::Timed::timedsaferun( 5, 'grep', 'libconv.so', '/etc/ld.so.preload' );
    my $libs_so = Cpanel::SafeRun::Timed::timedsaferun( 5, 'grep', '/lib64/libs.so', '/etc/ld.so.preload' );
    my $libprochider_so = Cpanel::SafeRun::Timed::timedsaferun( 5, 'grep', 'libprocesshider', '/etc/ld.so.preload' );
    my $injectorso = Cpanel::SafeRun::Timed::timedsaferun( 5, 'grep', '/opt/injector.so', '/etc/ld.so.preload' );
    my $libcext_so_2 = Cpanel::SafeRun::Timed::timedsaferun( 5, 'grep', '/lib*/libcext.so.2', '/etc/ld.so.preload' );
    push( @SUMMARY, "> Found /usr/lib64/libcrypt.so.1.1.0 in /etc/ld.so.preload - Possible root-level compromise.") if( $libcrypt_so );
    push( @SUMMARY, "> Found libconv.so in /etc/ld.so.preload - Possible root-level compromise.") if( $libconv_so );
    push( @SUMMARY, "> Found /lib64/libs.so in /etc/ld.so.preload - Possible root-level compromise.") if( $libs_so );
    push( @SUMMARY, "> Found a libprocesshider.so in /etc/ld.so.preload - Possible root-level compromise.\n\t\\_ ps output and lsof output may not be conclusive.") if( $libprochider_so );
    push( @SUMMARY, "> Found /opt/injector.so in /etc/ld.so.preload - Possible root-level compromise.") if( $injectorso );
}

sub create_summary {
    open( my $CSISUMMARY, '>', "$csidir/summary.txt" ) or die("Cannot create CSI summary file $csidir/summary.txt: $!\n");
    if (@SUMMARY) {
        print $CSISUMMARY BOLD RED "\nWARNINGS\n";
        print $CSISUMMARY "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
        foreach (@SUMMARY) {
            print $CSISUMMARY $_, "\n";
        }
    }
    else {
        print $CSISUMMARY BOLD GREEN "> Congratulations, no negative items found!\n\n";
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
        print BOLD GREEN "> Congratulations, no negative items found!\n\n" unless( $cron );
    }

    create_summary();
    if (@SUMMARY) {
        # Can't recall what this Uniq is for... Removing for now, if it causes an issue I'll address it then.
        # Right now, it is interfering with the cve checks.
#        my @UniqSummary = uniq(@SUMMARY);
#        @SUMMARY = @UniqSummary;
        print_warn('The following negative items were found:');
        foreach (@SUMMARY) {
            print BOLD YELLOW $_ . "\n" unless( $cron );
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
            print BOLD YELLOW $_ . "\n" unless( $cron );
        }
    }
    print_separator(
'=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-='
    );
    if (@RECOMMENDATIONS) {
        print_recommendations(
            'You should consider making the following recommendations:');
        foreach (@RECOMMENDATIONS) {
            print BOLD YELLOW $_ . "\n" unless( $cron );
        }
    }
}

sub print_normal {
    my $text = shift;
    print "$text\n" unless( $cron );
}

sub print_normal_chomped {
    my $text = shift;
    print "$text" unless( $cron );
}

sub print_separator {
    my $text = shift;
    print BOLD BLUE "$text\n" unless( $cron );
}

sub print_header {
    my $text = shift;
    print BOLD CYAN "$text\n" unless( $cron );
}

sub print_status {
    my $text = shift;
    print YELLOW "$text\n" unless( $cron );
}

sub print_summary {
    my $text = shift;
    print BOLD YELLOW "$text\n" unless( $cron );
}

sub print_info {
    my $text = shift;
    print BOLD CYAN "[INFORMATIONAL]: $text\n" unless( $cron );
}

sub print_warn {
    my $text = shift;
    print BOLD RED "[WARNING]: $text\n" unless( $cron );
}

sub print_recommendations {
    my $text = shift;
    print BOLD GREEN "[RECOMMENDATIONS]: $text\n" unless( $cron );
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

sub check_for_evasive_libkey {
    my $EvasiveLibKey = Cpanel::SafeRun::Timed::timedsaferun( 3, 'strings', '/etc/ld.so.cache' );
    if ( grep { /\/tls/ } $EvasiveLibKey ) {
        push( @SUMMARY, "> [Possible Rootkit: Ebury/Libkeys] - " . CYAN "Hidden/Evasive evidence of Ebury/Libkeys Rootkit found.\n\t \\_ TECH-759");
    }
}

sub check_for_unowned_libkeyutils_files {
    return if !$LIBKEYUTILS_FILES_REF;
    my @unowned_libs;
    for my $lib (@$LIBKEYUTILS_FILES_REF) {
        chomp( my $rpm_check =
              Cpanel::SafeRun::Timed::timedsaferun( 0, 'rpm', '-qf', "$lib" ) );
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
            push( @SUMMARY, expand( CYAN "\t\\_ $unowned_lib is not owned by any RPM" ) );
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
    my $ssh_version = timed_run( 0, $ssh, '-V' );
    return if $ssh_version !~ m{ \A OpenSSH_5 }xms;
    my $ssh_G = timed_run( 0, $ssh, '-G' );

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

sub check_for_glutton_php {
    return unless my $netstat_out = Cpanel::SafeRun::Timed::timedsaferun( 0, 'netstat', '-upnl' );
    for my $line ( split( '\n', $netstat_out ) ) {
        if ( $line =~ m{php-fpm} ) {
            push( @SUMMARY, "> [Possible Glutton PHP Backdoor] - " . CYAN "php-fpm running on udp port: " . $line );
            last;
        }
    }
    return unless my $netstat_out = Cpanel::SafeRun::Timed::timedsaferun( 0, 'netstat', '-pnu' );
    for my $line ( split( '\n', $netstat_out ) ) {
        if ( $line =~ m{kworker} ) {
            push( @SUMMARY, "> [Possible Glutton PHP Backdoor] - " . CYAN "kworker process ESTABLISHED on udp port: " . $line );
            last;
        }
    }
}

sub check_for_melofee {
    return unless my $netstat_out = Cpanel::SafeRun::Timed::timedsaferun( 0, 'netstat', '-tpn' );
    for my $line ( split( '\n', $netstat_out ) ) {
        if ( $line =~ m{kworkerx} ) {
            push( @SUMMARY, "> [Possible Rootkit: Melofee] - " . CYAN "kworkerx kernel driver found: " . $line );
            last;
        }
    }
}

sub check_for_ebury_socket {
    return unless my $netstat_out = Cpanel::SafeRun::Timed::timedsaferun( 0, 'netstat', '-nap' );
    for my $line ( split( '\n', $netstat_out ) ) {
        if ( $line =~ m{@/proc/udevd|@/run/systemd/log} ) {
            push( @SUMMARY, "> [Possible Rootkit: Ebury] - " . CYAN "Ebury socket connection found: " . $line );
            last;
        }
    }
}

sub check_for_ngioweb {
    return if ( !-e "/etc/machine-id" );
    return unless (Cpanel::SafeRun::Timed::timedsaferun( 3, 'grep', 'ddb0b49d10ec42c38b1093b8ce9ad12a', '/etc/machine-id' ) );
    push( @SUMMARY, "Found evidence of Linux.Ngioweb Rootkit\n\t\\_ /etc/machine-id contains: ddb0b49d10ec42c38b1093b8ce9ad12a");
}

sub check_for_hiddenwasp {
    if ( -e ("/lib/libselinux.a") ) {
        my $HideShell = Cpanel::SafeRun::Timed::timedsaferun( 3, 'strings', '/lib/libselinux.a' );
        if ( grep { /HIDE_THIS_SHELL/ } $HideShell ) {
            push @SUMMARY, "> Found HIDE_THIS_SHELL in the /lib/libselinux.a file. Could indicate HiddenWasp Rootkit";
        }
    }
    # Check for specific TCP ports
    my @ports = qw( tcp:61091 tcp:65130 tcp:65439 tcp:1234 tcp:25905 tcp:8816 tcp:4444 tcp:6667 tcp:5822);
    foreach my $port (@ports) {
        chomp($port);
        my $lsof = Cpanel::SafeRun::Timed::timedsaferun( 4, 'lsof', '-i', $port );
        push @SUMMARY, "> Found socket listening on port $port. Could indicate possible root compromise" if( $lsof );
    }
}

sub check_for_fritzfrog {
    my $lsof = Cpanel::SafeRun::Timed::timedsaferun( 0, 'lsof' );
    my @lsof = split /\n/, $lsof;
    foreach $lsof(@lsof) {
        chomp($lsof);
        next unless( $lsof =~ m/^(nginx|ifconfig|php-fpm|apache2|libexec)'/ );
        next unless( $lsof =~ m/deleted/ );
        my ( $binary, $pid, $user ) = (split( /\s+/, $lsof));
        next unless( $user eq 'root' );
        push @SUMMARY, "> Found possible FritzFrog malware. $binary running on pid $pid";
    }
}

sub check_for_log4JShell_attempts {
    my @logs2chk;
    my $regexp = '\$?\{jndi:(ldap|ldaps|rmi|dns):\/[\/]?[a-z-\.0-9].*|\${jndi:\${lower:l}\${lower:d}\${lower:a}\${lower:p}:\/[\/]?[a-z-\.0-9].*|\${jndi:\${lower:l}\${lower:d}a\${lower:p}:\/[\/]?[a-z-\.0-9].*';
    @logs2chk = glob( q{ /var/log/nginx/domains/*_log });
    push @logs2chk, '/var/log/apache2/access_log';
    push @logs2chk, '/var/log/apache2/error_log';
    push @logs2chk, '/usr/local/cpanel/logs/access_log';
    push @logs2chk, '/usr/local/cpanel/logs/login_log';
    push @logs2chk, '/usr/local/cpanel/logs/session_log';
    my $showHeader=0;
    my $lastlogfile = "";
    foreach my $logfile(@logs2chk) {
        open( my $fh, '<', $logfile ) or next;
        while( <$fh> ) {
            chomp;
            if ( $_ =~ m/$regexp/gmi ) {
                push @INFO, "> Found attempts of old Log4JShell hacks in the following log file(s). Should be checked but might be false-positives." unless( $showHeader );
                $showHeader=1;
                push @INFO, CYAN "\t\\_ $logfile contains " . MAGENTA "\${jndi:ldap " . GREEN "( Check with " . WHITE "grep '\${jndi:ldap' $logfile" . GREEN " )" unless( $logfile eq $lastlogfile );
                $lastlogfile = $logfile;
            }
        }
        close ( $fh );
    }
}

sub check_for_dirtycow_passwd {
    print_header("[ Checking for evidence of DirtyCow within /etc/passwd ]");
    return unless my $gecos = ( getpwuid(0) )[6];
    if ( $gecos eq "pwned" ) {
        push( @SUMMARY,
            "> [DirtyCow] - Evidence of FireFart/DirtyCow compromise found." );
        push( @SUMMARY,
            expand( CYAN
"\t \\_ Run: getent passwd 0 and notice the 5th field says 'pwned'"
        ) );
        my $HasPwnd =
          Cpanel::SafeRun::Timed::timedsaferun( 4, 'getent passwd 0' );
        chomp($HasPwnd);
        push( @SUMMARY, expand( MAGENTA "\t \\_ $HasPwnd" ) );
    }
    opendir my $dh, "/tmp";
    my @tmpdirfiles = readdir($dh);
    closedir $dh;
    foreach my $tmpfile(@tmpdirfiles) {
        next unless( $tmpfile =~ m/passwd/ );
        my $passwdBAK = Cpanel::SafeRun::Timed::timedsaferun( 4, 'stat', '-c', "%n [Owned by %U]", "/tmp/$tmpfile" );
        my @passwdBAK = split /\n/, $passwdBAK;
        my $passwdBAKcnt = @passwdBAK;
        my $passwdBAK;
        if ( $passwdBAKcnt > 0 ) {
            push( @SUMMARY, MAGENTA "> Possible backup of /etc/passwd found (could indicate root comp):" );
            foreach $passwdBAK (@passwdBAK) {
                chomp($passwdBAK);
                push( @SUMMARY, expand( CYAN "\t\\_ " . $passwdBAK ) );
            }
        }
    }
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
        my $SuckItStrings = Cpanel::SafeRun::Timed::timedsaferun( 3, 'strings', '-a', '/sbin/init' );
        if ( grep { m{HOME=[a-zA-Z0-9]|fuck|backdoor|bin/rcpc|bin/login}i } $SuckItStrings ) {
            $SuckItCount++;
        }
    }
    my $procMaps = Cpanel::SafeRun::Timed::timedsaferun( 4, 'cat', '/proc/1/maps' );
    if ( grep { m{init\.}i } $procMaps ) {
        $SuckItCount++;
    }
    my $initSymLink    = Cpanel::SafeRun::Timed::timedsaferun( 2, 'ls', '-li', '/sbin/init' );
    my $telinitSymLink = Cpanel::SafeRun::Timed::timedsaferun( 2, 'ls', '-li', '/sbin/telinit' );
    my ( $SLInode1, $isLink1 ) = ( split( /\s+/, $initSymLink ) )[ 0, 1 ];
    my ( $SLInode2, $isLink2 ) = ( split( /\s+/, $telinitSymLink ) )[ 0, 1 ];
    if ( $SLInode1 == $SLInode2 and substr( $isLink1, 0, 1 ) ne "l" or substr( $isLink2, 0, 1 ) ne "l" ) {
        $SuckItCount++;
    }
    my $SuckItHidden = Cpanel::SafeRun::Timed::timedsaferun( 2, 'touch', "$csidir/suckittest.mem", "$csidir/suckittest.xrk" );
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
    if ( -e "$csidir/suckittest.mem" ) { unlink("$csidir/suckittest.mem"); }
    if ( -e "$csidir/suckittest.xrk" ) { unlink("$csidir/suckittest.xrk"); }
}

sub check_authorized_keys_file {
    my $keysfile = '/root/.ssh/authorized_keys';
    open( my $fh, '<', $keysfile ) or return;
    while( <$fh> ) {
        chomp( $_ );
        if ( $_ =~ m/REDIS0006 crackitA/ ) {
            push( @SUMMARY, "> [Possible Rootkit: Redis Hack] - " . CYAN "Evidence of the Redis Hack compromise found in /root/.ssh/authorized_keys.");
        }
        if ( $_ =~ m/rbdYSfTEtykGg/ ) {
            push( @SUMMARY, "> [Possible Rootkit] - " . CYAN "Suspicious string [rbdYSfTEtykGg] found within /root/.ssh/authorized_keys.");
        }
        if ( $_ eq "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDSEuS/A5HLzAwCbs+fqxCv1rLZ+x4vCdzcfLppJuCHnD2EO58W4aNDxtn2IBooyr4zylBJrNa64nQ3L7MvxckQMMLWkN6owZPtJs7+BPIsljX+Kz0svqGHDYk5KyQQ+O/uWVUU96X4NkyE4BxeQnH6jCYw2FCcnudsS5GLseBUozQvQlQEErRq3ma3skzZGB4kOq6He7ksaEUFjzgyfAQHzr1hPX5KJ/du4z7fX0KqUphK4AXbPL4Pqkusw4PeQLDjZGO8hRkDMVjnaPNliAS2pV9Guw+L7SLvXGHsz1Q+tT54JaSHkJoN6a0lJ/L3IehVTi/ZLLh4GgZ1WpWH7EqL" ) {
            push( @SUMMARY, "> Possible Ebury Rootkit: - " . CYAN "Suspicious ssh-rsa key found in /root/.ssh/authorized_keys file.");
        }
        if ( $_ eq "AAAAB3NzaC1yc2EAAAADAQABAAACAQC/yU0iqklqw6etPlUon4mZzxslFWq8G8sRyluQMD3i8tpQWT2cX/mwGgSRCz7HMLyxt87olYIPemTIRBiyqk8SLD3ijQpfZwQ9vsHc47hdTBfj89FeHJGGm1KpWg8lrXeMW+5jIXTFmEFhbJ18wc25Dcds4QCM0DvZGr/Pg4+kqJ0gLyqYmB2fdNzBcU05QhhWW6tSuYcXcyAz8Cp73JmN6TcPuVqHeFYDg05KweYqTqThFFHbdxdqqrWy6fNt8q/cgI30NBa5W2LyZ4b1v6324IEJuxImARIxTc96Igaf30LUza8kbZyc3bewY6IsFUN1PjQJcJi0ubVLyWyyJ554Tv8BBfPdY4jqCr4PzaJ2Rc1JFJYUSVVT4yX2p7L6iRpW212eZmqLMSoR5a2a/tO2s1giIlb+0EHtFWc2QH7yz/ZBjnun7opIoslLVvYJ9cxMoLeLr5Ig+zny+IEA3x090xtcL62X0jea6btVnYo7UN2BARziisZze6oVuOTCBijuyvOM6ROZ6s/wl4CQAOSLDeFIP5L1paP9V1XLaYLDBAodNaUPFfTxggH3tZrnnU8Dge5/1JNa08F3WNUPM1S1x8L2HMatwc82x35jXyBSp3AMbdxMPhvyYI8v2J1PqJH8OqGTVjdWe40mD2osRgLo1EOfP/SFBTD5VEo95K2ZLQ==" ) {
            push( @SUMMARY, "> Possible Ebury Rootkit: - " . CYAN "Suspicious ssh-rsa key found in /root/.ssh/authorized_keys file.");
        }
        if ( $_ eq "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzml2PeIHOUG+78TIk0lQcR5JC/mlDElDtplEfq8KDiJFwD8z9Shhk2kG0pwzw9uUr7R24h8lnh9DWpiKfoy4MeMFrTO8akT1hXf4yn9IEEHdiq9hVz1ZkEnUdjyzuvXGIOcRe2FqQaovFY15gSDZzJc5K6NMT8uW1aitHAsYXZDW8uh+/SJAqcCCVUtVnZRj4nlhQxW2810CJGQQrixkkww7F/9XRlddH3HkNuRlZLQMk5oGHTxeySKKfqoAoXgZXac9VBAPRUU+0PrBrOSWlXFbGBPJSdvDfxBqcg4hguacD1EW0/5ORR7Ikp1i6y+gIpdydwxW51yAqrYqHI5iD" ) {
            push( @SUMMARY, "> [Possible Rootkit] - " . CYAN "Suspicious ssh-rsa key found within /root/.ssh/authorized_keys.");
        }
        if ( $_ =~ m/ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC\/2CmHl\/eiVchVmng4TEPAx0n0\+6R0Rb\/W\+zlwCR\+\/g3MHqsiadebQx4/ ) {
            push( @SUMMARY, "> [Possible p2pinfect Rootkit] - " . CYAN "Suspicious ssh-key found within /root/.ssh/authorized_keys.");
        }
        if ( $_ =~ m/AAAAB3NzaC1yc2EAAAADAQABAAABgQDtlkWJzOwt6Erl3lDRq\+QUSop854X\/tC9BcU0bBk\+5qLvPAU\/FIsQmIPGjW5xNa/ ) {
            push( @SUMMARY, "> [NoaBot SSH key detected] - " . CYAN "Suspicious ssh-key found within /root/.ssh/authorized_keys.");
        }
        if ( $_ =~ m/AAAAB3NzaC1yc2EAAAABJQAAAQEAoBjnno5GBoIuIYIhrJsQxF6OPHtAbOUIEFB\+gdfb1tUTjs\+f9zCMGkmNmH45fYVukw6IwmhTZ/ ) {
            push( @SUMMARY, "> [Mexals SSH key detected] - " . CYAN "Suspicious ssh-key found within /root/.ssh/authorized_keys.");
        }
        if ( $_ =~ m/ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuhPmv3xdhU7JbMoc\/ecBTDxiGqFNKbe564p4aNT6JbYWjNwZ5z6E4iQQDQ0bEp7uBtB0/ ) {
            push( @SUMMARY, "> [dhcpd cryptominer SSH key detected] - " . CYAN "Suspicious ssh-key found within /root/.ssh/authorized_keys.");
        }
        if ( $_ =~ m/MIIJrTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI8vKBZRGKsHoCAggA|MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAECBBBC3juWsJ7DsDd2wH2XI+vUBIIJ|UCQ2viiVV8pk3QSUOiwionAoe4j4cBP3Ly4TQmpbLge9zRfYEUVe4LmlytlidI7H|O+bWbjqkvRXT9g\/SELQofRrjw\/W2ZqXuWUjhuI9Ruq0qYKxCgG2DR3AcqlmOv54g/ ) {
            push( @SUMMARY, "> [Outlaw cryptominer SSH key detected] - " . CYAN "Suspicious ssh-key found within /root/.ssh/authorized_keys.");
        }
    }
    close($fh);
}

sub check_for_linux_lady {
    my $lsof = Cpanel::SafeRun::Timed::timedsaferun( 2, 'lsof', '-i', 'tcp:6379' );
    my @lsof = split /\n/, $lsof;
    foreach $lsof(@lsof) {
        chomp($lsof);
        my ( $comm, $pid, $user ) = (split( /\s+/, $lsof));
        next unless( $user eq 'root' );
        push @SUMMARY, "> Found socket listening on port 6379 (Redis server?). Running as root - " . RED "VERY DANGEROUS!" . expand( CYAN "\n\t\\_[ Could indicate LinuxLady rootkit ]" );
        last;
    }
}

sub check_for_twink {
    my $lsof = Cpanel::SafeRun::Timed::timedsaferun( 2, 'lsof', '-i', 'tcp:322' );
    return unless( $lsof );
    my $roots_crontab = Cpanel::SafeRun::Timed::timedsaferun( 3, 'crontab', '-l', '-u', 'root' );
    my @roots_crontab = split /\n/, $roots_crontab;
    foreach my $line(@roots_crontab) {
        if ( $line =~ m{/tmp/twink} ) {
            push @SUMMARY, "> Found sshd listening on " . CYAN "port 322" . YELLOW " and " . RED "/tmp/twink" . YELLOW " in roots crontab. Indicates a possible rootkit";
            last;
        }
    }
}

sub check_for_libkeyutils_symbols {
    local $ENV{'LD_DEBUG'} = 'symbols';
    my $output = timed_run( 0, '/bin/true' );
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
    check_for_linux_lady();
    check_for_twink();
    check_for_cronRAT();
    check_for_ncom_rootkit();
    check_env_for_susp_vars();
    check_for_perfcc();
    check_for_xbash();
    check_for_cdorked_A();
    check_for_cdorked_B();
    check_for_suckit();
    check_authorized_keys_file();
    check_for_libkeyutils_symbols();
    check_for_unowned_libkeyutils_files();
    check_for_evasive_libkey();
    check_for_ebury_ssh_G();
    check_for_ebury_ssh_shmem();
    check_for_melofee();
    check_for_glutton_php();
    check_for_ebury_socket();
    check_for_dragnet();
    check_for_exim_vuln();
    check_for_hiddenwasp();
    check_for_fritzfrog();
    check_for_ngioweb();
    check_for_dirtycow_passwd();
    check_for_lilocked_ransomware();
    check_for_filenew_ransomware();
    check_for_sedexp();
    check_for_junglesec();
    check_for_panchan();
    check_for_chaos();
}

sub get_httpd_path {
    if ( -x '/usr/sbin/httpd' ) {
        return '/usr/sbin/httpd';
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
    if ( ! -d "$csidir" ) {
        mkdir( "$csidir", 0755 );
    }
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
    my $lcUserToScan = shift;
    my $RealHome     = Cpanel::PwCache::gethomedir($lcUserToScan);
    if ( !( -e ("$RealHome") ) ) {
        print_warn("$lcUserToScan has no /home directory!");
        logit( $lcUserToScan . " has no /home directory!" );
        return;
    }
    my $pubhtml = "public_html";
    if ($customdir) {
        if ( -e "$RealHome/$customdir" ) {
            $pubhtml = $customdir;
        }
    }
    print_status(
        "Checking $RealHome/$pubhtml for symlinks to other locations...");
    logit( "Checking for symlink hacks in " . $RealHome . "/" . $pubhtml );
    my @symlinks;
    my @conffiles =
      qw( functions.php confic.php db.php wp-config.php configuration.php conf_global.php Settings.php config.php settings.php settings.inc.php submitticket.php );
    my $conffile;
    my $headerprinted = 0;
    my $hp1           = 0;
    my $hp2           = 0;

    foreach $conffile (@conffiles) {
        chomp($conffile);
        my $findit = Cpanel::SafeRun::Timed::timedsaferun( 0, 'find', "$RealHome/$pubhtml", '-type', 'l', '-lname', "$HOMEDIR/*/$pubhtml/$conffile", '-ls' );
        push @symlinks, $findit unless( ! $findit );
    }
    my $headerprinted = 0;
    my $hp1           = 0;
    my $hp2           = 0;
    foreach my $symlink (@symlinks) {
        my ( $symUID, $symGID, $link, $pointer, $realpath ) = ( split( /\s+/, $symlink ) )[ 5, 6, 11, 12, 13 ];
        my ( $SLfilename, $SLdir ) = fileparse($link);
        next if ( $SLdir =~ m{/home/virtfs} );
        push @SUMMARY, YELLOW "> Found symlink hacks under $SLdir" unless ($headerprinted);
        $headerprinted = 1;
        my $fStat = stat($realpath);
        if ( -e _ ) {
            if ( $symUID eq "root" or $symGID eq "root" ) {
                if ( $hp1 == 0 ) {
                    push( @SUMMARY, expand( CYAN "\t\\_ root owned symlinks " . BOLD RED "(should be considered root compromised!): ") );
                    $hp1 = 1;
                }
                push( @SUMMARY, expand( "\t\t\\_ " . MAGENTA $link . " " . $pointer . " " . $realpath) );
            }
            else {
                if ( $hp2 == 0 ) {
                    push( @SUMMARY, expand( CYAN "\t\\_ User owned ($symUID) symlinks: " ) );
                    $hp2 = 1;
                }
                push( @SUMMARY, expand( "\t\t\\_ " . MAGENTA $link . " " . $pointer . " " . $realpath) );
            }
        }
    }

    # Check users crontab for suspicious entries.
    my @susp_cron_strings;
    my $susp_crons_ref = get_suspicious_cron_strings();
    push @susp_cron_strings, @$susp_crons_ref;
    print_status( "Checking crontab for user: $lcUserToScan" );
    my $usercrontab = Cpanel::SafeRun::Errors::saferunnoerror( 3, 'crontab', '-l', '-u', "$lcUserToScan" );
    my @usercrontab = split /\n/, $usercrontab;
    foreach my $susp_cron_string (@susp_cron_strings) {
        chomp($susp_cron_string);
        foreach my $crontab_line (@usercrontab) {
            chomp($crontab_line);
            next unless( $crontab_line =~ m{$susp_cron_string} );
            my $isCommented = ( substr( $crontab_line,0,1) eq "#" ) ? 1 : 0;
            my ($cmd) = (split( /\s+/, $crontab_line))[5];
            push @SUMMARY, "> $lcUserToScan crontab contains a suspicious entry that should be investigated";
            push @SUMMARY, expand( CYAN "\t\\_ $cmd" );
            push @SUMMARY, expand( BLUE "\t\\_ Might be commented out." ) if ( $isCommented );
        }
    }
    # check users .bashrc file - CX-590
    if ( -s "$HOMEDIR/$lcUserToScan/.bashrc" ) {
        my @usersbashrc = Cpanel::SafeRun::Timed::timedsaferun(2, 'cat', "$HOMEDIR/$lcUserToScan/.bashrc" );
        foreach my $susp_cron_string (@susp_cron_strings) {
            chomp($susp_cron_string);
            if ( grep { /$susp_cron_string/ } @usersbashrc ) {
                push @SUMMARY, "> Suspicious entry found within users .bashrc file [ $HOMEDIR/$lcUserToScan/.bashrc ]";
            }
        }
    }

    # Check for shadow.roottn.bak hack variants
    print_status("Checking for shadow.roottn.bak hack variants...");
    my $shadow_roottn_baks = Cpanel::SafeRun::Timed::timedsaferun( 0, 'find', "$RealHome/etc", '-name', 'shadow\.*', '-print' ) unless ( !-d "$RealHome/etc" );
    if ($shadow_roottn_baks) {
        my @shadow_roottn_baks = split "\n", $shadow_roottn_baks;
        my $showHeader=0;
        foreach $shadow_roottn_baks (@shadow_roottn_baks) {
            push @SUMMARY, "> Found the following directories containing possible variant of the shadow.roottn.bak hack:" unless( $showHeader);
            push @SUMMARY, expand( MAGENTA "\t \\_ See: https://github.com/bksmile/WebApplication/blob/master/smtp_changer/wbf.php") unless( $showHeader);
            $showHeader=1;
            chomp($shadow_roottn_baks);
            next if ( $shadow_roottn_baks =~ m{shadow.png|shadow.lock|/home/virtfs} );
            push @SUMMARY, expand( CYAN "\t\t\\_ " . $shadow_roottn_baks );
        }
    }
    # CX-395 new roottn check
    my $chk_shadow_for_roottn = Cpanel::SafeRun::Timed::timedsaferun( 0, 'find', $RealHome, '-name', 'shadow' );
    my @chk_shadow_for_roottn = split /\n/, $chk_shadow_for_roottn;
    my $found_roottn = "";
    my $showHeader=0;
    foreach my $file( @chk_shadow_for_roottn ) {
        $found_roottn = Cpanel::SafeRun::Timed::timedsaferun( 0, 'egrep', '\$roottn\$', $file );
        if ( $found_roottn ) {
            push @SUMMARY, "> Found evidence of shadow.roottn hack in $file" unless( $showHeader );
            push @SUMMARY, expand( MAGENTA "\t \\_ See: https://github.com/bksmile/WebApplication/blob/master/smtp_changer/wbf.php") unless( $showHeader );
            $showHeader=1;
            push @SUMMARY, expand( CYAN "\t\t\\_ " . $file . YELLOW " [ Check with " . BLUE "egrep '\\\$roottn\\\$' " . $file . YELLOW " ]" ) if ( $found_roottn );
            $found_roottn = "";
        }
    }

    # Check cgi-bin directory for suspicious bash script
    print_status("Checking cgi-bin directory for suspicious bash script");
    if ( -e ("$RealHome/$pubhtml/cgi-bin/jarrewrite.sh") ) {
        push @SUMMARY,
"> Found suspicious bash script $RealHome/$pubhtml/cgi-bin/jarrewrite.sh";
    }

    # Check for wp-rest-api class (not normal)
    print_status("Checking for suspicious wp-rest-api class");
    if ( -e ("$RealHome/$pubhtml/class-wp-rest-api.php") ) {
        push @SUMMARY,
"> Found suspicious class in $RealHome/$pubhtml/class-wp-rest-api.php";
    }

    # SMTPF0x/AnonymousF0x checks
    if ( -e ("$RealHome/.anonymousFox") ) {
        push @SUMMARY, "> Found suspicious file $RealHome/.anonymousFox";
    }

    if ( -e ("$RealHome/etc/shadow") ) {
        open( my $fh, '<', "$RealHome/etc/shadow" );
        while ( <$fh> ) {
            if ( $_ =~ m{anonymousfox-|smtpf0x-|anonymousfox|smtp} ) {
                push @SUMMARY, "> Found suspicious smtpF0x user in " . CYAN "$RealHome/etc/shadow" . YELLOW " file";
                last;
            }
        }
        close($fh);
    }
    if ( -d ("$RealHome/$pubhtml/ConfigF0x") ) {
        push @SUMMARY,
          "> Found suspicious ConfigFox directory in $RealHome/$pubhtml/";
    }
    if ( -e ("$RealHome/.cpanel/.contactemail") ) {
        open( my $fh, '<', "$RealHome/.cpanel/.contactemail" );
        while ( <$fh> ) {
            if ( $_ =~ m{anonymousfox-|smtpf0x-|anonymousfox|smtpf} ) {
                push @SUMMARY, "> Found suspicious smtpF0x user in " . CYAN "$RealHome/.cpanel/.contactemail" . YELLOW " file";
                last;
            }
        }
        close($fh);
    }
    find( { wanted => \&smtpfoxhacks, }, "$RealHome/etc/");

    sub smtpfoxhacks {
        return if( -d $File::Find::name );
        my $hassmtpF0x = Cpanel::SafeRun::Timed::timedsaferun( 0, 'grep', '-E', 'anonymousfox-|smtpf0x-|anonymousfox|smtpf', "$File::Find::name" );
        if ( $hassmtpF0x ) {
            push @SUMMARY, "> Found suspicious smtpF0x/AnonymousF0x vulnerability in " . CYAN $File::Find::name;
        }
    }

    my @smtpF0x_files = qw( F.py f.php llsjxdcr.php mblircic.php vfmuqyvp.php bkV7.txt );
    foreach my $smtpF0xFile(@smtpF0x_files) {
        chomp($smtpF0xFile);
        if ( -e "$RealHome/$smtpF0xFile" || -e "$RealHome/$pubhtml/$smtpF0xFile" ) {
            my $outputline=Cpanel::SafeRun::Timed::timedsaferun( 0, 'find', $RealHome, '-name', $smtpF0xFile );
            chomp($outputline);
            push @SUMMARY, "> Found suspicious smtpF0x/AnonymousF0x file: " . CYAN $outputline;
        }
    }

    # Check for php scripts within the SSL DCV check directories.
    print_status("Checking for php scripts in $RealHome/$pubhtml/.well-known");
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
                  "> Found php script under $RealHome/$pubhtml/.well-known" );
            $headerprinted = 1;
        }
        push( @SUMMARY, expand( CYAN "\t\\_ $file" ) );
    }

    # Check for accesshash file in homedir
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

    # Check for .my.cnf file in homedir.
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

    # Check for .env file in homedir
    print_status( "Checking for .env file in " . $RealHome . "..." );
    logit( "Checking for .env file in " . $RealHome );
    if ( -e ("$RealHome/.env") ) {

        push( @RECOMMENDATIONS,
"> Found $RealHome/.env file! - May contain passwords for MySQL. Consider removing!"
        );
        logit(
"Found $RealHome/.env file! - May contain passwords for MySQL. Consider removing!"
        );
    }

    # Check for Troldesh Ransomware
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
            push( @SUMMARY, expand( CYAN "\t\\_ $fullpath" ) );
        }
    }

    print_status("Checking for RotaJakiro backdoor");
    logit("Checking for RotaJakiro backdoor");
    if ( -e "$RealHome/.gvfsd/.profile/gvfsd-helper" ) {
        push( @SUMMARY,
"> Found possible malicious RotaJakiro backdoor at $RealHome/.gvfsd/.profile/gvfsd-helper"
        );
    }
    if ( -e "$RealHome/.dbus/sessions/session-dbus" ) {
        push( @SUMMARY,
"> Found possible malicious RotaJakiro backdoor at $RealHome/.dbus/sessions/session-dbus"
        );
    }
    if ( -e "$RealHome/.X11/X0-lock" ) {
        push( @SUMMARY,
"> Found possible malicious RotaJakiro backdoor at $RealHome/.X11/X0-lock"
        );
    }
    if ( -e "$RealHome/.X11/.X11-lock" ) {
        push( @SUMMARY,
"> Found possible malicious RotaJakiro backdoor at $RealHome/.X11/.X11-lock"
        );
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

    # SOP-28 - look for massearchtraffic.top within fucntions.php file.
    my $massearchtraffic_malware = Cpanel::SafeRun::Timed::timedsaferun( 0, 'find', "$RealHome", '-name', 'functions.php', '-not', '-path', "/home/virtfs/*", '-a', '-not', '-path', '*/[@.]*', '-exec', 'grep', 'massearchtraffic.top', '{}', '+' );
    my $showHeader=0;
    if ( $massearchtraffic_malware ) {
        push( @SUMMARY, "> Found malicious redirect URL within functions.php file" ) unless( $showHeader );;
        $showHeader=1;
        push( @SUMMARY, MAGENTA "\t\\_  $massearchtraffic_malware") if ( $massearchtraffic_malware );
    }

    my $susp_dir = Cpanel::SafeRun::Timed::timedsaferun( 0, 'find', "$RealHome/$pubhtml", '-type', 'd', '-print' );
    my @susp_dir = split /\n/, $susp_dir;
    my $showHeader=0;
    foreach $susp_dir(@susp_dir) {
        chomp($susp_dir);
        if ( $susp_dir =~ m{wp-content/plugins/[a-zA-Z]{10}$} ) {
            push @SUMMARY, "> Found suspicious randomized 10 character directory name in a WordPress plugins folder:" unless( $showHeader );
            $showHeader=1;
            push @SUMMARY, expand( CYAN "\t\\_ $susp_dir" );
            if ( -e "$susp_dir/three-column-screen-layout.php" ) {
                push @SUMMARY, expand( MAGENTA "\t\t\\_ Also contains the " . WHITE "three-column-screen-layout.php" . MAGENTA " file." );
                push @SUMMARY, expand( MAGENTA "\t\t\\_ Likely related to the AnonymousF0x exploit" );
            }
        }
    }

    # Check for malicious @include line in wp-config.php files
    my $wp_config_files = Cpanel::SafeRun::Timed::timedsaferun( 0, 'find', "$RealHome/$pubhtml", '-type', 'f', '-name', 'wp-config.php', '-print' );
    my @wp_config_files = split /\n/, $wp_config_files;
    my $showHeader=0;;
    foreach my $wp_conffile(@wp_config_files) {
        chomp($wp_conffile);
        my $found = Cpanel::SafeRun::Timed::timedsaferun( 0, 'grep', '-E', '^\@include', $wp_conffile );
        if ( $found ) {
            push @SUMMARY, "> Found suspicious \@include line within $wp_conffile";
            push @SUMMARY, expand( MAGENTA "\t\\_ $found" );
        }
    }

    # Legion Malware - https://thehackernews.com/2023/05/legion-malware-upgraded-to-target-ssh.html
    my @files=qw( /.aws/credentials /_profiler/phpinfo /administrator/.env /api/.env /apps/.env /conf/.env /config/.env /config/aws.yml /core/Datavase/.env /core/app/.env /cron/.env /cronlab/.env /database/.env /debug/default/view.html /debug/default/view?panel=config /en/.env /exapi/.env /frontend/web/debug/default/view /lab/.env /laravel/.env /lib/.env /library/.env /psnlink/.env /saas/.env /sapi/debug/default/view /site/.env /sitemaps/.env /sites/all/libraries/mailchimp/.env /symfony/public/_profiler/phpinfo /tool/view/phpinfo.view.php /tool/view/phpinfo.view.php /wp-content/.env /tools/.env /uploads/.env /v1/.env /v2/.env /vendor/.env /web/.env /web/debug/default/view /wp-config.php-backup );
    my $showHeader=0;
    foreach my $file(@files) {
        chomp($file);
        next unless( -e "$RealHome/$pubhtml/$file" );
        push @SUMMARY, "> Found possible existence of Legion Malware found in $RealHome/$pubhtml" unless( $showHeader );
        $showHeader=1; 
        push @SUMMARY, expand( CYAN "\t\\_ $file" );
    }

    if ( -d "$RealHome/$pubhtml" ) {
        my $chk4ico = 0;
        my $chk4suspwp = 0;
        my @chk4ico;
        my @chk4suspwp;
        find( { wanted => \&wpchecks, }, "$RealHome/$pubhtml/");

        sub wpchecks {
            return if( -d $File::Find::name );
            if ( $File::Find::name =~ m{wp-includes} && $File::Find::name =~ m{.ico$} ) {
                $chk4ico = 1;
                push @chk4ico, $File::Find::name;
            }
            if ( $File::Find::name =~ m{wp-tmp.php|wp-feed.php|wp-vcd.php} ) {
                $chk4suspwp = 1;
                push @chk4suspwp, $File::Find::name;
                push( @SUMMARY, "> Found possible malicious WordPress files in $RealHome/$pubhtml directory.");
                foreach my $susp_wp_files_found (@chk4suspwp) {
                    chomp($susp_wp_files_found);
                    push( @SUMMARY, expand( WHITE "\t\\_ $susp_wp_files_found" ) );
                }
            }
        }
        if ($chk4ico) {
            push( @SUMMARY, "> Found possible malicious ico file(s) in $RealHome/$pubhtml/wp-includes directory." );
            foreach my $icoFound (@chk4ico) {
                chomp($icoFound);
                push( @SUMMARY, expand( WHITE "\t\\_ $icoFound" ) );
            }
        }
        if ( $chk4ico || $chk4suspwp ) {
            push @SUMMARY, " ";
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

    # Check images and favicon.ico files for shellcode/malware
    find( { wanted => \&imagefiles, }, "$RealHome/$pubhtml/");
    my $showHeader=0;
    sub imagefiles {
        return if( -d $File::Find::name );
        if ( $File::Find::name =~ m{.jpg$|.jpeg$|.gif$|.png$|.ico$} ) {
            my $header = Cpanel::SafeRun::Timed::timedsaferun( 3, 'strings', $File::Find::name );
            my $found=0;
            if ( $header =~ m{eval|function|String.from|CharCode|<\?php|halt_compiler|bin.*bash} ) {
                push @SUMMARY, "> Possible malware/shellcode injection found within the following files:" unless( $showHeader );
                $showHeader=1;
                push @SUMMARY, "\t\\_ $File::Find::name";
            }
        }
    }

    if ( -d "$RealHome/$pubhtml" ) {
        logit("Running a user scan for $lcUserToScan");
        my $yara_available = check_for_yara();
        if ($yara_available) {
            my @yara_urls = qw( https://raw.githubusercontent.com/cPanelPeter/infection_scanner/master/suspicious_strings.yara https://raw.githubusercontent.com/CpanelInc/tech-CSI/master/php_webshell_rules.yara);
            print_header("Downloading yara rules to $csidir");
            my @data;
            for my $URL (@yara_urls) {
                chomp($URL);
                my $response = HTTP::Tiny->new->get($URL);
                if ( $response->{success} ) {
                    my $yara_filename = basename($URL);
                    chomp($yara_filename);
                    open( YARAFILE, ">$csidir/$yara_filename" );
                    print YARAFILE $response->{content};
                    close(YARAFILE);
                    push @data, "$csidir/$yara_filename"
                      if ( -e "$csidir/$yara_filename" );
                }
                else {
                    print_status("Failed to download $URL");
                }
            }
            push @data, "/usr/local/maldetect/sigs/rfxn.yara"
              if ( -e "/usr/local/maldetect/sigs/rfxn.yara" );
            push @data, "/usr/local/cpanel/3rdparty/share/clamav/rfxn.yara"
              if ( -e "/usr/local/cpanel/3rdparty/share/clamav/rfxn.yara" );

            print CYAN "Scanning "
              . WHITE $RealHome
              . "/$pubhtml... (Using the following YARA rules)\n" unless( $cron );

            my ( @results, $results );
            foreach my $file (@data) {
                chomp($file);
                print BOLD BLUE "\tYara File: $file\n" unless( $cron );
                $results .=
                  Cpanel::SafeRun::Timed::timedsaferun( 0, 'yara', '-fwNr',
                    "$file", "$RealHome/$pubhtml" );
            }
            my @results   = split /\n/, $results;
            my $resultcnt = @results;
            if ( $resultcnt > 0 ) {
                push @SUMMARY,
"> A general Yara scan of the $lcUserToScan account found the following suspicious items...";
                foreach my $yara_result (@results) {
                    next if ( $yara_result =~ m{.yar|.yara|CSI|rfxn|.hdb|.ndb|csi.pl|modsec_vendor_configs|access_log|swpDSK|\.svg|\.json|\.pot|\.js|\.md} );
                    my ( $triggered_rule, $triggered_file, $triggered_string );
                    chomp($yara_result);
                    if ( substr( $yara_result, 0, 2 ) eq "0x" ) {
                        ($triggered_string) =
                          ( split( /: /, $yara_result ) )[1];
                    }
                    else {
                        ( $triggered_rule, $triggered_file ) =
                          ( split( '\s+', $yara_result ) );
                        $triggered_rule =~ s/_triggered//g;
                    }
                    if ( $triggered_rule =~ m/Rule_/ ) {
                        $triggered_string = YELLOW "See: " . BOLD BLUE "https://cpaneltech.ninja/cgi-bin/triggered.cgi?$triggered_rule";
                    }
                    my $ChangeDate;
                    my $ChangeDateStat = Cpanel::SafeRun::Timed::timedsaferun( 3, 'stat', $triggered_file );
                    my @ChangeDateStat = split /\n/, $ChangeDateStat;
                    foreach my $line( @ChangeDateStat ) {
                        next unless( $line =~ m/Change: / );
                        ($ChangeDate) = ( split( /\./, $line ) );
                        last;
                    }
                    $ChangeDate =~ s/Change: //;
                    # check hash of $triggered_file against known256_hashes.txt
                    my ($sha256only) = (split(/\s+/,Cpanel::SafeRun::Timed::timedsaferun( 0, 'sha256sum', "$triggered_file" )))[0];
                    my $knownHash  = known_sha256_hashes($sha256only);
                    my $susp_hash="";
                    if ($knownHash) {
                        $susp_hash = expand( CYAN "\n\t\t\\_ Has a hash " . GREEN . $sha256only . MAGENTA " known to be suspicious!" );
                    }
                    push @SUMMARY,
                        expand( "\t\\_ File: "
                      . MAGENTA $triggered_file
                      . YELLOW " looks suspicious. "
                      . GREEN "Changed on ["
                      . $ChangeDate . "] "
                      . $susp_hash . " "
                      . BOLD CYAN
                      "\n\t\t\\_ [Triggered: $triggered_rule] $triggered_string" )
                      unless ( $triggered_file =~ m/\.yar|\.yara|CSI|rfxn|\.hdb|\.ndb/ );
                }
            }
        }
        else {
            ## grep scan (not Yara) a bit slower but should catch the same things.
            my $url = URI->new( 'https://raw.githubusercontent.com/cPanelPeter/infection_scanner/master/strings.txt');
            my $ua = LWP::UserAgent->new( ssl_opts => { verify_hostname => 0 } );
            my $res         = $ua->get($url);
            my $definitions = $res->decoded_content;
            my @DEFINITIONS = $definitions;
            use open ":std", ":encoding(UTF-8)";
            open( my $fh, '>:encoding(UTF-8)', "$csidir/csi_detections.txt" );
            foreach my $def (@DEFINITIONS) {
                print $fh $def;
            }
            close($fh);
            print "Scanning $RealHome/$pubhtml for known phrases/strings\n";
            # This one cannot be changed from qx to use Cpanel::SafeRun::Timed. Won't work with this particular command.
            my $retval = qx[ LC_ALL=C grep --exclude="*.zip|*.gz" -srIwf $csidir/csi_detections.txt $RealHome/$pubhtml/* ];
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
            my $ChangeDate;
            foreach $FileOnly (@newRetVal) {
                my $ChangeDateStat = Cpanel::SafeRun::Timed::timedsaferun( 3, 'stat', $FileOnly );
                my @ChangeDateStat = split /\n/, $ChangeDateStat;
                foreach my $line( @ChangeDateStat ) {
                    next unless( $line =~ m/Change: / );
                    ($ChangeDate) = ( split( /\./, $line ) );
                    last;
                }
                $ChangeDate =~ s/Change: //;
                # check hash of $triggered_file against known256_hashes.txt
                my ($sha256only) = (split(/\s+/,Cpanel::SafeRun::Timed::timedsaferun( 0, 'sha256sum', "$FileOnly" )))[0];
                my $knownHash  = known_sha256_hashes($sha256only);
                my $susp_hash="";
                if ($knownHash) {
                    $susp_hash = expand( CYAN "\n\t\t\\_ Has a hash " . GREEN . $sha256only . MAGENTA " known to be suspicious!" );
                }
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
                          . $susp_hash
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
        my $findit = Cpanel::SafeRun::Timed::timedsaferun( 0, 'find', $HOMEDIR, '-type', 'l', '-lname', "$HOMEDIR/*/$conffile", '-ls' );
        push @symlinks, $findit unless( ! $findit );
    }
    my $headerprinted = 0;
    my $hp1           = 0;
    my $hp2           = 0;
    my $symlink;
    foreach $symlink (@symlinks) {
        my ( $symUID, $symGID, $link, $pointer, $realpath ) = ( split( /\s+/, $symlink ) )[ 5, 6, 11, 12, 13 ];
        my ( $SLfilename, $SLdir ) = fileparse($link);
        next if ( $SLdir =~ m{/home/virtfs} );
        next unless( -d $realpath );
        push( @SUMMARY, YELLOW "> Found symlink hacks under $SLdir" ) unless ($headerprinted);
        $headerprinted = 1;
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
                    push( @SUMMARY,
                        expand( CYAN "\t\\_ User owned ($symUID) symlink: " ) );
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

sub check_for_sedexp {
    my $find_sedexp=Cpanel::SafeRun::Timed::timedsaferun( 0, 'grep', '-srl', 'sedexp', '/dev/udef/*' );
    return unless( $find_sedexp );
    push( @SUMMARY, YELLOW "> Found possible sedexp malware in /lib/udev directory");
    push( @SUMMARY, expand( "\t\\_ $find_sedexp" ));
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

sub check_if_symlink_protect_on {
    return unless( -e '/etc/apache2/conf/httpd.conf' );
    open( my $fh, '<', '/etc/apache2/conf/httpd.conf' );
    while( <$fh> ) {
        next unless( $_ eq 'SymlinkProtect Off' );
        push @RECOMMENDATIONS, expand( "Apache SymLinkProtection is disabled, recommendation is to enable this" );
        last;
    }
    close( $fh );
}

sub check_cookieipvalidation {
    my $resultJSON = get_whmapi1( 'get_tweaksetting', 'key=cookieipvalidation' );
    my $result = $resultJSON->{data}->{tweaksetting}->{value};
    if ( $result ne 'strict' ) {
        push @RECOMMENDATIONS, "> Cookie IP Validation isn't set to strict - Consider changing this in Tweak Settings.";
        return;
    }
}

sub check_xframe_content_headers {
    my $resultJSON = get_whmapi1( 'get_tweaksetting', 'key=xframecpsrvd' );
    my $result = $resultJSON->{data}->{tweaksetting}->{value};
    if ( !$result ) {
        push @RECOMMENDATIONS, "> X-Frame-Options and X-Content-Type-Options not enabled for cpsrvd - Consider enabling this in Tweak Settings.";
        return;
    }
}

sub security_advisor {
    unlink("/var/cpanel/security_advisor_history.json") if ( -e ("/var/cpanel/security_advisor_history.json") );
    my $SecAdvisor = Cpanel::SafeRun::Timed::timedsaferun( 0, '/usr/local/cpanel/scripts/check_security_advice_changes' );
    my @SecAdvisor = split /\n/, $SecAdvisor;
    push( @RECOMMENDATIONS, YELLOW "> " . MAGENTA "\t============== SECURITY ADVISOR RESULTS ===============" );
    foreach my $SecAdvLine(@SecAdvisor) {
        next if( $SecAdvLine =~ m{High|Info|Advice|Type|Module|Medium} );
        push( @RECOMMENDATIONS, BOLD CYAN $SecAdvLine . "\n" ) unless ( $SecAdvLine eq "" );
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
    no warnings;    ## no critic (TestingAndDebugging::ProhibitNoWarnings)
    my $sshd_settings  = Cpanel::SafeRun::Timed::timedsaferun( 4, 'sshd', '-T' );
    my %sshd_conf      = map { split( /\s+/, $_ ) } $sshd_settings;
    if ( $sshd_conf{'permitrootlogin'} =~ m/^[Yy][Ee][Ss]/ ) {
        push @RECOMMENDATIONS,  "> PermitRootLogin is set to yes in /etc/ssh/sshd_config - consider setting to no or without-password instead!";
    }
    if ( $sshd_conf{'passwordauthentication'} =~ m/^[Yy][Ee][Ss]/ ) {
        push @RECOMMENDATIONS,  "> PasswordAuthentication is set to yes in /etc/ssh/sshd_config - consider using ssh keys instead!";
    }

    my $attr = isImmutable("/etc/ssh/sshd_config");
    push( @SUMMARY, "> The /etc/ssh/sshd_config file is " . MAGENTA "[IMMUTABLE]" ) unless( ! $attr );
    push @SUMMARY, expand( CYAN "\t\\_ indicates possible root-level compromise!" ) unless( ! $attr );
    return unless ( -e "/root/.ssh/authorized_keys" );
    my $authkeysGID    = ( stat("/root/.ssh/authorized_keys")->gid );
    open( my $fh, '<', '/root/.ssh/authorized_keys' );
    while( <$fh> ) {
        if ( $_ =~ m{mdrfckr} ) { 
            push @SUMMARY, "> /root/.ssh/authorized_keys file contains a malicious key!";
            last;
        }
    }
    close($fh);
    my $authkeysGname = getgrgid($authkeysGID);
    if ( $authkeysGID > 0 ) {
        push @SUMMARY,
            "> The /root/.ssh/authorized_keys file has invalid group ["
          . MAGENTA $authkeysGname
          . YELLOW "] - "
          . CYAN "indicates possible root-level compromise";
    }
    my $attr = isImmutable('/root/.ssh/authorized_keys');
    push @SUMMARY, "> The /root/.ssh/authorized_keys file set to " . MAGENTA "[IMMUTABLE]" unless( ! $attr );
    push @SUMMARY, expand( CYAN "\t\\_ indicates possible root-level compromise!" ) unless( ! $attr );
}

sub misc_checks {
    my @dirs     = undef;
    my @files    = undef;
    my $fullpath = "";

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
    my $objdump = Cpanel::SafeRun::Timed::timedsaferun( 2, 'objdump', '-T', '/usr/bin/ssh', '/usr/sbin/sshd' );
    my @objdump = split /\n/, $objdump;
    my $spymaster = grep ( { /spy_master/ } @objdump );
    if ($spymaster) {
        push @SUMMARY, "> Suspicious file found: evidence of spy_master running in ssh/sshd [ $spymaster ]";
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
                push( @SUMMARY, expand( CYAN "\t\\_ $fullpath" ) );
                vtlink($fullpath);
            }
        }
    }

    return unless my @crons_aref = get_cron_files();
    my @susp_cron_strings;
    my $susp_crons_ref = get_suspicious_cron_strings();
    push @susp_cron_strings, @$susp_crons_ref;
    my @cronContains = undef;
    my $isImmutable  = "";
    my ( $roots_crontab_file ) = ( $distro ne "ubuntu" ) ? '/var/spool/cron/root' : '/var/spool/cron/crontabs/root';
    for my $cron (@crons_aref) {
        if ( $cron eq $roots_crontab_file ) {
            my $rootscron = Cpanel::SafeRun::Timed::timedsaferun( 5, 'crontab', '-l' );
            my @rootscron = split( /\n/, $rootscron );
            my $croncnt   = @rootscron;
            if ( -e '/var/cpanel/dnslonly') {
                if ( $croncnt < 7 ) {
                    push @SUMMARY, "> Root's crontab contains less than 7 lines (not normal for cPanel DNSOnly servers), could indicate a root compromise";
                    next;
                }
            }
            if ( $croncnt < 15 ) {
                push @SUMMARY, "> Root's crontab contains less than 15 lines (not normal for cPanel servers), could indicate a root compromise";
            }
            if ( -z $cron ) {
                push @SUMMARY, "> Root's crontab is empty!\n\t\\_ Should never happen on a cPanel server and indicates a possible root compromise";
            }
        }
        $isImmutable = isImmutable($cron);
        my $attr = isImmutable($cron);
        if ($attr) {
            $isImmutable = MAGENTA "[IMMUTABLE]";
        }
        else { 
            $isImmutable = "";
        }
        if ( open my $cron_fh, '<', $cron ) {
            while (<$cron_fh>) {
                chomp($_);
                foreach my $susp_cron_string (@susp_cron_strings) {
                    chomp($susp_cron_string);
                    if ( $_ =~ m{$susp_cron_string} ) {
                        push @cronContains,
                            expand( CYAN "\t \\_ "
                        . $cron
                        . "\n\t\t \\_ Contains: [ "
                        . RED $_
                        . CYAN " ] $isImmutable" ) unless( $cron =~ m{BitdefenderRedline} );
                    }
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
        next if !-d $dir;
        for my $file (@files) {
            $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
                push( @SUMMARY,
                    "> Suspicious files found: possible bitcoin miner." );
                push( @SUMMARY, expand( CYAN "\t \\_ " . $fullpath . " exists" ) );
            }
        }
    }
    if ( -e "/bin/systemctl" ) {
        my $systemctl_status = Cpanel::SafeRun::Timed::timedsaferun( 5, 'systemctl', 'status', 'rc-local.service' );
        my @systemctl_status = split /\n/, $systemctl_status;
        if ( grep ( { /mysql --noTest/ } @systemctl_status ) ) {
            push @SUMMARY, "> Found evidence of a bitcoin miner in /etc/rc.d/rc.local";
            push @SUMMARY, expand( "\t\\_ rc-local.service should not be running with mysql --noTest" );
        }
    }

    my $dhcpd_bin = Cpanel::SafeRun::Timed::timedsaferun( 5, 'ls', '-al', '/bin/' );
    my @dhcpd_bin = split /\n/, $dhcpd_bin;
    foreach my $line(@dhcpd_bin) {
        chomp($line);
        push @SUMMARY, "> Found evidence of the dhcpd cryptominer in /bin directory" if ( $line =~ m/\A[a-z0-9]{26}\z/ );
        push @SUMMARY, expand( CYAN "\t\\_ $line" ) if ( $line =~ m/\A[a-z0-9]{26}\z/ );
    }

    open( my $fh, '<', '/etc/rc.local' ) || return;
    while ( <$fh> ) {
        chomp;
        push @SUMMARY, "> Found evidence of the dhcpd cryptominer in the /etc/rc.local file." if ( $_ =~ 'dhcpd' );
    }
    close( $fh );
}

sub vtlink {
    my $FileToChk = shift;
    chomp($FileToChk);
    return if ( !-e "$FileToChk" );
    my $fStat = stat($FileToChk);
    if ( -f _ or -d _ and not -z _ ) {
        my ($FileU)  = getpwuid( ( $fStat->uid ) );
        my ($FileG)  = getgrgid( ( $fStat->gid ) );
        $FileU = "UNKNOWN" if ( $FileU eq "" );
        $FileG = "UNKNOWN" if ( $FileG eq "" );
        my $FileSize = $fStat->size;
        my $ctime    = $fStat->ctime;
        my $sha256   = Cpanel::SafeRun::Timed::timedsaferun( 4, 'sha256sum', $FileToChk );
        ($sha256only) = ( split( /\s+/, $sha256 ) )[0];
        my $ignoreHash = ignoreHashes($sha256only);
        my $knownHash  = known_sha256_hashes($sha256only);

        push @SUMMARY, expand( "> Suspicious file found: " . CYAN $FileToChk );

        # First let's check Virustotal.com
        my $ticketnum = $ENV{'TICKET'};
        $ticketnum = "DEBUG" if ($debug);
        my $ipaddr = Cpanel::SafeRun::Timed::timedsaferun( 0, 'curl', '-s', '-4', "https://myip.cpanel.net/v1.0/" );
        chomp($ipaddr);
        if ( $sha256only && $ipaddr && $ticketnum && iam('cptech') || $debug ) {
            my $vtdata = Cpanel::SafeRun::Timed::timedsaferun( 10, 'curl', '-s', '-4', "https://cpaneltech.ninja/cgi-bin/virustotal_check.pl?hash=$sha256only&ip=$ipaddr&ticket=$ticketnum" );
            my $output = decode_json($vtdata);
            my $URL    = $output->{data}->{links}->{self};
            $URL .= "/detection";
            $URL =~ s/api/gui/g;
            $URL =~ s/v3\///g;
            $URL =~ s/files/file/g;
            if ( !$ignoreHash ) {
                push @SUMMARY,
                  "> Checking hash at VirusTotal.com (3rd party)"
                  . expand( YELLOW "  [ Type: "
                      . CYAN $output->{data}->{attributes}
                      ->{type_description}
                      . YELLOW " ]"
                      . YELLOW "\n\t\\_ Size: "
                      . CYAN $FileSize
                      . YELLOW " Date Changed: "
                      . CYAN scalar localtime($ctime)
                      . YELLOW " Owned by U/G: "
                      . CYAN $FileU . "/"
                      . $FileG );
                if ( defined $output->{data}->{attributes}->{sha256} ) {
                    push @SUMMARY,
                      expand(
                            YELLOW "\t \\_ 256hash: "
                          . CYAN $output->{data}->{attributes}->{sha256}
                          . YELLOW "\n\t\\_ Classification: "
                          . CYAN $output->{data}->{attributes}
                          ->{popular_threat_classification}
                          ->{suggested_threat_label}
                          . YELLOW "\n\t\\_ "
                          . $output->{data}->{attributes}
                          ->{last_analysis_stats}->{malicious}
                          . CYAN
" anti-virus engines detected this as malicious at VirusTotal.com"
                          . YELLOW "\n\t\\_ First Seen: "
                          . CYAN scalar localtime(
                            $output->{data}->{attributes}
                              ->{first_submission_date}
                          )
                          . YELLOW
                          . " / Last Analyzed: "
                          . CYAN scalar localtime(
                            $output->{data}->{attributes}
                              ->{last_analysis_date}
                          )
                      );
                }
                else {
                    push @SUMMARY,
                      expand( YELLOW
                          "\t \\_ No matches found at VirusTotal.com" );
                }
            }
        }
        else {
            if ( !$ignoreHash ) {
                push @SUMMARY,
                  "> Checking hash at VirusTotal.com (3rd party)"
                  . expand( YELLOW "\n\t\\_ Size: "
                      . CYAN $FileSize
                      . YELLOW " Date Changed: "
                      . CYAN scalar localtime($ctime)
                      . YELLOW " Owned by U/G: "
                      . CYAN $FileU . "/"
                      . $FileG );
                push @SUMMARY, expand( RED "\t \\_ Unable to verify at virustotal.com. Please check manually by visiting:");
                push @SUMMARY, expand( GREEN "\t \\_ " . WHITE "https://www.virustotal.com/#/file/$sha256only/detection");
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

sub rpm_yum_running_chk {
    my $continue = has_ps_command();
    return unless ($continue);
    for my $process (@process_list) {
        # CX-482
        next unless( $process =~ m{/usr/bin/rpm|/usr/bin/yum|apt upgrade|/usr/lib/apt/apt.systemd.daily update|lock_is_held update} );
        next if( $process =~ m{grep|wp-toolkit-cpanel} );
        logit("An rpm/yum or apt process may be running");
        print_warn( "An rpm/yum or apt process may be running (possible lock exists). Could cause some checks to hang waiting for process to complete.");
        exit;
    }
}

sub chk_shadow_hack {
    my $shadow_roottn_baks = Cpanel::SafeRun::Timed::timedsaferun( 0, 'find', $HOMEDIR, '-name', 'shadow\.*', '-print' );
    if ($shadow_roottn_baks) {
        my @shadow_roottn_baks = split "\n", $shadow_roottn_baks;
        my $showHeader = 0;
        foreach $shadow_roottn_baks (@shadow_roottn_baks) {
            next unless( $shadow_roottn_baks =~ m{/etc/} );
            push @SUMMARY, "> Found the following directories containing the shadow.roottn.bak hack:" unless( $showHeader );
            push @SUMMARY, expand( MAGENTA "\t \\_ See: https://github.com/bksmile/WebApplication/blob/master/smtp_changer/wbf.php") unless( $showHeader );
            $showHeader=1;
            chomp($shadow_roottn_baks);
            push @SUMMARY, expand( CYAN "\t\t\\_ " . $shadow_roottn_baks );
        }
    }
    # CX-395 new roottn check
    my $chk_shadow_for_roottn = Cpanel::SafeRun::Timed::timedsaferun( 0, 'find', $HOMEDIR, '-name', 'shadow' );
    my @chk_shadow_for_roottn = split /\n/, $chk_shadow_for_roottn;
    my $found_roottn = "";
    my $showHeader=0;
    foreach my $file( @chk_shadow_for_roottn ) {
        $found_roottn = Cpanel::SafeRun::Timed::timedsaferun( 0, 'egrep', '\$roottn\$', $file );
        if ( $found_roottn ) {
            push @SUMMARY, "> Found evidence of shadow.roottn hack in $file" unless( $showHeader );
            push @SUMMARY, expand( MAGENTA "\t \\_ See: https://github.com/bksmile/WebApplication/blob/master/smtp_changer/wbf.php") unless( $showHeader );
            $showHeader=1;
            push @SUMMARY, expand( CYAN "\t\t\\_ " . $file . YELLOW " [ Check with " . BLUE "egrep '\\\$roottn\\\$' " . $file . YELLOW " ]" ) if ( $found_roottn );
            $found_roottn = "";
        }
    }
}

sub check_for_exim_vuln {
    my $chk_eximlog;
    $chk_eximlog = Cpanel::SafeRun::Timed::timedsaferun( 0, 'grep', '-E', '\${run', '/var/log/exim_mainlog' ) unless( ! -e '/var/log/exim_mainlog' );;
    $chk_eximlog .= Cpanel::SafeRun::Timed::timedsaferun( 0, 'zgrep', '-E', '\${run', '/var/log/exim_mainlog.1.gz' ) unless( ! -e '/var/log/exim_mainlog.1.gz' );
    $chk_eximlog .= Cpanel::SafeRun::Timed::timedsaferun( 0, 'zgrep', '-E', '\${run', '/var/log/exim_mainlog.2.gz' ) unless( ! -e '/var/log/exim_mainlog.2.gz' );
    $chk_eximlog .= Cpanel::SafeRun::Timed::timedsaferun( 0, 'zgrep', '-E', '\${run', '/var/log/exim_mainlog.3.gz' ) unless( ! -e '/var/log/exim_mainlog.3.gz' );
    $chk_eximlog .= Cpanel::SafeRun::Timed::timedsaferun( 0, 'zgrep', '-E', '\${run', '/var/log/exim_mainlog.4.gz' ) unless( ! -e '/var/log/exim_mainlog.4.gz' );
    my @chk_eximlog = split /\n/, $chk_eximlog;
    if ($chk_eximlog) {
        push @SUMMARY, "> Found the following string in /var/log/exim_mainlog file. Possible root-level compromise was attempted:";
        foreach $chk_eximlog (@chk_eximlog) {
            push @SUMMARY, expand( CYAN "\t\\_$chk_eximlog" );
        }
    }
}

sub spamscriptchk {
    #  Check for obfuscated Perl spamming script - will be owned by user check ps for that user and /tmp/dd
    opendir my $dh, "/tmp";
    my @tmpdirfiles = readdir($dh);
    closedir $dh;
    my $totaltmpfiles = @tmpdirfiles;
    return if $totaltmpfiles > 1000;
    my $showHeader = 0;
    my $susp_string_found = 0;
    foreach my $file_in_tmp (@tmpdirfiles) {
        chomp($file_in_tmp);
        next if ( $file_in_tmp eq "." || $file_in_tmp eq ".." );
        my $isASCII = Cpanel::SafeRun::Timed::timedsaferun( 0, 'file', "/tmp/$file_in_tmp" );
        next unless( grep { /ASCII/ } $isASCII);
        open( my $fh, '<', "/tmp/$file_in_tmp" );
        while ( <$fh> ) {
            next unless( $_ =~ m/295c445c5f495f5f4548533c3c3c3d29/);
            $susp_string_found = 1;
        }
        close( $fh );
        if ($susp_string_found) {
            push @SUMMARY, "> Found evidence of user spamming script in /tmp directory" unless ($showHeader);
            $showHeader = 1;
            my $FileU = Cpanel::SafeRun::Timed::timedsaferun( 4, 'stat', '-c', "%U", "/tmp/$file_in_tmp" );
            chomp($FileU);
            my $ExistsinTmp = " [ Exists and is owned by: " . CYAN $FileU . YELLOW " ]";
            push @SUMMARY, expand( "\t\\_ /tmp/" . $file_in_tmp . " " . $ExistsinTmp . "\n" );
        }
    }
}

sub check_for_ita_perl_hack {
    my $dir='/usr/local/share/. /ita';
    my $file='/usr/local/share/. /ita.gz';
    return unless( -d $dir );
    push @SUMMARY, MAGENTA "> POSSIBLE ROOT-LEVEL COMPROMISE! " . YELLOW "Suspicious directory found: " . WHITE $dir;
    push @SUMMARY, YELLOW "\t\\_ This directory has been known to send spam/phishing emails out and is in a root owned location."; 
    if ( -e $file ) {
        push @SUMMARY, MAGENTA "> Suspicious file found: " . CYAN $file;
        push @SUMMARY, YELLOW "\t\\_ This file has been known to be malicious and is in a root owned location."; 
    }
}

sub user_crons {
    my $crondir = ( $distro eq "ubuntu" ) ? "/var/spool/cron/crontabs" : "/var/spool/cron";
    opendir my $dh, $crondir;
    my @allcrons = readdir($dh);
    closedir $dh;
    my $usercron;
    my @crondata;
    my $cronline;
    my @susp_cron_strings;
    my $susp_crons_ref = get_suspicious_cron_strings();
    push @susp_cron_strings, @$susp_crons_ref;
    foreach $usercron (@allcrons) {
        open( USERCRON, "$crondir/$usercron" );
        next if ( $usercron eq 'root' );
        @crondata = <USERCRON>;
        close(USERCRON);
        foreach $cronline (@crondata) {
            chomp($cronline);
            if ( $cronline =~ m{ perl \s (?:/var)?/tmp/[a-zA-Z]+ }xms ) {
                push @SUMMARY,
                    expand( CYAN "> Found suspicious cron entry in the "
                  . MAGENTA $usercron
                  . CYAN " user account:"
                  . YELLOW "\n\t\\_ $cronline" );
            }
            foreach my $susp_cron_string (@susp_cron_strings) {
                chomp($susp_cron_string);
                if ( $cronline =~ m{$susp_cron_string} ) {
                    push @SUMMARY,
                        expand( CYAN "> Found suspicious cron entry in the "
                    . MAGENTA $usercron
                    . CYAN " user account:"
                    . YELLOW "\n\t\\_ $cronline" );
                }
            }
        }
    }
}

sub check_for_Super_privs {
    return if !-e "/var/lib/mysql/mysql.sock";
    my $MySQLSuperPriv = Cpanel::SafeRun::Timed::timedsaferun( 5, 'mysql', '-BNe', "SELECT Host,User FROM mysql.user WHERE Super_priv='Y'" );
    my @MySQLSuperPriv = split /\n/, $MySQLSuperPriv;
    my $showHeader=0;
    foreach $MySQLSuperPriv(@MySQLSuperPriv) {
        next if( $MySQLSuperPriv =~ m{root|mysql.session} );
        push @SUMMARY, "> The following MySQL users have the Super Privilege:" unless($showHeader);
        $showHeader=1;
        my ( $MySQLHost, $MySQLUser ) = ( split( /\s+/, $MySQLSuperPriv ) );
        push @SUMMARY, expand( CYAN "\t \\_ User: " . MAGENTA $MySQLUser . CYAN " on Host: " . MAGENTA $MySQLHost );
    }
}

sub check_for_mysqlbackups_user {
    return if !-e "/var/lib/mysql/mysql.sock";
    my $mysqlbackups_user = Cpanel::SafeRun::Timed::timedsaferun( 5, 'mysql', '-BNe', "SELECT User FROM mysql.user WHERE User LIKE 'mysqlbackups%'" );
    if ($mysqlbackups_user) {
        push @SUMMARY, CYAN
"> Found mysqlbackups user in MySQL.user table - Could be a MySQL backdoor";
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
    my @allcrons = glob( q{ /etc/cron.d/{.,}* /etc/cron.hourly/{.,}* /etc/cron.daily/{.,}* /etc/cron.weekly/{.,}* /etc/cron.monthly/{.,}* /etc/crontab /var/spool/cron/root /var/spool/cron/crontabs/root });
    my @cronlist;
    foreach my $cron( @allcrons ) {
        next if( grep { /\.{1,2}$/ } $cron );
        push @cronlist, $cron;
    }
    return @cronlist;
}

sub get_last_logins_WHM {
    my $lcUser = shift;
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
        push( @INFO, expand( CYAN "\t\\_ $success ($num $times)" ) ) unless ( $success =~ m/208\.74\.123\.|184\.94\.197\./ );
    }
}

sub get_last_logins_SSH {
    my $lcUser = shift;
    if ( !-e "/var/log/wtmp" ) {
        push @SUMMARY,
"> /var/log/wtmp is missing - last command won't work - could not check for root SSH logins";
        return;
    }
    my $dt   = DateTime->now;
    my $mon  = $dt->month_abbr;
    my $year = $dt->year;

    my $LastSSHRootLogins = Cpanel::SafeRun::Timed::timedsaferun( 4, 'last', '-F', 'root' );
    my @LastSSHRootLogins = split /\n/, $LastSSHRootLogins;
    my $SSHLogins         = "";
    my @SSHIPs            = undef;
    foreach $SSHLogins (@LastSSHRootLogins) {
        my ( $lastIP, $cDay, $cMonth, $cDate, $cTime, $cYear ) = ( split( /\s+/, $SSHLogins ) )[ 2, 3, 4, 5, 6, 7 ];
        next unless( $lastIP );
        if ( $lastIP =~ m{:} ) {
            $lastIP .= "::";
            push @SSHIPs, $lastIP if( Cpanel::Validate::IP::is_valid_ipv6( $lastIP ));
            next;
        }
        push @SSHIPs, $lastIP unless ( ! Cpanel::Validate::IP::v4::is_valid_ipv4( $lastIP ) );
    }
    splice( @SSHIPs, 0, 1 );
    my @sortedIPs     = uniq @SSHIPs;
    my $headerPrinted = 0;
    foreach $SSHLogins (@sortedIPs) {
        if ( $headerPrinted == 0 ) {
            push( @INFO, "> The following IP address(es) logged on via SSH successfully as " . CYAN $lcUser . YELLOW " (in $mon):" );
            $headerPrinted = 1;
        }
        push( @INFO, expand( CYAN "\t\\_ IP: $SSHLogins" ) ) unless ( $SSHLogins =~ m/208.74.12|184.94.197./ );
    }
}

sub check_secure_log {
    my $lcUser = shift;
    my $max_output = 3;
    my $hasJctl = ( -x '/usr/bin/journalctl' ) ? 1 : 0;
    my $secure_log_file;
    if ( $distro eq 'ubuntu' ) {
        $secure_log_file = '/var/log/auth.log';
    }
    else {
        $secure_log_file = '/var/log/secure';
    }
    if ( -f $secure_log_file ) {
        my $output_line=0;
        my $showHeader=0;
        open( my $fh, '<', $secure_log_file );
        while( <$fh> ) {
            chomp($_);
            next unless( $_ =~ m/Accepted publickey|Accepted password/ );
            if ( $_ =~ m/for $lcUser from/ ) {
                next if( $_ =~ m/208\.74\.123|184\.94\.197/ );
                push( @INFO, "> The following entries for $lcUser were found in $secure_log_file:" ) unless( $showHeader );;
                $showHeader=1;
                push @INFO, expand( CYAN "\t\\_ $_") unless( $output_line > $max_output );
                $output_line++;
            }
        }
        close( $fh );
    }
    if ( $hasJctl ) {
        my $showHeader=0;
        my $output_line=0;
        my $jctl_info = Cpanel::SafeRun::Timed::timedsaferun( 0, 'journalctl', '-u', 'sshd', '--no-pager' );
        my @jctl_info = split /\n/, $jctl_info;
        foreach my $line(@jctl_info) {
            chomp($line);
            next unless( $line =~ m/Accepted publickey|Accepted password/ );
            if ( $line =~ m/for $lcUser from/ ) {
                next if( $line =~ m/208\.74\.123|184\.94\.197/ );
                push( @INFO, "> The following entries were found via a journalctl call:" ) unless( $showHeader );
                $showHeader=1;
                push @INFO, expand( CYAN "\t\\_ $line" ) unless( $output_line > $max_output );
                $output_line++;
            }
        }
    }
}

sub get_whm_terminal_logins {
    my $lcUser = shift;
    my $dt     = DateTime->now;
    my $year   = $dt->year;
    open( ACCESSLOG, "/usr/local/cpanel/logs/access_log" );
    my @ACCESSLOG = <ACCESSLOG>;
    close(ACCESSLOG);
    my $accessline;
    my @Success;

    foreach $accessline (@ACCESSLOG) {
        chomp($accessline);
        my ( $ipaddr, $user, $date, $haslogin, $status ) = ( split( /\s+/, $accessline ) )[ 0, 2, 3, 6, 8 ];
        if ( $user eq "$lcUser" and $status eq "200" and $haslogin =~ m{scripts12/terminal} and $date =~ m/$year/ ) {
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
            push( @INFO, "> The following IP address(es) logged on via the WHM terminal (SSH) successfully as " . CYAN $lcUser );
            $headerPrinted = 1;
        }
        chomp($success);
        $num   = grep { $_ eq $success } @Success;
        $times = "time";
        my $dispDate = "";
        if ( $num > 1 ) { $times = "times"; }
        push( @INFO, expand( CYAN "\t\\_ $success ($num $times)" ) ) unless ( $success =~ m/208\.74\.123\.|184\.94\.197\./ );
    }
}

sub get_session_logins {
    my $lcUser = shift;
    my $dt     = DateTime->now;
    my $year   = $dt->year;
    open( SESSLOG, "/usr/local/cpanel/logs/session_log" );
    my @SESSLOG = <SESSLOG>;
    close(SESSLOG);
    my $sessline;
    my @Success;

    foreach $sessline (@SESSLOG) {
        chomp($sessline);
        my ( $date, $app, $ipaddr, $user ) = ( split( /\s+/, $sessline ) )[ 0, 4, 5, 7 ];
        if ( substr( $user,0,length($lcUser) ) eq $lcUser and $app eq "[whostmgrd]" and $sessline =~ m{possessed=0} and $date =~ m/$year/ ) {
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
            chop($lcUser);
            push( @INFO, "> The following IP address(es) successfully logged on via a session as " . CYAN $lcUser );
            $headerPrinted = 1;
        }
        chomp($success);
        $num   = grep { $_ eq $success } @Success;
        $times = "time";
        my $dispDate = "";
        if ( $num > 1 ) { $times = "times"; }
        push( @INFO, expand( CYAN "\t\\_ $success ($num $times)" ) ) unless ( $success =~ m/208\.74\.123\.|184\.94\.197\./ );
    }
}

sub get_root_pass_changes {
    my $lcUser = shift;
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
            push( @INFO, "> The following IP address(es) changed roots password via WHM (in $year):");
            $headerPrinted = 1;
        }
        chomp($success);
        my $dispDate = "";
        $num   = grep { $_ eq $success } @Success;
        $times = "time";
        if ( $num > 1 ) { $times = "times"; }
        push( @INFO, expand( CYAN "\t\\_ $success ($num $times)" ) ) unless ( $success =~ m/208\.74\.123\.|184\.94\.197\./ );
    }
}

sub check_api_tokens_log {
    return unless ( -e "/usr/local/cpanel/logs/api_tokens_log" );
    open( my $fh, "<", "/usr/local/cpanel/logs/api_tokens_log" );
    my $cnt = 0;
    my @api_tokens;
    while (<$fh>) {
        next unless ( $_ =~ m{json-api/passwd} );
        push @api_tokens, $_;
        $cnt++;
        last if $cnt > 10;
    }
    if ( $cnt >= 10 ) {
        my ($first_line) = ( split( /\s+/, @api_tokens[0] ) )[0];
        my ($last_line)  = ( split( /\s+/, @api_tokens[-1] ) )[0];
        if ( $first_line eq $last_line ) {
            push @SUMMARY,
"> Excessive (10 or more) password changes via root owned API token found in api_tokens_log file.\n\t\\_ Should be reviewed by an administrator or security consultant.";
        }
    }
}

sub check_file_for_elf {
    my $tcFile  = shift;
    $tcFile =~ s/'//g;
    chomp($tcFile);
    my $ELFfile = Cpanel::SafeRun::Timed::timedsaferun( 0, 'file', "$tcFile" );
    return 1 if ( $ELFfile =~ m/ ELF / );
    return 0;
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
    my $lilockedFound = Cpanel::SafeRun::Timed::timedsaferun( 0, 'find', '/', '-xdev', '-maxdepth', '3', '-name', "*.lilocked", '-print' );
    my @lilockedFound = split /\n/, $lilockedFound;
    if ($lilockedFound) {
        push( @SUMMARY, "> Evidence of lilocked ransomware detected." );
        foreach $lilockedFound (@lilockedFound) {
            chomp($lilockedFound);
            push( @SUMMARY, expand( CYAN "\t\\_ $lilockedFound" ) );
        }
    }
}

sub check_for_filenew_ransomware {
    my $filenewFound = Cpanel::SafeRun::Timed::timedsaferun( 0, 'find', '/', '-xdev', '-maxdepth', '3', '-name', "*.filenew", '-print' );
    my @filenewFound = split /\n/, $filenewFound;
    if ($filenewFound) {
        push( @SUMMARY, "> Evidence of ransomware detected." );
        foreach $filenewFound (@filenewFound) {
            chomp($filenewFound);
            push( @SUMMARY, expand( CYAN "\t\\_ $filenewFound" ) );
        }
    }
    if ( -e '/root/How-To-Restore-Your-Files.txt' ) {
        push( @SUMMARY, "> Evidence of ransomware detected." );
        push( @SUMMARY, expand( CYAN "\t\\_ How-To-Restore-Your-Files.txt ransome note found in /root." ) );
    }
}

sub check_sudoers_file {
    my @sudoersfiles = glob(q{/etc/sudoers.d/*});
    push @sudoersfiles, "/etc/sudoers" unless ( !-e "/etc/sudoers" );
    my $showHeader          = 0;
    my $external_ip_address = Cpanel::SafeRun::Timed::timedsaferun( 0, 'curl', '-s', '-4', "https://myip.cpanel.net/v1.0/" );
    chomp($external_ip_address);
    my $isAWS_IP = getAWS_IPs($external_ip_address);
    foreach my $sudoerfile (@sudoersfiles) {
        chomp($sudoerfile);
        next if ( $sudoerfile =~ m{/etc/sudoers.d/ticket[0-9]} );
        open( my $fh, '<', $sudoerfile );
        my @sudoers = <$fh>;
        close($fh);
        foreach my $sudoerline (@sudoers) {
            chomp($sudoerline);
            next
              if ( $sudoerline =~ m/^(#|$|root|Defaults|%wheel|%sudo|%admin)/ );
            next if ( $sudoerline =~ m/ec2-user/ && $isAWS_IP );
            next
              if ( $sudoerline =~
                m/cloudlinux|centos|ubuntu|wp-toolkit|cloud-user|rocky/ );
            next unless ( $sudoerline =~ m/ALL$/ );
            push @SUMMARY,
              "Found non-root users with insecure privileges in a sudoer file."
              unless ( $showHeader == 1 );
            $showHeader = 1;
            if ( $sudoerline =~ m/ALL, !root/ ) {
                push @SUMMARY,
expand( "\t\\_ $sudoerfile: $sudoerline has !root - might be susceptible to CVE-2019-14287" );
            }
            else {
                push @SUMMARY, expand( CYAN "\t\\_ $sudoerfile: " . MAGENTA $sudoerline );
            }
        }
    }
}

sub getAWS_IPs {
    my $chkIP = shift;
    chomp($chkIP);
    use NetAddr::IP;
    my $AWSsubnets = Cpanel::SafeRun::Timed::timedsaferun( 0, 'curl', '-s', '-4',
        'https://ip-ranges.amazonaws.com/ip-ranges.json' );
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

sub FileExists {
    my $param = shift;
    foreach my $file2 (@{$param}) {
        if (-e "$file2") {
            return 1;
        }
    }
    return 0;
}

sub look_for_suspicious_files {
    my $url = URI->new( 'https://raw.githubusercontent.com/CpanelInc/tech-CSI/master/suspicious_files.txt');
    my $ua      = LWP::UserAgent->new( ssl_opts => { verify_hostname => 0 } );
    my $res     = $ua->get($url);
    my $content = $res->decoded_content;
    my @files   = split /\n/, $content;
    for my $file (@files) {
        $file =~ s/'//g;
        my $fileType;
        chomp($file);
        my @arr = glob( $file );
        my $result = FileExists(\@arr);
        next unless( $result );
        use File::Basename;
        my $dirname=dirname($file);
        if ( $dirname ) {
            push @SUMMARY, "> A suspicious file was found within " . WHITE $dirname;
            push @SUMMARY, CYAN "\t\\_ Run: " . MAGENTA "file $file" . CYAN " to get the full name.";
            next;
        }
        my $fStat = lstat($file);
        my $fileType = "file"      unless ( -d $file );
        my $fileType = "directory" unless ( -f $file );
        my ($FileU)  = getpwuid( ( $fStat->uid ) );
        my ($FileG)  = getgrgid( ( $fStat->gid ) );
        my $FileSize = $fStat->size;
        my $ctime    = $fStat->ctime;
        my $isNOTowned;
        if ( $distro eq "ubuntu" ) {
            open( STDERR, '>', '/dev/null' ) if ( ! $debug );
            $isNOTowned = Cpanel::SafeRun::Timed::timedsaferun( 5, 'dpkg', '-S', $file );
            close( STDERR ) if ( ! $debug );
        }
        else {
            $isNOTowned = Cpanel::SafeRun::Timed::timedsaferun( 5, 'rpm', '-qf', $file );
        }
        chomp($isNOTowned);
        my $RPMowned = ( $isNOTowned eq "no path found matching pattern" || $isNOTowned eq "" || $isNOTowned =~ m/not owned by/ ) ? "No" : "Yes";
        my $isImmutable = ( isImmutable($file) ) ? MAGENTA " [IMMUTALBE]" : "";
        my $isELF = check_file_for_elf($file);
        my $ignoreHash = ignoreHashes($sha256only);
        if ($isELF) {
            my $contains_bash = Cpanel::SafeRun::Timed::timedsaferun( 0, 'hexdump', '-C', "$file" );
            if ( $contains_bash =~ m/bin.*bash|<\?php/ ) {
                push @SUMMARY, expand( "> $file contains shell/php code within the header - Found via hexdump -C $file | egrep 'bin.*bash|<\?php'");
            }
            my $sha256 = Cpanel::SafeRun::Timed::timedsaferun( 0, 'sha256sum', "$file" );
            chomp($sha256);
            ($sha256only) = ( split( /\s+/, $sha256 ) )[0];
            my $ignoreHash = ignoreHashes($sha256only);
            vtlink($file) unless ($ignoreHash);
        }
        else {
            push @SUMMARY,
            expand( "> Suspicious $fileType found: "
                  . CYAN $file
                  . $isImmutable
                  . expand( YELLOW "\n\t\\_ Size: "
                  . CYAN $FileSize
                  . YELLOW " Date Changed: "
                  . CYAN scalar localtime($ctime)
                  . YELLOW " PKG Is Owned: "
                  . CYAN $RPMowned
                  . YELLOW " Owned by U/G: "
                  . CYAN $FileU . "/"
                  . $FileG ) );
        }
    }
}

sub check_proc_sys_vm {
    my $sysctl = { map { split( /\s=\s/, $_, 2 ) } split( /\n/, timed_run( 0, 'sysctl', '-a' ) ) };
    if ( defined( $sysctl->{'vm.nr_hugepages'} )
        && $sysctl->{'vm.nr_hugepages'} > 0 )
    {
        push( @SUMMARY,
                "> Found suspicious value for vm.nr_hugepages ["
              . CYAN $sysctl->{'vm.nr_hugepages'}
              . YELLOW "] - Possible cryptominer?" );
    }
    if ( defined( $sysctl->{'net.ipv4.tcp_timestamps'} )
        && $sysctl->{'net.ipv4.tcp_timestamps'} == 0 )
    {
        push( @SUMMARY,
"> Found net.ipv4.tcp_timestamps is disabled - Possible BrickerBot DDoS #malware?"
        );
    }
}

sub known_sha256_hashes {
    my $checksum = shift;
    my $x=grep { /$checksum/ } @knownhashes;
    return 1 if ( grep { /$checksum/ } @knownhashes );
    return 0;
}

sub check_authn_cpanelid {
    my $authn_user='/var/cpanel/authn/links/users/root/root.db';
    return unless( -e $authn_user );
    push( @SUMMARY, "> Found $authn_user file\n\t\\_ This is highly unusual and could indicate a root compromise!");
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
}

sub get_api_tokens {
    my $list_tokensJSON = get_whmapi1( 'api_token_list' );
    my $showHeader=0;
    for my $token_hr ( values %{ $list_tokensJSON->{data}->{tokens} // {} } ) {
        my $expires_at = ( $token_hr->{'expires_at'} ) ? scalar(localtime( $token_hr->{'expires_at'} )) : "Never";
        push @INFO, "> The following API Tokens are present (hopefully you are aware of them)?" unless( $showHeader );
        $showHeader=1;
        push @INFO, expand( CYAN "\t\\_ Token Name: " . GREEN $token_hr->{'name'} . CYAN "  Created: " . GREEN scalar(localtime($token_hr->{'create_time'})) . CYAN "  Expires: " . GREEN $expires_at );
        push @INFO, expand( BLUE "\t\t\\_ACLS:\t" . YELLOW , join(", ", map { "" . $_ } grep { $token_hr->{'acls'}->{$_} } keys %{ $token_hr->{'acls'} // {} }) );
        my $x=join("", map { " " . $_ } grep { $token_hr->{'acls'}->{$_} } keys %{ $token_hr->{'acls'} // {} }), "\n";
        if ( $x =~ m{ all } ) {
            push @INFO, expand( RED "\tDANGER! - The " . GREEN $token_hr->{name} . RED " API Token has the ALL ACL enabled!" );
        }
    }
}

sub check_for_junglesec {
    my $iptables_rules = Cpanel::SafeRun::Timed::timedsaferun( 0, 'iptables', '-L', '-n' );
    my @iptables_rules = split /\n/, $iptables_rules;
    foreach my $IPRule(@iptables_rules) {
        next unless( $IPRule =~ m{dport 64321} );
        if ( $IPRule =~ m{j ACCEPT} ) {
            push( @SUMMARY, "> Port 64321 set to ACCEPT in firewall - evidence of backdoor created by JungleSec Ransomware");
        }
        last;
    }
    my $SearchJungleSec = Cpanel::SafeRun::Timed::timedsaferun( 0, 'find', '/', '-xdev', '-maxdepth', '3', '-name', '*junglesec*', '-print' );
    if ($SearchJungleSec) {
        push( @SUMMARY, "> Found possible JungleSec Ransomware - found several encrypted files with the junglesec extension.");
        push( @SUMMARY, expand( CYAN "\t\\_ Run: " . MAGENTA "find / -xdev -maxdepth 3 -name '*junglesec*'" ) );
    }
}

sub check_for_chaos {
    my $uname_output = Cpanel::SafeRun::Timed::timedsaferun( 4, 'uname', '-a' );
    return unless( $uname_output =~ m/获取失败/ );
    push( @SUMMARY, "> Found possible evidence of Chaos Rootkit" );
    push( @SUMMARY, expand( "\t\\_ uname -a command returned 获取失败 which translates to GET failed and is evidence of this rootkit" ));
}

sub check_for_panchan {
    my $persist=0;
    my $binary=0;
    my $listening_port=0;

    my $check_persist = Cpanel::SafeRun::Timed::timedsaferun( 0, 'systemctl', 'list-units', '--full', '-all' );
    my @check_persist = split( /\n/, $check_persist );
    if ( grep { /systemd-worker.service/ } @check_persist ) {
        $persist=1;
    }

    my $xinetd_files = Cpanel::SafeRun::Timed::timedsaferun( 0, 'find', '/.*', '-maxdepth', '1', '-name', 'xinetd', '-type', 'f' );
    my @xinetd_files = split /\n/, $xinetd_files;
    if ( grep { /xinetd/ } @xinetd_files ) {
        $persist=1;
    }
    my $check_port = Cpanel::SafeRun::Timed::timedsaferun( 0, 'netstat', '-lno' );
    my @check_port = split /\n/, $check_port;
    if ( grep { /1919/ } @check_port ) {
        $listening_port=1;
    }
    if ( $persist && $binary && $listening_port ) {
        push @SUMMARY, "> Found evidence of possible panchan botnet";
        push @SUMMARY, expand( YELLOW "\t\\_ Tests performed:" );
        push @SUMMARY, expand( CYAN "\t\t\\_ systemctl list-units --full -all | grep 'systemd-worker.service'" );
        push @SUMMARY, expand( CYAN "\t\t\\_ find /.* -maxdepth 1 -name xinetd -type f | grep 'xinetd'" );
        push @SUMMARY, expand( CYAN "\t\t\\_ netstat -lno | grep -wq 1919" );
    }
}

sub isImmutable {
    my $FileToCheck = shift;
    return if !-e $FileToCheck;
    return if -l $FileToCheck;
    my $attr = Cpanel::SafeRun::Timed::timedsaferun( 3, '/usr/bin/lsattr', $FileToCheck );
    return 1 if ( $attr =~ m/^\s*\S*[ai]/ );
    return 0;
}

sub chk_md5_htaccess {
    if (! $cpconf{'use_apache_md5_for_htaccess'} ) {
        push @RECOMMENDATIONS, "> Use MD5 passwords with Apache is disabled in Tweak Settings.";
        push @RECOMMENDATIONS, expand( CYAN "\t\\_ Uses Crypt-encoded passwords instead of MD5-encoded passwords.");
        push @RECOMMENDATIONS, expand( CYAN "\t\\_ This limits a maximum of 8 characters which isn't very secure.");
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

sub check_cpupdate_conf {
    return unless my $cpupdate_conf = get_cpupdate_conf();
    my $showHeader = 0;
    if ( $cpupdate_conf->{'UPDATES'} eq "never" ) {
        push @RECOMMENDATIONS, "> Checking the /etc/cpupdate.conf file..."
          unless ($showHeader);
        push @RECOMMENDATIONS,
          expand( CYAN "\t\\_ Automatic cPanel Updates are disabled" );
        $showHeader = 1;
    }
    if ( $cpupdate_conf->{'UPDATES'} eq "manual" ) {
        push @RECOMMENDATIONS, "> Checking the /etc/cpupdate.conf file..."
          unless ($showHeader);
        push @RECOMMENDATIONS,
          expand( CYAN "\t\\_ Automatic cPanel Updates are set to manual" );
        $showHeader = 1;
    }
    if ( $cpupdate_conf->{'RPMUP'} eq "never" ) {
        push @RECOMMENDATIONS, "> Checking the /etc/cpupdate.conf file..."
          unless ($showHeader);
        push @RECOMMENDATIONS, expand( CYAN "\t\\_ Automatic RPM Updates are disabled" );
        $showHeader = 1;
    }
    if ( $cpupdate_conf->{'RPMUP'} eq "manual" ) {
        push @RECOMMENDATIONS, "> Checking the /etc/cpupdate.conf file..."
          unless ($showHeader);
        push @RECOMMENDATIONS,
          CYAN expand( "\t\\_ Automatic RPM Updates are set to manual" );
        $showHeader = 1;
    }
    if ( $cpupdate_conf->{'SARULESUP'} eq "never" ) {
        push @RECOMMENDATIONS, "> Checking the /etc/cpupdate.conf file..."
          unless ($showHeader);
        push @RECOMMENDATIONS,
          expand( CYAN
"\t\\_ Automatic SARULESUP Updates are disabled - SpamAssassin rules might be outdated" );
        $showHeader = 1;
    }
    if ( $cpupdate_conf->{'SARULESUP'} eq "manual" ) {
        push @RECOMMENDATIONS, "> Checking the /etc/cpupdate.conf file..."
          unless ($showHeader);
        push @RECOMMENDATIONS,
          expand( CYAN
"\t\\_ Automatic SARULESUP Updates are set to manual - SpamAssassin rules might be outdated" );
        $showHeader = 1;
    }
}

sub check_apache_modules {
    return if ( !-d "/etc/apache2/modules" );
    my $ApacheMod;
    opendir( APACHEMODS, "/etc/apache2/modules" );
    my @ApacheMods = sort( readdir(APACHEMODS) );
    closedir(APACHEMODS);
    my @OnlyApacheMods;
    my $FoundOne=0;
    my @FoundMod;
    my @OnlyApacheMods;
    if ( $distro eq 'ubuntu' ) {
        open( STDERR, '>', '/dev/null' ) if ( ! $debug );
        my $allApacheMods = Cpanel::SafeRun::Timed::timedsaferun( 5, 'dpkg', '-L', 'ea-apache24' );
        my @allApacheMods = split /\n/, $allApacheMods;
        foreach my $ApacheMod( @allApacheMods ) {
            next unless( $ApacheMod =~ m{modules/mod_} );
            $ApacheMod =~ s{/usr/lib64/apache2/modules/}//g;
            push @OnlyApacheMods, $ApacheMod;
        }
        my $allApacheMods = Cpanel::SafeRun::Timed::timedsaferun( 5, 'dpkg', '-l', "ea-apache24*" );
        my @allApacheMods = split /\n/, $allApacheMods;
        foreach my $ApacheMod( @allApacheMods ) {
            next unless( $ApacheMod =~ m{mod-} );
            $ApacheMod = ( split( /\s+/, $ApacheMod ) )[1];
            $ApacheMod =~ s{ea-apache24-}{}g;
            $ApacheMod =~ s{-}{_}g;
            $ApacheMod .= ".so";
            push @OnlyApacheMods, $ApacheMod;
        }
        close( STDERR ) if ( ! $debug );
        foreach my $line( @ApacheMods ) {
            next if( $line eq "." || $line eq ".." );
            # quick patch to address CPANEL-40756
            if ( $line eq 'mod_evasive24.so' ) {
                $line = 'mod_evasive.so';
            }
            if ( ! grep { m/$line/ } @OnlyApacheMods ) {
                $FoundOne++;
                push @FoundMod, $line . " ";
            }
        }
    }
    else {          ## RPM based
        open( STDERR, '>', '/dev/null' ) if ( ! $debug );
        foreach my $line( @ApacheMods ) {
            next if( $line eq "." || $line eq ".." );
            my $rpmInfo = Cpanel::SafeRun::Timed::timedsaferun( 2, 'rpm', '-qf', "/etc/apache2/modules/$line" );
            if ( $rpmInfo =~ m{not owned} ) {
                $FoundOne++;
                push @FoundMod, $line . " ";
            }
        }
        close( STDERR ) if ( ! $debug );
    }

    if ($FoundOne > 0) {
        push( @SUMMARY, expand( "> Found an Apache module in /etc/apache2/modules that is not owned by any package.\n\t\\_ " . CYAN "Should be investigated " . MAGENTA @FoundMod));
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

sub ignoreHashes {
    my $HashToIgnore  = shift;
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
    my $UNP_backdoors = Cpanel::SafeRun::Timed::timedsaferun( 0, 'find', '-L', '/usr/local/cpanel/base/unprotected/', '-name', '*.php', '-print' );
    if ($UNP_backdoors) {
        my @UNP_backdoors = split "\n", $UNP_backdoors;
        push @SUMMARY, "> Found suspicious PHP files (possible backdoor) in /usr/local/cpanel/base/unprotected";
        foreach $UNP_backdoors (@UNP_backdoors) {
            chomp($UNP_backdoors);
            vtlink($UNP_backdoors);
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
            get_last_logins_WHM($lcReseller);
            get_session_logins($lcReseller . ':');
            get_whm_terminal_logins($lcReseller);
            get_last_logins_SSH($lcReseller);
            check_secure_log($lcReseller);
            get_root_pass_changes($lcReseller);
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
    return 1 if ($whichPS);
    push @SUMMARY,
        '> '
      . CYAN
      . 'ps command is missing (checked for /usr/bin/ps and /bin/ps)'
      . YELLOW ' - Could indicate a possible root-level compromise';
    return 0;
}

sub check_for_yara {
    return 1 if ( -e "/usr/local/bin/yara" );
    if ( $cron ) {
        logit( 'Yara engine not installed, skipping Yara scans' );
        return 0;       ## Don't ask to install Yara engine if running via cron
    }
    my $continue_yara_install = "Yara engine not installed, OK to install?";
    if (
        !IO::Prompt::prompt(
            $continue_yara_install . " [y/N]: ",
            -default => 'n',
            -yes_no
        )
      )
    {
        print_status("User opted to NOT install Yara!");
        logit("User aborted Yara install");
        return 0;
    }
    my $yara_headers =
      Cpanel::SafeRun::Timed::timedsaferun( 30, 'curl', '-sL', '-4', '--head',
        'https://github.com/VirusTotal/yara/releases/latest' );
    my @yara_headers = split /\n/, $yara_headers;
    my $yara_version;
    foreach my $line (@yara_headers) {
        chomp($line);
        next unless ( $line =~ m/Location:/i );
        my ($yara_url) = ( split( /\s+/, $line ) )[1];
        $yara_version = ( split( /\//, $yara_url ) )[-1];
        last;
    }
    if ( !$yara_version ) {
        print_status(
            "Could not obtain latest Yara version - Installation failed!");
        logit("Couldn't obtain lastest Yara version");
        return 0;
    }
    chomp($yara_version);
    print_status("Downloading latest version of Yara [$yara_version]...");
    logit("Downloading latest Yara tarball");
    chdir("$csidir");
    my $download_yara = Cpanel::SafeRun::Timed::timedsaferun( 30, 'wget', '-q',
        "https://github.com/VirusTotal/yara/archive/$yara_version.tar.gz" );
    if ( -e "$csidir/$yara_version.tar.gz" ) {
        print_status("Extracting Yara tarball...");
        logit("Extracting Yara tarball");
        my $extract_tarball =
          Cpanel::SafeRun::Timed::timedsaferun( 20, 'tar', 'xzf',
            "$csidir/$yara_version.tar.gz" );
        $yara_version =~ s/v//g;
        if ( -d "$csidir/yara-$yara_version" ) {
            chdir("$csidir/yara-$yara_version");
            print_status("Installing Yara - patience is a virtue...");
            logit("Installing Yara");
            spin();
            print "Running bootstrap.sh\n" unless ( !$debug );
            my $install_yara =
              Cpanel::SafeRun::Timed::timedsaferun( 60,
                "./bootstrap.sh 2>&1 > /dev/null" )
              unless ($debug);
            my $install_yara =
              Cpanel::SafeRun::Timed::timedsaferun( 60, "./bootstrap.sh" )
              unless ( !$debug );
            spin();
            print "Running configure\n" unless ( !$debug );
            my $install_yara =
              Cpanel::SafeRun::Timed::timedsaferun( 60,
                "./configure 2>&1 > /dev/null" )
              unless ($debug);
            my $install_yara =
              Cpanel::SafeRun::Timed::timedsaferun( 60, "./configure" )
              unless ( !$debug );
            spin();
            print "Running make\n" unless ( !$debug );
            my $install_yara =
              Cpanel::SafeRun::Timed::timedsaferun( 60,
                "make 2>&1 > /dev/null" )
              unless ($debug);
            my $install_yara =
              Cpanel::SafeRun::Timed::timedsaferun( 60, "make" )
              unless ( !$debug );
            spin();
            print "Running make install\n" unless ( !$debug );
            my $install_yara =
              Cpanel::SafeRun::Timed::timedsaferun( 60,
                "make install 2>&1 > /dev/null" )
              unless ($debug);
            my $install_yara =
              Cpanel::SafeRun::Timed::timedsaferun( 60, "make install" )
              unless ( !$debug );
            spin();
            print "Running make check\n" unless ( !$debug );
            my $install_yara =
              Cpanel::SafeRun::Timed::timedsaferun( 60,
                "make check 2>&1 > /dev/null" )
              unless ($debug);
            my $install_yara =
              Cpanel::SafeRun::Timed::timedsaferun( 60, "make check" )
              unless ( !$debug );
            spin();

            if ( !-e "/etc/ld.so.conf.d/yaralib.conf" ) {
                print "Creating /etc/ld.so.conf.d/yaralib.conf\n"
                  unless ( !$debug );
                Cpanel::SafeRun::Timed::timedsaferun( 40, 'echo',
                    '/usr/local/lib', '>', '/etc/ld.so.conf.d/yaralib.conf' );
                print "Running ldconfig\n" unless ( !$debug );
                Cpanel::SafeRun::Timed::timedsaferun( 40, 'ldconfig' );
            }
            if ( -e "/usr/local/bin/yara" ) {
                print_header("Yara successfully installed!");
                logit("Yara install successful");
                return 1;
            }
            else {
                print_header("Yara install failed!");
                logit("Yara install failed");
                return 0;
            }
        }
        else {
            print_header("Extraction failed!");
            logit("Yara extraction failed");
            return 0;
        }
    }
    else {
        print_header("Download failed!");
        logit("Yara download failed");
        return 0;
    }
}

sub check_for_suspicious_user {
    my @users_to_lookfor=qw( ferrum darmok cokkokotre1 akay phishl00t o monerodaemon suhelper sudev jewbags );
    foreach my $user(@users_to_lookfor) {
        chomp($user);
        open( STDERR, '>', '/dev/null' ) if ( ! $debug );
        my $id_found = Cpanel::SafeRun::Timed::timedsaferun( 5, 'id', $user );
        close( STDERR ) if ( ! $debug );
        if ( $id_found ) {
            push @SUMMARY, "> Found suspicious user " . CYAN $user . YELLOW " in /etc/passwd file.";
        }
    }
}

sub check_hosts_file {
    return unless ( -e "/etc/hosts" );
    if ( open( my $fh, '<', '/etc/hosts' ) ) {
        my $showHeader = 0;
        while (<$fh>) {
            if ( $_ =~
m/localhost blockchain.info|localhost 100.100.25.3 jsrv.aegis.aliyun.com|localhost 100.100.25.4 update.aegis.aliyun.co|localhost 185.164.72.119|localhost pinto.mamointernet.icu|localhost lsd.systemten.org|localhost ix.io|fuck you "sic"/
              )
            {
                push @SUMMARY,
"> Possible crypto malware on this server (suspicious entries found in /etc/hosts file"
                  unless ($showHeader);
                $showHeader = 1;
            }
        }
    }
}

sub check_etc_files {
    my @susp_users = qw( gh0stx sclipicibosu mexalzsherifu Aut0m );
    return unless ( -e '/etc/group' ) ;    ## If this is true, you have more serious problems.
    my @dirs = qw( /etc /etc/sudoers.d );
    my @files = qw( group passwd sudoers );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            my $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
                open( my $fh, '<', "$dir/$file" );
                while ( <$fh> ) {
                    foreach my $susp_user (@susp_users) {
                        chomp($susp_user);
                        if ( $_ =~ m{$susp_user} ) {
                            push @SUMMARY, "> Found suspicious user in $dir/$file - " . CYAN $susp_user;
                        }
                    }
                }
                close( $fh );
            }
        }
    }
}

sub check_binaries_for_shell {
    my @binaries =
      qw( /bin/ping /usr/bin/crontab /usr/bin/newgrp /usr/bin/pkexec /bin/su /usr/bin/quota );
    foreach my $binary (@binaries) {
        my $isELF = check_file_for_elf($binary);
        next unless ($isELF);
        my $contains_bash =
          Cpanel::SafeRun::Timed::timedsaferun( 0, 'hexdump', '-C', "$binary" );
        if ( $contains_bash =~ m/bin.*bash|<\?php/ ) {
            push @SUMMARY,
"> The $binary program contains hidden malware in header (hexdump -C $binary | egrep 'bin.*bash|<\?php')";
        }
    }
}

sub _init_run_state {
    return if defined $RUN_STATE;
    $RUN_STATE = {
        STATE => 0,
        type  => {
            cptech => 1 << 0,
        },
    };
    return 1;
}

sub _set_run_type {
    my ($type) = @_;
    print STDERR "Runtime type ${type} doesn't exist\n" and return
      unless exists $RUN_STATE->{type}->{$type};
    return $RUN_STATE->{STATE} |= $RUN_STATE->{type}->{$type};
}

sub iam {    ## no critic (RequireArgUnpacking)
    my $want = 0;
    grep {
        return 0 unless exists $RUN_STATE->{type}->{$_};
        $want |= $RUN_STATE->{type}->{$_}
    } @_;
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

sub check_for_ncom_rootkit {
    return if !-e "/etc/ld.so.preload";
    return if -e "/lib/libgrubd.so";
    my @strings =
      qw( libncom libselinux drop_suidshell_if_env_is_set shall_stat_return_error is_readdir64_result_invisible is_readdir_result_invisible drop_dupshell is_file_invisible);
    if ( -e '/lib64/libncom.so.4.0.1' || -e '/lib64/libselinux.so.4' ) {
        my $load_preload = Cpanel::SafeRun::Timed::timedsaferun( 0, 'strings',
            '/etc/ld.so.preload' );
        my @load_preload = split /\n/, $load_preload;
        foreach my $preload (@load_preload) {
            chomp($preload);
            if ( grep { /$preload/ } @strings ) {
                push( @SUMMARY,
expand( "\t\\_ /etc/ld.so.preload contains evidence of NCOM rootkit [ "
                      . CYAN $preload
                      . " ]" ) );
            }
        }
    }
}

sub check_env_for_susp_vars {
    my @env = Cpanel::SafeRun::Timed::timedsaferun( 0, 'env' );
    if ( grep { /HIDE_THIS_SHELL/ } @env ) {
        push @SUMMARY, "> Found HIDE_THIS_SHELL environment variable. Could indicate presence of the Azazel Rootkit";
    }
    if ( grep { /I_AM_HIDDEN/ } @env ) {
        push @SUMMARY, "> Found I_AM_HIDDEN environment variable. Could indicate presence of the Hiddenwasp Rootkit";
    }
    if ( grep { /HTTP_SETTHIS/ } @env ) {
        push @SUMMARY, "> Found HTTP_SETTHIS environment variable. Could indicate presence of the Symbiote Rootkit";
    }
    if ( grep { /AAZHDE/ } @env ) {
        push @SUMMARY, "> Found AAZHDE environment variable. Could indicate presence of the perfcc/perfctl coin miner";
    }
}

sub check_for_perfcc {
    my @suspfiles = qw( '*/.local/bin/ldd', '*/.local/bin/lsof', '*/.local/bin/top', '*/.local/bin/crontab' );
    my @suspfound;
    my $findit=Cpanel::SafeRun::Timed::timedsaferun( 0, 'find', $HOMEDIR, '-type', 'd', '-iwholename', '*/.local/bin' );
    return unless( $findit );
    push @suspfound, $findit if ( $findit );
    my $findit=Cpanel::SafeRun::Timed::timedsaferun( 0, 'find', $HOMEDIR, '-type', 'f', '-iwholename', '*/.local/bin/ldd' );
    push @suspfound, $findit if ( $findit );
    my $findit=Cpanel::SafeRun::Timed::timedsaferun( 0, 'find', $HOMEDIR, '-type', 'f', '-iwholename', '*/.local/bin/lsof' );
    push @suspfound, $findit if ( $findit );
    my $findit=Cpanel::SafeRun::Timed::timedsaferun( 0, 'find', $HOMEDIR, '-type', 'f', '-iwholename', '*/.local/bin/top' );
    push @suspfound, $findit if ( $findit );
    my $findit=Cpanel::SafeRun::Timed::timedsaferun( 0, 'find', $HOMEDIR, '-type', 'f', '-iwholename', '*/.local/bin/crontab' );
    push @suspfound, $findit if ( $findit );
    my $x=@suspfound;
    if ( $x > 1 ) {
        push @SUMMARY, "> Found evidence of the Perf.cc/Perfctl malware: ";
        foreach my $suspfile(@suspfound) {
            chomp($suspfile);
            push @SUMMARY, expand( CYAN "\t\\_ $suspfile" );
        }
    }
}

sub check_for_xbash {
    return if( ! -f '/etc/my.cnf' );
    my $XBash_Table;
    my $RansomwareNote;
    my ( %mycnf_variables, $mycnf_key, $mycnf_value );
    open( my $fh, '<', '/etc/my.cnf' );
    while( <$fh> ) {
        next if( substr( $_, 0,1 ) eq "#" || substr( $_, 0,1 ) eq "[" );
        next if( $_ eq "" );
        ($mycnf_key, $mycnf_value ) = ( split( /=/, $_ ) );
        chomp($mycnf_value);
        next if ( $mycnf_key eq "" or $mycnf_value eq "" );
        $mycnf_variables{$mycnf_key} = $mycnf_value;
    }
    close($fh);
    my $mysql_datadir = ( defined $mycnf_variables{'datadir'} ) ? $mycnf_variables{'datadir'} : '/var/lib/mysql';
    if ( -d $mysql_datadir ) {
        opendir( my $dh, $mysql_datadir );
        my @mysql_databases = readdir($dh);
        closedir $dh;
        foreach my $database (@mysql_databases) {
            chomp $database;
            next unless ( $database =~ m/PLEASE_READ|README_TO_RECOVER|GODRANSOM/ );
            push( @SUMMARY, "> Possible Xbash variant ransomware detected. Database's missing? Database " . CYAN $database . YELLOW " exists!" );
            if ( -e '/run/mysqld/mysqld.pid' ) {
                $XBash_Table = Cpanel::SafeRun::Timed::timedsaferun( 6, 'mysql', '-BNe', "SHOW TABLES FROM $database;" );
                chomp($XBash_Table);
                if ($XBash_Table) {
                    $RansomwareNote = Cpanel::SafeRun::Timed::timedsaferun( 6, 'mysql', '-BNe', "SELECT * FROM $database.$XBash_Table;" );
                    if ($RansomwareNote) {
                        chomp($RansomwareNote);
                        push( @SUMMARY, expand( CYAN "\t\\_ Ransomeware Note: $RansomwareNote" ) );
                    }
                }
            }
        }
    }
}

sub check_for_cronRAT {

    # check for evidence of cronRAT - https://sansec.io/research/cronrat
    my @dirs = qw( /dev/shm /tmp /var/tmp );
    my @files = qw( www-shared server-worker-shared sql-shared php-shared systemd-user.lock php.lock php-fpm.lock www-server.lock php_sess_RANDOM zend_cache___RANDOM php_cache www_cache worker_cahce logo_edited_DATE.png user_edited_DATE.css custom_edited_DATE.css );
    # Yes, the misspelling of worker_cahce is intentional :)
    my $fullpath;
    my $fullstat;
    my $showHeader=0;
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            $fullpath = $dir . "/" . $file;
            open( STDERR, '>', '/dev/null' ) if ( ! $debug );
            ($fullstat) = Cpanel::SafeRun::Timed::timedsaferun( 2, 'stat', $fullpath );
            close( STDERR ) if ( ! $debug );
            next unless( $fullstat );
            my @fullstat = split /\n/, $fullstat;
            foreach my $line( @fullstat ) {
                next unless( $line =~ m{File:} );
                my ( $foundPath ) = ( split( /\s+/, $line ))[2];
                chomp($foundPath);
                push @SUMMARY, "> Suspicious files found: possible cronRAT exploit." unless( $showHeader );
                push @SUMMARY, expand( "\t\\_ See: https://sansec.io/research/cronrat" ) unless( $showHeader );
                $showHeader=1;
                push @SUMMARY, expand( CYAN "\t \\_ " . $fullpath . " exists" ) unless ( !$fullpath );
            }
        }
    }

    for my $file( @files ) {
        chomp($file);
        my $found = Cpanel::SafeRun::Timed::timedsaferun( 0, 'find', '/run/user', '-iname', $file, '-print' );
        if ( $found ) {
            push @SUMMARY, "> Suspicious files found: possible cronRAT exploit." unless( $showHeader );
            push @SUMMARY, expand( "\t\\_ See: https://sansec.io/research/cronrat" ) unless( $showHeader );
            chomp( $found );
            push @SUMMARY, expand( CYAN "\t \\_ " . $found . " exists" );
        }
    }

    my @globfiles = glob( '/proc/*/environ' );
    my $searchstring = 'LD_L1BRARY_PATH';
    my $showHeader=0;
    foreach my $environ_proc(@globfiles) {
        chomp($environ_proc);
        my $found = Cpanel::SafeRun::Timed::timedsaferun( 4, 'grep', '--text', $searchstring, $environ_proc );
        if ( $found ) {
            push( @SUMMARY, "> Suspicious process(es) found: possible cronRAT exploit." ) unless( $showHeader );
            $showHeader=1;
            push( @SUMMARY, expand( CYAN "\t \\_ " . $found ) ) unless ( !$found );
        }
    }
}

sub get_hashes {
    my $url      = URI->new( 'https://raw.githubusercontent.com/CpanelInc/tech-CSI/master/known_256hashes.txt');
    my $ua      = LWP::UserAgent->new( ssl_opts => { verify_hostname => 0 } );
    my $res     = $ua->get($url);
    return $res->decoded_content;
}

sub check_for_cve_vulnerabilities {
    my $url = URI->new( 'https://raw.githubusercontent.com/CpanelInc/tech-CSI/master/cve_data.json');
    my $ua;
    my $res;
    my $CVEDATA;
    my @CVEDATA;
    $ua  = LWP::UserAgent->new( ssl_opts => { verify_hostname => 0 } );
    $res = $ua->get($url);
    $CVEDATA  = $res->decoded_content;
    @CVEDATA  = split /\n/, $CVEDATA;
    open( my $fh, '>', "$csidir/cve_data.json" );
    foreach my $line(@CVEDATA) {
        chomp($line);
        print $fh $line . "\n";
    }
    close( $fh );
    my $data;
    if ( open ( my $json_stream, "$csidir/cve_data.json" ) ) {
        local $/ = undef;
        my $json = JSON::PP->new;
        $data = $json->decode(<$json_stream>);
        close($json_stream);
    }
    my $showHeader=0;
    foreach my $line( @{ $data } ) {
        my $pkg = $line->{Package_Name};
        my $cve = $line->{CVE_ID};
        my $patchedver = $line->{Patched_Version};
        my $firstvuln = $line->{First_Vulnerable_Version};
        my $os_vuln = $line->{OS_Vulnerable};

        if ( is_os_vulnerable( $os_vuln ) ==0 ) {
            print CYAN "Skipping " . YELLOW $pkg . CYAN " checks because this OS is " . GREEN "NOT vulnerable\n" if ( $debug );
            next;
        }

        # Check if package is installed
        print CYAN "Checking if " . YELLOW $pkg . " is installed: " if ( $debug );
        my $installed = is_installed( $pkg );
        my $is_installed = ( $installed ) ? "Yes" : "No";
        print GREEN $is_installed . "\n" if ( $debug );
        next unless( $installed );

        # Check if package is kernel or linux-headers (if so, uname -r must be added)
        print CYAN "Checking if " . YELLOW $pkg . " is a kernel/linux-header package: " if ( $debug );
        my $pkg1 = is_kernel( $pkg );        ## Checks to see if $pkg is a kernel or linux-headers pacakge!
        my $is_kernel = ( $pkg1 =~ m{kernel|linux-header} ) ? "Yes" : "No";
        print GREEN $is_kernel . "\n" if ( $debug );
        $pkg=$pkg1;

        # If we get here, it is installed, now get the version number
        print CYAN "Getting version number of " . YELLOW $pkg . ": " if ( $debug );
        chomp( my $pkgver = get_pkg_version( $pkg ) );
        my $digitpkgver = digit_to_alpha( $pkgver ) // '' if ( $pkg =~ m{openssl} && $pkgver < 3);
        chomp( $pkgver );

        # report first vulnerable version (if verbose or debug is enabled)
        my $alphapkgver = alpha_to_digit( $firstvuln ) // '' if ( $pkg =~ m{openssl} && $pkgver < 3);

        # check changelog for the CVE
        my $found_in_changelog = found_in_changelog( $pkg, $cve );
        next unless( ! $found_in_changelog );

        # check version against the nonvuln variable
        my $op='>';
        chomp($pkgver);
        chomp($patchedver);
        next if ( version_compare( $pkgver, $op, $patchedver ) );

        # check to see if version is less than the firstvuln variable
        my $op2='<';
        chomp($firstvuln);
        next if ( version_compare( $pkgver, $op2, $firstvuln ) );

        #print "DEBUG: pkg=$pkg / pkgver=$pkgver / firstvuln=$firstvuln / patchedver=$patchedver\n";
        push @SUMMARY, "> The following packages might be vulnerable to known CVE's" unless( $showHeader );
        $showHeader=1;
        push @SUMMARY, expand( CYAN "\t\\_ $pkg is Vulnerable to $cve" );
        push @SUMMARY, expand( GREEN "\t\\_ The following check was used to verify this");
        if ( $distro eq 'ubuntu' ) {
            push @SUMMARY, expand( YELLOW "\t\\_ zgrep -E '" . $cve . "' /usr/share/doc/" .  $pkg . "/changelog.Debian.gz");
        }
        else {
            push @SUMMARY, expand( YELLOW "\t\\_ rpm -q --changelog " . $pkg . " | grep -E '" . $cve ."'");
            push @SUMMARY, expand( CYAN "\t\\_ This check does NOT take corrupt RPM dbs into account, and CAN report false-positive results if corrupt.");
        }
        push @SUMMARY, expand( BOLD BLUE "\t-----" );
    }
}

sub is_os_vulnerable {
    my $tcOSData = shift;
    my @tcOSData = split /\s+/, $tcOSData;
    my $os_vulnerable=0;
    if ( $tcOSData eq 'ALL' ) {
        return 1;
    }
    foreach my $tcOSLine(@tcOSData) {
        chomp($tcOSLine);
        my ( $tcOSDist,$tcOSVer ) = (split( /\-/, $tcOSLine ));
        chomp( $tcOSDist);
        chomp( $tcOSVer);
        my $op='>=';
        if ( $distro eq $tcOSDist ) {
            if ( version_compare( $distro_version, $op, $tcOSVer) ) {
                $os_vulnerable=1;
                last;
            }
        }
    }
    return $os_vulnerable;
}

sub digit_to_alpha {
    my $tcPkgVer = shift;
    return unless ( $tcPkgVer =~ /(\d+)\.(\d+)\.(\d+)([a-z])([a-z]?)/ );
    my $retPkgVer;
    my ( $maj, $min, $patch ) = ( $1, $2, $3 );
    # If we map the alphas into a number and sum the values the version will be compatible with version_compare()
    # and save us a lot of trouble, i.e. h=8, m=13, and za=27
    my %al2num = map { ( "a" .. "z" )[ $_ - 1 ] => $_ } ( 1 .. 26 );
    my $sub = 0;
    if ($4) { $sub += $al2num{ lc($4) } }
    if ($5) { $sub += $al2num{ lc($5) } }
    $retPkgVer = join( '.', $maj, $min, $patch, $sub );
    return $retPkgVer;
}

sub alpha_to_digit {
    my $tcPkgVer = shift;
    my @letters = ( "a" .. "z" );
    my $retPkgVer;
    my ( $maj, $min, $patch, $sub ) = ( split( /\./, $tcPkgVer ) );
    my $sub1 = $letters[ $sub - 1 ];
    $retPkgVer = join( '.', $maj, $min, $patch );
    $retPkgVer .= $sub1;
}

sub is_kernel {
    my $tcPkg = shift;
    if ( $tcPkg =~ m{kernel|linux-headers} ) {
        open( STDERR, '>', '/dev/null' ) if ( ! $debug );
        my $uname = Cpanel::SafeRun::Timed::timedsaferun( 0, 'uname', '-r' );
        close( STDERR ) if ( ! $debug );
        chomp($uname);
        if ( $distro eq 'ubuntu' ) {
            $tcPkg="linux-headers-$uname";
        }
        else {
            $tcPkg="kernel-$uname";
        }
        $gl_is_kernel=1;
    }
    return $tcPkg;
}

sub found_in_changelog {
    my $tcPkg = shift;
    my $tcCVE = shift;
    my $in_chglog=0;
    my $in_chglog1=0;
    if ($distro eq 'ubuntu' ) {
        if ( ! -f "/usr/share/doc/$tcPkg/changelog.Debian.gz" ) {
            print RED "\n\t\\_ WARNING! - /usr/share/doc/$tcPkg/changelog.Debian.gz IS MISSING!!! - ";
            $in_chglog1=0;
            return $in_chglog;
        }
        else {
            open( STDERR, '>', '/dev/null' ) if ( ! $debug );
            $in_chglog1 = ( Cpanel::SafeRun::Timed::timedsaferun( 0, 'zgrep', '-E', "$tcCVE", "/usr/share/doc/$tcPkg/changelog.Debian.gz" ) ) ? 1 : 0;
            close( STDERR ) if ( ! $debug );
            $in_chglog=1 unless( $in_chglog1 == 0 );
            return $in_chglog;
        }
    }
    else {
        open( STDERR, '>', '/dev/null' ) if ( ! $debug );
        $in_chglog1 = Cpanel::SafeRun::Timed::timedsaferun( 0, 'rpm', '-q', "$tcPkg", '--changelog' );
        close( STDERR ) if ( ! $debug );
        $in_chglog = ( grep { /$tcCVE/ } $in_chglog1 ) ? 1 : 0;
        return $in_chglog;
    }
    if ( $in_chglog == 0 && $gl_is_kernel == 1 ) {
        return $in_chglog unless( -x '/usr/bin/kcarectl' );
        print BOLD GREEN "\n\t\\_ Not found via regular changelog, KernelCare detected - Checking with --patch-info: " if ( $debug );
        open( STDERR, '>', '/dev/null' ) if ( ! $debug );
        my $patchinfo = Cpanel::SafeRun::Timed::timedsaferun(3, 'kcarectl', '--patch-info' );
        close( STDERR ) if ( ! $debug );
        my @patchinfo = split /\n/, $patchinfo;
        my $in_chglog = ( grep { /$tcCVE/ } @patchinfo ) ? 1 : 0;
        return $in_chglog;
    }
    #return $in_chglog;
}

sub is_installed {
    my $tcPkg = shift;
    my $is_installed=0;
    my $pkgversion=0;
    if ( $distro eq 'ubuntu' ) {
        open( STDERR, '>', '/dev/null' ) if ( ! $debug );
        my $installed_package=Cpanel::SafeRun::Timed::timedsaferun( 0, 'dpkg-query', '-W', '-f=${binary:Package}\n', $tcPkg );
        close( STDERR ) if ( ! $debug );
        if ( $installed_package ) {
            $is_installed=1;
        }
        return $is_installed;
    }
    else {
        open( STDERR, '>', '/dev/null' ) if ( ! $debug );
        my $is_installed1=Cpanel::SafeRun::Timed::timedsaferun( 0, 'rpm', '-q', $tcPkg );
        close( STDERR ) if ( ! $debug );
        chomp($is_installed1);
        my $is_installed = ! grep { /is not installed/ } $is_installed1;
        return $is_installed;
    }
}

sub get_pkg_version {
    my $tcPkg = shift;
    my $pkgversion;
    if ( $distro eq 'ubuntu' ) {
        open( STDERR, '>', '/dev/null' ) if ( ! $debug );
        $pkgversion=Cpanel::SafeRun::Timed::timedsaferun( 0, 'dpkg-query', '-W', '-f=${Version}\n', "$tcPkg" );
        close( STDERR ) if ( ! $debug );
    }
    else {
        open( STDERR, '>', '/dev/null' ) if ( ! $debug );
        $pkgversion=Cpanel::SafeRun::Timed::timedsaferun( 0, 'rpm', '-q', '--queryformat', '%{Version}-%{Release}', $tcPkg );
        close( STDERR ) if ( ! $debug );
    }
    if ( $gl_is_kernel == 0 ) {
        $pkgversion =~ s/$tcPkg//g;
    }
    chomp($pkgversion);
    $pkgversion =~ s/$tcPkg//g;
    $pkgversion =~ s/^\.\.//;
    $pkgversion =~ s/^\-\-//;
    $pkgversion =~ s/\-/\./g;
    $pkgversion =~ s/(\.x86_64|\.cpanel|\.cloudlinux|\.deb.*|\.noarch|.1ubuntu.*|ubuntu.*|\.cp\d+.*|\.el.*|\+.*)//g;

    return $pkgversion;
}

sub version_compare {
    # example: return if version_compare($ver_string, qw( >= 1.2.3.3 ));
    # Must be no more than four version numbers separated by periods and/or underscores.
    my ( $ver1, $mode, $ver2 ) = @_;
    return if ( !defined($ver1) || ( $ver1 =~ /[^\._0-9]/ ) );
    return if ( !defined($ver2) || ( $ver2 =~ /[^\._0-9]/ ) );
    # Shamelessly copied the comparison logic out of Cpanel::Version::Compare
    my %modes = (
        '>' => sub {
            return if $_[0] eq $_[1];
            return _version_cmp(@_) > 0;
        },
        '<' => sub {
            return if $_[0] eq $_[1];
            return _version_cmp(@_) < 0;
        },
        '==' => sub { return $_[0] eq $_[1] || _version_cmp(@_) == 0; },
        '!=' => sub { return $_[0] ne $_[1] && _version_cmp(@_) != 0; },
        '>=' => sub {
            return 1 if $_[0] eq $_[1];
            return _version_cmp(@_) >= 0;
        },
        '<=' => sub {
            return 1 if $_[0] eq $_[1];
            return _version_cmp(@_) <= 0;
        }
    );
    return if ( !exists $modes{$mode} );
    return $modes{$mode}->( $ver1, $ver2 );
}

sub _version_cmp {
    my ( $first, $second ) = @_;
    my ( $a1,    $b1, $c1, $d1, $e1, $f1 ) = split /[\._]/, $first;
    my ( $a2,    $b2, $c2, $d2, $e2, $f2 ) = split /[\._]/, $second;
    for my $ref ( \$a1, \$b1, \$c1, \$d1, \$e1, \$f1, \$a2, \$b2, \$c2, \$d2, \$e2, \$f2,) {    # Fill empties with 0
        $$ref = 0 unless defined $$ref;
    }
    return $a1 <=> $a2 || $b1 <=> $b2 || $c1 <=> $c2 || $d1 <=> $d2 || $e1 <=> $e2 || $f1 <=> $f2;
}

sub get_suspicious_cron_strings {
    my $url = URI->new( 'https://raw.githubusercontent.com/CpanelInc/tech-CSI/master/suspicious_cron_strings.txt');
    my $ua = LWP::UserAgent->new( ssl_opts => { verify_hostname => 0 } );
    my $res       = $ua->get($url);
    my $susp_cron_strings = $res->decoded_content;
    my @susp_cron_strings = split /\n/, $susp_cron_strings;
    return \@susp_cron_strings;
}

sub check_for_cve_2021_4034 {
    my $authlog;
    if ( $distro eq 'ubuntu' ) {
        $authlog = '/var/log/auth.log';
    }
    else {
        $authlog = '/var/log/secure';
    }
    open( my $fh, '<', $authlog);
    while( <$fh> ) {
        if ( $_ =~ m{The value for the SHELL variable was not found the /etc/shells file} ) {
            push @SUMMARY, "> Found possible root compromise using CVE-2021-4034";
            push @SUMMARY, expand( "\t\\_ The string " . CYAN "The value for the SHELL variable was not found the /etc/shells file" . YELLOW " was found in the $authlog file" );
            last;
        }
    }
    close($fh);
}

sub check_lsof_deleted {
    my @suspicious_binaries = qw( memfd perfctl );
    my $lsof = Cpanel::SafeRun::Timed::timedsaferun( 0, 'lsof' );
    my @lsof = split /\n/, $lsof;
    my $showHeader=0;
    foreach my $line(@lsof) {
        next unless( $line =~ m{(deleted)} );
        foreach my $suspbin(@suspicious_binaries) {
            if ( $line =~ m/$suspbin/ ) {
                next if ( $line =~ m{dbus-brok} );
                push @SUMMARY, "> Found deleted files/binaries running in memory that could be suspicious" unless( $showHeader );
                $showHeader=1;
                push @SUMMARY, "\t\\_  $line";
            }
        }
    }
}

sub check_for_bpfdoor {
    my $has_packet_recvmsg = Cpanel::SafeRun::Timed::timedsaferun( 0, 'grep', 'packet_recvmsg', "/proc/*/stack" );
    push @SUMMARY, "> Found evidence of possible BPFDoor hack $has_packet_recvmsg" if( $has_packet_recvmsg );
    my $wait_for_more_packets = Cpanel::SafeRun::Timed::timedsaferun( 0, 'grep', 'wait_for_more_packets', "/proc/*/stack" );
    push @SUMMARY, "> Found evidence of possible BPFDoor hack $wait_for_more_packets" if( $wait_for_more_packets );
    my $start_port=42391;
    my $end_port=43391;
    my $chk_iptables = Cpanel::SafeRun::Timed::timedsaferun( 0, 'iptables', '-L', '-n' );
    my @chk_iptables = split /\n/, $chk_iptables;
    while( $start_port <= $end_port ) {
        if ( grep { /$start_port/ } @chk_iptables ) {
            push @SUMMARY, "> Found evidence of possible BFPDoor hack $chk_iptables";
        }
        $start_port++;
    }
}

sub check_for_susp_rc_modules {
    return unless( -s '/etc/rc.modules' );
    if ( -d '/etc/rc.modules/' ) {
        push @SUMMARY, "> /etc/rc.modules is a directory - please check contents manually!\n";
        return;
    }
    my @ignore = qw( acpiphp ip_conntrack_ftp );
    my $line;
    open( my $fh, '<', '/etc/rc.modules' );
    while ( <$fh> ) {
        $line = $_;
        chomp($line);
        my $showHeader=0;
        next if ( grep { $line =~ $_ } @ignore );
        push @SUMMARY, "> Possible rootkit presence in /etc/rc.modules file - contains suspicious entry." unless($showHeader);
        $showHeader=1;
        push @SUMMARY, "\t\\_ $line";
    }
    close( $fh );
}

sub check_for_lkm_rootkits {
    my @lookfor=qw( reptile_module diamorphine sysinitd );
    foreach my $lkm(@lookfor) {
        chomp($lkm);
        my $lsmod=Cpanel::SafeRun::Timed::timedsaferun( 0, 'lsmod' );
        my @lsmod=split /\n/,$lsmod;
        foreach my $lsmod_line(@lsmod) {
            chomp( $lsmod_line );
            my ( $lsmodule ) = (split( /\s+/, $lsmod_line ));
            if ( $lsmodule =~ m{$lkm} ) {
                push @SUMMARY, "> Found evidence of possible LKM rootkit " . MAGENTA $lkm . YELLOW " module loaded.";
            }
        }
    }
}

sub check_dev_shm_for_elf {
    my @searchfor=qw( ELF script );
    my $findcmd = Cpanel::SafeRun::Timed::timedsaferun( 0, 'find', "/dev/shm", '-type', 'f' );
    chomp($findcmd);
    my @findcmd = split /\n/, $findcmd;
    foreach my $foundline(@findcmd) {
        my $filetype=Cpanel::SafeRun::Timed::timedsaferun( 0, 'file', '-p', $foundline );
        chomp($filetype);
        foreach my $searchstring (@searchfor) {
            chomp($searchstring);
            if ( $filetype =~ m/$searchstring/ ) {
                push @SUMMARY, "> The " . CYAN $foundline . YELLOW " file is of the type " . MAGENTA $searchstring . YELLOW " and should be investigated.";
            }
        }
    }
}

sub check_auth_keys_for_commands {
    my @searchfor=qw( authorized_keys authorized_keys2 *id_*.pub );
    foreach my $search(@searchfor) {
        chomp($search);
        my $findcmd = Cpanel::SafeRun::Timed::timedsaferun( 0, 'find', "/", '-type', 'f', '-name', $search );
        my @findcmd = split /\n/, $findcmd;
        foreach my $line(@findcmd) {
            chomp($line);
            my $found = Cpanel::SafeRun::Timed::timedsaferun( 0, 'grep', '-rnwl', '-e', 'command=', $line );
            chomp($found);
            push @SUMMARY, "> The file " . GREEN $found . YELLOW " contains suspicious " . CYAN "command= [openssh specific]" . YELLOW " line which could be used to create backdoors." if ( $found );
        }
    }
}

sub check_for_freedownloadmanager_malware {
    return unless( $distro eq 'ubuntu' );
    my $detection = 0;
    my @detected;
    if ( grep { /deb.fdmpkg.org/ } '/etc/apt/sources.list.d/freedownloadmanager.list' ) {
        $detection++;
        push @detected, "\t\\_ Found deb.fdmpkg.org in /etc/apt/sources.list.d/freedownloadmanager.list";
    }
    if ( -e '/etc/cron.d/collect' ) {
        $detection++;
        push @detected, "\t\\_ Found presence of /etc/cron.d/collect file";
    }
    my @dirs = qw( /var/tmp /lost+found /lib /lib64 /etc/openal /etc/thermald );
    my @files = qw( crond bs atd exp_lin.so );
    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            my $fullpath = $dir . "/" . $file;
            stat $fullpath;
            if ( -f _ and not -z _ ) {
                $detection++;
                push @detected, "\t\\_ Found suspicious file $dir/$file";
            }
        }
    }
    my $apt_key_list = Cpanel::SafeRun::Timed::timedsaferun( 0, 'apt-key', 'list' );
    if ( grep { /B6D0 9383/ } $apt_key_list ) {
        $detection++;
        push @detected, "\t\\_ Found 'B6D0 9383' within the apt-key list command.";
    }
    if ( $detection ) {
        push @SUMMARY, "> Possible FreeDownloadManager Malware (Debian/Ubuntu only) found!";
        foreach my $line(@detected) {
            chomp($line);
            push @SUMMARY, "$line\n";
        }
    }
}

sub check_mounts {
    return unless( iam('cptech'));
    my $liscMounted = Cpanel::SafeRun::Timed::timedsaferun( 5, 'mount' );
    my @liscMounted = split /\n/, $liscMounted;
    return unless (@liscMounted);
    foreach my $mount_line (@liscMounted) {
        if ( $mount_line =~ m/cpanel.lisc|cpsanitycheck.so/ ) {
            push( @SUMMARY, "Suspicious Mount Found:\n" . CYAN . "\t\\_  $mount_line\n" . RED "\t\\_ Send this to L3 Please!" );
        }
    }
}

sub check_for_obsolete_shadow_hashes {
    my $md5hash=Cpanel::SafeRun::Timed::timedsaferun( 0, 'grep', '-c', '\$1\$', '/etc/shadow' );
    chomp($md5hash);
    if ( $md5hash > 0 ) {
        push( @INFO, "> Found $md5hash obsolete password hash(es) [MD5] in /etc/shadow file.");
        push( @INFO, CYAN "\t\\_ Run: " . WHITE "grep '\\\$1\\\$' /etc/shadow" . CYAN " to find them.");
    }
}

sub compare_hash_of_shells {
    return unless( -f '/etc/shells' );
    my ($nologinhash)=(split( /\s+/, Cpanel::SafeRun::Timed::timedsaferun( 0, 'sha1sum', '/sbin/nologin' )))[0];
    chomp($nologinhash);
    open( my $fh, '<', '/etc/shells' );
    while ( <$fh> ) {
        chomp;
        next if -l $_;
        next unless -f $_;
        next if ( $_ eq '/sbin/nologin' );
        my ($hashline,$shellfile)=(split( /\s+/, Cpanel::SafeRun::Timed::timedsaferun( 0, 'sha1sum', $_ )));
        chomp($hashline);
        chomp($shellfile);
        if ( $hashline eq $nologinhash ) {
            push( @SUMMARY, "> The SHA1 hash for /sbin/nologin is identical to the one for $shellfile - Could indicate a compromise!" );
        }
    }
}

sub get_rpm_href {
    return get_apt_href() if ( $distro eq 'ubuntu');
    return unless my $list = Cpanel::SafeRun::Timed::timedsaferun( 0, 'rpm', '-qa', '--queryformat', q{%{NAME}\t%{VERSION}\t%{RELEASE}\n} );
    my %rpms;
    for my $line ( split( /\n/, $list ) ) {
        my ( $name, $version, $release ) = split( /\t/, $line );
        push @{ $rpms{$name} }, {
            'version'     => defined $version     ? $version     : '',
            'release'     => defined $release     ? $release     : '',
        };
    }
    return \%rpms;
}

sub get_apt_href {
    return unless my $list = Cpanel::SafeRun::Timed::timedsaferun( 0, 'dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${Architecture}\t${Maintainer}\n' );
    my %rpms;
    for my $line ( split( /\n/, $list ) ) {
        my ( $name, $version, $arch, $maintainer ) = split( /\t/, $line );
        push @{ $rpms{$name} }, {
            'version' => defined $version ? $version : '',
            'arch' => defined $arch ? $arch : '',
            'maintainer' => defined $maintainer ? $maintainer : '',
        };
    }
    return \%rpms;
}

sub check_email_filters {
    my $susp_filter1 = Cpanel::SafeRun::Timed::timedsaferun( 0, "grep -srl '\$header_from: contains \"@\"' $HOMEDIR/*/etc/*/*/filter" );
    chomp($susp_filter1);
    push @SUMMARY, ">Found possible suspicious email filter in $susp_filter1" if ( $susp_filter1 );
    push @SUMMARY, expand( "\t\\_ filter contains only an @, indicating all email to be forwarded/filtered" ) if ( $susp_filter1 );
    my $susp_filter2 = Cpanel::SafeRun::Timed::timedsaferun( 0, "grep -srl '\$header_from: contains \"mailer-daemon\"' $HOMEDIR/*/etc/*/*/filter" );
    chomp($susp_filter2);
    push @SUMMARY, ">Found possible suspicious email filter in $susp_filter2" if ( $susp_filter2 );
    push @SUMMARY, expand( "\t\\_ filter contains possible redirect of mailer-daemon" ) if ( $susp_filter2 );
}

sub send_email {
    my $epochdate=time();
    my $date=scalar localtime( $epochdate );
    my $to='root';
    my $from='root';
    my $subject="CSI Summary Report for $date on $hostname";

    open( my $fh, '<', "$csidir/summary.txt" );
    my @data=<$fh>;
    close($fh);
    open( OUTPUT, ">$csidir/summary.txt" );
    foreach my $line(@data) {
        chomp($line);
        $line =~ s/\e\[[0-9;]*m//g;
        print OUTPUT $line . "\n";
    }
    close(OUTPUT);

    use MIME::Lite;
    my $msg = MIME::Lite->new(
        From     => $from,
        To       => $to,
        Subject  => $subject,
        Type     => 'TEXT',
        Path     => "$csidir/summary.txt",
    );
    $msg->attach (
        Type => 'TEXT',
        Path => "$csidir/csi.log"
    );
    $msg->send;
}

=encoding utf-8

=head1 COPYRIGHT

Copyright 2023, cPanel, L.L.C.
All rights reserved.
http://cpanel.net

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the owner nor the names of its contributors may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=head1 CSI - cPanel Security Investigator

=head1 USAGE/OPTIONS

=over

=item quick scan [DEAULT] - Perform a quick scan of the server

=item --userscan cPanelUser - Scans an individual user account.

=item --symlink - Includes a check for symlink hacks during scan.

=item --secadv - Includes Security Advisor Results during scan.

=item --full - Performs a full scan including symlink and secadv & Yara scan.

=item --yarascan - Skips confirmation during --full scan. CAUSES HIGH LOAD!!!

=item --overwrite - Use already exisitng /root/CSI directory.

=item --cron - Run via cron. You can create /etc/cron.daily/csi with the contents below (one line):

=back

curl -s https://raw.githubusercontent.com/CpanelInc/tech-csi/master/csi.pl | /usr/local/cpanel/3rdparty/bin/perl - --cron

Then change the permissions to 0755 [chmod 0755 /etc/cron.daily/csi].

=cut

# EOF
