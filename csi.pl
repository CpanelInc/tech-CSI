#!/usr/bin/perl

# Copyright(c) 2013 cPanel, Inc.
# All rights Reserved.
# copyright@cpanel.net
# http://cpanel.net
# Unauthorized copying is prohibited

# Tested on cPanel 11.30 - 11.44

# Maintainer: Samir Jafferali

use strict;
use warnings;

use Cwd 'abs_path';
use File::Basename;
use File::Spec;
use POSIX;
use Time::Local;
use Getopt::Long;
use Term::ANSIColor qw(:constants);
$Term::ANSIColor::AUTORESET = 1;

my $version = '3.0.15';

###################################################
# Check to see if the calling user is root or not #
###################################################

if ( $> != 0 ) {
    die "This script needs to be ran as the root user\n";
}

###########################################################
# Parse positional parameters for flags and set variables #
###########################################################

# Set defaults for positional parameters
my $no3rdparty = 0;    # Default to running 3rdparty scanners
my $short=0;
my $fh = ' ';
my $scan = 0;
my $a_type = 0;    # Defaults to searching for only POST requests
my $range = "60";    # Defaults to 60 seconds
my $owner = "owner";
my $epoc_time = '0';

GetOptions(
    'no3rdparty' => \$no3rdparty,
    'file=s' => \$fh,
    'rootkitscan' => \$scan,
    'get' => \$a_type,
    'range=i' => \$range,
    'timestamp=i' => \$epoc_time,
    'user=s' => \$owner,
    'short' => \$short,
);

#######################################
# Set variables needed for later subs #
#######################################

chomp( my $wget = qx(which wget) );
chomp( my $make = qx(which make) );

my $top    = File::Spec->curdir();
my $csidir = File::Spec->catdir( $top, 'CSI' );

my $rkhunter_bin   = File::Spec->catfile( $csidir, 'rkhunter',   'bin', 'rkhunter' );
my $chkrootkit_bin = File::Spec->catfile( $csidir, 'chkrootkit', 'chkrootkit' );

my $CSISUMMARY;

my @SUMMARY;

my $touchfile = '/var/cpanel/perl/easy/Cpanel/Easy/csi.pm';
my @logfiles  = (
    '/usr/local/apache/logs/access_log',
    '/usr/local/apache/logs/error_log',
    '/var/log/messages',
    '/var/log/maillog',
    '/var/log/wtmp',
    '/root/.bash_history',
);

my $systype;
my $os;
my $linux;
my $freebsd;

my $filename;
my $epoc_mtime;
my $epoc_ctime;
my @mbash;
my @mmessages;
my @mftp;
my @mcpanel;
my @maccess;

my %mon2num = qw(
  jan 1  feb 2  mar 3  apr 4  may 5  jun 6
  jul 7  aug 8  sep 9  oct 10 nov 11 dec 12
);


######################
# Run code main body #
######################

if ($fh ne " ") {
    logfinder(); 
    exit;
}
if ($epoc_time != "0" ) {
    time_logfinder();
    exit;
}
if ($scan == "1" ) { 
    scan();
    exit;
}
show_help();

########
# Subs #
########

sub show_help {
    print_header("\ncPanel Security Inspection Version $version");
    print_header("Usage: perl csi.pl [options] [function]\n");
    print_header("Functions");
    print_header("=================");
    print_status("--rootkitscan              Performs a variety of checks to detect root level compromises.");
    print_status("--file [file/directory]    Searches all available log files for the change and modify timestamp of the file/directory");
    print_status("                           provided in effort to determine how a file was modified or changed. ");
    print_status("--timestamp [timestamp]    Similar to --file, but allows you to specify a epoch timestamp if the file is no longer");
    print_status("                           available. The --user flag is required when using this function.\n");
    print_header("Options (rootkitscan)");
    print_header("=================");
    print_status("--no3rdparty               Disables running of 3rdparty scanners.\n");
    print_header("Options (file/timestamp)");
    print_header("=================");
    print_status("--user [user]              Override detected owner of file with custom user to search for.");
    print_status("--range [seconds]          Specify search range in seconds. Default is 60 seconds.");
    print_status("--short                    Do not print verbose output.");
    print_status("--get                      By default, CSI only searches for POST requests. This option enables searching of GET requests as well.");
    print_normal(" ");
    print_header("Examples");
    print_header("=================");
    print_status("Timestamp: ");
    print_status("            csi.pl --timestamp 1407114375 --user cpuser");
    print_status("            csi.pl --timestamp 1407114375 --user cpuser --range 120");
    print_status("File: ");
    print_status("            csi.pl --file /home/zyreperm/ii.php");
    print_status("            csi.pl --file /home/zyreperm/ii.php --user ipadbest --short");
    print_status("Rootkitscan: ");
    print_status("            csi.pl --rootkitscan");
    print_status("            csi.pl --rootkitscan --no3rdparty");
    print_normal(" ");
}

sub disclaimer {
    print_normal('');
    print_header('########################################################################');
    print_header('### DISCLAIMER! cPanel\'s Technical Support does not provide            #');
    print_header('### security consultations services. The only support services we      #');
    print_header('### can provide at this time is to perform a minimal analysis of the   #');
    print_header('### possible security breach solely for the purpose of determining if  #');
    print_header('### cPanel\'s software was involved or used in the security breach.     #');
    print_header('########################################################################');
    print_header('### If it is suspect to be root compromised, only Level lll Analysts   #');
    print_header('### should be handling the issue. Account level compromises are        #');
    print_header('### investigated as a courtesy and carry no guarantees.                #');
    print_header('########################################################################');
    print_normal('');
}

sub logfinder {
    disclaimer() if (!$short);
    detect_system();
    print_normal('') if (!$short);
    print_header('[ Starting cPanel Security Inspection: Logfinder Mode ]') if (!$short);
    print_header("[ Version $version on Perl $] ]") if (!$short);
    print_header("[ System Type: $systype ]") if (!$short);
    print_header("[ OS: $os ]") if (!$short);
    print_normal('') if (!$short);
    print_header("[ Available flags when running $0 --file (if any): ]") if (!$short);
    print_header('[     --range (specify custom search range in seconds) ]') if (!$short);
    print_header('[     --get (show GET requests as well as POST) ]') if (!$short);
    print_header('[     --user (force user) ]') if (!$short);
    print_header('[     --short (do not print verbose output) ]') if (!$short);
    print_normal('') if (!$short);
    if (!-e $fh) {
        print_error("$fh not found. Exiting... \n");
        exit ; 
    }
    $filename= basename $fh ;
    $epoc_mtime= (stat($fh))[9];
    $epoc_ctime= (stat($fh))[10];
    if ($owner eq "owner") {
        my $file_uid= (stat($fh))[4];
        $owner= (getpwuid $file_uid)[0];
    }
    print_filestats(); 
    my $differ="1";
    if ($epoc_ctime != $epoc_mtime) {
        $differ="2";
    }
    while ($differ > 0 ) {
        search_logs();
        print_matches();
        print "\n" if (!$short);
        $epoc_mtime=$epoc_ctime ;
        --$differ ;
    }
}

sub time_logfinder {
    disclaimer() if (!$short);
    detect_system();
    print_normal('') if (!$short);
    print_header('[ Starting cPanel Security Inspection: Logfinder Mode ]') if (!$short);
    print_header("[ Version $version on Perl $] ]") if (!$short);
    print_header("[ System Type: $systype ]") if (!$short);
    print_header("[ OS: $os ]") if (!$short);
    print_normal('') if (!$short);
    print_header("[ Available flags when running $0 --timestamp (if any): ]") if (!$short);
    print_header('[     --range (specify custom search range in seconds) ]') if (!$short);
    print_header('[     --get (show GET requests as well as POST) ]') if (!$short);
    print_header('[     --user (force user) ]') if (!$short);
    print_header('[     --short (do not print verbose output) ]') if (!$short);
    print_normal('') if (!$short);
    $epoc_mtime=$epoc_time ; 
    $epoc_ctime=$epoc_time ;    
    $filename = ".";
    if ($owner eq "owner") {
        print_error("Providing the user via --user is required when using --timestamp. Exiting... \n");
        exit ;
    }
    print_filestats ()  ; 
    search_logs();
    print_matches();
}

sub search_logs {
    my $tmpepoc= $epoc_mtime - $range;
    my $searchmbash= "^#$tmpepoc";
    my $searchmmessages= "^".strftime("%b %d %H:%M:%S",localtime($tmpepoc));
    my $searchmftp= "^".strftime("%a %b %d %H:%M:%S %Y",localtime($tmpepoc));
    my $searchmcpanel= strftime("%m/%d/%Y:%H:%M:%S",gmtime($tmpepoc));
    my $searchmaccess= strftime("%d/%b/%Y:%H:%M:%S",localtime($tmpepoc));
    @mbash=();
    @mmessages=();
    @mftp=();
    @mcpanel=();
    @maccess =();
    for (my $i=0; $i <= $range * 2 ; $i++) {
        $tmpepoc++ ;
        $searchmbash= "$searchmbash|^#$tmpepoc";
        $searchmmessages= "$searchmmessages|^".strftime("%b %d %H:%M:%S",localtime($tmpepoc));
        $searchmftp= "$searchmftp|^".strftime("%a %b %d %H:%M:%S %Y",localtime($tmpepoc));
        $searchmcpanel= "$searchmcpanel|".strftime("%m/%d/%Y:%H:%M:%S",gmtime($tmpepoc));
        $searchmaccess= "$searchmaccess|".strftime("%d/%b/%Y:%H:%M:%S",localtime($tmpepoc));
    }

    print_header("Searching for: ".localtime($epoc_mtime)." ($epoc_mtime)") if (!$short);
    print_header("----------------------------------------------------") if (!$short);
    print_normal_chomped("[+] Checking .bash_history files... ") if (!$short);
    push @mbash, qx(egrep -HA1 "$searchmbash" /root/.bash_history);
    if (-e "/home/$owner/.bash_history") {
        push @mbash, qx(egrep -HA1 "$searchmbash" /home/$owner/.bash_history);
    }
    chomp(@mbash); 
    print_normal("Done. ".scalar @mbash / "2". " results found.") if (!$short);

    print_normal_chomped("[+] Checking /var/log/messages... ") if (!$short);
    my ($second, $minute, $hour, $dayofmonth, $month, $year, $dayofweek, $dayofyear, $daylightsavings) = localtime();
    opendir(DIR, "/var/log/");
    my @files = grep(/^messages/,readdir(DIR));
    closedir(DIR);
    foreach my $file (@files) {
        my $firstline ;
        my $lastline ;
        if ($file =~ /\.gz$/) {
            chomp($firstline=qx(zcat /var/log/$file | head -1 | awk '{print\$1" "\$2" "\$3}'));
            chomp($lastline=qx(zcat /var/log/$file | tail -1 | awk '{print\$1" "\$2" "\$3}'));
        } else {
            chomp($firstline=qx(head -1 /var/log/$file | awk '{print\$1" "\$2" "\$3}'));
            chomp($lastline=qx(tail -1 /var/log/$file | awk '{print\$1" "\$2" "\$3}'));
        }
        $firstline =~ s/:/ /g;
        $lastline =~ s/:/ /g;
        my @first= split(/ /, $firstline);
        my @last= split(/ /, $lastline);

        $firstline = timelocal($first[4],$first[3],$first[2],$first[1],$mon2num{ lc substr($first[0], 0, 3) }-1,$year);
        $lastline = timelocal($last[4],$last[3],$last[2],$last[1],$mon2num{ lc substr($last[0], 0, 3) }-1,$year);

        if ($firstline < $epoc_mtime && $lastline > $epoc_mtime) {
                push @mmessages, qx(zegrep -H "$searchmmessages" /var/log/$file | grep $filename);
        }
    }
    chomp(@mmessages); 
    print_normal("Done. ".scalar @mmessages. " results found.") if (!$short);

    print_normal_chomped("[+] Checking ftpxferlog... ") if (!$short);
    push @mftp, qx(egrep -H "$searchmftp" /usr/local/apache/domlogs/$owner/ftp.* /usr/local/apache/domlogs/ftpxferlog 2> /dev/null | grep $filename | grep $owner);
    chomp(@mftp);
    print_normal("Done. ".scalar @mftp. " results found.") if (!$short);

    print_normal_chomped("[+] Checking cPanel access logs... ") if (!$short);
    my $type;
    if ( $a_type == "1" ) {
        $type="POST|GET";
    } else {
        $type="POST";
    }
    if (-d "/usr/local/cpanel/logs/archive") {
        @files=(); 
        opendir(DIR, "/usr/local/cpanel/logs/archive");
        @files = grep(/^access_log/,readdir(DIR));
        closedir(DIR);
        foreach my $file (@files) {
            my $firstline ;
            my $lastline ;
            chomp($firstline=qx(zcat /usr/local/cpanel/logs/archive/$file | head -1 | awk -F'[' '{print\$2}' | awk '{print\$1}'));
            chomp($lastline=qx(zcat /usr/local/cpanel/logs/archive/$file | tail -1 | awk -F'[' '{print\$2}' | awk '{print\$1}'));
            $firstline =~ tr/\/|:/ / ;
            $lastline =~ tr/\/|:/ / ;
            my @first= split(/ /, $firstline);
            my @last= split(/ /, $lastline);

            $firstline = timelocal($first[5],$first[4],$first[3],$first[1],$first[0],$first[2]);
            $lastline = timelocal($last[5],$last[4],$last[3],$last[1],$last[0],$last[2]);

            if ($firstline < $epoc_mtime && $lastline > $epoc_mtime) {
                push @mcpanel, qx(zegrep -H "$searchmcpanel" /usr/local/cpanel/logs/archive/$file | egrep "$type");
            }
        }
    }
    my $firstline ;
    my $lastline ;
    chomp($firstline=qx(head -1 /usr/local/cpanel/logs/access_log | awk -F'[' '{print\$2}' | awk '{print\$1}'));
    chomp($lastline=qx(tail -1 /usr/local/cpanel/logs/access_log | awk -F'[' '{print\$2}' | awk '{print\$1}'));
    $firstline =~ tr/\/|:/ / ;
    $lastline =~ tr/\/|:/ / ;
    my @first= split(/ /, $firstline);
    my @last= split(/ /, $lastline);
    $firstline = timelocal($first[5],$first[4],$first[3],$first[1],$first[0],$first[2]);
    $lastline = timelocal($last[5],$last[4],$last[3],$last[1],$last[0],$last[2]);
    if ($firstline < $epoc_mtime && $lastline > $epoc_mtime) {
        push @mcpanel, qx(egrep -H "$searchmcpanel" /usr/local/cpanel/logs/access_log | egrep "$type");
    }
    chomp(@mcpanel);
    print_normal("Done. ".scalar @mcpanel. " results found.") if (!$short);

    if ($owner ne "root") {
        print_normal_chomped("[+] Checking Apache access logs... ") if (!$short); 

        opendir(DIR, "/home/$owner/access-logs");
        my @files = grep(/^(?!(ftp|\.))/,readdir(DIR));
        closedir(DIR);
        foreach my $file (@files) {
            if (-z "/home/$owner/access-logs/$file") {
                next ;
            }
            my $firstline ;
            my $lastline ;
            chomp($firstline=qx(head -1 /home/$owner/access-logs/$file | awk -F'[' '{print\$2}' | awk '{print\$1}'));
            chomp($lastline=qx(tail -1 /home/$owner/access-logs/$file | awk -F'[' '{print\$2}' | awk '{print\$1}'));
            $firstline =~ tr/\/|:/ / ;
            $lastline =~ tr/\/|:/ / ;
            my @first= split(/ /, $firstline);
            my @last= split(/ /, $lastline);
            $firstline = timelocal($first[5],$first[4],$first[3],$first[0],$mon2num{ lc substr($first[1], 0, 3) }-1,$first[2]);
            $lastline = timelocal($last[5],$last[4],$last[3],$last[0],$mon2num{ lc substr($last[1], 0, 3) }-1,$last[2]);
            if ($firstline < $epoc_mtime && $lastline > $epoc_mtime) {
                push @maccess, qx(egrep -H "$searchmaccess" /home/$owner/access-logs/$file | egrep "$type");
            }
        }
        opendir(DIR, "/home/$owner/logs");
        @files = grep(/^(?!(ftp|\.))/,readdir(DIR));
        closedir(DIR);
        foreach my $file (@files) {
            my $firstline ;
            my $lastline ;
            chomp($firstline=qx(zcat /home/$owner/logs/$file | head -1 | awk -F'[' '{print\$2}' | awk '{print\$1}'));
            chomp($lastline=qx(zcat /home/$owner/logs/$file | tail -1  | awk -F'[' '{print\$2}' | awk '{print\$1}'));
            $firstline =~ tr/\/|:/ / ;
            $lastline =~ tr/\/|:/ / ;
            my @first= split(/ /, $firstline);
            my @last= split(/ /, $lastline);
            $firstline = timelocal($first[5],$first[4],$first[3],$first[0],$mon2num{ lc substr($first[1], 0, 3) }-1,$first[2]);
            $lastline = timelocal($last[5],$last[4],$last[3],$last[0],$mon2num{ lc substr($last[1], 0, 3) }-1,$last[2]);
            if ($firstline < $epoc_mtime && $lastline > $epoc_mtime) {
                push @maccess, qx(zegrep -H "$searchmaccess" /home/$owner/logs/$file | egrep "$type");
            }
        }
        chomp (@maccess);
        print_normal("Done. ".scalar @maccess. " results found.") if (!$short);
    }
    print_normal(" ") if (!$short);
}

sub print_matches {
    print_header("Matches: ".localtime($epoc_mtime)." ($epoc_mtime)") if (!$short); 
    print_header("---------------------------------------------") if (!$short);

    if (scalar @mbash > 0) {
        print MAGENTA ".bash_history\n" if (!$short);
        foreach (@mbash) {
                print_status($_);
        }
    print_normal (" ") if (!$short);
    }

    if (scalar @mmessages > 0) {
        print MAGENTA "/var/log/messages\n" if (!$short);
        foreach (@mmessages) {
                print_status($_);
        }
    print_normal (" ") if (!$short);
    }

    if (scalar @mftp > 0) {
        print MAGENTA "ftpxferlog\n" if (!$short); 
        foreach (@mftp) {
                print_status($_);
        }
    print_normal (" ") if (!$short);
    }

    if (scalar @mcpanel > 0) {
        print MAGENTA "cPanel Access Logs\n" if (!$short); 
        foreach (@mcpanel) {
                print_status($_);
        }
    print_normal (" ") if (!$short);
    }

    if (scalar @maccess > 0) {
        print MAGENTA "Apache Access Logs\n" if (!$short); 
        foreach (@maccess) {
                print_status($_);
        }
    print_normal (" ") if (!$short);
    }
}

sub print_filestats {
    print_header( "\nStatistics: ") if (!$short);
    print_header( "---------------------------------------------------------") if (!$short);
    print_status( "File: " . File::Spec->rel2abs($fh) ) if (!$short && !$epoc_time);
    print_status( "Size: " . (stat($fh))[7] ) if (!$short && !$epoc_time );
    print_status( "Modify Time: " . localtime($epoc_mtime) . " ($epoc_mtime)" ) if (!$short && !$epoc_time);
    print_status( "Change Time: " . localtime($epoc_ctime) . " ($epoc_ctime)" ) if (!$short && !$epoc_time);
    print_status( "Timestamp: " . localtime($epoc_time) . " ($epoc_time)" ) if (!$short && $epoc_time);
    print_status( "User: " . $owner ) if (!$short);
    print_status("Search Range: $range seconds ") if (!$short);
    print CYAN "---------------------------------------------------------\n" if (!$short);

    if ($epoc_ctime != $epoc_mtime) {
        print_warn("Change and modify timestamps are different. Will search logs twice.") if (!$short);
    }
    if ($owner eq "root") {
        print_warn("User root detected. Skipping some checks.") if (!$short);
    }
    if (! -e "/var/cpanel/users/$owner" && $owner ne "root") {
        print_error("User ($owner) not found. Exiting...\n") if (!$short);
        exit;
    }
    print_normal("\n") if (!$short); 
}

sub scan {
    disclaimer();
    detect_system();
    print_normal('');
    print_header('[ Starting cPanel Security Inspection: Rootkitscan Mode ]');
    print_header("[ Version $version on Perl $] ]");
    print_header("[ System Type: $systype ]");
    print_header("[ OS: $os ]");
    print_normal('');
    print_header("[ Available flags when running $0 --rootkitscan (if any): ]");
    print_header('[     --no3rdparty (disables running of 3rdparty scanners) ]');
    print_normal('');
    print_header('[ Cleaning up from earlier runs, if needed ]');
    check_previous_scans();
    print_normal('');

    create_summary();

    if ( !$no3rdparty ) {

        if ( -f "Makefile.csi" ) {
            print_header('[ Makefile already present ]');
        }
        else {
            print_header('[ Fetching Makefile ]');
            fetch_makefile();
        }
        print_normal('');

        print_header('[ Building Dependencies ]');
        install_sources();
        print_normal('');

        print_header('[ Running 3rdparty rootkit and security checking programs ]');
        run_rkhunter();
        run_chkrootkit();
        print_normal('');

        print_header('[ Cleaning up ]');
        cleanup();
        print_normal('');
    }
    else {
        print_header('[ Running without 3rdparty rootkit and security checking programs ]');
        print_normal('');

    }

    print_header('[ Checking logfiles ]');
    check_logfiles();
    print_normal('');

    print_header('[ Checking for bad UIDs ]');
    check_uids();
    print_normal('');

    print_header('[ Checking for rootkits ]');
    check_rootkits();
    print_normal('');

    print_header('[ Checking Apache configuration ]');
    check_httpd_config();
    print_normal('');

    print_header('[ Checking for mod_security ]');
    check_modsecurity();
    print_normal('');

    print_header('[ Checking for index.html in /tmp and /home ]');
    check_index();
    print_normal('');

    print_header('[ Checking for modified suspended page ]');
    check_suspended();
    print_normal('');

    print_header('[ Checking if root bash history has been tampered with ]');
    check_history();
    print_normal('');

#    print_header('[ Checking /tmp for known hackfiles ]');
#    check_hackfiles();
#    print_normal('');

    print_header('[ Checking process list ]');
    check_processes();
    print_normal('');

    if ($linux) {
        print_header('[ Checking for modified/hacked SSH ]');
        check_ssh();
        print_normal('');

        print_header('[ Checking for unowned libraries in /lib, /lib64 ]');
        check_lib();
        print_normal('');

        print_header('[ Checking if kernel update is available ]');
        check_kernel_updates();
        print_normal('');
    }

    print_header('[ cPanel Security Inspection Complete! ]');
    print_normal('');

    print_header('[ CSI Summary ]');
    dump_summary();
    print_normal('');

}

sub detect_system {

    chomp( $systype = qx(uname -a | cut -f1 -d" ") );

    if ( $systype eq 'Linux' ) {
        $linux = 1;
        $os    = qx(cat /etc/redhat-release);
        push @logfiles, '/var/log/secure';
    }
    elsif ( $systype eq 'FreeBSD' ) {
        $freebsd = 1;
        $os      = qx(uname -r);
        push @logfiles, '/var/log/auth.log';
    }
    else {
        print_error("Could not detect OS!");
        print_info("System Type: $systype");
        print_status("Please report this if you believe it is an error!");
        print_status("Exiting!");
        exit 1;
    }
    chomp($os);

}

sub fetch_makefile {

    if ( -x $wget ) {
        my $makefile_url = 'https://raw.githubusercontent.com/cPanelSamir/CSI/master/Makefile.csi';
        my @wget_cmd = ( "$wget", "-q", "--no-check-certificate", "$makefile_url" );
        system(@wget_cmd);
    }
    else {
        print_error('Wget is either not installed or has no execute permissions, please check $wget');
        print_normal('Exiting CSI ');
        exit 1;
    }

    print_status('Done.');

}

sub install_sources {

    if ( -x $make ) {
        print_status('Cleaning up from previous runs');
        my $makefile = File::Spec->catfile( $top, 'Makefile.csi' );

        my @cleanup_cmd = ( "$make", "-f", "$makefile", "uberclean" );
        system(@cleanup_cmd);

        print_status('Running Makefile');

        my @make_cmd = ( "$make", "-f", "$makefile" );
        system(@make_cmd);

    }
    else {
        print_error("Make is either not installed or has no execute permissions, please check $make");
        print_normal('Exiting CSI ');
        exit 1;
    }
    print_status('Done.');

}

sub check_previous_scans {

    if ( -e $touchfile ) {
        push @SUMMARY, "*** This server was previously flagged as compromised and hasn't been reloaded, or $touchfile has not been removed. (This means this ticket should probably be escalated to a Level 3 Analyst for verification.) ***";
    }

    opendir(DIR, "/usr/share/doc");
    my @files = grep(/\.cp/,readdir(DIR));
    closedir(DIR);

    foreach my $file (@files) {
         push @SUMMARY, "*** This server was previously flagged as compromised and hasn't been reloaded, or /usr/share/doc/$file has not been removed. (This means this ticket should probably be escalated to a Level 3 Analyst for verification.) ***";
    }

    if ( -d $csidir ) {
        chomp( my $date = qx(date +%Y%m%d) );
        print_info("Existing $csidir is present, moving to $csidir-$date");
        rename "$csidir", "$csidir-$date";
        mkdir $csidir;
    }
    else {
        mkdir $csidir;
    }

    print_status('Done.');

}

sub check_kernel_updates {

    chomp( my $newkernel = qx(yum check-update kernel | grep kernel | awk '{ print \$2 }') );
    if ( $newkernel ne '' ) {
        push @SUMMARY, "Server is not running the latest kernel, kernel update available: $newkernel";
    }

    print_status('Done.');

}

sub run_rkhunter {

    print_status('Running rkhunter. This will take a few minutes.');

    qx($rkhunter_bin --cronjob --rwo > $csidir/rkhunter.log 2>&1);

    if ( -s "$csidir/rkhunter.log" ) {
        open( my $LOG, '<', "$csidir/rkhunter.log" )
          or die("Cannot open logfile $csidir/rkhunter.log: $!");
        my @results = grep /Rootkit/, <$LOG>;
        close $LOG;
        if (@results) {
            push @SUMMARY, "Rkhunter has found a suspected rootkit infection(s):";
            foreach (@results) {
                push @SUMMARY, $_;
            }
            push @SUMMARY, "More information can be found in the log at $csidir/rkhunter.log";
        }
    }
    print_status('Done.');

}

sub run_chkrootkit {

    print_status('Running chkrootkit. This will take a few minutes.');

    qx($chkrootkit_bin 2> /dev/null | egrep 'INFECTED|vulnerable' | grep -v "INFECTED (PORTS:  465)" > $csidir/chkrootkit.log 2> /dev/null);

    if ( -s "$csidir/chkrootkit.log" ) {
        open( my $LOG, '<', "$csidir/chkrootkit.log" )
          or die("Cannot open logfile $csidir/chkrootkit.log: $!");
        my @results = <$LOG>;
        close $LOG;
        if (@results) {
            push @SUMMARY, 'Chkrootkit has found a suspected rootkit infection(s):';
            foreach (@results) {
                push @SUMMARY, $_;
            }
        }
    }
    print_status('Done.');

}

sub check_logfiles {

    if ( !-d '/usr/local/apache/logs' ) {
        push @SUMMARY, "/usr/local/apache/logs directory is not present";
    }
    foreach my $log (@logfiles) {
        if ( !-f $log ) {
            push @SUMMARY, "Log file $log is missing or not a regular file";
        } elsif ( -z $log ) {
            push @SUMMARY, "Log file $log exists, but is empty";
        }
    }
    print_status('Done.');

}

sub check_index {

    if ( -f '/tmp/index.htm' or -f '/tmp/index.html' ) {
        push @SUMMARY, 'Index file found in /tmp';
    }
    print_status('Done.');

}

sub check_suspended {

    if ( -f '/var/cpanel/webtemplates/root/english/suspended.tmpl' ) {
        push @SUMMARY, 'Custom account suspended template found at /var/cpanel/webtemplates/root/english/suspended.tmpl';
        push @SUMMARY, '     This could mean the admin just created a custom template or that an attacker gained access';
        push @SUMMARY, '     and created it (hack page)';
    }
    print_status('Done.');

}

sub check_history {

    if ( -e '/root/.bash_history' ) {
        if ( -l '/root/.bash_history' ) {
            my $result = qx(ls -la /root/.bash_history);
            push @SUMMARY, "/root/.bash_history is a symlink, $result";
        }
        elsif ( !-s '/root/.bash_history' and !-l '/root/.bash_history' ) {
            push @SUMMARY, "/root/.bash_history is a 0 byte file";
        }
    }
    else {
        push @SUMMARY, "/root/.bash_history is not present, this indicates probable tampering";
    }

    print_status('Done.');

}

sub check_modsecurity {

    my $result = qx(/usr/local/apache/bin/apachectl -M 2>/dev/null);

    if ( $result !~ /security2_module|security_module/ ) {
        push @SUMMARY, "Mod Security is disabled";
    }

    print_status('Done.');

}

sub check_hackfiles {

    open( my $TMPLOG, '>', "$csidir/tmplog" )
      or die("Cannot open $csidir/tmplog: $!");

    my @wget_hackfiles = ( "$wget", '-q', 'http://csi.cptechs.info/hackfiles', '-O', "$csidir/hackfiles" );

    system(@wget_hackfiles);
    open( my $HACKFILES, '<', "$csidir/hackfiles" )
      or die("Cannot open $csidir/hackfiles: $!");

    my @tmplist = qx(find /tmp -type f);
    my @hackfound;

    while (<$HACKFILES>) {
        chomp( my $file_test = $_ );
        foreach (@tmplist) {
            if ( /\b$file_test$/ ) {
                push( @hackfound, $_ );
            }
        }
    }

    if (@hackfound) {
        foreach my $file (@hackfound) {
            chomp $file;
            print $TMPLOG "---------------------------\n";
            print $TMPLOG "Processing $file\n";
            print $TMPLOG "\n";
            print $TMPLOG "File metadeta:\n";
            print $TMPLOG stat $file if ( -s $file );
            print $TMPLOG "\n";
            print $TMPLOG "File type:\n";
            print $TMPLOG qx(file $file) if ( -s $file );
            push @SUMMARY, "$file found in /tmp, check $csidir/tmplog for more information";

            if ( $file =~ 'jpg' ) {
                print $TMPLOG "\n";
                print $TMPLOG "$file has .jpg in the name, let's check out the first few lines to see of it really is a .jpg\n";
                print $TMPLOG "Here are the first 5 lines:\n";
                print $TMPLOG "===========================\n";
                print $TMPLOG qx(cat -n $file | head -5);
                print $TMPLOG "===========================\n";
            }
        }
        print $TMPLOG "---------------------------\n";
    }

    close $TMPLOG;
    close $HACKFILES;
    unlink "$csidir/hackfiles";
    print_status('Done.');

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
        push @SUMMARY, 'Users with UID of 0 detected:';
        foreach (@baduids) {
            push( @SUMMARY, $_ );
        }
    }
    print_status('Done.');

}

sub check_httpd_config {

    my $httpd_conf = '/usr/local/apache/conf/httpd.conf';
    if ( -f $httpd_conf ) {
        my $apache_options = qx(grep -A1 '<Directory "/">' $httpd_conf);
        if (    $apache_options =~ 'FollowSymLinks'
            and $apache_options !~ 'SymLinksIfOwnerMatch' ) {
            push @SUMMARY, 'Apache configuration allows symlinks without owner match';
        }
    }
    else {
        push @SUMMARY, 'Apache configuration file is missing';
    }
    print_status('Done.');

}

sub check_processes {

    chomp( my @ps_output = qx(ps aux) );
    foreach my $line (@ps_output) {
        if ( $line =~ 'sleep 7200' ) {
            push @SUMMARY, "Ps output contains 'sleep 7200' which is a known part of a hack process:";
            push @SUMMARY, "     $line";
        }
        if ( $line =~ / perl$/ ) {
            push @SUMMARY, "Ps output contains 'perl' without a command following, which probably indicates a hack:";
            push @SUMMARY, "     $line";
        }
    }
    print_status('Done.');

}

sub check_ssh {

    my @ssh_errors;
    my $ssh_verify;

    # Check RPM verification for SSH packages
    foreach my $rpm (qx(rpm -qa openssh*)) {
        chomp($rpm);
        $ssh_verify = qx(rpm -V $rpm | egrep -v 'ssh_config|sshd_config|pam.d|/usr/libexec/openssh/ssh-keysign|/usr/bin/ssh-agent');
        if ( $ssh_verify ne '' ) {
            push( @ssh_errors, " RPM verification on $rpm failed:\n" );
            push( @ssh_errors, " $ssh_verify" );
        }
    }

    # Check RPM verification for keyutils-libs
    my $keyutils_verify = qx(rpm -V keyutils-libs);
    if ( $keyutils_verify ne "" ) {
        push( @ssh_errors, " RPM verification on keyutils-libs failed:\n" );
        push( @ssh_errors, " $keyutils_verify" );
    }

    # Check process list for suspicious SSH processes
    my @process_list = qx(ps aux | grep "sshd: root@" | egrep -v 'pts|priv');
    if ( @process_list and $process_list[0] =~ 'root' ) {
        push( @ssh_errors, " Suspicious SSH process(es) found:\n" );
        push( @ssh_errors, " $process_list[0]" );
    }

    # If any issues were found, then write those to CSISUMMARY
    if (@ssh_errors) {
        push @SUMMARY, "System has detected the presence of a *POSSIBLY* compromised SSH:\n";
        foreach (@ssh_errors) {
            push( @SUMMARY, $_ );
        }
    }
    print_status('Done.');
    
}

sub check_lib {

    my @lib_errors;
    my @lib_files = glob '/lib*/*';

    foreach my $file (@lib_files) {
        if ( -f $file && -l $file ) {
            $file = abs_path($file);
        }
        if ( qx(rpm -qf $file) =~ /not owned by any package/ and -f $file ) {
            my $md5sum = qx(md5sum $file);
            push( @lib_errors, " Found $file which is not owned by any RPM.\n" );
            push( @lib_errors, " $md5sum" );
        }
    }

    # If any issues were found, then write those to CSISUMMARY
    if (@lib_errors) {
        push @SUMMARY, "System has detected the presence of a library file not owned by an RPM, these libraries *MAY* indicate a compromise or could have been custom installed by the administrator.\n";
        foreach (@lib_errors) {
            push( @SUMMARY, $_ );
        }
    }
    print_status('Done.');

}

sub check_rootkits {

    if ( chdir('/usr/local/__UMBREON') ) {
	push @SUMMARY, 'Evidence of UMBREON rootkit detected';
        print_status('Done.');
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
        print_status('No negative items were found');
    }
    else {
        print_warn('The following negative items were found:');
        foreach (@SUMMARY) {
            print BOLD GREEN "\t", '* ', $_, "\n";
        }
        print_normal('');
        print_normal('');
        print_warn('[L1/L2] If you believe there are negative items warrant escalating this ticket as a security issue then please read over https://cpanel.wiki/display/LS/CSIEscalations');
        print_normal('');
        print_warn('You need to understand exactly what the output is that you are seeing before escalating the ticket to L3.');
        print_normal('');
        print_status('[L3 only] If a rootkit has been detected, please mark the ticket Hacked Status as \'H4x0r3d\' and run:');
        print_normal('YOURNAME=$FIRSTNAME ; TICKET=$TICKETNUM ; touch /usr/share/doc/.cp.$YOURNAME.`date +"%F"`_`hostname -i`_$TICKET');
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
    print BLUE "$text\n";
}

sub print_header {
    my $text = shift;
    print CYAN "$text\n";
}

sub print_status {
    my $text = shift;
    print YELLOW "$text\n";
}

sub print_summary {
    my $text = shift;
    print GREEN "$text\n";
}

sub print_info {
    my $text = shift;
    print GREEN "[INFO]: $text\n";
}

sub print_warn {
    my $text = shift;
    print BOLD RED "*[WARN]*: $text\n";
}

sub print_error {
    my $text = shift;
    print BOLD MAGENTA "**[ERROR]**: $text\n";
}

sub cleanup {
    my $makefile = File::Spec->catfile( $top, 'Makefile.csi' );
    my @make_clean = ( "$make", "-f", "$makefile", "clean" );
    my @move_makefile = ( "/bin/mv", "$makefile", "CSI" );
    system(@make_clean);
    system(@move_makefile);
}

# EOF
