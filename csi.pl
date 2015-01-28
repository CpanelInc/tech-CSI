#!/usr/bin/perl

# Copyright(c) 2013 cPanel, Inc.
# All rights Reserved.
# copyright@cpanel.net
# http://cpanel.net
# Unauthorized copying is prohibited

# Tested on cPanel 11.30 - 11.46

# Maintainer: Samir Jafferali

use strict;
use warnings;

use Cwd 'abs_path';
use File::Basename;
use File::Spec;
use POSIX;
use Time::Local;
use Getopt::Long;
use IO::Socket::INET;
use Term::ANSIColor qw(:constants);
$Term::ANSIColor::AUTORESET = 1;

my $version = '3.3.3';

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
my $debug=0;
my $binscan=0;
my $fh = ' ';
my $scan = 0;
my $a_type = 0;    # Defaults to searching for only POST requests
my $range = "60";    # Defaults to 60 seconds
my $owner = "owner";
my $epoc_time = '0';
my @process_list = get_process_list();
my %process; &get_process_pid_hash(\%process);
my %ipcs; &get_ipcs_hash(\%ipcs);

GetOptions(
    'no3rdparty' => \$no3rdparty,
    'file=s' => \$fh,
    'rootkitscan' => \$scan,
    'get' => \$a_type,
    'range=i' => \$range,
    'timestamp=i' => \$epoc_time,
    'user=s' => \$owner,
    'short' => \$short,
    'bincheck' => \$binscan,
    'bugreport' => \$debug,
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

# Checks if the disclaimer has already been shown on this machine
if (!-e '/usr/share/doc/.csidisclaimer') {
    qx(/bin/touch /usr/share/doc/.csidisclaimer);
    disclaimer (); 
} else {
    my $disclaimertime = (stat('/usr/share/doc/.csidisclaimer'))[9];
    my $currenttime = qx(date +%s);
    if (($currenttime - $disclaimertime) > 86400) {
         qx(/bin/touch /usr/share/doc/.csidisclaimer);
         disclaimer ();
    }
}

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
if ($binscan == "1" ) { 
    bincheck();
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
    print_status("--bincheck                 Performs RPM verification on core system binaries and prints active aliases.");
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
    print_header("Options (bincheck)");
    print_header("=================");
    print_status("--bug                      Generates bug report for RPM verification failed files.");
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
    print_status("Bincheck: ");
    print_status("            csi.pl --bincheck");
    print_normal(" ");
}

sub bincheck {
    detect_system();
    print_normal('');
    print_header('[ Starting cPanel Security Inspection: Bincheck Mode ]');
    print_header("[ Version $version ]");
    print_header("[ System Type: $systype ]");
    print_header("[ OS: $os ]");
    print_normal('');
    print_header("[ Available flags when running csi.pl --bincheck: ]");
    print_header('[     --bug (generates a bug report for invalid output) ]');
    print_normal('');
    my @rpms = qw(
        abrt
        abrt-addon-ccpp
        abrt-addon-kerneloops
        abrt-addon-python
        abrt-tui
        acl
        acpid
        alsa-lib
        alsa-utils
        aspell
        aspell-devel
        at
        attr
        audit
        augeas
        authconfig
        autoconf
        automake
        b43-fwcutter
        bash
        bc
        bind
        bind-devel
        bind-utils
        binutils
        bison
        blktrace
        bridge-utils
        btparser
        busybox
        bzip2
        ca-certificates
        checkpolicy
        chkconfig
        cl-MySQL55-client
        cl-MySQL55-devel
        cl-MySQL55-server
        cloog-ppl
        compat-db42
        compat-db43
        ConsoleKit
        coreutils
        cpanel-userperl
        cpio
        cpp
        cpuspeed
        cracklib
        cracklib-dicts
        crda
        cronie
        cronie-anacron
        crontabs
        cryptsetup-luks
        curl
        cvs
        cyrus-sasl
        cyrus-sasl-lib
        dash
        db4-utils
        dbus
        dbus-glib
        desktop-file-utils
        device-mapper
        device-mapper-event
        device-mapper-persistent-data
        dhclient
        diffutils
        dmidecode
        dmraid
        dmraid-events
        dos2unix
        dosfstools
        dovecot
        dracut
        e2fsprogs
        ed
        efibootmgr
        eject
        elfutils
        elinks
        ethtool
        exim
        expat
        expect
        file
        filesystem
        findutils
        fipscheck
        flex
        fontconfig
        fprintd
        freetype-devel
        ftp
        gawk
        gcc
        gcc-c++
        GConf2
        gdb
        gd-devel
        gdk-pixbuf2
        gd-progs
        gettext
        ghostscript
        ghostscript-devel
        glib2
        glibc
        glibc-common
        gnupg2
        governor-mysql
        grep
        groff
        grub
        grubby
        gtk2
        gzip
        hal
        hdparm
        hunspell
        ImageMagick
        ImageMagick-c++-devel
        ImageMagick-devel
        info
        initscripts
        iotop
        iproute
        iptables
        iptables-ipv6
        iputils
        irqbalance
        iw
        jwhois
        kbd
        kernelcare
        kexec-tools
        kpartx
        krb5-devel
        lcms
        less
        libcap
        libcgroup
        libcom_err-devel
        libcroco
        libgcj
        libgpg-error
        libhugetlbfs-utils
        libidn
        libjpeg-turbo
        libpng-devel
        libproxy-bin
        libreport
        libreport-cli
        libreport-compat
        libreport-plugin-kerneloops
        libreport-plugin-logger
        libreport-plugin-mailx
        libreport-plugin-reportuploader
        libreport-plugin-rhtsupport
        librsvg2
        libselinux
        libselinux-utils
        libtar
        libtiff
        libtool
        libuser
        libwmf
        libxml2
        libxml2-devel
        libXpm-devel
        logrotate
        lsof
        lua
        lve
        lvemanager
        lve-stats
        lve-utils
        lvm2
        lynx
        m4
        mailx
        make
        MAKEDEV
        man
        mdadm
        microcode_ctl
        mingetty
        mlocate
        module-init-tools
        mtr
        nano
        nc
        ncurses
        ncurses-devel
        net-tools
        newt
        ngrep
        nss-sysinit
        nss-tools
        ntsysv
        numactl
        openssh
        openssh-clients
        openssh-server
        openssl
        p11-kit
        pam
        pango
        parted
        passwd
        patch
        pciutils
        pcmciautils
        pcre
        pcre-devel
        perl
        perl-CPANPLUS
        perl-DBI
        perl-devel
        perl-libwww-perl
        perl-Module-CoreList
        pinentry
        pinfo
        pkgconfig
        plymouth
        plymouth-scripts
        pm-utils
        policycoreutils
        polkit
        portreserve
        ppl
        prelink
        procps
        psacct
        psmisc
        pure-ftpd
        python
        python-devel
        python-ethtool
        python-tools
        python-urlgrabber
        quota
        rcs
        rdate
        readahead
        rfkill
        rhn-check
        rhn-client-tools
        rhnsd
        rhn-setup
        rng-tools
        rpm
        rsync
        rsyslog
        screen
        sed
        setserial
        setuptool
        sgml-common
        sgpio
        shadow-utils
        shared-mime-info
        sharutils
        smartmontools
        sos
        sqlite
        strace
        stunnel
        sudo
        sysstat
        system-config-firewall-base
        system-config-firewall-tui
        system-config-network-tui
        systemtap-runtime
        sysvinit-tools
        tar
        tcl
        tcpdump
        tcp_wrappers
        tcsh
        telnet
        time
        tk
        tmpwatch
        traceroute
        udev
        unixODBC
        unzip
        upstart
        usbutils
        usermode
        util-linux-ng
        vconfig
        vim-common
        vim-enhanced
        vim-minimal
        wget
        which
        wireless-tools
        xdg-utils
        xorg-x11-font-utils
        xz
        xz-lzma-compat
        yum
        yum-utils
        zip
    );
    
    my %okbins = (
        '/bin/su', '.M....G..',
        '/bin/ping', '.M.......',
        '/bin/ping6', '.M.......',
        '/usr/bin/locate', '.M.......',
        '/usr/bin/quota', '.M.......',
        '/usr/bin/screen', '.M.......',
        '/usr/sbin/userhelper', '.M.......',
        '/usr/bin/chsh', '.M.......',
        '/usr/bin/ld', '.M....G..',
        '/usr/bin/c99', '.M....G..',
        '/usr/bin/gcc', '.M....G..',
        '/usr/bin/x86_64-redhat-linux-gcc', '.M....G..',
        '/usr/bin/c++', '.M....G..',
        '/usr/bin/g++', '......G..',
        '/usr/bin/x86_64-redhat-linux-c++', '......G..',
        '/usr/bin/x86_64-redhat-linux-g++', '......G..',
    );

    my @badbins ;
    my @warnbins;
    print "\n[      Running RPM Checks      ]\n ";
    my $x=0 ; 
    for my $rpm (@rpms) {
        $x++;
        push @badbins, qx(rpm -V $rpm 2> /dev/null | egrep "/(s)?bin");
        if ($x=="10") {
	    print "=";
	    $x=0;
        }
    }
    my @debuglist;
    chomp (@badbins);
    print "\n";

    foreach (@badbins) {
        if ($_ =~ m/(S.*|.*5.*|.*L.*)    \//) {
            push @warnbins, $_;
            my $index = 0;
            $index++ until $badbins[$index] eq "$_";
            splice(@badbins, $index, 1);
        } elsif ($_ =~ m/missing     \//) {
            my $index = 0;
            $index++ until $badbins[$index] eq "$_";
            splice(@badbins, $index, 1);
        }
    }

    foreach (@badbins) {
        my $binary=(split (/    /, $_))[1];
        my $verify_string=(split (/    /, $_))[0];
        if (exists $okbins{$binary}) {
            my $verify_okstring= $okbins{$binary};
            if ($verify_string ne $verify_okstring) {
                print BOLD YELLOW ON_BLACK "[INFO] * Modified Attribute: ".$binary."\n";
                if ($debug) {
                    push @debuglist, "RPM: ".qx(rpm -qf $binary);
                    push @debuglist, "File: ".$_;
                    push @debuglist, "Classification: [INFO] * Modified Attribute";
                    push @debuglist, "=============";
                }
            }
         } else {
             print BOLD YELLOW ON_BLACK "[INFO] * Modified Attribute: ".$binary."\n";
             if ($debug) {
                 push @debuglist, "RPM: ".qx(rpm -qf $binary);
                 push @debuglist, "File: ".$_;
                 push @debuglist, "Classification: [INFO] * Modified Attribute";
                 push @debuglist, "=============";
             }
         }
    }

    foreach (@warnbins) {
        my $binary=(split (/    /, $_))[1];
        my $verify_string=(split (/    /, $_))[0];
        if (exists $okbins{$binary}) {
            my $verify_okstring= $okbins{$binary};
            if ($verify_string ne $verify_okstring) {
                print BOLD RED ON_BLACK "[WARN] * Modified Binary: ".$binary."\n";
                if ($debug) {
                    push @debuglist, "RPM: ".qx(rpm -qf $binary);
                    push @debuglist, "File: ".$_;
                    push @debuglist, "Classification: [WARN] * Modified Binary";
                    push @debuglist, "=============";
                }
            }
        } else {
            print BOLD RED ON_BLACK "[WARN] * Modified Binary: ".$binary."\n";
             if ($debug) {
                 push @debuglist, "RPM: ".qx(rpm -qf $binary);
                 push @debuglist, "File: ".$_;
                 push @debuglist, "Classification: [INFO] * Modified Attribute";
                 push @debuglist, "=============";
             }
        }
    }

    my @aliases=grep /^alias/, qx{/bin/bash -ic alias};
    print BOLD GREEN ON_BLACK "[ALIASES] * ".scalar @aliases." Found\n";
    foreach (@aliases) {
        print BOLD CYAN ON_BLACK "\t- ";
        print BOLD CYAN ON_BLACK $_;
    }
    print BOLD GREEN ON_BLACK '[!] Run "unalias -a" to unset all aliases'."\n";
    print BOLD MAGENTA '[NOTE] * If any of the above binaries should not be showing up in the above list, run this script with --bug to generate a bug report'."\n\n";
    
    if ($debug) {
        chomp (@debuglist);
        my $ticket = "";
        if (exists $ENV{HISTFILE}) {
            if ( $ENV{HISTFILE} =~ /ticket.(\d+)$/ ) {
                $ticket = $1;
            }
        }
        my $date=qx(date);
        my $kernel=qx(uname -r);
        my $arch=qx(uname -p);
        my $cp_version=qx(cat /usr/local/cpanel/version);
        my $os=qx(cat /etc/redhat-release);
        chomp ($ticket);
        chomp ($date);

        my $message =  " =============================================\n CSI Bug Report: $date\n =============================================\n Kernel: $kernel Arch: $arch OS: $os cPanel: $cp_version Ticket: $ticket\n\n\n";

        print "Please send the below report to samir.jafferali\@cpanel.net.\n\n";
        print " --REPORT START--\n";
        print $message ; 
        print " -DEBUG START-\n";
        foreach (@debuglist) {
            print " ".$_."\n";
        }
        print "  -DEBUG STOP-\n";
        print " --REPORT END--\n\n\n";
    }
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

sub logfinder {
    detect_system();
    print_normal('') if (!$short);
    print_header('[ Starting cPanel Security Inspection: Logfinder Mode ]') if (!$short);
    print_header("[ Version $version ]") if (!$short);
    print_header("[ System Type: $systype ]") if (!$short);
    print_header("[ OS: $os ]") if (!$short);
    print_normal('') if (!$short);
    print_header("[ Available flags when running csi.pl --file: ]") if (!$short);
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
    detect_system();
    print_normal('') if (!$short);
    print_header('[ Starting cPanel Security Inspection: Logfinder Mode ]') if (!$short);
    print_header("[ Version $version ]") if (!$short);
    print_header("[ System Type: $systype ]") if (!$short);
    print_header("[ OS: $os ]") if (!$short);
    print_normal('') if (!$short);
    print_header("[ Available flags when running csi.pl --timestamp: ]") if (!$short);
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
    if (-s '/usr/local/apache/domlogs/ftpxferlog') {
        my $firstline ;
        my $lastline ;
        chomp($firstline=qx(head -1 /usr/local/apache/domlogs/ftpxferlog | awk '{print\$2" "\$3" "\$4" "\$5}'));
        chomp($lastline=qx(tail -1 /usr/local/apache/domlogs/ftpxferlog | awk '{print\$2" "\$3" "\$4" "\$5}'));
        $firstline =~ tr/\/|:/ / ;
        $lastline =~ tr/\/|:/ / ;
        my @first= split(/ /, $firstline);
        my @last= split(/ /, $lastline);

        $firstline = timelocal($first[4],$first[3],$first[2],$first[1],$mon2num{ lc substr($first[0], 0, 3) }-1,$first[5]);
        $lastline = timelocal($last[4],$last[3],$last[2],$last[1],$mon2num{ lc substr($last[0], 0, 3) }-1,$last[5]);

        if ($firstline < $epoc_mtime && $lastline > $epoc_mtime) {
            push @mftp, qx(egrep -H "$searchmftp" /usr/local/apache/domlogs/ftpxferlog);
        }
    }

    if ($owner ne "root") {
        @files=();
        opendir(DIR, "/home/$owner/logs");
        @files = grep(/^ftp.*/,readdir(DIR));
        closedir(DIR);
        foreach my $file (@files) {
            my $filesize = -s "/home/$owner/logs/$file";
            if ( $filesize > 80 ) {
                my $firstline ;
                my $lastline ;
                chomp($firstline=qx(zcat /home/$owner/logs/$file | head -1 | awk '{print\$2" "\$3" "\$4" "\$5}'));
                chomp($lastline=qx(zcat /home/$owner/logs/$file | tail -1 | awk '{print\$2" "\$3" "\$4" "\$5}'));
                $firstline =~ tr/\/|:/ / ;
                $lastline =~ tr/\/|:/ / ;
                my @first= split(/ /, $firstline);
                my @last= split(/ /, $lastline);

                $firstline = timelocal($first[4],$first[3],$first[2],$first[1],$mon2num{ lc substr($first[0], 0, 3) }-1,$first[5]);
                $lastline = timelocal($last[4],$last[3],$last[2],$last[1],$mon2num{ lc substr($last[0], 0, 3) }-1,$last[5]);
                if ($firstline < $epoc_mtime && $lastline > $epoc_mtime) {
                    push @mftp, qx(zegrep -H "$searchmftp" /home/$owner/logs/$file);
                }
            }
        }
    }
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

            $firstline = timelocal($first[5],$first[4],$first[3],$first[1],$first[0]-1,$first[2]);
            $lastline = timelocal($last[5],$last[4],$last[3],$last[1],$last[0]-1,$last[2]);

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
    my @first ; 
    my @last ; 
    @first= split(/ /, $firstline);
    @last= split(/ /, $lastline);
    $firstline = timelocal($first[5],$first[4],$first[3],$first[1],$first[0]-1,$first[2]);
    $lastline = timelocal($last[5],$last[4],$last[3],$last[1],$last[0]-1,$last[2]);
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
    detect_system();
    print_normal('');
    print_header('[ Starting cPanel Security Inspection: Rootkitscan Mode ]');
    print_header("[ Version $version ]");
    print_header("[ System Type: $systype ]");
    print_header("[ OS: $os ]");
    print_normal('');
    print_header("[ Available flags when running csi.pl --rootkitscan: ]");
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
        my @wget_cmd = ( "$wget", "-q", "--no-check-certificate", "$makefile_url", "-O", "/root/Makefile.csi" );
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

    qx($chkrootkit_bin 2> /dev/null | egrep 'INFECTED|vulnerable' | grep -v "INFECTED (PORTS:  465)" | grep -v "passwd" > $csidir/chkrootkit.log 2> /dev/null);

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

sub get_process_list { # Usage of this needs to be deprecated in favor of the %process hash
    return split /\n/, timed_run( 0, 'ps', 'axwwwf', '-o', 'user,pid,cmd' );
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
    ## UMBREON CHECK
    if ( chdir('/usr/local/__UMBREON__') ) {
	push @SUMMARY, 'Evidence of UMBREON rootkit detected';
    }
    
    ## JYNX2 CHECK
    if ( chdir '/usr/bin64' ) {
        my @found_jynx2_files = ();
        my @jynx2_files = qw( 3.so 4.so );
        for (@jynx2_files) {
            my $file = "/usr/bin64/" . $_;
            if ( -e $file ) {
                push(@found_jynx2_files, $file);
            }
        }
        if ( (scalar @found_jynx2_files) != 0 ) {
            push @SUMMARY, 'Evidence of JYNX 2 rootkit detected';
        }
    }
    
    ## DRAGNET CHECK
    if ( open my $fh, '<', '/proc/self/maps' ) {
        while (<$fh>) {
            if ( m{ (\s|\/) libc\.so\.0 (\s|$) }x ) {
            push @SUMMARY, 'Evidence of DRAGNET rootkit detected';
            last;
            }
        }
        close($fh);
    }
    
    ## EBURY ROOT FILE CHECK
    my $eburyfile = '/home/ ./root';
    if ( -e $eburyfile ) {
    	push @SUMMARY, 'Evidence of EBURY rootkit detected. Found file: ' . $eburyfile;
    }
    
    ## BG BOTNET CHECK
    check_for_bg_botnet();
    
    ## LIBKEYUTILS CHECKS
    check_for_libkeyutils_filenames();
    check_sha1_sigs_libkeyutils();
    
    ## CDORKED/EBURY CHECKS
    check_for_ebury_ssh_banner();
    check_for_cdorked_A();
    check_for_cdorked_B();
    check_sha1_sigs_httpd();
    check_sha1_sigs_named();
    check_sha1_sigs_ssh();
    check_sha1_sigs_ssh_add();
    check_sha1_sigs_sshd();
    check_for_ebury_socket();
    check_for_ebury_ssh_G();
    check_for_ebury_ssh_shmem();
    
    print_status('Done.');
}

sub check_for_bg_botnet {
    my @found_bg_files = ();
    # Not including the following /tmp files in the list because any non-root user can create them and trigger a false-positive just for the lolz.
    # /tmp/bill.lock
    # /tmp/gates.lock
    # /tmp/moni.lock
    # /tmp/notify.file
    # /bin/ps, /bin/netstat, and /usr/sbin/lsof have also been found to be modified
    # This one is causing some rare false-positives:
    # /root/aa
    my @bg_files = qw(
        /boot/pro
        /boot/proh
        /etc/sfewfesfsh
        /usr/bin/pojie
        /etc/atdd
        /etc/atddd
        /etc/cupsdd
        /etc/cupsddd
        /etc/dsfrefr
        /etc/ferwfrre
        /etc/gfhddsfew
        /etc/gfhjrtfyhuf
        /etc/ksapd
        /etc/ksapdd
        /etc/kysapd
        /etc/kysapdd
        /etc/rewgtf3er4t
        /etc/sdmfdsfhjfe
        /etc/sfewfesfs
        /etc/sksapd
        /etc/sksapdd
        /etc/skysapd
        /etc/skysapdd
        /etc/xfsdx
        /etc/xfsdxd
        /usr/bin/.sshd
        /usr/bin/bsd-port/getty
        /usr/lib/libamplify.so
        /etc/rc.d/init.d/DbSecuritySpt
        /etc/rc.d/init.d/selinux
    );
    for my $file (@bg_files) {
        if ( -e $file ) {
            push(@found_bg_files, $file);
        }
    }
    return unless ( scalar @found_bg_files );
    push @SUMMARY, 'BG BOTNET: The following files were found: ' . join(" ", @found_bg_files);
}

sub check_for_ebury_ssh_shmem {
    # As far as we know, sshd sholudn't be using shared memory at all, so any usage is a strong sign of ebury.
    return if ! defined($ipcs{root}{mp});

    for my $href ( @{$ipcs{root}{mp}} ) {
        my $shmid = $href->{shmid};
        my $cpid = $href->{cpid};
        if ( $process{$cpid}{CMD} && $process{$cpid}{CMD} =~ m{ \A /usr/sbin/sshd \b }x ) {
            push @SUMMARY, 'EBURY: Shared memory segment created by sshd process exists -  sshd PID:' . $cpid . ' shmid:' . $shmid;
            last;
        }
    }
}

sub check_for_ebury_ssh_G {
    my $ssh = '/usr/bin/ssh';
    return if !-e $ssh;
    return if !-f $ssh;
    return if !-x $ssh;
    return if -z $ssh;

    my $ssh_G = timed_run_trap_stderr( 0, $ssh, '-G' );
    if ( $ssh_G !~ /illegal|unknown/ ) {
        push @SUMMARY, 'EBURY: ' . $ssh . " -G' did not return either 'illegal' or 'unknown'";
    }
}

sub check_for_cdorked_A {
    my $apache_bin = '/usr/local/apache/bin/httpd';
    my $max_bin_size = 10_485_760; # avoid slurping too much mem
    return if ( !-f $apache_bin );
    return if ((stat($apache_bin))[7] > $max_bin_size );

    my $has_cdorked = 0;
    my $signature;
    my @apache_bins = ();
    push @apache_bins, $apache_bin;


    for my $process (@process_list) {
        if ( $process =~ m{ \A root \s+ (\d+) [^\d]+ $apache_bin }xms ) {
            my $pid = $1;
            my $proc_pid_exe = "/proc/" . $pid . "/exe";
            if ( -l $proc_pid_exe && readlink($proc_pid_exe) =~ m{ \(deleted\) }xms ) {
                next if ((stat($proc_pid_exe))[7] > $max_bin_size );
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
            $signature = $check_bin . ": \"" . $1 . "\"";
            $has_cdorked = 1;
            last;
        }
    }

    if ( $has_cdorked == 1 ) {
        push @SUMMARY, 'CDORKED: String found in $signature (see ticket 4482347)';
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
        push @SUMMARY, 'CDORKED: The following files were found (note the spaces at the end of the files): ' . $cdorked_files;
    }
}

sub check_sha1_sigs_libkeyutils {
    my $libs = shift;
    return if !$libs;

    my $trojaned_lib;

    # p67 http://www.welivesecurity.com/wp-content/uploads/2014/03/operation_windigo.pdf
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

    for my $lib (@$libs) {
        next unless my $checksum = timed_run( 0, 'sha1sum', "$lib" );
        chomp $checksum;
        $checksum =~ s/\s.*//g;
        if ( grep { /$checksum/ } @checksums ) {
            $trojaned_lib = "$lib\n\tSHA-1 checksum: $checksum";
            last;
        }
    }

    if ( $trojaned_lib ) {
    	push @SUMMARY, 'EBURY: The following files were found : ' . $trojaned_lib;
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
        push @SUMMARY, "EBURY: " . $ssh_add . " has a SHA-1 signature of " . $sha1sum;
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
        push @SUMMARY, "EBURY: " . $sshd . " has a SHA-1 signature of " . $sha1sum;

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
        push @SUMMARY, "EBURY: " . $ssh . " has a SHA-1 signature of " . $sha1sum;
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
        PeerAddr    => $host,
        PeerPort    => $port,
        Proto       => 'tcp',
        Timeout     => 5,
    ) or return;

    $ssh_banner = readline $sock;
    close $sock;
    return if !$ssh_banner;
    chomp $ssh_banner;

    if ( $ssh_banner =~ m{ \A SSH-2\.0-[0-9a-f]{22,46} }xms ) {
        push @SUMMARY, 'sshd banner matches known signature from ebury infected machines: ' . $ssh_banner;
    }
}

sub check_for_ebury_socket {
    return unless my $netstat_out = timed_run( 0, 'netstat', '-nap' );
    for my $line ( split( '\n', $netstat_out ) ) {
        if ( $line =~ m{@/proc/udevd} ) {
            push @SUMMARY, 'EBURY: "netstat -nap" output contains: ' . $line;
            last;
        }
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
        push @SUMMARY, "CDORKED: " . $named . " has a SHA-1 signature of " . $sha1sum;
    }
}

sub check_sha1_sigs_httpd {
    my $httpd = '/usr/local/apache/bin/httpd';
    return if !-e $httpd;
    my $infected = 0;
    return unless my $sha1sum = timed_run( 0, 'sha1sum', $httpd );
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
        push @SUMMARY, "CDORKED: " . $httpd . " has a SHA-1 signature of " . $sha1sum;
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
                );

    for my $dir (@dirs) {
        next if !-e $dir;
        for my $file (@files) {
            if ( -f "${dir}/${file}" and !-z "${dir}/${file}" ) {
                $bad_libs .= "\t${dir}/${file}\n";
            }
        }
    }

    if ($bad_libs) {
    	push @SUMMARY, "EBURY: The following file(s) were found: " . $bad_libs; 
    }
}

sub get_process_pid_hash ($) {
    my ($href) = @_;
    for ( split /\n/, timed_run( 0, 'ps', 'axwww', '-o', 'user,pid,ppid,cmd' ) ) {
        # nobody    5403  1666 /usr/local/apache/bin/httpd -k start -DSSL
        if ( m{ ^ ([^\s]+) \s+ (\d+) \s+ (\d+) \s+ (.*?) \s* $ }xms ) {
            ${$href}{$2}{USER} = $1;
            ${$href}{$2}{PPID} = $3;
            ${$href}{$2}{CMD} = $4;
        }
    }
}

sub get_ipcs_hash ($) {
    my ($href) = @_;
    my $header = 0;
    # For now, all we need is shared memory segment owner and creator-pid, but the data structure is extensible.
    # ipcs -m -p
    #
    #------ Shared Memory Creator/Last-op --------
    #shmid      owner      cpid       lpid
    #2228224    root       992        992
    #2588673    root       1309       1315
    #2195458    root       985        985
    #2621443    root       1309       1315
    for ( split /\n/, timed_run( 0, 'ipcs', '-m', '-p' ) ) {
        if ( $header == 0 ) {
            $header = 1 if m/^ shmid \s+ owner \s+ cpid \s+ lpid \s* $/ix;
            next;
        }
        my @ipcs = split(/\s+/, $_, 5);
        push @{${$href}{$ipcs[1]}{'mp'}}, { # Key by owner, type 'mp' (-m -p output)
            'shmid' => $ipcs[0],
            'cpid' => $ipcs[2],
            'lpid' => $ipcs[3]
        };
    }
}

sub timed_run_trap_stderr { # Borrowed from Cpanel::SafeRun::Timed and modified
    my ( $timer, @PROGA ) = @_;
    $timer = $timer ? $timer : 25; # A timer value of 0 means use the default, currently 25.
    return if ( substr( $PROGA[0], 0, 1 ) eq '/' && !-x $PROGA[0] );

    open( my $save_stderr_fh, '>&STDERR' );
    open( STDERR, '>', '/dev/null' );

    my $output = ""; # In the event of time-out or failure, return empty string instead of undef.
    my $complete = 0;
    my $pid;
    my $fh;    # Case 63723: must declare $fh before eval block in order to avoid unwanted implicit waitpid on die
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

sub timed_run { # Borrowed from Cpanel::SafeRun::Timed and modified
    my ( $timer, @PROGA ) = @_;
    $timer = $timer ? $timer : 25; # A timer value of 0 means use the default, currently 25.
    return if ( substr( $PROGA[0], 0, 1 ) eq '/' && !-x $PROGA[0] );

    open( my $save_stderr_fh, '>&STDERR' );
    open( STDERR, '>', '/dev/null' );

    my $output = ""; # In the event of time-out or failure, return empty string instead of undef.
    my $complete = 0;
    my $pid;
    my $fh;    # Case 63723: must declare $fh before eval block in order to avoid unwanted implicit waitpid on die
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
        kill( 15, $pid );    #TERM
        sleep(2);            # Give the process a chance to die 'nicely'
        kill( 9, $pid );     #KILL
    }
    open( STDERR, '>&=' . fileno($save_stderr_fh) );
    return $output;
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
