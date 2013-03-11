#!/usr/bin/perl

# Copyright(c) 2013 cPanel, Inc.
# All rights Reserved.
# copyright@cpanel.net
# http://cpanel.net
# Unauthorized copying is prohibited

# Tested on cPanel 11.30 - 11.36

# Maintainers: Charles Boyd, Marco Ferrufino, Dan Stewart

use strict;
use warnings;

use Cwd 'abs_path';
use File::Spec;
use Term::ANSIColor qw(:constants);
$Term::ANSIColor::AUTORESET = 1;

my $version = '2.0.5';

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
my $no3rdparty = 0;		# Default to running 3rdparty scanners

foreach my $arg (@ARGV) {
  if ( $arg =~ '--no3rdparty' ) {
    $no3rdparty = 1;
  }
}

#######################################
# Set variables needed for later subs #
#######################################

chomp( my $wget = qx(which wget) );
chomp( my $make = qx(which make) );

my $top = File::Spec->curdir();
my $csidir = File::Spec->catdir($top,'CSI');

my $rkhunter_bin = File::Spec->catfile( $csidir, 'rkhunter', 'bin', 'rkhunter' );
my $chkrootkit_bin = File::Spec->catfile( $csidir, 'chkrootkit', 'chkrootkit' );
my $lynis_bin = File::Spec->catfile( $csidir, 'lynis', 'lynis' );

my $CSISUMMARY;
my $touchfile = '/var/cpanel/perl/easy/Cpanel/Easy/csi.pm';
my @logfiles  = (
		 '/usr/local/apache/logs/access_log',
		 '/usr/local/apache/logs/error_log',
		 '/var/log/messages',
		 '/var/log/maillog',
		 '/var/log/wtmp',
		);
my $systype;
my $os;
my $linux;
my $freebsd;

######################
# Run code main body #
######################

scan();

########
# Subs #
########

sub scan {

  detect_system();
  print_normal('');
  print_header('[ Starting cPanel Security Inspection ]');
  print_header("[ Version $version on Perl $] ]");
  print_header("[ System Type: $systype ]");
  print_header("[ OS: $os ]" );
  print_normal('');
  print_header("[ Available flags when running $0 (if any): ]");
  print_header('[     --no3rdparty (disables running of 3rdparty scanners) ]') unless ($no3rdparty);
  print_normal('');
  print_header('[ Cleaning up from earlier runs, if needed ]');
  check_previous_scans();
  print_normal('');

  create_summary();

  unless ( $no3rdparty ) {

    if ( -f "Makefile.csi" ) {
      print_header('[ Makefile already present ]');
    } else {
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
    run_lynis();
    print_normal('');

    print_header('[ Cleaning up ]');
    cleanup();
    print_normal('');
  } else {
    print_header('[ Running without 3rdparty rootkit and security checking programs ]');
    print_normal('');
  }

  print_header('[ Checking logfiles ]');
  check_logfiles();
  print_normal('');

  print_header('[ Checking for bad UIDs ]');
  check_uids();
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

  print_header('[ Checking /tmp for known hackfiles ]');
  check_hackfiles();
  print_normal('');

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

  $systype = qx(uname -a | cut -f1 -d" ");
  chomp($systype);

  if ( $systype eq 'Linux' ) {
    $linux = 1;
    $os = qx(cat /etc/redhat-release);
    push @logfiles, '/var/log/secure';
  } elsif ( $systype eq 'FreeBSD' ) {
    $freebsd = 1;
    $os = qx(uname -r);
    push @logfiles, '/var/log/auth.log';
  } else {
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
    my $makefile_url = 'http://cptechs.info/csi/Makefile.csi';
    my @wget_cmd = ( "$wget", "-q", "$makefile_url" );
    system(@wget_cmd);
  } else {
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

  } else {
    print_error('Make is either not installed or has no execute permissions, please check $make');
    print_normal('Exiting CSI ');
    exit 1;
  }
  print_status('Done.');

}

sub check_previous_scans {

  if ( -e $touchfile ) {
    print $CSISUMMARY "*** This server was previously flagged as compromised and hasn't been reloaded, or $touchfile has not been removed. ***\n";
    print $CSISUMMARY "\n";
  }

  if ( -d $csidir ) {
    chomp( my $date = qx(date +%Y%m%d) );
    print_info("Existing $csidir is present, moving to $csidir-$date");
    rename "$csidir", "$csidir-$date";
    mkdir $csidir;
  } else {
    mkdir $csidir;
  }

  print_status('Done.');

}

sub check_kernel_updates {

  chomp( my $newkernel = qx(yum check-update kernel | grep kernel | awk '{ print \$2 }') );
  if ( $newkernel ne '' ) {
    print $CSISUMMARY "Server is not running the latest kernel, kernel update available: $newkernel\n";
  }

  print_status('Done.');

}

sub run_rkhunter {

  print_status('Running rkhunter. This will take a few minutes.');

  qx($rkhunter_bin --cronjob --rwo > $csidir/rkhunter.log 2>&1);

  if ( -s "$csidir/rkhunter.log" ) {
    open( my $RKHUNTLOG, '<', "$csidir/rkhunter.log" )
      or die("Cannot open logfile $csidir/rkhunter.log: $!");
    my @lines = grep /Rootkit/, <$RKHUNTLOG>;
    if (@lines) {
      print $CSISUMMARY "Rkhunter has found a suspected rootkit infection(s):\n";
      print $CSISUMMARY "@lines\n";
      print $CSISUMMARY "More information can be found in the log at $csidir/rkhunter.log\n";
    }
    close $RKHUNTLOG;
  }

  print_status('Done.');

}

sub run_chkrootkit {

  print_status('Running chkrootkit. This will take a few minutes.');

  qx($chkrootkit_bin 2> /dev/null | egrep 'INFECTED|vulnerable' | grep -v "INFECTED (PORTS:  465)" > $csidir/chkrootkit.log 2> /dev/null);

  if ( -s "$csidir/chkrootkit.log" ) {
    open( my $LOG, '<', "$csidir/chkrootkit.log" )
      or die("Cannot open logfile $csidir/chkrootkit.log: $!");
    print $CSISUMMARY
      "Chkrootkit has found a suspected rootkit infection(s):\n";
    my @results = <$LOG>;
    print $CSISUMMARY "@results\n";
    close $LOG;
  }

  print_status('Done.');

}

sub run_lynis {

  print_status('Running Lynis. This will take a few minutes.');

  qx($lynis_bin -c -Q --no-colors > $csidir/lynis.output.log 2>&1);
  rename "/var/log/lynis.log", "$csidir/lynis.report.log";

  print_status('Done.');

}

sub check_logfiles {

  if ( !-d '/usr/local/apache/logs' ) {
    print $CSISUMMARY ("/usr/local/apache/logs directory is not present");
  }

  foreach my $log (@logfiles) {
    if ( !-f $log ) {
      print $CSISUMMARY
	"Log file $log is missing or not a regular file\n";
    }
  }

  print_status('Done.');

}

sub check_index {

  if ( -f '/tmp/index.htm' or -f '/tmp/index.html' ) {
    print $CSISUMMARY "Index file found in /tmp\n";
  }

  print_status('Done.');

}

sub check_suspended {

  if ( -f '/var/cpanel/webtemplates/root/english/suspended.tmpl' ) {
    print $CSISUMMARY "Custom account suspended template found at /var/cpanel/webtemplates/root/english/suspended.tmpl\n";
    print $CSISUMMARY "     This could mean the admin just created a custom template or that an attacker gained access\n";
    print $CSISUMMARY "     and created it (hack page)\n";
  }
    
  print_status('Done.');

}

sub check_history {

  if ( -e '/root/.bash_history' ) {
    if ( -l '/root/.bash_history' ) {
      my $result = qx(ls -la /root/.bash_history);
      print $CSISUMMARY "/root/.bash_history is a symlink, $result\n";
    } elsif ( !-s '/root/.bash_history' and !-l '/root/.bash_history' ) {
      print $CSISUMMARY "/root/.bash_history is a 0 byte file\n";
    }
  } else {
    print $CSISUMMARY "/root/.bash_history is not present, this indicates probable tampering\n";
  }

  print_status('Done.');

}

sub check_modsecurity {

  my $result = qx(/usr/local/apache/bin/apachectl -M 2>/dev/null);

  if ( $result !~ /security2_module|security_module/ ) {
    print $CSISUMMARY "Mod Security is disabled\n";
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
    foreach my $name (@tmplist) {
      if ( $name =~ /\b$file_test$/ ) {
	push( @hackfound, $name );
      }
    }
  }

  if ( @hackfound ) {
    foreach my $file (@hackfound) {
      chomp $file;
      print $TMPLOG "---------------------------\n";
      print $TMPLOG "Processing $file\n";
      print $TMPLOG "\n";
      print $TMPLOG "File metadeta:\n";
      print $TMPLOG stat $file if ( -s $file );
      print $TMPLOG "\n";
      print $TMPLOG "File type:\n";
      print $TMPLOG `file $file` if ( -s $file );
      print $CSISUMMARY "$file found in /tmp, check $csidir/tmplog for more information\n";

      if ( $file =~ 'jpg' ) {
	print $TMPLOG "\n";
	print $TMPLOG "$file has .jpg in the name, let's check out the first few lines to see of it really is a .jpg\n";
	print $TMPLOG "Here are the first 5 lines:\n";
	print $TMPLOG "===========================\n";
	print $TMPLOG `cat -n $file | head -5`;
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
    if ( $uid == 0 && ! $user eq "root" ) {
      push @baduids, $user;
    }
  }
  endpwent();

  if ( @baduids ) {
    print $CSISUMMARY "Users with UID of 0 detected:\n";
    foreach my $bad ( @baduids ) {
      print_warn( "$bad" );
      print $CSISUMMARY "$bad\n";
    }
    print $CSISUMMARY "\n";
  }
  print_status( 'Done.' );
}

sub check_httpd_config {

  my $httpd_conf = '/usr/local/apache/conf/httpd.conf';
  if ( -f $httpd_conf ) {
    my $apache_options = qx(grep -A1 '<Directory "/">' $httpd_conf);
    if (    $apache_options =~ 'FollowSymLinks'
            and $apache_options !~ 'SymLinksIfOwnerMatch' ) {
      print $CSISUMMARY "Apache configuration allows symlinks without owner match\n";
    }
  } else {
    print $CSISUMMARY "Apache configuration file is missing\n";
  }
  print_status('Done.');

}

sub check_processes {

  chomp( my @ps_output = qx(ps aux) );
  foreach my $line (@ps_output) {
    if ( $line =~ 'sleep 7200' ) {
      print $CSISUMMARY "Ps output contains 'sleep 7200' which is a known part of a hack process:\n";
      print $CSISUMMARY "     $line\n";
    }
    if ( $line =~ / perl$/ ) {
      print $CSISUMMARY "Ps output contains 'perl' without a command following, which probably indicates a hack:\n";
      print $CSISUMMARY "     $line\n";
    }
  }
    
  print_status('Done.');

}

sub check_ssh {

  my @ssh_errors;
  my $ssh_verify;

  # Check RPM verification for SSH packages
  foreach my $rpm ( qx(rpm -qa openssh*) ) {
    chomp($rpm);
    $ssh_verify = qx(rpm -V $rpm | egrep -v 'ssh_config|sshd_config|pam.d');
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
    print $CSISUMMARY "System has detected the presence of a *POSSIBLY* compromised SSH:\n";
    print $CSISUMMARY @ssh_errors;
  }

  print_status('Done.');

}

sub check_lib {

  my @lib_errors;
  my @lib_files = glob '/lib*/*';

  foreach my $file (@lib_files) {
    if (-f $file && -l $file) {
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
    print $CSISUMMARY "System has detected the presence of a library file not owned by an RPM, these libraries *MAY* indicate a compromise or could have been custom installed by the administrator.\n";
    print $CSISUMMARY @lib_errors;
  }
    
  print_status('Done.');

}

sub create_summary {

  open( $CSISUMMARY, '>', "$csidir/summary" )
    or die("Cannot create CSI summary file $csidir/summary: $!\n");

}

sub dump_summary {

  if ( -z $CSISUMMARY ) {
    print_status("No negative items were found");
  } else {
    open $CSISUMMARY, '<', "$csidir/summary";
    print_warn("The following negative items were found:");
    while (<$CSISUMMARY>) {
      print BOLD GREEN $_;
    }
    print_normal('');
    print_normal('');
    print_status("[L1/L2] If a rootkit(s) or hack files in /tmp were found then please copy/paste the summary output into the ticket and escalate it to L3.");
    print_status("[L3 only] If a rootkit has been detected, please mark the ticket Hacked Status as 'H4x0r3d' and run:");
    print_normal("touch $touchfile");
  }

  close $CSISUMMARY;

}

sub cleanup {
  my $makefile = File::Spec->catfile( $top, 'Makefile.csi' );
  my @make_clean = ( "$make", "-f", "$makefile", "clean" );
  system(@make_clean);

}

sub print_normal {
  my $text = shift;
  print "$text\n";

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
    # EOF
