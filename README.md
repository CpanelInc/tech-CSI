CSI (cPanel Security Investigator)

A script that provides a variety of functions to assist with the investigation of both root- and user-level compromises. 
By default, Its purpose is to scan for rootkits or root-level compromises.  But it can also perform a user level scan.  

Originally, this script installed some 3rd party tools such as rkhunter and chkrootkit.  But those programs have not been 
updated in a number of years and seem to have been abandoned.  This script has been completedly overhauled since then and 
they have since been removed.

########################################################################
### DISCLAIMER! cPanel's Technical Support does not provide            #
### security consultation services. The only support services we       #
### can provide at this time is to perform a minimal analysis of the   #
### possible security breach solely for the purpose of determining if  #
### cPanel's software was involved or used in the security breach.     #
########################################################################
### As with any anti-malware scanning system false positives may occur #
### If anything suspicious is found, it should be investigated by a    #
### professional security consultant. There are never any guarantees   #
########################################################################

Usage: /usr/local/cpanel/3rdparty/bin/perl csi.pl [options] [function]

Functions
=================
With no arguments, performs a quick scan looking for IoC's.

--bincheck  Performs RPM verification on core system binaries and prints active aliases.

--userscan cPanelUser  Performs YARA scan [using clamscan if ClamAV is installed] for a single cPanel User..

Additional scan options available
=================
--shadow    Performs a check on all email accounts looking for variants of shadow.roottn hack.
--symlink   Performs a symlink hack check for all accounts.
--secadv    Runs Security Advisor
--full      Performs all of the above checks - very time consuming.

Examples
=================
            /root/csi.pl [DEFAULT] quick scan
            /root/csi.pl --symlink
            /root/csi.pl --full
Bincheck:
            /root/csi.pl --bincheck
Userscan
            /root/csi.pl --userscan myuser

