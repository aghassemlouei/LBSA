#!/bin/bash

#------------------------------------------------------------------------------------------------------------------------------
# LBSA - Linux Basic Security Audit script
#------------------------------------------------------------------------------------------------------------------------------
# (c) Neale Rudd, 2008-2014, All rights reserved
# Download latest version from http://wiki.metawerx.net/wiki/LBSA
# Version 1.0.49
# Last updated 31/03/2014 5:25AM
#
# License: GPL v3
# Language: Shell script (bash)
# Required permissions: root or equivalent
# Script type: Check and report (no modifications are made to your system)
# Expected output: System Checks Completed
# Source: http://wiki.metawerx.net/wiki/LBSA
#
#------------------------------------------------------------------------------------------------------------------------------
# GUIDE
#------------------------------------------------------------------------------------------------------------------------------
# This script runs a series of basic linux security checks for Continuous
# Policy Enforcement (CPE).  It is, and will always be, a work in progress.
# The script was originally designed for use on Ubuntu, but will most likely
# work with other distros.
#
# The checks are far from exhaustive, but can highlight some basic setup 
# issues from default linux installs and continuously enforce policies that
# you require in your specific environment.
#
# These checks include a subset of setup policies which I use for hardening
# server configurations.  As such, not all checks may be suitable for your
# environment.  For example, I don't allow root to login over SSH.  This may
# cause issues in your environment, or may be too restrictive for home use in
# some cases.
#
# If your own settings are more restrictive than these, or you have your own
# opinions on the settings, then modify this script to suit your own purposes.
# The main idea is to have a script that can enforce your own policies, and to
# run it regularly.  It is not necessary to follow my policies line-by-line.
# 
# That said, this script should be suitable for most servers and home users
# "as-is", and for other admins it should give you some ideas for your own
# script, or at very least should make for a good read :-)
#
# Usage notes
# Ideally, this script would be called by a wrapper script of your own, which
# implements other checks more specific to your environment.  For example,
# if you run Apache, you may want to also check various folder permissions
# for Apache, then call this script as the final step of your own script.
# The script should be called regularly by cron or another scheduler and mail
# results to the administrator for review if the output changes.
#
# Criticisms and Counter Arguments (Feb 2013)
# In a comment on reddit, someones mentioned I ought to be dunked in honey
# and given to a colony of ants for writing lines that are longer than 80
# characters.  I agree and I now have a new fear on ants, thank you.
# Many lines are still longer than 80 characters.  Sorry, they just are.
# They also commented that passwd -l root will lock the root account from
# accessing the console.  This may be correct but I still recommend it.
# They also commented that if there is proper configuration management, then
# checking folder and file permissions is unnecessary.  I respectully disagree.
# If a system is breached, folder and file permissions may be changed and
# continuous policy checking is one way to be alerted to such a change quickly.
# Finally, they commented that "moving the SSH port from 22, which is asinine
# and provides no actual protection, simply makes it more difficult for people
# to manage those systems."  I also respectfully disagree with that - Port
# scanning bots hit port 22 and changing the default port helps to reduce
# automated threats.  Using a different port than 22 does not make it more
# difficult to manage systems if you are using a configuration management
# system or only have a single server to worry about.
# Ref: http://wiki.centos.org/HowTos/Network/SecuringSSH
#
# Disclaimer
# This is a free script provided to the community.  I am not responsible
# for any changes you make to your own system.  All opinions expressed are my
# own and are not necessarily the opinion of my employer, any company or
# organisation, or anyone else.
#
# Recent changes:
# 1.0.49 - Modified the hashing time suggestion for password-based logins
# 1.0.48 - Added test to find SSH-key based logins in non-home folders
# 1.0.47 - Switched to octal permissions
# 1.0.47 - Added warnings for BlowFish and SHA256 (SHA512 is available)
# 1.0.47 - Added recommendations for multiple hashing rounds in /etc/shadow
# 1.0.47 - Fixed bug which caused script to wait when outputing MD5 warning
# 1.0.46 - Added GPL v3 License
# 1.0.46 - Switched to use of check_path function instead of all the loops
# 1.0.45 - Changed use of ls to stat for 25% speed improvement
# 1.0.45 - Removed UUOC (useless use of cat)
# 1.0.45 - Commenting changes, reduced header comments width to <80 chars
#
# Other useful tools:
# * Bastille - hardening toolkit which covers lots of things not covered here
# * AIDE - monitor for file changes
# * fail2ban - scan logs, ban IP addresses
#
#
#------------------------------------------------------------------------------------------------------------------------------
# HOW TO USE
#------------------------------------------------------------------------------------------------------------------------------
# First, change parameters in the SETTINGS section to suit your environment,
# or call this script from a wrapper script that sets these variables.
#
# The script should be executed as root with bash.
# eg:
#   export LBSA_PERMITTED_LOGIN_ACCOUNTS="nrudd|sjackson"
#   bash sec_lbsa.sh
#
# A series of checks are executed
# No modifications are performed
#
# Running this script should produce no result except the phrase
# "System Checks Completed", at position 0 of the output.
# If there is any other output, then one or more warnings have been issued
#
# This can be used in cron or another scheduler to send a mail using a command
# like the following:
#   export LBSA_PERMITTED_LOGIN_ACCOUNTS="nrudd|sjackson";
#   LBSA_RESULTS=`bash sec_lbsa.sh`;
#   if [ "$LBSA_RESULTS" != "System Checks Completed" ]; then {your sendmail command here}; fi
#
#
#------------------------------------------------------------------------------------------------------------------------------
# SETTINGS
#------------------------------------------------------------------------------------------------------------------------------
# Settings are in if-blocks in case you want to call this script from a
# wrapper-script to avoid modifying it.  This allows for easier upgrades.

# Permitted Login Accounts
#    Specify the list of permitted logins in quotes, separated by |
#    If there are none, just leave it blank.  root should not be listed here, as we don't want root logging in via SSH either.
#    Valid examples:
#    LBSA_PERMITTED_LOGIN_ACCOUNTS=""
#    LBSA_PERMITTED_LOGIN_ACCOUNTS="user1"
#    LBSA_PERMITTED_LOGIN_ACCOUNTS="user1|user2|user3"
if [ ! -n "$LBSA_PERMITTED_LOGIN_ACCOUNTS" ]; then
    LBSA_PERMITTED_LOGIN_ACCOUNTS=""
fi

# If you aren't worried about allowing any/all SSH port forwarding, change this to yes
if [ ! -n "$LBSA_ALLOW_ALL_SSH_PORT_FORWARDING" ]; then
    LBSA_ALLOW_ALL_SSH_PORT_FORWARDING=no
fi

# Set this to yes to provide additional SSH recommendations
if [ ! -n "$LBSA_INCLUDE_EXTRA_SSH_RECOMMENDATIONS" ]; then
    LBSA_INCLUDE_EXTRA_SSH_RECOMMENDATIONS=no
fi



#------------------------------------------------------------------------------------------------------------------------------
# FUNCTIONS
#------------------------------------------------------------------------------------------------------------------------------

# Check permissions, owner and group, output warnings if they do not match
check_path() {

	PERMS=$1			# recommended perms, eg: 755 (rwxr-xr-x)
	OWNER=$2			# recommended owner
	GROUP=$3			# recommended group
	CHECKPATH=$4		# path to check
	
	if [ -e $CHECKPATH ]; then
	
		# Run commands
		CPERMS=`stat -L -c %a $CHECKPATH`
		COWNER=`stat -L -c %U $CHECKPATH`
		CGROUP=`stat -L -c %G $CHECKPATH`

		# Compare
	    if [ "$CPERMS" != "$PERMS" ]; then
	    	echo "Permission recommendation for [$CHECKPATH] is [$PERMS].  Current setting is [$CPERMS]"
    	fi
	    if [ "$COWNER" != "$OWNER" ]; then
	    	echo "Owner recommendation for [$CHECKPATH] is [$OWNER].  Current setting is [$COWNER]"
    	fi
	    if [ "$CGROUP" != "$GROUP" ]; then
	    	echo "Group recommendation for [$CHECKPATH] is [$GROUP].  Current setting is [$CGROUP]"
		fi
	fi
}


#------------------------------------------------------------------------------------------------------------------------------
# PASSWORD-BASED LOGIN HASH CHECK
#------------------------------------------------------------------------------------------------------------------------------

# ACCT_HASHING
# Make sure no account is using MD5, they should be upgraded to use SHA-512
# On older installs, when accounts were set up MD5 was the default, and this cannot be auto-upgraded during Linux updates
# man crypt for details
# 1 MD5, 2a BlowFish, 5 SHA-256, 6 SHA-512
# Ref: http://linux.die.net/man/3/crypt
# This is only really important if the /etc/shadow file is compromised after a breakin

if [ "`chpasswd --help | grep -e " \-s, "`" = "" -o "`chpasswd --help | grep -e " \-c, "`" = "" ]; then
	echo "WARNING: Your version of chpasswd does not support crypt-method or sha-round. You cannot use the latest hashing algorithms."
	HASH=":\$1\$"
	if [ "`fgrep "$HASH" /etc/shadow`" != "" ]; then
		echo "WARNING: Your passwords are stored as MD5 hashes.  Upgrade your kernel and your chpasswd command to enable SHA-256/SHA-512 hashes.  See: http://en.wikipedia.org/wiki/MD5, http://en.wikipedia.org/wiki/Rainbow_table"
	fi
else
	# MD5 is trivial to dehash within seconds using a rainbow table website so your plaintext passwords will be immediately readable
	HASH=":\$1\$"
	if [ "`fgrep "$HASH" /etc/shadow`" != "" ]; then
		echo "Warning: 1 or more account passwords use MD5 hashing.  When these accounts were set up, MD5 may have been the default but it is now easily decodable.  See: http://en.wikipedia.org/wiki/MD5, http://en.wikipedia.org/wiki/Rainbow_table";
		echo "Update these accounts to SHA512*200000 or stronger with chpasswd or passwd: " `fgrep "$HASH" /etc/shadow | cut -d ":" -f 1`
		echo "eg: chpasswd -c SHA512 -s 200000 <<<'user:newPassword'"
	fi
	HASH=":\$2a\$"
	if [ "`fgrep "$HASH" /etc/shadow`" != "" ]; then
		echo "Warning: 1 or more account passwords use BlowFish hashing.  This is a hashing algorithm designed in 1993 which the creator now recommends against using.  See: http://en.wikipedia.org/wiki/Blowfish_(cipher)";
		echo "Update these accounts to SHA512*200000 or stronger with chpasswd or passwd: " `fgrep "$HASH" /etc/shadow | cut -d ":" -f 1`
		echo "eg: chpasswd -c SHA512 -s 200000 <<<'user:newPassword'"
	fi
	HASH=":\$5\$"
	if [ "`grep "$HASH" /etc/shadow`" != "" ]; then
		echo "Warning: 1 or more account passwords use SHA-256 hashing.  SHA-512 is now available and uses more rounds to encrypt.  See: http://en.wikipedia.org/wiki/SHA-2";
		echo "Update these accounts to SHA512*200000 or stronger with chpasswd or passwd: " `fgrep "$HASH" /etc/shadow | cut -d ":" -f 1`
		echo "eg: chpasswd -c SHA512 -s 200000 <<<'user:newPassword'"
	fi
	HASH=":\$[0-9]"
	if [ "`grep "$HASH" /etc/shadow | grep -v "\$rounds="`" != "" ]; then
		echo "Warning: 1 or more account passwords are using a single round of hashing.  By increasing the number of hashing rounds, the computational time to verify a login password will increase and so will the computational time to reverse your hashes in case of a break-in.  See: http://en.wikipedia.org/wiki/Key_stretching";
		echo "Update these accounts to SHA512*200000 or stronger with chpasswd or passwd: " `grep "$HASH" /etc/shadow | cut -d ":" -f 1`
		echo "eg: chpasswd -c SHA512 -s 200000 <<<'user:newPassword'"
		echo "To see the time overhead for 200000 rounds, use this command ..."
		echo "time chpasswd -S -c SHA512 -s 200000 <<<'testuser:testpass'"
		echo "... change the -s parameter until the time is acceptable (eg: 0.2-0.5s) then use the new value to change your password."
	fi
fi


#------------------------------------------------------------------------------------------------------------------------------
# LOGINS
#------------------------------------------------------------------------------------------------------------------------------

# ROOT_NOT_LOCKED
# Make sure root account is locked (no SSH login, no console logins)
if [ "$LBSA_ALLOW_ROOT_LOGIN" != "true" ]; then passwd -S root | grep -v " L " | xargs -r -iLINE echo -e "Warning: root account is not locked and may allow login over SSH or other services.  Warning: When locked, root will not be able to log in at the console - make sure you have another user configured with sudo access.  Use [passwd -dl root] and [chage -E-1 root] to ensure the root account is locked but can still run cron jobs. [LINE]\n"; fi
# Fix: passwd -dl root; chage -E-1 root;

# ROOT_PASS_TIMING
# Make sure root password is set to 0 min 99999 max 7 warning -1 inactivity
# This may occur with ROOT_PASS_EXPIRES
passwd -S root | grep -v "0 99999 7 -1" | xargs -r -iLINE echo -e "Warning: root account has non-standard min/max/wait/expiry times set.  If the root password expires, cron jobs and other services may stop working until the password is changed. [LINE]\n"
# Fix: chage -m 0 -M 99999 -W 7 -I -1 root

# ROOT_PASS_EXPIRES
# Make sure root password is set to never expire
# This will normally occur with ROOT_PASS_TIMING
chage -l root | grep "Password expires" | grep -v never | xargs -r -iLINE echo -e "Warning: root password has an expiry date.  If the root password expires, cron jobs and other services may stop working until the password is changed. [LINE]\n"
# Fix: chage -m 0 -M 99999 -W 7 -I -1 root

# ROOT_ACCT_EXPIRES
# Make sure root account is set to never expire
chage -l root | grep "Account expires" | grep -v never | xargs -r -iLINE echo -e "Warning: root account has an expiry date -- though Linux surely protects against it expiring automatically [recommend setting it to never expire]. [LINE]\n"
# Fix: chage -E-1 root

# UNEXPECTED_USER_LOGINS_PRESENT
# Make sure the users that can log in, are ones we know about
# First, get user list, excluding any we already have stated should be able to log in
if [ "$LBSA_PERMITTED_LOGIN_ACCOUNTS" = "" ]; then
    USERLIST=`cat /etc/passwd | cut -f 1 -d ":"`
else
    USERLIST=`grep -v -w -E "$LBSA_PERMITTED_LOGIN_ACCOUNTS" /etc/passwd | cut -f 1 -d ":"`
fi
# Find out which ones have valid passwords
LOGINLIST=""
for USERNAME in $USERLIST
do
    if [ "`passwd -S $USERNAME | grep \" P \"`" != "" ]; then
        if [ "$LOGINLIST" = "" ]; then
            LOGINLIST="$USERNAME"
        else
            LOGINLIST="$LOGINLIST $USERNAME"
        fi
    fi
done
# Report
if [ "$LOGINLIST" != "" ]; then
    echo "Warning: the following user(s) are currently granted login rights to this machine: [$LOGINLIST]."
    echo "If users in this list should be allowed to log in, please add their usernames to the LBSA_PERMITTED_LOGIN_ACCOUNTS setting in this script, or set the environment variable prior to calling this script."
    echo "If an account is only used to run services, or used in cron, the account should not be permitted login rights, so lock the account with [passwd -dl <username>] to help prevent it being abused."
    echo "Note: after locking the account, the account will also be marked as expired, so use [chage -E-1 <username>] to set the account to non-expired/never-expire, otherwise services or cron tasks that rely on the user account being active will fail."
    echo ""
fi
# Fix: lock the specified accounts then set them non-expired, or specify the users that are listed are ok to log in by
# adding them to LBSA_PERMITTED_LOGIN_ACCOUNTS


#------------------------------------------------------------------------------------------------------------------------------
# Key-based logins that are not in the /home folder
# - Comment this section out if you have a valid need for these
#------------------------------------------------------------------------------------------------------------------------------

# List anything that's not in the home folder (protected above)
RESULT1=`grep -v ':/home/' /etc/passwd | cut -d : -f 6 | xargs -r -IFOLDER ls -al FOLDER/.ssh/authorized_keys 2>/dev/null`
RESULT2=`grep -v ':/home/' /etc/passwd | cut -d : -f 6 | xargs -r -IFOLDER ls -al FOLDER/.ssh/authorized_keys2 2>/dev/null`
if [ "$RESULT1" != "" -o "$RESULT2" != "" ]; then
	echo "Warning: the following files allow key-based login to your system and are not inside your /home folder"
	echo "Unless you created these logins intentionally, this could indicate a back-door into your system"
	if [ "$RESULT1" != "" ]; then echo "$RESULT1"; fi
	if [ "$RESULT2" != "" ]; then echo "$RESULT2"; fi
fi


#--------------------------------------------------------------------------------------------------------------
# General
#--------------------------------------------------------------------------------------------------------------

# Ensure /etc/hosts contains an entry for this server name
export LBSA_HOSTNAME=`hostname`
if [ "`grep -w "$LBSA_HOSTNAME$" /etc/hosts | grep -v "^#"`" = "" ]; then
	echo "There is no entry for the server's name [`hostname`] in /etc/hosts.  This may cause unexpected performance problems for local connections and NFS issues.  Add the IP and name in /etc/hosts, eg: 192.168.0.1 `hostname`";
	echo;
fi


#--------------------------------------------------------------------------------------------------------------
# SSH Setup
#--------------------------------------------------------------------------------------------------------------

# Ensure SSHD config is set securely (we do use TcpForwarding, so allow TcpForwarding)
if [ "`grep -E ^Port /etc/ssh/sshd_config`"                     = "Port 22"                    ]; then echo "SSHD Config: Port is set to default (22).  Recommend change to a non-standard port to make your SSH server more difficult to find/notice.  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^ListenAddress /etc/ssh/sshd_config`"            = ""                           -a "$LBSA_ALLOW_SSH_ALL_ADDRESSES" != "true" ]; then echo "SSHD Config: ListenAddress is set to default (all addresses).  SSH will listen on ALL available IP addresses.  Recommend change to a single IP to reduce the number of access points.  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^PermitRootLogin /etc/ssh/sshd_config`"         != "PermitRootLogin no"         -a "$LBSA_ALLOW_ROOT_LOGIN" != "true" -a "$LBSA_ALLOW_ROOT_LOGIN_SSHCERT" != "true" ]; then echo "SSHD Config: PermitRootLogin should be set to no (prefer log in as a non-root user, then sudo/su to root).  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^PermitEmptyPasswords /etc/ssh/sshd_config`"    != "PermitEmptyPasswords no"    ]; then echo "SSHD Config: PermitEmptyPasswords should be set to no (all users must use passwords/keys).  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^UsePrivilegeSeparation /etc/ssh/sshd_config`"  != "UsePrivilegeSeparation yes" ]; then echo "SSHD Config: UsePrivilegeSeparation should be set to yes (to chroot most of the SSH code, unless on older RHEL).  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^Protocol /etc/ssh/sshd_config`"                != "Protocol 2"                 ]; then echo "SSHD Config: Protocol should be set to 2 (unless older Protocol 1 is really needed).  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^X11Forwarding /etc/ssh/sshd_config`"           != "X11Forwarding no"           ]; then echo "SSHD Config: X11Forwarding should be set to no (unless needed).  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^StrictModes /etc/ssh/sshd_config`"             != "StrictModes yes"            ]; then echo "SSHD Config: StrictModes should be set to yes (to check file permissions of files such as ~/.ssh, ~/.ssh/authorized_keys etc).  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^IgnoreRhosts /etc/ssh/sshd_config`"            != "IgnoreRhosts yes"           ]; then echo "SSHD Config: IgnoreRhosts should be set to yes (this method of Authentication should be avoided).  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^HostbasedAuthentication /etc/ssh/sshd_config`" != "HostbasedAuthentication no" ]; then echo "SSHD Config: HostbasedAuthentication should be set to no (this method of Authentication should be avoided).  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^RhostsRSAAuthentication /etc/ssh/sshd_config`" != "RhostsRSAAuthentication no" ]; then echo "SSHD Config: RhostsRSAAuthentication should be set to no (this method of Authentication should be avoided).  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^GatewayPorts /etc/ssh/sshd_config`"            != ""                           ]; then echo "SSHD Config: GatewayPorts is configured.  These allow listening on non-localhost addresses on the server.  This is disabled by default, but has been added to the config file.  Recommend remove this setting unless needed.  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^PermitTunnel /etc/ssh/sshd_config`"            != ""                           ]; then echo "SSHD Config: PermitTunnel is configured.  This allows point-to-point device forwarding and Virtual Tunnel software such as VTun to be used.  This is disabled by default, but has been added to the config file.  Recommend remove this setting unless needed.  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi

# Commenting out Subsystem sftp is fairly pointless, SCP can still be used and most tools fall back to SCP automatically.  Additionally, it's possible to copy files using just SSH and redirection.
# if [ "`grep -E "^Subsystem sftp" /etc/ssh/sshd_config`"      != ""                           ]; then echo "SSHD Config: Comment out Subsystem SFTP (unless needed).  While enabled, any user with SSH shell access can browse the filesystem and transfer files using SFTP/SCP.  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi

if [ "$LBSA_ALLOW_ALL_SSH_PORT_FORWARDING" != "yes" ]; then
    if [ "`grep -E ^AllowTcpForwarding /etc/ssh/sshd_config`" != "" ]; then 
        if [ "`grep -E ^AllowTcpForwarding /etc/ssh/sshd_config`" != "AllowTcpForwarding no" ]; then
            if [ "`grep -E ^PermitOpen /etc/ssh/sshd_config`" = "" ]; then
                echo "SSHD Config: AllowTcpForwarding has been explicitly set to something other than no, but no PermitOpen setting has been specified.  This means any user that can connect to a shell or a forced-command based session that allows open port-forwarding, can port forward to any other accessible host on the network (authorized users can probe or launch attacks on remote servers via SSH port-forwarding and make it appear that connections are coming from this server).  Recommend disabling this feature by adding [AllowTcpForwarding no], or if port forwarding is required, providing a list of allowed host:ports entries with PermitOpen.  For example [PermitOpen sql.myhost.com:1433 mysql.myhost.com:3306].  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."
                echo "* Note: If this is ok for this machine, set LBSA_ALLOW_ALL_SSH_PORT_FORWARDING=yes in this script, or set the environment variable prior to calling this script."
                echo
            fi
        fi
    fi
    if [ "`grep -E ^AllowTcpForwarding /etc/ssh/sshd_config`" = "" ]; then 
        if [ "`grep -E ^PermitOpen /etc/ssh/sshd_config`" = "" ]; then
            echo "SSHD Config: AllowTcpForwarding is not specified, so is currently set to the default (yes), but no PermitOpen setting has been specified.  This means any user that can connect to a shell or a forced-command based session that allows open port-forwarding, can port forward to any other accessible host on the network (authorized users can probe or launch attacks on remote servers via SSH port-forwarding and make it appear that connections are coming from this server).  Recommend disabling this feature by adding [AllowTcpForwarding no], or if port forwarding is required, providing a list of allowed host:ports entries with PermitOpen.  For example [PermitOpen sql.myhost.com:1433 mysql.myhost.com:3306].  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."
            echo "* Note: If this is ok for this machine, set LBSA_ALLOW_ALL_SSH_PORT_FORWARDING=yes in this script, or set the environment variable prior to calling this script."
            echo
        fi
    fi
fi

# Additional recommendations (These are not critical, but helpful.  These are typically not specified so strictly by default
# so will almost definitely require the user to change some of the settings manually.  They are in an additional section
# because they are not as critical as the settings above.
if [ "$LBSA_INCLUDE_EXTRA_SSH_RECOMMENDATIONS" = "yes" ]; then

    # Specify DenyUsers/DenyGroups for extra protection against root login over SSH
    if [ "$LBSA_ALLOW_ROOT_LOGIN" != "true" ]; then
        if [ "`grep -E ^DenyUsers /etc/ssh/sshd_config | grep root`"  = "" ]; then echo "SSHD Config: (Extra Recommendation) DenyUsers is not configured, or is configured but has not listed the root user.  Recommend adding [DenyUsers root] as an extra protection against root login (allow only su/sudo to obtain root access).  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
        if [ "`grep -E ^DenyGroups /etc/ssh/sshd_config | grep root`" = "" ]; then echo "SSHD Config: (Extra Recommendation) DenyGroup is not configured, or is configured but has not listed the root group.  This means that if a user is added to the root group and are able to log in over SSH, then that login is effectively the same as a root login anyway.  Recommend adding [DenyUsers root] as an extra protection against root login (allow only su/sudo to obtain root access).  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
    fi

    # Get rid of annoying RDNS lookups which can cause timeouts if RDNS fails
    if [ "`grep -E "^UseDNS no" /etc/ssh/sshd_config`" = "" ]; then echo "SSHD Config: (Extra Recommendation) Set UseDNS no.  This will stop RDNS lookups during authentication.  Advantage 1: RDNS can be spoofed, which will place an incorrect entry in auth.log causing problems with automated log-based blocking of brute-force attack sources.  This change will eliminate the problem of RDNS spoofing.  Advantage 2: If RDNS fails, timeouts can occur during SSH login, preventing access to the server in worst cases.  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi

	# Reduce timeouts, max attempts and max number of concurrent logins
	LoginGraceTime=`grep ^LoginGraceTime /etc/ssh/sshd_config | tr -s " " | cut -d " " -f 2`
	if [ "$LoginGraceTime" = "" ]; then LoginGraceTime=120; fi
	MaxAuthTries=`grep ^MaxAuthTries /etc/ssh/sshd_config | tr -s " " | cut -d " " -f 2`
	if [ "$MaxAuthTries" = "" ]; then MaxAuthTries=6; fi
	MaxStartups=`grep ^MaxStartups /etc/ssh/sshd_config | tr -s " " | cut -d " " -f 2`
	if [ "$MaxStartups" = "" ]; then MaxStartups=10; fi
	MaxConcurrent=`expr "$MaxStartups" "*" "$MaxAuthTries"`
	if [ "$LoginGraceTime" -gt 30 ]; then echo "SSHD Config: (Extra Recommendation) LoginGraceTime is set to [$LoginGraceTime].  This setting can be used to reduce the amount of time a user is allowed to spend logging in.  A malicious user can use a large time window to more easily launch DoS attacks or consume your resources.  Recommend reducing this to 30 seconds (or lower) with the setting [LoginGraceTime 30].  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
	if [ "$MaxAuthTries" -gt 4 ]; then echo "SSHD Config: (Extra Recommendation) MaxAuthTries is set to [$MaxAuthTries].  This allows the user $MaxAuthTries attempts to log in per connection.  The total number of concurrent login attempts your machine provides are ($MaxAuthTries MaxAuthTries) * ($MaxStartups MaxStartups) = $MaxConcurrent.  Note that only half of these will be logged.  Recommend reducing this to 4 (or lower) with the setting [MaxAuthTries 4].  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
	if [ "$MaxStartups" -gt 3 ]; then echo "SSHD Config: (Extra Recommendation) MaxStartups is set to [$MaxStartups].  This allows the user to connect with $MaxStartups connections at the same time, before authenticating.  The total number of concurrent login attempts your machine provides are ($MaxAuthTries MaxAuthTries) * ($MaxStartups MaxStartups) = $MaxConcurrent.  Note that only half of these will be logged.  Recommend reducing this to 3 (or lower) with the setting [MaxStartups 3].  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
fi


#------------------------------------------------------------------------------------------------------------------------------
# PERMISSIONS / OWNERS / GROUPS  -  LINUX TOP LEVEL FOLDER
#------------------------------------------------------------------------------------------------------------------------------

check_path 755 root root /bin
check_path 755 root root /boot
check_path 755 root root /dev
check_path 755 root root /etc
check_path 755 root root /home
check_path 755 root root /lib
check_path 755 root root /lib64
check_path 755 root root /media
check_path 755 root root /mnt
check_path 755 root root /opt
check_path 555 root root /proc
check_path 700 root root /root
check_path 755 root root /run
check_path 755 root root /sbin
check_path 755 root root /srv
if [ "`stat -L -c %a /sys | grep -v "555"`" = "" ]; then
	# Allow sys to be 555 on newer distros like 12.10 onwards
	check_path 555 root root /sys
else
	check_path 755 root root /sys
fi
check_path 1777 root root /tmp
check_path 755 root root /usr
check_path 755 root root /var


#------------------------------------------------------------------------------------------------------------------------------
# PERMISSIONS / OWNERS / GROUPS  -  /ETC/SSH FOLDER
# Auto-fix all warnings in this area with: chmod 600 -R /etc/ssh; chown root:root -R /etc/ssh
#------------------------------------------------------------------------------------------------------------------------------

# 600 seems ok for the entire /etc/ssh folder.  I can connect to SSH OK, and make outgoing SSH connections OK as various users.
# This prevents non-root users from viewing or modifying SSH config details which could be used for attacks on other user
# accounts or potential privelege elevation.
check_path 600 root root /etc/ssh/moduli
check_path 600 root root /etc/ssh/sshd_config
check_path 600 root root /etc/ssh/sshd_host_dsa_key
check_path 600 root root /etc/ssh/sshd_host_rsa_key
check_path 600 root root /etc/ssh/sshd_host_ecdsa_key
check_path 600 root root /etc/ssh/sshd_host_key
check_path 600 root root /etc/ssh/blacklist.DSA-1024
check_path 600 root root /etc/ssh/blacklist.RSA-2048

# Ubuntu defaults private keys to 600 all other files to 644
# CentOS defaults public keys to 644 all other files to 600
check_path 600 root root /etc/ssh/ssh_config
check_path 600 root root /etc/ssh/ssh_host_dsa_key.pub
check_path 600 root root /etc/ssh/ssh_host_rsa_key.pub
check_path 600 root root /etc/ssh/ssh_host_ecdsa_key.pub
check_path 600 root root /etc/ssh/ssh_host_key.pub

# Ubuntu defaults folder to 755
# CentOS defaults folder to 755
check_path 600 root root /etc/ssh


#------------------------------------------------------------------------------------------------------------------------------
# PERMISSIONS / OWNERS / GROUPS  -  /ETC FOLDER SPECIAL FILES
#------------------------------------------------------------------------------------------------------------------------------

# These are just the Ubuntu defaults as per 12.04, ensure they haven't changed
check_path 440 root root /etc/sudoers
check_path 600 root root /etc/.pwd.lock
check_path 600 root root /etc/gshadow-
check_path 600 root root /etc/group-
check_path 600 root root /etc/shadow-
check_path 600 root root /etc/passwd-
check_path 640 root daemon /etc/at.deny
check_path 640 root fuse /etc/fuse.conf
check_path 640 root shadow /etc/shadow
check_path 640 root shadow /etc/gshadow
check_path 755 root root /etc/rmt
check_path 755 root root /etc/rc.local


#--------------------------------------------------------------------------------------------------------------
# CHECK FOR WORLD WRITABLE FOLDERS
#--------------------------------------------------------------------------------------------------------------

# Search for world writables in /etc or other folders
FOLDERS="/etc /bin /sbin /usr/bin"
for FOLDER in $FOLDERS
do
    # Find any files/folders in /etc which are world-writable
    # Future: also need to ensure files are owned by root.  If not, they may be able to be written to anyway.
    if [ "`find $FOLDER -type f -perm -002`" != "" ]; then
        echo "Warning: There are files under [$FOLDER] which are world writable.  It is a security risk to have world-writables in this folder, as they may be modified by other users and executed as root."
        echo "A complete list of these files follows:"
        find $FOLDER -type f -perm -002 | xargs -r ls -al
        echo ""
    fi
    if [ "`find $FOLDER -type d -perm -002`" != "" ]; then
        echo "Warning: There are folders in [$FOLDER] which are world writable.  It is a security risk to have world-writables in this folder, as they may be modified by other users and executed as root."
        echo "A complete list of these folders follows:"
        find $FOLDER -type d -perm -002
        echo ""
    fi
done


#--------------------------------------------------------------------------------------------------------------
# CHECK FOR INSECURE TMP AND SHM FOLDERS /tmp, /usr/tmp, /var/tmp, /dev/shm
#--------------------------------------------------------------------------------------------------------------

# TODO: this doesn't check /usr/tmp or /var/tmp yet

# /tmp

# First ensure that /tmp is a separate partition in mtab, otherwise the following tests are useless
if [ "$LBSA_ALLOW_NON_SEPARATE_TMP_PARTITION" != "true" ]; then
    if [ "`cat /etc/mtab | grep /tmp`" = "" ]; then
	    echo "Warning: /tmp is not a separate partition, so cannot be marked nodev/nosuid/noexec.  Override this warning with LBSA_ALLOW_NON_SEPARATE_TMP_PARTITION=true";
    else

    # Ensure noexec
    # Note: Even though most admins recommend /tmp is noexec, the aptitude (apt-get) tool in do-release-upgrade mode
    # require exec permissions in /tmp and will stop with an error before installing the upgrade because /tmp has no exec permissions.
    # Workaround: Either edit /etc/apt/apt.conf and change the TempDir for apt to something else (such as /var/cache/apt/tmp), or before using the do-release-upgrade command, use this command to temporarily assign exec rights on /tmp: [mount -oremount,exec /tmp]
    if [ "`cat /etc/mtab | grep /tmp | grep noexec`" = "" ]; then
        echo "Warning: /tmp has EXECUTE permissions.  Recommend adding noexec attribute to mount options for /tmp, in /etc/fstab."
        echo "This change will help in preventing malicious users from installing and executing binary files from the folder."
        echo "To test, run these commands.  The output should say Permission denied if your system is already protected: cp /bin/ls /tmp; /tmp/ls; rm /tmp/ls;"
        echo "Tip: after adding the attribute, you can remount the partition with [mount -oremount /tmp] to avoid having to reboot."
        echo "Note: Even though most admins recommend /tmp is noexec, Ubuntu release upgrades require exec permissions in /tmp for some reason and will stop with an error before installing the upgrade because /tmp has no exec permissions."
        echo "Workaround: Either edit /etc/apt/apt.conf and change the TempDir for apt to something else (such as /var/cache/apt/tmp), or before using the do-release-upgrade command, use this command to temporarily assign exec rights on /tmp: [mount -oremount,exec /tmp]"
        echo ""
    fi
    
    # Ensure nosuid
    if [ "`cat /etc/mtab | grep /tmp | grep nosuid`" = "" ]; then
        echo "Warning: /tmp has SUID permissions.  Recommend adding nosuid attribute to mount options for /tmp, in /etc/fstab."
        echo "This change will help in preventing malicious users from setting SUID on files on this folder.  SUID files will run as root if they are owned by root."
        echo "Tip: after adding the attribute, you can remount the partition with [mount -oremount /tmp] to avoid having to reboot."
        echo ""
    fi
    
    # Ensure nodev
    if [ "`cat /etc/mtab | grep /tmp | grep nodev`" = "" ]; then
        echo "Warning: /tmp has DEVICE permissions.  Recommend adding nodev attribute to mount options for /tmp, in /etc/fstab."
        echo "This change will help in preventing malicious users from creating device files in the folder.  Device files should be creatable in temporary folders."
        echo "Tip: after adding the attribute, you can remount the partition with [mount -oremount /tmp] to avoid having to reboot."
        echo ""
        fi
    fi
fi

# /dev/shm

if [ "`cat /etc/mtab | grep /dev/shm`" != "" ]; then

    # Ensure noexec
    if [ "`cat /etc/mtab | grep /dev/shm | grep noexec`" = "" ]; then
        echo "Warning: /dev/shm has EXECUTE permissions.  Recommend adding noexec attribute to mount options for /dev/shm, in /etc/fstab."
        echo "This change will help in preventing malicious users from installing and executing malicious files from the folder."
        echo "To test, run these commands.  The output should say Permission denied if your system is already protected: cp /bin/ls /dev/shm; /dev/shm/ls; rm /dev/shm/ls;"
        if [ "`cat /etc/fstab | grep /dev/shm`" = "" ]; then
            echo "Note: you do not currently have /dev/shm listed in /etc/fstab, so it is being mounted with default options by Linux."
            echo "To fix, add this line to /etc/fstab, then remount it with [mount -oremount /dev/shm] to avoid having to reboot."
            echo "none /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0"
            echo ""
        else
            echo "Tip: after adding the attribute, you can remount the partition with [mount -oremount /dev/shm] to avoid having to reboot."
        fi
        echo ""
    fi
    
    # Ensure nosuid
    if [ "`cat /etc/mtab | grep /dev/shm | grep nosuid`" = "" ]; then
        echo "Warning: /dev/shm has SUID permissions.  Recommend adding nosuid attribute to mount options for /dev/shm, in /etc/fstab."
        echo "This change will help in preventing malicious users from setting SUID on files on this folder.  SUID files will run as root if they are owned by root."
        if [ "`cat /etc/fstab | grep /dev/shm`" = "" ]; then
            echo "Note: you do not currently have /dev/shm listed in /etc/fstab, so it is being mounted with default options by Linux."
            echo "To fix, add this line to /etc/fstab, then remount it with [mount -oremount /dev/shm] to avoid having to reboot."
            echo "none /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0"
            echo ""
        else
            echo "Tip: after adding the attribute, you can remount the partition with [mount -oremount /dev/shm] to avoid having to reboot."
        fi
        echo ""
    fi
    
    # Ensure nodev
    if [ "`cat /etc/mtab | grep /dev/shm | grep nodev`" = "" ]; then
        echo "Warning: /dev/shm has DEVICE permissions.  Recommend adding nodev attribute to mount options for /dev/shm, in /etc/fstab."
        echo "This change will help in preventing malicious users from creating device files in the folder.  Device files should be creatable in temporary folders."
        if [ "`cat /etc/fstab | grep /dev/shm`" = "" ]; then
            echo "Note: you do not currently have /dev/shm listed in /etc/fstab, so it is being mounted with default options by Linux."
            echo "To fix, add this line to /etc/fstab, then remount it with [mount -oremount /dev/shm] to avoid having to reboot."
            echo "none /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0"
            echo ""
        else
            echo "Tip: after adding the attribute, you can remount the partition with [mount -oremount /dev/shm] to avoid having to reboot."
        fi
        echo ""
    fi
fi


#--------------------------------------------------------------------------------------------------------------
# CHECK HEARTBEAT CONFIG (if present)
#--------------------------------------------------------------------------------------------------------------

if [ -e /etc/ha.d ]; then

    # Default is 755, but no reason for non-root users to have access to these details
	check_path 755 root root /etc/ha.d

    # Default is 600, but make sure it doesn't change
    # If details are known by user accounts, they can potentially send malicious heartbeat messages over UDP and cause havoc
    # If heartbeat is not installed, this file will not be present
	check_path 600 root root /etc/ha.d/authkeys
fi


#--------------------------------------------------------------------------------------------------------------
# CHECK DRBD CONFIG (if present)
#--------------------------------------------------------------------------------------------------------------

if [ -e /etc/drbd.conf ]; then

    # Default is 755, but if users have access to this file they can find out the shared-secret encryption key
	check_path 600 root root /etc/drbd.conf

    # Check that drbd.conf contains shared-secret keys, otherwise there is no protection against malicious external DRBD packets
    if [ "`grep shared-secret /etc/drbd.conf`" = "" ]; then
        echo "Warning: No shared-secret configured in /etc/drbd.conf.  There is no protection against malicious external DRBD packets which may cause data corruption on your DRBD disks.  Ensure that every disk is configured with a shared-secret attribute."; echo;
    fi
fi


#--------------------------------------------------------------------------------------------------------------
# DONE
#--------------------------------------------------------------------------------------------------------------

echo "System Checks Completed"


#--------------------------------------------------------------------------------------------------------------
# Notes
#--------------------------------------------------------------------------------------------------------------

# Show account expiry/change info for all logins
#  cat /etc/passwd | cut -f 1 -d ":" | xargs -r -I USERNAME sh -c "(echo "USERNAME:"; chage -l USERNAME;)"
# Future: check sysctl network settings
# Done: implement more functions instead of repetitive code-blocks
# Future: since changing to sh, echo -e causes the text "-e" to be printed if using sh instead of bash.  Fix it.

