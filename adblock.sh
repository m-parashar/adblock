#!/bin/sh
# set -euxo pipefail
# File: adblock.sh
#
# Adblock for DD-WRT
#
# AUTHOR: Manish Parashar
#
# https://github.com/m-parashar/adblock
# https://www.dd-wrt.com/phpBB2/viewtopic.php?t=307533
#
# Thanks: List providers, contributors, and users.
#
# Installation:
# Give the script permissions to execute:
# chmod +x adblock.sh
#
# Add the hosts file and extra configuration to DD-WRT's dnsmasq config via Services -> Additional DNSMasq Options
# conf-file=/jffs/dnsmasq/mpdomains
# addn-hosts=/jffs/dnsmasq/mphosts
#
# optional:
# Never forward plain names (without a dot or domain part)
# domain-needed
# Never forward addresses in the non-routed address spaces.
# bogus-priv
#
# Log each DNS query as it passes through dnsmasq.
# log-queries
# log-facility=/jffs/dnsmasq/dnsmasq.log
# log-async
#
# Go to Administration -> Cron (Sets the script to update itself. Choose your own schedule.)
# Build the adblock files on MON and THU at 6AM
# 0 6 * * 1,4 root /jffs/dnsmasq/adblock.sh
#

VERSION="20200130"

###############################################################################

# define aggressiveness: [ 0 | 1 | 2 | 3 ]
# 0: bare minimum protection from ads and malware
# 1: toned down, tuxedo wearing ad-slaying professional mode [DEFAULT]
# 2: optimum protection
# 3: ramped up, stone cold ad-killing maniac mode
# either change this here or use command line argument
export BLITZ=1

# online/offline mode switch
# DO NOT CHANGE; use command line argument instead
export ONLINE=1

# URL to ping and confirm connectivity status
export PING_TARGET="google.com"

# where ads go to die
# do not use 0.0.0.0 or 127.0.0.1
export ADHOLE_IP="0.1.2.3"

# for REMOTE MODE
# define ROUTER IP here
export REMOTE_MODE=0
export REMOTE_IP="192.168.1.1"
export REMOTE_USER="root"

# verbosity control
# 0: write to screen & log file
# 1: write to log file only
# exceptions: help, version, errors, warnings
export QUIET=0

# secure communication switch
# if enabled, cURL uses certificates for safe and
# secure TLS/SSL communication
export SECURL=0

# day of week
export DAYOFWEEK=$(date +"%u")

# distribution mode / defaults switch
# if set to 1, ignores myblacklist/mywhitelist files
# DO NOT CHANGE; use command line argument instead
export DISTRIB=0

# block Facebook
# f: only block Facebook and Messenger services
# F: block Facebook, Instagram, and WhatsApp
export NOFB=0

# define dnsmasq directory and path
# needn't be /jffs, could be /opt
# preferably use a USB drive for this
if [ -d "/jffs/dnsmasq" ]; then
	export MPDIR="/jffs/dnsmasq"
else
	export REMOTE_MODE=1
	export MPDIR="."
	export REMOTE_DIR="/jffs/dnsmasq"
fi

# temporary directory
if [ -d "/tmp" ]; then
	export TMPDIR="/tmp"
else
	export TMPDIR="."
fi

# log file
export LOGFILE="${MPDIR}/log.adblock"
#[ -s $LOGFILE ] && rm -f $LOGFILE
[ ! -f $LOGFILE ] && touch $LOGFILE
export DEBUG=0
export ERRLOG="${MPDIR}/log.adblock.errors"
[ ! -f $ERRLOG ] && touch $ERRLOG

# dnsmasq hosts & domain files
export mphosts="${MPDIR}/mphosts"
export mphostspaused="${MPDIR}/mphosts.zzz"
export tmphosts="${TMPDIR}/mphosts.tmp"

# temporary dnsmasq hosts & domain files
export mpdomains="${MPDIR}/mpdomains"
export mpdomainspaused="${MPDIR}/mpdomains.zzz"
export tmpdomains="${TMPDIR}/mpdomains.tmp"

# pause flag
export pauseflag="${MPDIR}/PAUSED"

# blacklist file: a list of blacklisted domains one per line
export blacklist="${MPDIR}/blacklist"

# whitelist file: a list of whitelisted domains one per line
export whitelist="${MPDIR}/whitelist"

# encoded whitelist file: a list of whitelisted domains one per line
export base64wl="${MPDIR}/base64wl"

# user's custom blacklist file: a list of blacklisted domains one per line
export myblacklist="${MPDIR}/myblacklist"

# user's custom whitelist file: a list of whitelisted domains one per line
export mywhitelist="${MPDIR}/mywhitelist"

###############################################################################

# help cron a bit
export SHELL=/bin/sh
if [ ! $REMOTE_MODE -eq 1 ]; then
	export PATH=/bin:/usr/bin:/sbin:/usr/sbin:/jffs/sbin:/jffs/bin:/jffs/usr/sbin:/jffs/usr/bin:/mmc/sbin:/mmc/bin:/mmc/usr/sbin:/mmc/usr/bin:/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:"${MPDIR}"
	export LD_LIBRARY_PATH=/lib:/usr/lib:/jffs/lib:/jffs/usr/lib:/jffs/usr/local/lib:/mmc/lib:/mmc/usr/lib:/opt/lib:/opt/usr/lib
	export PWD="${MPDIR}"
fi
LC_ALL=C
export LC_ALL

###############################################################################
# check if cURL exists
if [ -z "$(which curl)" ]; then
	echo ">>> WARNING: cURL not found"
	echo ">>> ERROR: ABORTING"
	exit 1
fi

export CURL_CA_BUNDLE="${MPDIR}/cacert.pem"
alias MPGET="curl -f -s -k"
alias MPGETSSL="curl -f -s -k"
[ $SECURL -eq 1 ] && unalias MPGETSSL && alias MPGETSSL="curl -f -s --capath ${MPDIR} --cacert $CURL_CA_BUNDLE"
alias MPGETMHK="curl -f -s -A "Mozilla/5.0" -e http://forum.xda-developers.com/"
alias SEDCLEAN="sed -r 's/^[[:blank:]]*//; s/[[:blank:]]*$//; s/^[[:punct:]]*//; s/[[:punct:]]*$//; /^$/d; /^\s*$/d'"
alias GREPFILTER="grep -o '^[^#]*' | grep -vF -e \"::\" -e \";\" -e \"//\" -e \"http\" -e \"https\" -e \"@\" -e \"mailto\" | tr -cd '\000-\177'"

###############################################################################

cd "${MPDIR}"
logger ">>> $(basename "$0") started"

###############################################################################

# print & log
printAndLog ()
{
	[ $QUIET -eq 0 ] && echo "$1"
	echo "$1" >> $LOGFILE
}

# Remote router operations
downloadRemote ()
{
	printAndLog "> Downloading files from router ..."
	scp $REMOTE_USER@$REMOTE_IP:"$REMOTE_DIR/my*list" $MPDIR
}

# upload blocklists to the remote system
uploadRemote ()
{
	printAndLog "> Uploading files to router ..."
	scp $MPDIR/mpdomains $MPDIR/mphosts $MPDIR/my*list $REMOTE_USER@$REMOTE_IP:$REMOTE_DIR
}

# print file size
printFileSize ()
{
	printAndLog "# Size of $1: `du -h $1 | awk '{print $1}'`"
}

# restart dnsmasq
restartDnsmasq ()
{
	logger ">>> $(basename "$0") restarting dnsmasq"
	if [ $REMOTE_MODE -eq 1 ]; then
		ssh $REMOTE_USER@$REMOTE_IP killall -HUP dnsmasq
	else
		killall -HUP dnsmasq
	fi
	logger ">>> $(basename "$0") restarted dnsmasq"
}

# resume protection
protectOn ()
{
	if [ -f $pauseflag ] && { [ -f $mphostspaused ] || [ -f $mpdomainspaused ]; }; then
		printAndLog ">>> RESUMING PROTECTION"
		mv $mphostspaused $mphosts
		mv $mpdomainspaused $mpdomains
		rm -f $pauseflag
		restartDnsmasq
	fi
	logger ">>> $(basename "$0") finished"
	exit 0
}

# pause protection
protectOff ()
{
	printAndLog ">>> WARNING: PAUSING PROTECTION"
	[ -f $mphosts ] && mv $mphosts $mphostspaused
	[ -f $mpdomains ] && mv $mpdomains $mpdomainspaused
	echo "" > $mphosts
	echo "" > $mpdomains
	echo "PAUSED" > $pauseflag
	restartDnsmasq
	printAndLog ">>> Type $(basename "$0") --resume to resume protection."
	logger ">>> $(basename "$0") finished"
	exit 0
}

# print help options
printHelp ()
{
	echo ""
	echo "USAGE:"
	printf '\t'; echo "$(basename "$0") [-? | -h | --help] [-v | --version] [-1] [-2] [-b | --bl=<domain.name>] [-w | --wl=<domain.name>] ..."
	echo ""
	echo "OPERATION:"
	printf '\t'; echo -n "[-0]"; printf '\t\t\t\t'; echo "BLITZ=0: safe minimum protection"
	printf '\t'; echo -n "[-1]"; printf '\t\t\t\t'; echo "BLITZ=1: increased protection [DEFAULT]"
	printf '\t'; echo -n "[-2]"; printf '\t\t\t\t'; echo "BLITZ=2: optimum protection"
	printf '\t'; echo -n "[-3]"; printf '\t\t\t\t'; echo "BLITZ=3: unlock maximum protection"
	printf '\t'; echo -n "[-f]"; printf '\t\t\t\t'; echo "Block Facebook and Messenger services"
	printf '\t'; echo -n "[-F]"; printf '\t\t\t\t'; echo "Block Facebook, Messenger, Instagram, WhatsApp"
	printf '\t'; echo -n "[-d | -D]"; printf '\t\t\t'; echo "Ignore myblacklist/mywhitelist entries"
	printf '\t'; echo -n "[--remote=]"; echo -n "remote.ip"; printf '\t\t'; echo "Update your system remotely; default: $REMOTE_IP"
	printf '\t'; echo -n "[-b | --bl=]"; echo -n "domain.name"; printf '\t\t'; echo "Add domain.name to myblacklist"
	printf '\t'; echo -n "[-w | --wl=]"; echo -n "domain.name"; printf '\t\t'; echo "Add domain.name to mywhitelist"
	printf '\t'; echo -n "[-i | --ip=]"; echo -n "ip.ad.dr.ss"; printf '\t\t'; echo "Send ads to this IP; default: $ADHOLE_IP"
	printf '\t'; echo -n "[-q | --debug]"; printf '\t\t\t'; echo "Log errors to STDOUT and $ERRLOG"
	printf '\t'; echo -n "[-q | --quiet]"; printf '\t\t\t'; echo "Print outout to log file only"
	printf '\t'; echo -n "[-p | --pause]"; printf '\t\t\t'; echo "Pause protection"
	printf '\t'; echo -n "[-r | --resume]"; printf '\t\t\t'; echo "Resume protection"
	printf '\t'; echo -n "[-s | --secure]"; printf '\t\t\t'; echo "Use cURL CA certs for secure file transfer"
	printf '\t'; echo -n "[-o | --offline]"; printf '\t\t'; echo "Process local lists without downloading"
	printf '\t'; echo -n "[-h | --help]"; printf '\t\t\t'; echo "Display this help screen and exit"
	printf '\t'; echo -n "[-u | --update]"; printf '\t\t\t'; echo "Update $(basename "$0") to the latest version"
	printf '\t'; echo -n "[-v | --version]"; printf '\t\t'; echo "Print $(basename "$0") version and exit"
	echo ""
	echo "EXAMPLES:"
	printf '\t'; echo "$(basename "$0") -s2 --ip=172.31.255.254 --bl=example1.com --wl=example2.com"
	printf '\t'; echo "$(basename "$0") -3Fqs -b example1.com -w example2.com --wl=example3.com"
	printf '\t'; echo "$(basename "$0") -2f --remote=192.168.1.1"
	echo ""
	logger ">>> $(basename "$0") finished"
	exit 0
}

# update to the latest version
selfUpdate ()
{
	TMPFILE="/tmp/mpupdate"

	printAndLog ">>> Checking for updates."

	if ping -q -c 1 -W 1 google.com >/dev/null; then
		MPGETSSL https://raw.githubusercontent.com/m-parashar/adblock/master/$(basename "$0") > $TMPFILE

		if [ 0 -eq $? ]; then
			old_md5=`md5sum $0 | cut -d' ' -f1`
			new_md5=`md5sum $TMPFILE | cut -d' ' -f1`

			if [ "$old_md5" != "$new_md5" ]; then
				NEWVER=`grep -w -m 1 "VERSION" $TMPFILE`
				printAndLog ">>> Update available: $NEWVER"
				OLDVER=`grep -w -m 1 "VERSION" $0 | cut -d \" -f2`
				cp $0 $0.$OLDVER
				chmod 755 $TMPFILE
				mv $TMPFILE $0
				printAndLog ">>> Updated to the latest version."
			else
				printAndLog ">>> No updates available."
			fi
		else
			printAndLog ">>> Update failed. Try again."
		fi
		rm -f $TMPFILE
	fi
	logger ">>> $(basename "$0") updated"
	logger ">>> $(basename "$0") finished"
	exit 0
}

###############################################################################
export CMDARGS=("$@")

# process command line arguments
while getopts "h?v0123fFdDpPqQrRsSoOuUb:w:i:-:" opt; do
	case ${opt} in
		h|\? ) printHelp ;;
		v    ) echo "$VERSION" ; logger ">>> $(basename "$0") finished" ; exit 0 ;;
		0    ) BLITZ=0 ;;
		1    ) BLITZ=1 ;;
		2    ) BLITZ=2 ;;
		3    ) BLITZ=3 ;;
		f    ) NOFB="f" ;;
		F    ) NOFB="F" ;;
		d|D  ) DISTRIB=1 ;;
		q|Q  ) QUIET=1 ;;
		p|P  ) protectOff ;;
		r|R  ) protectOn ;;
		s|S  ) SECURL=1 ;;
		o|O  ) ONLINE=0 ;;
		u|U  ) selfUpdate ;;
		b    ) echo "$OPTARG" >> $myblacklist ;;
		w    ) echo "$OPTARG" >> $mywhitelist ;;
		i    ) ADHOLE_IP="$OPTARG" ;;
		-    ) LONG_OPTARG="${OPTARG#*=}"
		case $OPTARG in
			bl=?*   ) ARG_BL="$LONG_OPTARG" ; echo $ARG_BL >> $myblacklist ;;
			bl*     ) echo ">>> ERROR: no arguments for --$OPTARG option" >&2; exit 2 ;;
			wl=?*   ) ARG_WL="$LONG_OPTARG" ; echo $ARG_WL >> $mywhitelist ;;
			wl*     ) echo ">>> ERROR: no arguments for --$OPTARG option" >&2; exit 2 ;;
			ip=?*   ) ARG_IP="$LONG_OPTARG" ; ADHOLE_IP=$ARG_IP ;;
			ip*     ) echo ">>> ERROR: no arguments for --$OPTARG option" >&2; exit 2 ;;
			remote=?*   ) ARG_RIP="$LONG_OPTARG" ; REMOTE_IP=$ARG_RIP
						  REMOTE_MODE=1 ;;
			remote*     ) echo ">>> ERROR: no arguments for --$OPTARG option" >&2; exit 2 ;;
			quiet   ) QUIET=1 ;;
			debug   ) DEBUG=1 ;;
			pause   ) protectOff ;;
			resume  ) protectOn ;;
			secure  ) SECURL=1 ;;
			offline ) ONLINE=0 ;;
			help    ) printHelp ;;
			update  ) selfUpdate ;;
			version ) echo "$VERSION" ; logger ">>> $(basename "$0") finished" ; exit 0 ;;
			quiet* | debug* | pause* | resume* | secure* | offline* | help* | update* | version* )
			echo ">>> ERROR: no arguments allowed for --$OPTARG option" >&2; exit 2 ;;
			'' )    break ;; # "--" terminates argument processing
			* )     echo ">>> ERROR: unsupported option --$OPTARG" >&2; exit 2 ;;
		esac ;;
  	  \? ) exit 2 ;;  # getopts already reported the illegal option
	esac
done

shift $((OPTIND-1)) # remove parsed options and args from $@ list

###############################################################################

# log errors if DEBUG is ON
if [ $DEBUG -eq 1 ]; then
	exec 2<&-
	exec 2<>$ERRLOG
fi

# display banner
TIMERSTART=`date +%s`
PRY=`date +%Y`
printAndLog "======================================================"
printAndLog "|                 adblock for DD-WRT                 |"
printAndLog "|                 https://adblock.sh                 |"
printAndLog "|       https://github.com/m-parashar/adblock        |"
printAndLog "|           Copyright $PRY Manish Parashar           |"
printAndLog "======================================================"
printAndLog "             `date`"
printAndLog "# VERSION: $VERSION"
printAndLog "# CMDARGS: $CMDARGS"

###############################################################################

# force resume if user forgets to turn it back on
if [ -f $pauseflag ] && { [ -f $mphostspaused ] || [ -f $mpdomainspaused ]; }; then
	printAndLog "# USER FORGOT TO RESUME PROTECTION AFTER PAUSING"
	protectOn
fi

###############################################################################
# download files from router if REMOTE: ON
if [ $REMOTE_MODE -eq 1 ]; then
	printAndLog "# REMOTE: ON | IP: $REMOTE_IP"
	downloadRemote
fi

# if internet is accessible, download files
if ping -q -c 1 -W 1 $PING_TARGET > /dev/null 2>&1; then

	printAndLog "# NETWORK: UP | MODE: ONLINE"
	printAndLog "# IP ADDRESS FOR ADS: $ADHOLE_IP"
	printAndLog "# SECURE [0=NO | 1=YES]: $SECURL"
	printAndLog "# BLITZ LEVEL [0|1|2|3]: $BLITZ"

	if [ ! -s cacert.pem ] || { [ "${DAYOFWEEK}" -eq 1 ] || [ "${DAYOFWEEK}" -eq 4 ]; }; then
		printAndLog "> Downloading / updating cURL certificates"
		MPGETSSL --remote-name --time-cond cacert.pem https://curl.haxx.se/ca/cacert.pem
	fi

	printAndLog "# Creating mpdomains file"
	MPGETSSL https://raw.githubusercontent.com/oznu/dns-zone-blacklist/master/dnsmasq/dnsmasq.blacklist | GREPFILTER | sed 's/0.0.0.0$/'$ADHOLE_IP'/' > $tmpdomains
	MPGETSSL https://raw.githubusercontent.com/notracking/hosts-blocklists/master/domains.txt | GREPFILTER | sed 's/0.0.0.0$/'$ADHOLE_IP'/' >> $tmpdomains
	MPGETSSL -d mimetype=plaintext -d hostformat=dnsmasq https://pgl.yoyo.org/adservers/serverlist.php? | GREPFILTER | sed 's/127.0.0.1$/'$ADHOLE_IP'/' >> $tmpdomains

	printAndLog "# Creating mphosts file"
	printAndLog "> Processing StevenBlack lists"
	MPGETSSL https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | GREPFILTER | awk '{print $2}' > $tmphosts

	printAndLog "> Processing notracking blocklists"
	MPGETSSL https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

	printAndLog "> Processing Disconnect.me lists"
	MPGETSSL https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt | GREPFILTER >> $tmphosts
	MPGETSSL https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt | GREPFILTER >> $tmphosts
	MPGETSSL https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt | GREPFILTER >> $tmphosts
	MPGETSSL https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt | GREPFILTER >> $tmphosts

	printAndLog "> Processing quidsup/notrack lists"
	MPGETSSL https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt | GREPFILTER >> $tmphosts
	MPGETSSL https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt | GREPFILTER >> $tmphosts

	printAndLog "> Processing MalwareDomains lists"
	MPGETSSL https://mirror1.malwaredomains.com/files/justdomains | GREPFILTER >> $tmphosts
	MPGETSSL https://mirror1.malwaredomains.com/files/immortal_domains.txt | GREPFILTER >> $tmphosts

	printAndLog "> Processing adaway list"
	MPGETSSL https://adaway.org/hosts.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

	if [ $BLITZ -ge 1 ]; then
		printAndLog "# Unlocking BLITZ=1 level lists"

		printAndLog "> Processing more StevenBlack lists"
		MPGETSSL https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.2o7Net/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Risk/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Spam/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts

		printAndLog "> Processing hosts-file ATS/EXP/GRM lists"
		MPGETSSL https://hosts-file.net/ad_servers.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://hosts-file.net/exp.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://hosts-file.net/grm.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

		printAndLog "> Processing hosts-file HJK/PUP lists"
		MPGETSSL https://hosts-file.net/hjk.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://hosts-file.net/pup.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

		printAndLog "> Processing dshield lists"
		MPGETSSL https://www.dshield.org/feeds/suspiciousdomains_High.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://www.dshield.org/feeds/suspiciousdomains_Medium.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://www.dshield.org/feeds/suspiciousdomains_Low.txt | GREPFILTER >> $tmphosts

		printAndLog "> Processing pgl.yoyo.org list"
		MPGETSSL -d mimetype=plaintext -d hostformat=unixhosts https://pgl.yoyo.org/adservers/serverlist.php? | GREPFILTER | awk '{print $2}' >> $tmphosts

		printAndLog "> Processing Securemecca list"
		MPGETSSL https://hostsfile.org/Downloads/hosts.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

		printAndLog "> Processing cryptomining and porn lists"
		MPGETSSL https://raw.githubusercontent.com/Marfjeh/coinhive-block/master/domains | GREPFILTER >> $tmphosts
		MPGETSSL https://zerodot1.gitlab.io/CoinBlockerLists/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_top1m.list | GREPFILTER >> $tmphosts

		printAndLog "> Processing Easylist & w3kbl lists"
		MPGETSSL https://v.firebog.net/hosts/AdguardDNS.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://v.firebog.net/hosts/Airelle-hrsk.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://v.firebog.net/hosts/Airelle-trc.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://v.firebog.net/hosts/BillStearns.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://v.firebog.net/hosts/Easylist.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://v.firebog.net/hosts/Easyprivacy.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://v.firebog.net/hosts/Prigent-Ads.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://v.firebog.net/hosts/Prigent-Malware.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://v.firebog.net/hosts/Prigent-Phishing.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://v.firebog.net/hosts/Shalla-mal.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://v.firebog.net/hosts/static/w3kbl.txt | GREPFILTER >> $tmphosts
	fi

	if [ $BLITZ -ge 2 ]; then
		printAndLog "# Unlocking BLITZ=2 level lists"

		printAndLog "> Processing even more StevenBlack lists"
		MPGETSSL https://raw.githubusercontent.com/StevenBlack/hosts/master/data/KADhosts/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/StevenBlack/hosts/master/data/UncheckyAds/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts

		printAndLog "> Processing hosts-file EMD/FSA lists"
		MPGETSSL https://hosts-file.net/emd.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://hosts-file.net/fsa.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

		printAndLog "> Processing hosts-file MMT/PHA lists"
		MPGETSSL https://hosts-file.net/mmt.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://hosts-file.net/pha.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

		printAndLog "> Processing Cameleon list"
		MPGET http://sysctl.org/cameleon/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts

		printAndLog "> Processing winhelp2002 list"
		MPGET http://winhelp2002.mvps.org/hosts.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

		printAndLog "> Processing someonewhocares list"
		MPGET http://someonewhocares.org/hosts/zero/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts

		printAndLog "> Processing anudeepND lists"
		MPGETSSL https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/anudeepND/youtubeadsblacklist/master/domainlist.txt | GREPFILTER >> $tmphosts

		printAndLog "> Processing CHEF-KOCH lists"
		MPGETSSL https://raw.githubusercontent.com/CHEF-KOCH/WebRTC-tracking/master/WebRTC.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/CHEF-KOCH/NSABlocklist/master/HOSTS/HOSTS | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/CHEF-KOCH/Audio-fingerprint-pages/master/AudioFp.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/CHEF-KOCH/Canvas-fingerprinting-pages/master/Canvas.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/CHEF-KOCH/Canvas-Font-Fingerprinting-pages/master/Canvas.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

		printAndLog "> Processing joewein.de LLC list"
		MPGETSSL https://www.joewein.net/dl/bl/dom-bl-base.txt | GREPFILTER >> $tmphosts

		printAndLog "> Processing Windows telemetry lists"
		MPGETSSL https://raw.githubusercontent.com/tyzbit/hosts/master/data/tyzbit/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

		printAndLog "> Processing smart TV blocklists"
		MPGETSSL https://v.firebog.net/hosts/static/SamsungSmart.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt | GREPFILTER >> $tmphosts

		printAndLog "> Processing a few more blocklists"
		MPGETSSL https://raw.githubusercontent.com/vokins/yhosts/master/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/piwik/referrer-spam-blacklist/master/spammers.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/HenningVanRaumle/pihole-ytadblock/master/ytadblock.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt | GREPFILTER >> $tmphosts
	fi

	if [ $BLITZ -ge 3 ]; then
		printAndLog "# Unlocking BLITZ=3 level lists"

		printAndLog "> Processing hosts-file PSH/PUP/WRZ lists"
		MPGETSSL https://hosts-file.net/psh.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://hosts-file.net/wrz.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

		printAndLog "> Processing Mahakala list"
		MPGETMHK http://adblock.mahakala.is/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts

		printAndLog "> Processing HostsFile.mine.nu list"
		MPGETSSL https://hostsfile.mine.nu/hosts0.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

		printAndLog "> Processing Kowabit list"
		MPGETSSL https://v.firebog.net/hosts/Kowabit.txt | GREPFILTER >> $tmphosts
	fi

	if [ $NOFB = "f" ]; then
		printAndLog "> Blocking Facebook and Messenger"
		MPGETSSL https://raw.githubusercontent.com/m-parashar/adblock/master/blacklists/facebookonly.block >> $tmphosts
	fi

	if [ $NOFB = "F" ]; then
		printAndLog "> Blocking Facebook, Messenger, Instagram, WhatsApp"
		MPGETSSL https://raw.githubusercontent.com/m-parashar/adblock/master/blacklists/facebookall.block >> $tmphosts
	fi

	printAndLog "> Updating official blacklist/whitelist files"
	MPGETSSL https://raw.githubusercontent.com/m-parashar/adblock/master/blacklists/blacklist | GREPFILTER > $blacklist
	MPGETSSL https://raw.githubusercontent.com/m-parashar/adblock/master/whitelists/whitelist | GREPFILTER > $whitelist
	if [ ! -z "$(which uudecode)" ]; then
		MPGETSSL https://raw.githubusercontent.com/m-parashar/adblock/master/whitelists/fruitydomains.uudecode > $base64wl
		LC_ALL=C uudecode $base64wl && cat applewhitelist >> $whitelist && rm applewhitelist && rm $base64wl
	fi
	if [ ! -z "$(which base64)" ]; then
		MPGETSSL https://raw.githubusercontent.com/m-parashar/adblock/master/whitelists/fruitydomains.base64 > $base64wl
		LC_ALL=C base64 -d -i $base64wl > applewhitelist && cat applewhitelist >> $whitelist && rm applewhitelist && rm $base64wl
	fi

else
	printAndLog "# NETWORK: DOWN | MODE: OFFLINE"
	logger ">>> $(basename "$0") finished"
	exit 0
fi

if [ $ONLINE -eq 0 ]; then
	printAndLog "# NETWORK: DOWN | MODE: OFFLINE"
	printAndLog "# OFFLINE PROCESSING"
	[ -s $mphosts ] && cat $mphosts | awk '{print $2}' > $tmphosts
	[ -s $mpdomains ] && cp $mpdomains $tmpdomains
	if [ $REMOTE_MODE -eq 1 ]; then
		uploadRemote
	fi
	restartDnsmasq
	logger ">>> $(basename "$0") finished"
	exit 0
fi

###############################################################################

# calculate and print file sizes
printFileSize $tmphosts
printFileSize $tmpdomains

# remove duplicates and extra whitespace, sort alphabetically
printAndLog "> Processing blacklist/whitelist files"
LC_ALL=C cat $blacklist | SEDCLEAN | sort | uniq > tmpbl && cp tmpbl $blacklist
LC_ALL=C cat $whitelist | SEDCLEAN | sort | uniq > tmpwl && cp tmpwl $whitelist

# if not building for distribution, process myblacklist and mywhitelist files
# remove duplicates and extra whitespace, sort alphabetically
# and allow users' myblacklist precedence over defaults
if [ $DISTRIB -eq 0 ] && { [ -s "$myblacklist" ] || [ -s "$mywhitelist" ]; }; then
	printAndLog "> Processing myblacklist/mywhitelist files"
	LC_ALL=C cat $myblacklist | SEDCLEAN | sort | uniq > tmpmybl && mv tmpmybl $myblacklist
	LC_ALL=C cat $mywhitelist | SEDCLEAN | sort | uniq > tmpmywl && mv tmpmywl $mywhitelist
	cat $blacklist | cat $myblacklist - > tmpbl
	cat $whitelist | cat $mywhitelist - | grep -Fvwf $myblacklist > tmpwl
fi

# trim leading and trailig whitespace, delete all blank lines including the ones with whitespace
# remove non-printable non-ASCII characters because DD-WRT dnsmasq throws "bad name at line n" errors
# merge blacklists with other lists and remove whitelist entries from the stream
printAndLog "> Processing final mphosts/mpdomains files"
LC_ALL=C cat $tmphosts | SEDCLEAN | cat tmpbl - | grep -Fvwf tmpwl | sort | uniq | awk -v "IP=$ADHOLE_IP" '{sub(/\r$/,""); print IP" "$0}' > $mphosts
LC_ALL=C cat $tmpdomains | SEDCLEAN | grep -Fvwf tmpwl | sort | uniq > $mpdomains

printAndLog "> Removing temporary files"
rm -f $tmphosts
rm -f $tmpdomains
rm -f tmpbl
rm -f tmpwl

# calculate and print file sizes
printFileSize $mphosts
printFileSize $mpdomains

# Count how many domains/whitelists were added so it can be displayed to the user
numHostsBlocked=$(cat $mphosts | wc -l | sed 's/^[ \t]*//')
printAndLog "# Number of ad hosts blocked: approx $numHostsBlocked"
numDomainsBlocked=$(cat $mpdomains | wc -l | sed 's/^[ \t]*//')
printAndLog "# Number of ad domains blocked: approx $numDomainsBlocked"


if [ $REMOTE_MODE -eq 1 ]; then
	uploadRemote
fi

# reload dnsmasq
restartDnsmasq

TIMERSTOP=`date +%s`
RTMINUTES=$(( $((TIMERSTOP - TIMERSTART)) /60 ))
RTSECONDS=$(( $((TIMERSTOP - TIMERSTART)) %60 ))
printAndLog "# Total time: $RTMINUTES:$RTSECONDS minutes"
printAndLog "# DONE"
logger ">>> $(basename "$0") finished"
exit 0
# FIN
