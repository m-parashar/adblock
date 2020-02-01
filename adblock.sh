#!/bin/sh
# set -euxo pipefail
# File: adblock.sh
#
# Adblock shell script for DD-WRT
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

VERSION="20200201"

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

# DEBUG mode
export DEBUG=0

# secure communication switch
# if enabled, cURL uses certificates for safe and
# secure TLS/SSL communication
export SECURL=0

# force wget even if curl is available, for testing
export FORCEWGET=0

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
[ ! -f $LOGFILE ] && touch $LOGFILE

# dnsmasq hosts & domain files
export MPHOSTS="${MPDIR}/mphosts"
export MPHOSTS_PAUSED="${MPDIR}/mphosts.zzz"
export TMPHOSTS="${TMPDIR}/mphosts.tmp"

# temporary dnsmasq hosts & domain files
export MPDOMAINS="${MPDIR}/mpdomains"
export MPDOMAINS_PAUSED="${MPDIR}/mpdomains.zzz"
export TMPDOMAINS="${TMPDIR}/mpdomains.tmp"

# pause flag
export PAUSE_FLAG="${MPDIR}/PAUSED"

# blacklist file: a list of blacklisted domains one per line
export BLACKLIST="${MPDIR}/blacklist"

# whitelist file: a list of whitelisted domains one per line
export WHITELIST="${MPDIR}/whitelist"

# encoded whitelist file: a list of whitelisted domains one per line
export BASE64WL="${MPDIR}/base64wl"

# user's custom blacklist file: a list of blacklisted domains one per line
export MY_BLACKLIST="${MPDIR}/myblacklist"

# user's custom whitelist file: a list of whitelisted domains one per line
export MY_WHITELIST="${MPDIR}/mywhitelist"

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
if [ -n "$(which curl)" ]; then
	export CURL_CA_BUNDLE="${MPDIR}/cacert.pem"
	alias MPGET="curl -f -s -S -k"
	alias MPGETSSL="curl -f -s -S -k"
	[ $SECURL -eq 1 ] && unalias MPGETSSL && alias MPGETSSL="curl -f -s -S --capath ${MPDIR} --cacert $CURL_CA_BUNDLE"
	alias MPGETMHK="curl -f -s -S -A "Mozilla/5.0" -e http://forum.xda-developers.com/"
else
	FORCEWGET=1
fi

# sed and grep filters
alias SEDCLEAN="sed -r 's/^[[:blank:]]*//; s/[[:blank:]]*$//; s/^[[:punct:]]*//; s/[[:punct:]]*$//; /^$/d; /^\s*$/d'"
alias GREPFILTER="grep -o '^[^#]*' | grep -vF -e \"::\" -e \";\" -e \"//\" -e \"http\" -e \"https\" -e \"@\" -e \"mailto\" | tr -cd '\000-\177'"
alias AWKFILTER="awk '{print \$2}'"

###############################################################################

cd "${MPDIR}"
logger "[INFO] $(basename "$0") started"

###############################################################################

# Remote router operations
downloadRemote ()
{
	echo "[PROC] Downloading files from router..."
	scp $REMOTE_USER@$REMOTE_IP:"$REMOTE_DIR/my*list" $MPDIR
}

# upload blocklists to the remote system
uploadRemote ()
{
	echo "[PROC] Uploading files to router..."
	scp $MPDIR/mpdomains $MPDIR/mphosts $MPDIR/my*list $REMOTE_USER@$REMOTE_IP:$REMOTE_DIR
}

# download/update cURL certificates
getcURLCerts ()
{
	if [ ! -s cacert.pem ] || { [ "${DAYOFWEEK}" -eq 1 ] || [ "${DAYOFWEEK}" -eq 4 ]; }; then
		echo "[PROC] Downloading / updating cURL certificate"
		MPGETSSL --remote-name --time-cond cacert.pem https://curl.haxx.se/ca/cacert.pem
	fi
}

# print file size
printFileSize ()
{
	echo "[INFO] Size of $1: `du -h $1 | awk '{print $1}'`"
}

# restart dnsmasq
restartDnsmasq ()
{
	logger "[INFO] $(basename "$0") restarting dnsmasq"
	if [ $REMOTE_MODE -eq 1 ]; then
		ssh $REMOTE_USER@$REMOTE_IP killall -HUP dnsmasq
	else
		killall -HUP dnsmasq
	fi
	logger "[INFO] $(basename "$0") restarted dnsmasq"
}

# resume protection
protectOn ()
{
	if [ -f $PAUSE_FLAG ] && { [ -f $MPHOSTS_PAUSED ] || [ -f $MPDOMAINS_PAUSED ]; }; then
		echo "[INFO] RESUMING PROTECTION"
		mv $MPHOSTS_PAUSED $MPHOSTS
		mv $MPDOMAINS_PAUSED $MPDOMAINS
		rm -f $PAUSE_FLAG
		restartDnsmasq
	fi
	logger "[INFO] $(basename "$0") finished"
	exit 0
}

# pause protection
protectOff ()
{
	echo "[WARNING] PAUSING PROTECTION"
	[ -f $MPHOSTS ] && mv $MPHOSTS $MPHOSTS_PAUSED
	[ -f $MPDOMAINS ] && mv $MPDOMAINS $MPDOMAINS_PAUSED
	echo "" > $MPHOSTS
	echo "" > $MPDOMAINS
	echo "PAUSED" > $PAUSE_FLAG
	restartDnsmasq
	echo "[INFO] Type $(basename "$0") --resume to resume protection."
	logger "[INFO] $(basename "$0") finished"
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
	printf '\t'; echo -n "[--debug]"; printf '\t\t\t'; echo "Debug the script in case of errors"
	printf '\t'; echo -n "[--wget]"; printf '\t\t\t'; echo "Force use of wget even if cURL is available"
	printf '\t'; echo -n "[--remote=]"; echo -n "remote.ip"; printf '\t\t'; echo "Update your system remotely; default: $REMOTE_IP"
	printf '\t'; echo -n "[-b | --bl=]"; echo -n "domain.name"; printf '\t\t'; echo "Add domain.name to myblacklist"
	printf '\t'; echo -n "[-w | --wl=]"; echo -n "domain.name"; printf '\t\t'; echo "Add domain.name to mywhitelist"
	printf '\t'; echo -n "[-i | --ip=]"; echo -n "ip.ad.dr.ss"; printf '\t\t'; echo "Send ads to this IP; default: $ADHOLE_IP"
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
	logger "[INFO] $(basename "$0") finished"
	exit 0
}

# update to the latest version
selfUpdate ()
{
	TMPFILE="/tmp/mpupdate"

	echo "[PROC] Checking for updates."

	if ping -q -c 1 -W 1 $PING_TARGET >/dev/null; then
		MPGETSSL https://raw.githubusercontent.com/m-parashar/adblock/master/$(basename "$0") > $TMPFILE

		if [ 0 -eq $? ]; then
			old_md5=`md5sum $0 | cut -d' ' -f1`
			new_md5=`md5sum $TMPFILE | cut -d' ' -f1`

			if [ "$old_md5" != "$new_md5" ]; then
				NEWVER=`grep -w -m 1 "VERSION" $TMPFILE`
				echo "[INFO] Update available: $NEWVER"
				OLDVER=`grep -w -m 1 "VERSION" $0 | cut -d \" -f2`
				cp $0 $0.$OLDVER
				chmod 755 $TMPFILE
				mv $TMPFILE $0
				echo "[INFO] Updated to the latest version."
			else
				echo "[INFO] No updates available."
			fi
		else
			echo "[ERROR] Update failed. Try again."
		fi
		rm -f $TMPFILE
	fi
	logger "[INFO] $(basename "$0") updated"
	logger "[INFO] $(basename "$0") finished"
	exit 0
}

###############################################################################

export CMDARGS="$@"

# process command line arguments
while getopts "h?v0123fFdDpPrRsSoOuUb:w:i:-:" opt; do
	case ${opt} in
		h|\? ) printHelp ;;
		v    ) echo "$VERSION" ; logger "[INFO] $(basename "$0") finished" ; exit 0 ;;
		0    ) BLITZ=0 ;;
		1    ) BLITZ=1 ;;
		2    ) BLITZ=2 ;;
		3    ) BLITZ=3 ;;
		f    ) NOFB="f" ;;
		F    ) NOFB="F" ;;
		d|D  ) DISTRIB=1 ;;
		p|P  ) protectOff ;;
		r|R  ) protectOn ;;
		s|S  ) SECURL=1 ;;
		o|O  ) ONLINE=0 ;;
		u|U  ) selfUpdate ;;
		b    ) echo "$OPTARG" >> $MY_BLACKLIST ;;
		w    ) echo "$OPTARG" >> $MY_WHITELIST ;;
		i    ) ADHOLE_IP="$OPTARG" ;;
		-    ) LONG_OPTARG="${OPTARG#*=}"
		case $OPTARG in
			bl=?*   ) ARG_BL="$LONG_OPTARG" ; echo $ARG_BL >> $MY_BLACKLIST ;;
			bl*     ) echo "[ERROR] no arguments for --$OPTARG option" >&2; exit 2 ;;
			wl=?*   ) ARG_WL="$LONG_OPTARG" ; echo $ARG_WL >> $MY_WHITELIST ;;
			wl*     ) echo "[ERROR] no arguments for --$OPTARG option" >&2; exit 2 ;;
			ip=?*   ) ARG_IP="$LONG_OPTARG" ; ADHOLE_IP=$ARG_IP ;;
			ip*     ) echo "[ERROR] no arguments for --$OPTARG option" >&2; exit 2 ;;
			remote=?*   ) ARG_RIP="$LONG_OPTARG" ; REMOTE_IP=$ARG_RIP
						  REMOTE_MODE=1 ;;
			remote*     ) echo "[ERROR] no arguments for --$OPTARG option" >&2; exit 2 ;;
			debug   ) DEBUG=1 ;;
			wget    ) FORCEWGET=1 ;;
			pause   ) protectOff ;;
			resume  ) protectOn ;;
			secure  ) SECURL=1 ;;
			offline ) ONLINE=0 ;;
			help    ) printHelp ;;
			update  ) selfUpdate ;;
			version ) echo "$VERSION" ; logger "[PROC] $(basename "$0") finished" ; exit 0 ;;
			debug* | wget* | pause* | resume* | secure* | offline* | help* | update* | version* )
			echo "[ERROR] no arguments allowed for --$OPTARG option" >&2; exit 2 ;;
			'' )    break ;; # "--" terminates argument processing
			* )     echo "[ERROR] unsupported option --$OPTARG" >&2; exit 2 ;;
		esac ;;
  	  \? ) exit 2 ;;  # getopts already reported the illegal option
	esac
done

shift $((OPTIND-1)) # remove parsed options and args from $@ list

###############################################################################

(
if [ $FORCEWGET -eq 1 ]; then
	SECURL=0
	unalias MPGET && alias MPGET="wget -qO- "
	unalias MPGETSSL && alias MPGETSSL="wget -qO- "
	unalias MPGETMHK && alias MPGETMHK="wget -U "Mozilla/5.0" -qO- "
fi

# display banner
TIMERSTART=`date +%s`
PRY=`date +%Y`
echo "======================================================"
echo "|                 adblock for DD-WRT                 |"
echo "|                 https://adblock.sh                 |"
echo "|       https://github.com/m-parashar/adblock        |"
echo "|           Copyright $PRY Manish Parashar           |"
echo "======================================================"
echo "             `date`"
echo "[INFO] VERSION: $VERSION"
echo "[INFO] CMDARGS: $CMDARGS"

###############################################################################

# force resume if user forgets to turn it back on
if [ -f $PAUSE_FLAG ] && { [ -f $MPHOSTS_PAUSED ] || [ -f $MPDOMAINS_PAUSED ]; }; then
	echo "# USER FORGOT TO RESUME PROTECTION AFTER PAUSING"
	protectOn
fi

###############################################################################
# download files from router if REMOTE: ON
if [ $REMOTE_MODE -eq 1 ]; then
	echo "# REMOTE: ON | IP: $REMOTE_IP"
	downloadRemote
fi

# if internet is accessible, download files
if ping -q -c 1 -W 1 $PING_TARGET > /dev/null 2>&1; then

	echo "[INFO] NETWORK: UP | MODE: ONLINE"
	echo "[INFO] IP ADDRESS FOR ADS: $ADHOLE_IP"
	echo "[INFO] SECURE [0=NO | 1=YES]: $SECURL"
	echo "[INFO] BLITZ LEVEL [0|1|2|3]: $BLITZ"

	# log errors if DEBUG is ON
	if [ $DEBUG -eq 1 ]; then
		set -x
	fi

	if [ $FORCEWGET -ne 1 ]; then
		getcURLCerts
	fi

	echo "[PROC] Creating mpdomains file"
	MPGETSSL "https://raw.githubusercontent.com/oznu/dns-zone-blacklist/master/dnsmasq/dnsmasq.blacklist" | GREPFILTER | sed 's/0.0.0.0$/'$ADHOLE_IP'/' > $TMPDOMAINS
	MPGETSSL "https://raw.githubusercontent.com/notracking/hosts-blocklists/master/domains.txt" | GREPFILTER | sed 's/0.0.0.0$/'$ADHOLE_IP'/' >> $TMPDOMAINS
	MPGETSSL "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=dnsmasq&showintro=0&mimetype=plaintext" | GREPFILTER | sed 's/127.0.0.1$/'$ADHOLE_IP'/' >> $TMPDOMAINS

	echo "[PROC] Creating mphosts file"
	echo "[PROC] Processing StevenBlack lists"
	MPGETSSL "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" | GREPFILTER | AWKFILTER > $TMPHOSTS

	echo "[PROC] Processing notracking blocklists"
	MPGETSSL "https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS

	echo "[PROC] Processing Disconnect.me lists"
	MPGETSSL "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt" | GREPFILTER >> $TMPHOSTS
	MPGETSSL "https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt" | GREPFILTER >> $TMPHOSTS
	MPGETSSL "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt" | GREPFILTER >> $TMPHOSTS
	MPGETSSL "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt" | GREPFILTER >> $TMPHOSTS

	echo "[PROC] Processing quidsup/notrack lists"
	MPGETSSL "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt" | GREPFILTER >> $TMPHOSTS
	MPGETSSL "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt" | GREPFILTER >> $TMPHOSTS

	echo "[PROC] Processing MalwareDomains lists"
	MPGETSSL "https://mirror1.malwaredomains.com/files/justdomains" | GREPFILTER >> $TMPHOSTS
	MPGETSSL "https://mirror1.malwaredomains.com/files/immortal_domains.txt" | GREPFILTER >> $TMPHOSTS

	echo "[PROC] Processing adaway list"
	MPGETSSL "https://adaway.org/hosts.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS

	if [ $BLITZ -ge 1 ]; then
		echo "[PROC] Unlocking BLITZ=1 level lists"

		echo "[PROC] Processing more StevenBlack lists"
		MPGETSSL "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.2o7Net/hosts" | GREPFILTER | AWKFILTER >> $TMPHOSTS
		MPGETSSL "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Risk/hosts" | GREPFILTER | AWKFILTER >> $TMPHOSTS
		MPGETSSL "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Spam/hosts" | GREPFILTER | AWKFILTER >> $TMPHOSTS

		echo "[PROC] Processing hosts-file ATS/EXP/GRM lists"
		MPGETSSL "https://hosts-file.net/ad_servers.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS
		MPGETSSL "https://hosts-file.net/exp.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS
		MPGETSSL "https://hosts-file.net/grm.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS

		echo "[PROC] Processing hosts-file HJK/PUP lists"
		MPGETSSL "https://hosts-file.net/hjk.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS
		MPGETSSL "https://hosts-file.net/pup.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS

		echo "[PROC] Processing dshield lists"
		MPGETSSL "https://www.dshield.org/feeds/suspiciousdomains_High.txt" | GREPFILTER >> $TMPHOSTS
		MPGETSSL "https://www.dshield.org/feeds/suspiciousdomains_Medium.txt" | GREPFILTER >> $TMPHOSTS
		MPGETSSL "https://www.dshield.org/feeds/suspiciousdomains_Low.txt" | GREPFILTER >> $TMPHOSTS

		echo "[PROC] Processing pgl.yoyo.org list"
		MPGETSSL "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=unixhosts&showintro=0&mimetype=plaintext" | GREPFILTER | AWKFILTER >> $TMPHOSTS

		echo "[PROC] Processing Securemecca list"
		MPGETSSL "https://hostsfile.org/Downloads/hosts.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS

		echo "[PROC] Processing cryptomining and porn lists"
		MPGETSSL "https://raw.githubusercontent.com/Marfjeh/coinhive-block/master/domains" | GREPFILTER >> $TMPHOSTS
		MPGETSSL "https://zerodot1.gitlab.io/CoinBlockerLists/hosts" | GREPFILTER | AWKFILTER >> $TMPHOSTS
		MPGETSSL "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS
		MPGETSSL "https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_top1m.list" | GREPFILTER >> $TMPHOSTS

		echo "[PROC] Processing Easylist & w3kbl lists"
		MPGETSSL "https://v.firebog.net/hosts/AdguardDNS.txt" | GREPFILTER >> $TMPHOSTS
		MPGETSSL "https://v.firebog.net/hosts/Airelle-hrsk.txt" | GREPFILTER >> $TMPHOSTS
		MPGETSSL "https://v.firebog.net/hosts/Airelle-trc.txt" | GREPFILTER >> $TMPHOSTS
		MPGETSSL "https://v.firebog.net/hosts/BillStearns.txt" | GREPFILTER >> $TMPHOSTS
		MPGETSSL "https://v.firebog.net/hosts/Easylist.txt" | GREPFILTER >> $TMPHOSTS
		MPGETSSL "https://v.firebog.net/hosts/Easyprivacy.txt" | GREPFILTER >> $TMPHOSTS
		MPGETSSL "https://v.firebog.net/hosts/Prigent-Ads.txt" | GREPFILTER >> $TMPHOSTS
		MPGETSSL "https://v.firebog.net/hosts/Prigent-Malware.txt" | GREPFILTER >> $TMPHOSTS
		MPGETSSL "https://v.firebog.net/hosts/Prigent-Phishing.txt" | GREPFILTER >> $TMPHOSTS
		MPGETSSL "https://v.firebog.net/hosts/Shalla-mal.txt" | GREPFILTER >> $TMPHOSTS
		MPGETSSL "https://v.firebog.net/hosts/static/w3kbl.txt" | GREPFILTER >> $TMPHOSTS
	fi

	if [ $BLITZ -ge 2 ]; then
		echo "[PROC] Unlocking BLITZ=2 level lists"

		echo "[PROC] Processing even more StevenBlack lists"
		MPGETSSL "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/KADhosts/hosts" | GREPFILTER | AWKFILTER >> $TMPHOSTS
		MPGETSSL "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/UncheckyAds/hosts" | GREPFILTER | AWKFILTER >> $TMPHOSTS
		MPGETSSL "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts" | GREPFILTER | AWKFILTER >> $TMPHOSTS

		echo "[PROC] Processing hosts-file EMD/FSA lists"
		MPGETSSL "https://hosts-file.net/emd.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS
		MPGETSSL "https://hosts-file.net/fsa.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS

		echo "[PROC] Processing hosts-file MMT/PHA lists"
		MPGETSSL "https://hosts-file.net/mmt.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS
		MPGETSSL "https://hosts-file.net/pha.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS

		echo "[PROC] Processing Cameleon list"
		MPGET "http://sysctl.org/cameleon/hosts" | GREPFILTER | AWKFILTER >> $TMPHOSTS

		echo "[PROC] Processing winhelp2002 list"
		MPGET "http://winhelp2002.mvps.org/hosts.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS

		echo "[PROC] Processing someonewhocares list"
		MPGET "http://someonewhocares.org/hosts/zero/hosts" | GREPFILTER | AWKFILTER >> $TMPHOSTS

		echo "[PROC] Processing anudeepND lists"
		MPGETSSL "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS
		MPGETSSL "https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS
		MPGETSSL "https://raw.githubusercontent.com/anudeepND/youtubeadsblacklist/master/domainlist.txt" | GREPFILTER >> $TMPHOSTS

		echo "[PROC] Processing CHEF-KOCH lists"
		MPGETSSL "https://raw.githubusercontent.com/CHEF-KOCH/WebRTC-tracking/master/WebRTC.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS
		MPGETSSL "https://raw.githubusercontent.com/CHEF-KOCH/NSABlocklist/master/HOSTS/HOSTS" | GREPFILTER | AWKFILTER >> $TMPHOSTS
		MPGETSSL "https://raw.githubusercontent.com/CHEF-KOCH/Audio-fingerprint-pages/master/AudioFp.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS
		MPGETSSL "https://raw.githubusercontent.com/CHEF-KOCH/Canvas-fingerprinting-pages/master/Canvas.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS
		MPGETSSL "https://raw.githubusercontent.com/CHEF-KOCH/Canvas-Font-Fingerprinting-pages/master/Canvas.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS

		echo "[PROC] Processing joewein.de LLC list"
		MPGETSSL "https://www.joewein.net/dl/bl/dom-bl-base.txt" | GREPFILTER >> $TMPHOSTS

		echo "[PROC] Processing Windows telemetry lists"
		MPGETSSL "https://raw.githubusercontent.com/tyzbit/hosts/master/data/tyzbit/hosts" | GREPFILTER | AWKFILTER >> $TMPHOSTS
		MPGETSSL "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS

		echo "[PROC] Processing smart TV blocklists"
		MPGETSSL "https://v.firebog.net/hosts/static/SamsungSmart.txt" | GREPFILTER >> $TMPHOSTS
		MPGETSSL "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt" | GREPFILTER >> $TMPHOSTS

		echo "[PROC] Processing a few more blocklists"
		MPGETSSL "https://raw.githubusercontent.com/vokins/yhosts/master/hosts" | GREPFILTER | AWKFILTER >> $TMPHOSTS
		MPGETSSL "https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts" | GREPFILTER | AWKFILTER >> $TMPHOSTS
		MPGETSSL "https://raw.githubusercontent.com/piwik/referrer-spam-blacklist/master/spammers.txt" | GREPFILTER >> $TMPHOSTS
		MPGETSSL "https://raw.githubusercontent.com/HenningVanRaumle/pihole-ytadblock/master/ytadblock.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS
		MPGETSSL "https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt" | GREPFILTER >> $TMPHOSTS
		MPGETSSL "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt" | GREPFILTER >> $TMPHOSTS
	fi

	if [ $BLITZ -ge 3 ]; then
		echo "[PROC] Unlocking BLITZ=3 level lists"

		echo "[PROC] Processing hosts-file PSH/PUP/WRZ lists"
		MPGETSSL "https://hosts-file.net/psh.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS
		MPGETSSL "https://hosts-file.net/wrz.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS

		echo "[PROC] Processing Mahakala list"
		MPGETMHK "http://adblock.mahakala.is/hosts" | GREPFILTER | AWKFILTER >> $TMPHOSTS

		echo "[PROC] Processing HostsFile.mine.nu list"
		MPGETSSL "https://hostsfile.mine.nu/hosts0.txt" | GREPFILTER | AWKFILTER >> $TMPHOSTS

		echo "[PROC] Processing Kowabit list"
		MPGETSSL "https://v.firebog.net/hosts/Kowabit.txt" | GREPFILTER >> $TMPHOSTS
	fi

	if [ $NOFB = "f" ]; then
		echo "[PROC] Blocking Facebook and Messenger"
		MPGETSSL "https://raw.githubusercontent.com/m-parashar/adblock/master/blacklists/facebookonly.block" >> $TMPHOSTS
	fi

	if [ $NOFB = "F" ]; then
		echo "[PROC] Blocking Facebook, Messenger, Instagram, WhatsApp"
		MPGETSSL "https://raw.githubusercontent.com/m-parashar/adblock/master/blacklists/facebookall.block" >> $TMPHOSTS
	fi

	if [ ! -s $TMPHOSTS ]; then
		printFileSize $TMPHOSTS
		printFileSize $TMPDOMAINS
		echo "[ERROR] Check logs. Quitting."
		logger "[INFO] $(basename "$0") finished"
		exit 2
	fi

	echo "[PROC] Updating official blacklist/whitelist files"
	MPGETSSL "https://raw.githubusercontent.com/m-parashar/adblock/master/blacklists/blacklist" | GREPFILTER > $BLACKLIST
	MPGETSSL "https://raw.githubusercontent.com/m-parashar/adblock/master/whitelists/whitelist" | GREPFILTER > $WHITELIST

	if [ -n "$(which uudecode)" ]; then
		MPGETSSL "https://raw.githubusercontent.com/m-parashar/adblock/master/whitelists/fruitydomains.uudecode" > $BASE64WL
		LC_ALL=C uudecode $BASE64WL && cat applewhitelist >> $WHITELIST && rm applewhitelist && rm $BASE64WL
	elif [ -n "$(which base64)" ]; then
		MPGETSSL "https://raw.githubusercontent.com/m-parashar/adblock/master/whitelists/fruitydomains.base64" > $BASE64WL
		LC_ALL=C base64 -d -i $BASE64WL > applewhitelist && cat applewhitelist >> $WHITELIST && rm applewhitelist && rm $BASE64WL
	fi

else
	echo "[INFO] NETWORK: DOWN | MODE: OFFLINE"
	logger "[INFO] $(basename "$0") finished"
	exit 0
fi

if [ $ONLINE -eq 0 ]; then
	echo "[INFO] NETWORK: UP | MODE: OFFLINE"
	echo "[INFO] OFFLINE PROCESSING"
	[ -s $MPHOSTS ] && cat $MPHOSTS | AWKFILTER > $TMPHOSTS
	[ -s $MPDOMAINS ] && cp $MPDOMAINS $TMPDOMAINS
	if [ $REMOTE_MODE -eq 1 ]; then
		uploadRemote
	fi
	restartDnsmasq
	logger "[INFO] $(basename "$0") finished"
	exit 0
fi

###############################################################################

# calculate and print file sizes
printFileSize $TMPHOSTS
printFileSize $TMPDOMAINS

# remove duplicates and extra whitespace, sort alphabetically
echo "[PROC] Processing blacklist/whitelist files"
LC_ALL=C cat $BLACKLIST | SEDCLEAN | sort | uniq > TMP_BLACKLIST && cp TMP_BLACKLIST $BLACKLIST
LC_ALL=C cat $WHITELIST | SEDCLEAN | sort | uniq > TMP_WHITELIST && cp TMP_WHITELIST $WHITELIST

# if not building for distribution, process myblacklist and mywhitelist files
# remove duplicates and extra whitespace, sort alphabetically
# and allow users' myblacklist precedence over defaults
if [ $DISTRIB -eq 0 ] && { [ -s "$MY_BLACKLIST" ] || [ -s "$MY_WHITELIST" ]; }; then
	echo "[PROC] Processing myblacklist/mywhitelist files"
	LC_ALL=C cat $MY_BLACKLIST | SEDCLEAN | sort | uniq > TMP_MYBLACKLIST && mv TMP_MYBLACKLIST $MY_BLACKLIST
	LC_ALL=C cat $MY_WHITELIST | SEDCLEAN | sort | uniq > TMP_MYWHITELIST && mv TMP_MYWHITELIST $MY_WHITELIST
	cat $BLACKLIST | cat $MY_BLACKLIST - > TMP_BLACKLIST
	cat $WHITELIST | cat $MY_WHITELIST - | grep -Fvwf $MY_BLACKLIST > TMP_WHITELIST
fi

# trim leading and trailig whitespace, delete all blank lines including the ones with whitespace
# remove non-printable non-ASCII characters because DD-WRT dnsmasq throws "bad name at line n" errors
# merge blacklists with other lists and remove whitelist entries from the stream
echo "[PROC] Processing final mphosts/mpdomains files"
LC_ALL=C cat $TMPHOSTS | SEDCLEAN | cat TMP_BLACKLIST - | grep -Fvwf TMP_WHITELIST | sort | uniq | awk -v "IP=$ADHOLE_IP" '{sub(/\r$/,""); print IP" "$0}' > $MPHOSTS
LC_ALL=C cat $TMPDOMAINS | SEDCLEAN | grep -Fvwf TMP_WHITELIST | sort | uniq > $MPDOMAINS

echo "[PROC] Removing temporary files"
rm -f $TMPHOSTS
rm -f $TMPDOMAINS
rm -f TMP_BLACKLIST
rm -f TMP_WHITELIST

unalias MPGET && unalias MPGETSSL && unalias MPGETMHK

# calculate and print file sizes
printFileSize $MPHOSTS
printFileSize $MPDOMAINS

# Count how many domains/whitelists were added so it can be displayed to the user
numHostsBlocked=$(cat $MPHOSTS | wc -l | sed 's/^[ \t]*//')
echo "[INFO] Number of hosts blocked: approx $numHostsBlocked"
numDomainsBlocked=$(cat $MPDOMAINS | wc -l | sed 's/^[ \t]*//')
echo "[INFO] Number of domains blocked: approx $numDomainsBlocked"

if [ $REMOTE_MODE -eq 1 ]; then
	uploadRemote
fi

# reload dnsmasq
restartDnsmasq

TIMERSTOP=`date +%s`
RTMINUTES=$(( $((TIMERSTOP - TIMERSTART)) /60 ))
RTSECONDS=$(( $((TIMERSTOP - TIMERSTART)) %60 ))
echo "[INFO] Total time: $RTMINUTES:$RTSECONDS minutes"
echo "[INFO] DONE"
logger "[INFO] $(basename "$0") finished"

# log errors if DEBUG is ON
if [ $DEBUG -eq 1 ]; then
	set +x
fi
) 2>&1 | tee $LOGFILE

exit 0
# FIN
