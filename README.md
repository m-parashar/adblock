# adblock.sh
---------
Adblock for DD-WRT (and other POSIX systems)

- [adblock.sh](#adblocksh)
  * [Requirements](#requirements)
  * [Installation](#installation)
  * [Configuration](#configuration)
  * [Screenshots](#screenshots)
  * [Links](#links)
  
Requirements
------------
1. DD-WRT on a router with USB port(s) and USB support enabled
2. curl (for best protection)
3. wget (fallback supported)
4. a USB flash drive partitioned as /jffs and /opt, optionally a swap partition as well.

Installation
------------
+ On router
  1. `cd /jffs/dnsmasq`
  2. `curl -o adblock.sh adblock.sh`
  3. `chmod +x adblock.sh`
  4. Optional: create `myblacklist` and `mywhitelist` files in the same directory and populate these with domains you want to blacklist or whitelist.
+ On a Linux system within the same network
  1. `mkdir adblock`
  2. `curl -o adblock.sh adblock.sh`
  3. `chmod +x adblock.sh`
  4. Use the `--remote=` command line argument to upload the lists to your router after generating locally.

Configuration
-------------
1. Enable DNSMasq and local DNS for LAN and WAN. Add these lines under the additional options section.
```shell
conf-file=/jffs/dnsmasq/mpdomains
addn-hosts=/jffs/dnsmasq/mphosts
```
2. Enter additional options for dnsmasq if required, for example:
```shell
domain-needed
bogus-priv
```
3. Under Administration -> Cron, enter this or choose your own schedule:
```shell
0 6 * * 1,4 root /jffs/dnsmasq/adblock.sh
```
4. Reboot after generating the lists.

Screenshots
-----------

![usb](https://i.imgur.com/xT7Wgp4.png)

![dnsmasq](https://i.imgur.com/0Y9bDdq.png)

![cron](https://i.imgur.com/yUpTGbJ.png)

![helpoptions](https://i.imgur.com/NXfmBRb.png)

Links
-----
`<Website>` : <https://adblock.sh>

`<DD-WRT Forum Post>` : <https://forum.dd-wrt.com/phpBB2/viewtopic.php?t=307533>
