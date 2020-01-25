#!/bin/sh

echo "> Creating archive for installation"
cd /jffs/dnsmasq
rm adblock.tar.gz
rm install-adblock.sh
tar czvf adblock.tar.gz README adblock.sh cacert.pem mpdomains mphosts

echo "> Generating installer stub"
cat << 'EOF' > install-adblock.sh
#!/bin/sh

echo "======================================================"
echo "|            Installing adblock for DD-WRT           |"
echo "|       https://github.com/m-parashar/adblock        |"
echo "|           Copyright $PRY Manish Parashar           |"
echo "======================================================"

# Create destination folder
DESTINATION="/jffs/dnsmasq"
mkdir -p ${DESTINATION}

# Find __ARCHIVE__ maker, read archive content and decompress it
ARCHIVE=$(awk '/^__ARCHIVE__/ {print NR + 1; exit 0; }' "${0}")
tail -n+${ARCHIVE} "${0}" | tar xzv -C ${DESTINATION}

# Any post-installation tasks

echo ""
echo "> Installation complete."
echo "> Don't forget to run adblock.sh in ${DESTINATION}"
echo ""

# Exit from the script with success (0)
exit 0

__ARCHIVE__
EOF

echo "> Creating installer for adblock"
cat adblock.tar.gz >> install-adblock.sh
chmod +x install-adblock.sh

echo "> Installer created."
