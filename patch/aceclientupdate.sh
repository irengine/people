#!/bin/sh
set -e

if test -z "$ACECLIENT_DIRECTORY"; then
	# You can override this default by setting ACECLIENT_DIRECTORY
	ACECLIENT_DIRECTORY=/home/rmrb-enewspaper/clientx/update
fi

LOG_FILE=${ACECLIENT_DIRECTORY}/acupdate.log
#MIRROR=http://irengine.com/
MIRROR=http://172.18.2.52/version

check_version() {

	echo "$0: Check version from ${MIRROR}." >> ${LOG_FILE}
	rm -f version.txt
	wget --append-output=${LOG_FILE} ${MIRROR}/version.txt

	if test ! -f localversion.txt; then
		ACTUAL_VERSION=0
	else
		ACTUAL_VERSION=$(cat localversion.txt)
	fi
	TARGET_VERSION=$(cat version.txt)
	if test $ACTUAL_VERSION -lt $TARGET_VERSION; then
		echo "$0: Download patch..." >> ${LOG_FILE}
		download_patch
	else
		echo "$0: No patch..." >> ${LOG_FILE}
	fi
}

download_patch() {

	rm -f acupdate.tar
	echo "$0: Download acupdate from ${MIRROR}." >> ${LOG_FILE}
	wget --append-output=${LOG_FILE} ${MIRROR}/acupdate.tar

	rm -f acupdate.md5
	echo "$0: Download acupdate.md5 from ${MIRROR}." >> ${LOG_FILE}
	wget --append-output=${LOG_FILE} ${MIRROR}/acupdate.md5

	#ACTUAL_MD5SUM=$(md5sum acupdate.tar | cut -f1 -d" ")
	ACTUAL_MD5SUM=$(md5sum acupdate.tar)
	TARGET_MD5SUM=$(cat acupdate.md5)

	echo "${ACTUAL_MD5SUM}-->${TARGET_MD5SUM}"
	if test "$ACTUAL_MD5SUM" != "$TARGET_MD5SUM"; then
		echo "The MD5 sum of the AceClient patch mismatches." >> ${LOG_FILE}
	else
		patch
	fi
}

patch() {
	if test ! -f acupdate.tar; then
		echo "$0: No patch found in ${ACECLIENT_DIRECTORY}." >> ${LOG_FILE}
	else
		echo "$0: Patching..." >> ${LOG_FILE}
		tar -xvf acupdate.tar
		chmod 777 update.sh
		exec ./update.sh
		#cp version.txt localversion.txt
	fi
}

# create AceClient directory
mkdir -p "${ACECLIENT_DIRECTORY}"
cd "${ACECLIENT_DIRECTORY}"

# clear log
> ${LOG_FILE}

#sleep 600

check_version
