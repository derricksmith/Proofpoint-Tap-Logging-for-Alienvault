#!/bin/bash
#title           :retrieve-tap-siem-logs.sh
#description     :This script retrieves SIEM logs from Proofpoint's Targeted Attack Protection service.
#author          :Proofpoint
#date            :2017-04-07
#version         :1.1
#usage           :bash retrieve-tap-siem-logs.sh

############################################################
#Version History
# 1.0    Initial Release
# 1.1    Some old versions of the 'date' command didn't support
#         ISO8601-formatted timestamps. Fixed to be friendlier to
#        those old versions.
# 1.2	 Modified by Derrick Smith - modified for alienvault directories, logs to single /var/log/ossim/proofpoint-tap.log file
############################################################


#=============USER CONFIGURABLE SETTINGS===================#
# The service principal and secret are used to authenticate to the SIEM API. They are generated on the settings page of the Threat Insight Dashboard.
PRINCIPAL=""
SECRET=""

# Determines which API method is used. Valid values are: "all", "issues",
# "messages/blocked", "messages/delivered", "clicks/permitted", and "clicks/blocked"
ACTION="all"

# Determines which format the log is downloaded in. Valid values are "syslog" and "json".
FORMAT="syslog"

# Determines where log file are downloaded. Defaults to the current working directory.
LOGDIR="/var/log/ossim"
#=============END USER CONFIGURABLE SETTINGS===================#

LASTRETRIEVALFILE="$LOGDIR/lastretrieval"
LOGFILESUFFIX="proofpoint-tap.log"
ERRORFILESUFFIX="tap-siem.error"
TMPFILESUFFIX="tap-siem.tmp"
CURRENTTIME_ISO=`date -Iseconds | tr "T" " "`
echo $CURRENTTIME_ISO
CURRENTTIME_SECS=`date -d "$CURRENTTIME_ISO" +%s`
echo $CURRENTTIME_SECS
function interpretResults {
        local STATUS=$1
        local EXITCODE=$2
        local TIME_ISO=$3
        local TIME_SECS=$4
        if [[ $EXITCODE -eq 0 ]] && [[ $STATUS -eq 200 ]]; then
                echo $TIME_ISO > $LASTRETRIEVALFILE
                cat "$LOGDIR/$TIME_SECS-$TMPFILESUFFIX" >> "$LOGDIR/$LOGFILESUFFIX"
				rm "$LOGDIR/$TIME_SECS-$TMPFILESUFFIX"
                echo "Retrieval successful. $LOGDIR/$LOGFILESUFFIX created."
                return 0
        fi
        if [[ $EXITCODE -eq 0 ]] && [[ $STATUS -eq 204 ]]; then
                echo $TIME_ISO > $LASTRETRIEVALFILE
                rm "$LOGDIR/$TIME_SECS-$TMPFILESUFFIX"
                echo "Retrieval successful. No new records found."
                return 0
        fi

        mv "$LOGDIR/$TIME_SECS-$TMPFILESUFFIX" "$LOGDIR/$TIME_SECS-$ERRORFILESUFFIX"
        echo "Retrieval unsuccessful. $LOGDIR/$TIME_SECS-$ERRORFILESUFFIX created."
        logger -p user.err "Failed to retrieve TAP SIEM logs. Error in $LOGDIR/$TIME_SECS-$ERRORFILESUFFIX."
        return 1
}

function retrieveSinceSeconds {
        SECONDS=$1
        STATUS=$(curl -X GET -w %{http_code} -o "$LOGDIR/$CURRENTTIME_SECS-$TMPFILESUFFIX" "https://tap-api-v2.proofpoint.com/v2/siem/$ACTION?format=$FORMAT&sinceSeconds=$SECONDS" --user "$PRINCIPAL:$SECRET" -s)
        EXITCODE=$?
        interpretResults $STATUS $EXITCODE "$CURRENTTIME_ISO" "$CURRENTTIME_SECS"
}

function retrieveSinceTime {
        TIME=$1
        STATUS=$(curl -X GET -w %{http_code} -o "$LOGDIR/$CURRENTTIME_SECS-$TMPFILESUFFIX" "https://tap-api-v2.proofpoint.com/v2/siem/$ACTION?format=$FORMAT&sinceTime=$TIME" --user "$PRINCIPAL:$SECRET" -s)
        EXITCODE=$?
        interpretResults $STATUS $EXITCODE "$CURRENTTIME_ISO" "$CURRENTTIME_SECS"
}

function retrieveInterval {
        START_ISO=$1
        END_ISO=$2
        END_SECS=$3
        STATUS=$(curl -X GET -w %{http_code} -o "$LOGDIR/$END_SECS-$TMPFILESUFFIX" "https://tap-api-v2.proofpoint.com/v2/siem/$ACTION?format=$FORMAT&interval=$START_ISO/$END_ISO" --user "$PRINCIPAL:$SECRET" -s)
        EXITCODE=$?
        interpretResults $STATUS $EXITCODE "$END_ISO" "$END_SECS"
}

if ! [[ -f $LASTRETRIEVALFILE ]]; then
        echo "No interval file found. Retrieving past hour's worth of data."
        retrieveSinceSeconds 3600
else
        LASTRETRIEVAL_ISO=`date -f "$LASTRETRIEVALFILE" -Iseconds `
        LASTRETRIEVAL_SECS=`date -d "$LASTRETRIEVAL_ISO" +%s`
    (( DIFF=$CURRENTTIME_SECS - $LASTRETRIEVAL_SECS ))

        if [ $DIFF -lt 60 ]; then
                echo "Last retrieval was $DIFF seconds ago. Minimum amount of time between requests is 60 seconds."
                logger -p user.err "Last retrieval was $DIFF seconds ago. Minimum amount of time between requests is 60 seconds. Exiting."
                exit 0
        fi

        if [ $DIFF -gt 43200 ]; then
            echo "Last successful retrieval of SIEM logs was $DIFF seconds ago. Maximum amount of time to look back is 43200 seconds (12 hours). Resetting last interval. Information older than 12 hours will not be retrieved."
                        logger -p user.warn "Last successful retrieval of SIEM logs was $DIFF seconds ago. Maximum amount of time to look back is 43200 seconds (12 hours). Resetting last interval. Information older than 12 hours will not be retrieved."
                        ((LASTRETRIEVAL_SECS=$CURRENTTIME_SECS-43140))
                        LASTRETRIEVAL_ISO=`date -d @$LASTRETRIEVAL_SECS -Iseconds`
                        (( DIFF= $CURRENTTIME_SECS - $LASTRETRIEVAL_SECS ))
    fi

        if [ $DIFF -gt 3600 ]; then
                echo "Last retrieval was $DIFF seconds ago. Maximum amount of allowable time for one request is 3600 seconds. Will split into several requests."
                START_ISO=$LASTRETRIEVAL_ISO
                START_SECS=$LASTRETRIEVAL_SECS
                while [ $DIFF -gt 3600 ]; do
                        ((END_SECS=$START_SECS+3600))
                        END_ISO=`date -d @$END_SECS -Iseconds`
                        (( DIFF=$CURRENTTIME_SECS - $END_SECS ))
                        retrieveInterval $START_ISO $END_ISO $END_SECS
                        START_SECS=$END_SECS
                        START_ISO=$END_ISO
                done
                LASTRETRIEVAL_ISO=$END_ISO
        fi

        if [ $DIFF -le 3600 ]; then
                retrieveSinceTime $LASTRETRIEVAL_ISO
        fi
fi
