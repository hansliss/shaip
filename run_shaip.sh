#!/bin/sh

CONFFILE=$1
DIR=/var/spool/pingtest
STATEFILE=$DIR/`basename $1`.state

#MAILRCPT="sms.studstad@nat.udac.se magnus.nilsson@nat.udac.se sms@proxy-gw.udac.se"
#MAILRCPT="magnus.nilsson@nat.udac.se sms@proxy-gw.udac.se"
MAILRCPT="Hans@Liss.pp.se"


notify()
{
    logger -i -p local2.notice -t pingtest "$1"
    for rcpt in $MAILRCPT
    do
      echo "$1" | Mail -s "" $rcpt
    done
}

NOW=`date +'%Y%m%d %H%M'`

shaip -c $CONFFILE -s $STATEFILE | while read line
do
    msg="`echo $line | sed 's/:down$/ nere/' | sed 's/:up$/ uppe igen/'` $NOW"
    notify "$msg"
done



