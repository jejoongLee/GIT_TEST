#!/bin/bash

V_SRCIP=$1
V_SRCPORT=$2
V_DSTIP=$3
V_DSTPORT=$4
V_PCAPFILE=$5
V_OUTFILE=$6

#tcpdump '(src V_SRCIP and src port V_SRCPORT and dst V_DSTIP and dst port V_DSTPORT) or (src V_DSTIP and src port V_DSTPORT and dst V_SRCIP and dst port V_SRCPORT)' -r V_PCAPFILE -w V_OUTFILE
tcpdump "(src $V_SRCIP and src port $V_SRCPORT and dst $V_DSTIP and dst port $V_DSTPORT) or (src $V_DSTIP and src port $V_DSTPORT and dst $V_SRCIP and dst port $V_SRCPORT)" -r $V_PCAPFILE -w $V_OUTFILE
exit