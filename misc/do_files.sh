#!/bin/sh

#
# Sample script to demonstate running honeysnap over all pcap files produced by a honeywall
# Each file's analysis goes in a separate output directory
#

# adjust the path in the for loop to your needs

for i in `find /data/var/log/snort -type f | grep -v argus | grep "/pcap." | grep -v unmerged | sort -u`
do 
  dir=`echo $i | sed -e 's/^.*snort\///g' -e 's/\/pcap.*$//g'`
  echo $i $dir
  honeysnap -c uka.cfg -f analysis_uka/$dir.log -o analysis_uka/$dir $i > /dev/null
done
