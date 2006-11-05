Honeysnap   
=========

What is it?
-----------

Honeysnap is a python application that can parse raw or gzipped pcap files and perform a number of diagnostics on the data.  It has been designed to be easily extended to perform more diagnostic duties.  It has also been designed to be minimally dependent on third party executables like tcpflow, etc.

The primary intention is to give a quick first look into a directory full of pcap data that has been pulled from a roo or some honeynet.

Honeysnap.py is derived/inspired by honeysnap.sh by David Watson, Steve Mumford, and Arthur Clune of the UK Honeynet Project. 

Honeysnap includes:

* Outgoing packet counts for telnet, ssh, http, https, ftp, smtp, and irc. This can be easily extended.
* Incoming and outgoing connection summaries
* Binary extraction from http, smtp, irc, and ftp.
* Word based inspection of IRC traffic.
* Support for sebek data

Installation
------------

See the INSTALL file

Use
---

Modify the honeynet.cfg file to do the operations you like, and specify the output directory. The included honeysnap.cfg file is well commented to help you get started.

to execute:
honeysnap -c honeysnap.cfg <pcapfile>

Efficency
---------

Increasing the max number of open files will make things faster. On most unix like OSs

$ ulimit -n 4096

Bugs/Help:
---------

Please send any bugs, tracebacks, comments, or patches to Arthur Clune (arthur@honeynet.org.uk) or Jed Haile (jed.haile@thelogangroup.biz)

Copyright: 
----------

All code in honeysnap is copyright The Honeynet Project.

Contact Information:
Jed Haile
jed.haile@thelogangroup.biz
