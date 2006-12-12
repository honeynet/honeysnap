#!/usr/bin/env python
################################################################################
# (c) 2006, The Honeynet Project
#   Author: Jed Haile  jed.haile@thelogangroup.biz
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
################################################################################

# $Id: xBytesNseconds.py 4518 2006-10-11 21:54:24Z jed $

import honeysnap
import sys, optparse, pcap, os, tempfile, gzip, time

VERSION=1.0

class xBytesnSecs(object):
    def __init__(self):
        """
        xBytesnSecs extracts flow statistics for tcp or udp flows that are greater than X bytes and less
        than N seconds.
        """
        # we use HoneysnapSingleton to store options
        hs = honeysnap.singletonmixin.HoneysnapSingleton.getInstance()
        options = hs.getOptions()
        self.options = options

    def run(self, f):
        # code to handle compressed or uncompressed pcap files
        try:
            tmph, tmpf = tempfile.mkstemp()
            tmph = open(tmpf, 'wb')
            gfile = gzip.open(f)
            tmph.writelines(gfile.readlines())
            gfile.close()
            del gfile
            tmph.close()
            deletetmp = 1
        except IOError:
            # got an error, must not be gzipped
            # should probably do a better check here
            tmpf = f
            deletetmp = 0
        # quick and dirty check file is a valid pcap file
        try:
            if os.path.exists(tmpf) and os.path.getsize(tmpf)>0 and os.path.isfile(tmpf):
                p = pcap.pcap(tmpf)
            else:
                raise OSError
        except OSError:
            print "File %s is not a pcap file or does not exist" % file
            sys.exit(1)

        # we will just write to stdout
        out = honeysnap.output.outputSTDOUT()

        # handle each honeypot IP individually, makes for nicer results
        # we could sort them out afterwords and only go through the pcap once
        # but this is the lazy man's approach, and I'm lazy today
        for hp in self.options['honeypots']:
            p = pcap.pcap(tmpf)
            # instantiate packetSummary object
            # this object sorts the pcap data into flow data
            s = honeysnap.packetSummary.Summarize(p, verbose=1)
            # filter the pcap data by honeypot IP
            filt = 'host %s' % hp
            s.setFilter(filt, file)
            # tell the object to write to stdout
            s.setOutput(out)
            # run it
            s.start()
            good = {}
            # next we have to go through the data collected by summarize and find the data we want
            # UDP and TCP are handled in separate dictionaries, so we will handle each of them
            # (I suppose it would be nice if this tool allowed you to specify if you wanted tcp OR udp)
            # tcp first
            for k,v in s.tcpports.iteritems():
                # find flows that meet constraints
                if (v[1]-v[0] < self.options['seconds']) and (v[3] > self.options['bytes']):
                    good[k] = v
            # replace summarize's tcpdata with our filtered data
            s.tcpports = good
            good = {}
            # now udp
            for k,v in s.udpports.iteritems():
                # find flows that meet constraints
                if (v[1]-v[0] < self.options['seconds']) and (v[3] > self.options['bytes']):
                    good[k] = v
            # replace summarize's udpdata with our filtered data
            s.udpports = good
            # being lazy again, using summarize's output func instead of writing one specific to this script
            # if I wanted different output I could use s.tcpports and s.udpports myself for my own output
            s.writeResults(limit=0)

        # all done, delete the tmp file
        if deletetmp:
            os.unlink(tmpf)

def parseOptions():
    parser = optparse.OptionParser(option_class=honeysnap.main.MyOption, version="%sprog %s" % ('%', VERSION))

    parser.add_option("-b", "--bytes", dest="bytes", type="int",
                        help="Look for flows greater than bytes, defaults to 0")
    parser.set_default("bytes", 0)
    parser.add_option("-s", "--seconds", dest="seconds", type="int",
                        help="Ceiling in seconds for candidate flows, defaults to sys.maxint")
    parser.set_default("seconds", sys.maxint)
    parser.add_option("-H", "--honeypots", dest="honeypots", action="extend", type="string",
                        help="Comma delimited list of honeypots")
    parser.set_default("honeypots", None)
    # parse command line
    options, args = parser.parse_args()

    return (parser.print_help, options, args)

def main():
    print_help, options, args = parseOptions()
    # optparse returns options as attributes of an object instance
    # honeysnap modules assume options are in a dictionary
    # grab the dict out of the options instance so our options are available as a dict
    o = options.__dict__
    options = o

    if len(sys.argv) > 0:
        if options['honeypots'] is None:
            print "No honeypots specified. Please use either -H or config file to specify honeypots.\n"
            sys.exit(2)

    # Summarize requires a time func
    options['time_convert_fn'] = lambda x: time.asctime(time.gmtime(x))
    # set up the singleton to hold our globals
    hsingleton = honeysnap.singletonmixin.HoneysnapSingleton.getInstance(options)
    # create an instance of the xBytes class
    summ = xBytesnSecs()

    # figure out if reading from a file or from stdin
    if len(args):
        for f in args:
            if os.path.exists(f) and os.path.isfile(f):
                summ.run(f)
            else:
                print "File not found: %s" % f
                sys.exit(2)
    else:
        # can't really do true stdin input, since we repeatedly parse
        # the file, so create a tempfile that is read from stdin
        # pass it to processFile
        fh = sys.stdin
        tmph, tmpf = tempfile.mkstemp()
        tmph = open(tmpf, 'wb')
        for l in fh:
            tmph.write(l)
        tmph.close()
        summ.run(tmpf)
        # all done, delete the tmp file
        os.unlink(tmpf)

if __name__ == "__main__":
    # everything happens in main
    main()


