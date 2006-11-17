################################################################################
# (c) 2005, The Honeynet Project
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

# $Id$

import sys
import socket
from optparse import OptionParser, Option, OptionValueError
import re
import string
import gzip
import os
from fnmatch import fnmatch
import ConfigParser
from ConfigParser import SafeConfigParser
import tempfile
import pcap

# all the honeysnap imports
# eventually all these will become UDAF modules
# and you will get them all by importing DA
import httpDecode
import ftpDecode
import smtpDecode
import tcpflow
from hsIRC import HoneySnapIRC
from ircDecode import ircDecode
from singletonmixin import HoneysnapSingleton
from pcapinfo import pcapInfo
from packetSummary import Summarize
from base import Base
from output import outputSTDOUT, rawPathOutput
from packetCounter import Counter
from pcapRE import pcapRE, wordSearch, pcapReCounter
from sebekDecode import sebekDecode
from util import make_dir

class MyOption(Option):
    """
    A class that extends option to allow us to have comma delimited command line args.
    Taken from the documentation for optparse.
    """
    ACTIONS = Option.ACTIONS + ("extend",)
    STORE_ACTIONS = Option.STORE_ACTIONS + ("extend",)
    TYPED_ACTIONS = Option.TYPED_ACTIONS + ("extend",)

    def take_action(self, action, dest, opt, value, values, parser):
        if action == "extend":
            lvalue = value.split(",")
            values.ensure_value(dest, []).extend(lvalue)
        else:
            Option.take_action(
                self, action, dest, opt, value, values, parser)

def setFilters(options):
    """Set filters for packet counts"""
    irc_ports = options["irc_ports"]
    if len(irc_ports)==1:
        irc_filter = "dst port %s" % irc_ports[0]
    else:
        irc_filter = "("
        port = [ 'dst port %s' % port for port in irc_ports ]
        irc_filter = irc_filter + " or ".join(port) + ")"
    return [ 
        ('All outbound IPv4 packets:', 'src host %s'),         
        ('Outbound FTP packets:','src host %s and dst port 21'),
        ('Outbound SSH packets:','src host %s and dst port 22'),
        ('Outbound Telnet packets:','src host %s and dst port 23'),
        ('Outbound SMTP packets:','src host %s and dst port 25'),
        ('Outbound HTTP packets:','src host %s and dst port 80'),
        ('Outbound HTTPS packets:','src host %s and dst port 443'),        
        ('Outbound Sebek packets:','src host %s and udp port %s' % ('%s', options["sebek_port"])),
        ('Outbound IRC packets:','src host %s and tcp and %s' % ('%s', irc_filter)),
        ('Served FTP packets:','dst host %s and dst port 21'),
        ('Served SMTP packets:','dst host %s and dst port 25'),
        ('Served HTTP packets:','dst host %s and dst port 80'),
        ('Served HTTPS packets:','dst host %s and dst port 443'),
        ]

def processFile(honeypots, file):
    """
    Process a pcap file.
    honeypots is a list of honeypot ip addresses
    file is the pcap file to parse
    This function will run any enabled options for each pcap file
    """
    hs = HoneysnapSingleton.getInstance()
    options = hs.getOptions()
    try:
        # This sucks. pcapy wants a path to a file, not a file obj
        # so we have to uncompress the gzipped data into
        # a tmp file, and pass the path of that file to pcapy
        tmph, tmpf = tempfile.mkstemp()
        tmph = open(tmpf, 'wb')
        gfile = gzip.open(file)
        tmph.writelines(gfile.readlines())
        gfile.close()
        del gfile
        tmph.close()
        deletetmp = 1
    except IOError:
        # got an error, must not be gzipped
        # should probably do a better check here
        tmpf = file
        deletetmp = 0
    options["tmpf"] = tmpf

    """
    if not os.path.exists(options["output_data_directory"]):
        # the directory isn't there
        try:
            os.mkdir(options["output_data_directory"])
            for i in options["honeypots"]:
                os.mkdir(options["output_data_directory"]+"/"+i)
            # now we can create the output file
            #outfile = sys.stdout
        except OSError:
            print "Error creating output directory"
            sys.exit(1)
    """
    try:
        if options["filename"] is not None:
            out = rawPathOutput(options["filename"], mode="a+")
        else:
            out = outputSTDOUT()
    except IOError:
        # we have some error opening the file
        # there is something at that path. Is it a directory?
        if not os.path.isdir(options["output_data_directory"]):
            print "Error: output_data_directory exists, but is not a directory."
        else:
            print "Unknown Error creating output file"
            sys.exit(1)

    # quick and dirty check file is a valid pcap file
    try:
        if os.path.exists(tmpf) and os.path.getsize(tmpf)>0 and os.path.isfile(tmpf):
            p = pcap.pcap(tmpf)
        else:
            raise OSError
    except OSError:
        print "File %s is not a pcap file or does not exist" % file
        sys.exit(1)

    if options["do_pcap"] == "YES":
        out("\n\nResults for file: %s\n\n" % file)
        out("Pcap file information:\n")
        pi = pcapInfo(tmpf)
        pi.setOutput(out)
        pi.getStats()
        myout = rawPathOutput(options["output_data_directory"] +"/pcapinfo.txt")
        pi.setOutput(myout)
        pi.getStats()

    if options["do_packets"] == "YES":
        out("\nIP packet summary for common ports:\n\n")
        out("%-40s %10s\n" % ("Filter", "Packets"))
        filters = setFilters(options)
        for i in filters:
            key, filt = i
            out(key+"\n")
            for hp in honeypots:
                p = pcap.pcap(tmpf)
                c = Counter(p)
                c.setOutput(out)
                f = filt % hp
                c.setFilter(f)
                c.count()
            out("\n")

    if options["do_incoming"] == "YES":
        for hp in options["honeypots"]:
            outdir = options["output_data_directory"] + "/%s/conns" % hp
            make_dir(outdir)
            p = pcap.pcap(tmpf)
            v = options["verbose_summary"]
            s = Summarize(p, verbose=v)
            filt = 'dst host %s' % hp
            s.setFilter(filt, file)
            s.start()
            if v:
                l = 0
            else:
                l = 10  
            fileout = rawPathOutput(outdir+"/incoming.txt", mode="w")                   
            for output in (fileout, out):
                s.setOutput(output)
                s.doOutput("\nIncoming Connections for %s\n" % hp)             
                s.writeResults(limit=l)
            del p


    if options["do_outgoing"] == "YES":
        for hp in options["honeypots"]:
            outdir = options["output_data_directory"] + "/%s/conns" % hp
            make_dir(outdir)
            p = pcap.pcap(tmpf)
            v = options["verbose_summary"]
            s = Summarize(p, verbose=v)
            filt = 'src host %s' % hp
            s.setFilter(filt, file)
            s.start()
            if v:
                l = 0
            else:
                l = 10      
            fileout = rawPathOutput(outdir+"/outgoing.txt", mode="w") 
            for output in (fileout, out):
                s.setOutput(output) 
                s.doOutput("\nOutgoing Connections for %s\n" % hp)                 
                s.writeResults(limit=l)  
            del p


    if options["do_irc_summary"] == "YES" or options["do_irc"] == "YES":
        """
        Here we will use PcapRE to find packets on irc_port with "PRIVMSG"
        in the payload.  Matching packets will be handed to wordsearch
        to hunt for any matching words.
        """
        for hp in options["honeypots"]:
            for port in options["irc_ports"]:
                out("\nIRC Summary for %s:%s\n\n" % (hp, port))
                p = pcap.pcap(tmpf)
                words = '0day access account admin auth bank bash #!/bin binaries binary bot card cash cc cent connect crack credit dns dollar ebay e-bay egg flood ftp hackexploit http leech login money /msg nologin owns ownz password paypal phish pirate pound probe prv putty remote resolved root rooted scam scan shell smtp sploit sterling sucess sysop sys-op trade uid uname uptime userid virus warez'
                if options["wordfile"]:
                    wfile = options["wordfile"]
                    if os.path.exists(wfile) and os.path.isfile(wfile):
                        wfp = open(wfile, 'rb')
                        words = wfp.readlines()
                        words = [w.strip() for w in words]
                        words = " ".join(words)
                ws = wordSearch()
                ws.setWords(words)
                ws.setOutput(out)
                #ws.setOutput(options["output_data_directory"] + "/results")
                r = pcapReCounter(p)
                r.setFilter("host %s and tcp and port %s" % (hp, port))
                r.setRE('PRIVMSG') 
                r.setWordSearch(ws)
                r.setOutput(out)
                r.start()
                r.writeResults()
                del p

    if options["do_irc_detail"] == "YES" or options["do_irc"] == "YES":
        out("\nAnaylsing IRC\n")          
        for hp in options["honeypots"]:
            outdir = options["output_data_directory"] + "/%s/irc" % hp
            for port in options["irc_ports"] :
                out("\nHoneypot %s, port %s\n\n" % (hp, port))
                hirc = HoneySnapIRC()
                hirc.connect(tmpf, "host %s and tcp and port %s" % (hp, port))
                hd = ircDecode()
                hd.setOutput(out)
                hd.setOutdir(outdir)
                hd.setOutfile('irclog-%s.txt' % port)
                hirc.addHandler("all_events", hd.decodeCB, -1)
                hirc.ircobj.add_global_handler("all_events", hd.printLines, -1)
                hirc.ircobj.process_once()
                hd.printSummary()
                del hd

    if options["all_flows"] == "YES":
        out("\nExtracting all flows\n")
        p = pcap.pcap(tmpf)
        de = tcpflow.tcpFlow(p)
        filt = "host "
        filt += " or host ".join(options["honeypots"])
        de.setFilter(filt)
        de.setOutdir(options["output_data_directory"]+ "/%s/flows")
        de.setOutput(out)
        de.start()
        de.dump_extract(options)
        del p

    if options["do_http"] == "YES":
        out("\nExtracting from HTTP\n\n")
        p = pcap.pcap(tmpf)
        de = tcpflow.tcpFlow(p)
        de.setFilter("port 80")
        de.setOutdir(options["output_data_directory"]+ "/%s/http")
        de.setOutput(out)
        decode = httpDecode.httpDecode()
        decode.setOutput(out)
        de.registerPlugin(decode.decode)
        de.start()
        de.dump_extract(options)
        del p


    if options["do_ftp"] == "YES":
        out("\nExtracting from FTP\n\n")
        p = pcap.pcap(tmpf)
        de = tcpflow.tcpFlow(p)
        de.setFilter("port 20 or port 21")
        de.setOutdir(options["output_data_directory"] + "/%s/ftp")
        de.setOutput(out)
        decode = ftpDecode.ftpDecode()
        decode.setOutput(out)
        de.registerPlugin(decode.decode)
        de.start()
        de.dump_extract(options)
        del p

    if options["do_smtp"] == "YES":
        out("\nExtracting from SMTP\n\n")
        p = pcap.pcap(tmpf)
        de = tcpflow.tcpFlow(p)
        de.setFilter("port 25")
        de.setOutdir(options["output_data_directory"] + "/%s/smtp")
        de.setOutput(out)
        decode = smtpDecode.smtpDecode()
        decode.setOutput(out)
        de.registerPlugin(decode.decode)
        de.start()
        de.dump_extract(options)
        del p

    if options["do_sebek"] == "YES":
        out("\nExtracting Sebek data\n")
        for hp in options["honeypots"]:
            out("\nHoneypot %s\n\n" % hp)
            sbd = sebekDecode(hp)
            sbd.setOutdir(options["output_data_directory"] + "/%s/sebek" % hp)
            sbd.setOutput(out)
            sbd.run()
            del sbd

    # delete the tmp file we used to hold unzipped data
    if deletetmp:
        os.unlink(tmpf)

def cleanup(options):
    """
    Clean up empty files, etc.
    """
    datadir = options["output_data_directory"]
    for root, dirs, files in os.walk(datadir, topdown=False):
        #print root, dirs, files
        for name in files:
            if os.stat(os.path.join(root, name)).st_size == 0:
                #print "removing %s" % os.path.join(root, name)
                os.remove(os.path.join(root, name))
        for name in dirs:
            if not len(os.listdir(os.path.join(root, name))):
                #print "removing dir %s" % os.path.join(root, name)
                os.rmdir(os.path.join(root, name))
    """
    for dir in ["/irc", "/http", "/ftp", "/smtp", "/sebek"]:
        if os.path.isdir(datadir+dir):
            files = os.listdir(datadir+dir)
        else:
            continue
        for f in files:
            file = datadir + dir + "/" + f
            if os.stat(file).st_size == 0:
                os.unlink(file)
    """

def store_int_array(option, opt_str, value, parser):
    """Store comman seperated integer values from options into an array"""
    a = []
    a = value.split(",")
    try:
        a = [ int(n) for n in a ]
    except ValueError:
        raise OptionValueError("Argument %s not an integer!" % opt_str)
    setattr(parser.values, option.dest, a)

def configOptions(parser):
    """Define options"""
    parser.add_option("-c", "--config", dest="config",type="string",
        help="Config file")
    parser.add_option("-f", "--file", dest="filename",type="string",
        help="Write report to FILE", metavar="FILE")
    parser.set_defaults(filename=None)
    parser.add_option("-o", "--output", dest="outputdir",type="string",
        help="Write output to DIR, defaults to /tmp/analysis", metavar="DIR")
    parser.set_defaults(outputdir="/tmp/analysis")
    parser.add_option("-t", "--tmpdir", dest="tmpdir",type="string",
        help="Directory to use as a temporary directory, defaults to /tmp")
    parser.set_defaults(tmpdir="/tmp")
    parser.add_option("-H", "--honeypots", dest="honeypots", action="extend", type="string",
        help="Comma delimited list of honeypots")
##    parser.add_option("-r", "--read", dest="files", type="string",
##                  help="Pcap file to be read. If this flag is set then honeysnap will not run in batch mode. Will also read from stdin.", metavar="FILE")
    parser.add_option("-d", "--dir", dest="files", type="string",
        help="Directory containing timestamped log directories. If this flag is set then honeysnap will run in batch mode. To limit which directories to parse, use -m (--mask)", metavar="FILE")

    parser.add_option("-m", "--mask", dest="mask", type="string",
        help = "Mask to limit which directories are recursed into.")
    parser.set_defaults(mask="*")

    parser.add_option("-w", "--words", dest="wordfile", type="string",
        help = "Pull wordlist from FILE", metavar="FILE")

    # summary options
    parser.add_option("--do-pcap", dest="do_pcap", action="store_const", const="YES",
        help = "Summarise pcap info")
    parser.set_defaults(do_pcap="YES")
    parser.add_option("--do-packets", dest="do_packets", action="store_const", const="YES",
        help = "Summarise packet counts")
    parser.set_defaults(do_packets="NO")
    parser.add_option("--do-incoming", dest="do_incoming", action="store_const", const="YES",
        help = "Summarise incoming traffic flows")
    parser.set_defaults(do_incoming="NO")
    parser.add_option("--do-outgoing", dest="do_outgoing", action="store_const", const="YES",
        help = "Summarise outgoing traffic flows")
    parser.set_defaults(do_outgoing="NO")
    parser.add_option("--verbose-summary", dest="verbose_summary", action="store_const", const=1,
        help = "Do verbose flow counts, indexes flows by srcip, sport, dstip, dport")
    parser.set_defaults(verbose_summary=0)

    # protocol options
##    parser.add_option("--do-telnet", dest="do_telnet", action="store_const", const="YES",
##            help = "Count outbound telnet")
##    parser.set_defaults(do_telnet="NO")
##    parser.add_option("--do-ssh", dest="do_ssh", action="store_const", const="YES",
##            help = "Count outbound ssh")
##    parser.set_defaults(do_ssh="NO")
    parser.add_option("--do-http", dest="do_http", action="store_const", const="YES",
        help = "Extract http data")
    parser.set_defaults(do_http="NO")
##    parser.add_option("--do-https", dest="do_https", action="store_const", const="YES",
##            help = "Count outbound https")
##    parser.set_defaults(do_https="NO")
    parser.add_option("--do-ftp", dest="do_ftp", action="store_const", const="YES",
        help = "Extract FTP data")
    parser.set_defaults(do_ftp="NO")
    parser.add_option("--do-smtp", dest="do_smtp", action="store_const", const="YES",
        help = "Extract smtp data")
    parser.set_defaults(do_smtp="NO")
    parser.add_option("--do-irc", dest="do_irc", action="store_const", const="YES",
        help = "Summarize IRC and do irc detail (same as --do-irc-detail and --do-irc-summary)")
    parser.set_defaults(do_irc="NO")
    parser.add_option("--do-irc-summary", dest="do_irc_summary", action="store_const", const="YES",
        help = "Sumarize IRC messages, providing a hit count for key words, use --words to supply a word file")
    parser.set_defaults(do_irc_summary="NO")
    parser.add_option("--do-irc-detail", dest="do_irc_detail", action="store_const", const="YES",
        help = "Extract IRC sessions, do detailed IRC analysis")
    parser.set_defaults(do_irc_detail="NO")
    parser.add_option("--irc-ports", action="callback", callback=store_int_array, dest="irc_ports", type="string",
        help = "Ports for IRC traffic")   
    parser.set_defaults(irc_ports=[6667]) 
    parser.add_option("--irc-limit", dest="irc_limit", type="int", help = "Limit IRC summary to top N items")
    parser.set_defaults(irc_limit=0)
    parser.add_option("--do-sebek", dest="do_sebek", action="store_const", const="YES",
        help = "Summarize Sebek")
    parser.set_defaults(do_sebek="NO")
    parser.add_option("--sebek-port", dest="sebek_port", type="int", help = "Port for sebek traffic")
    parser.set_defaults(sebek_port=1101)
    parser.add_option("--all-flows", dest="all_flows", action="store_const", const="YES",
        help = "Extract data from all tcp flows")
    parser.set_defaults(do_http="NO")
##    parser.add_option("--do-rrd", dest="do_rrd", action="store_const", const="YES",
##            help = "Do RRD, not yet implemented")
##    parser.set_defaults(do_rrd="NO")

    return parser.parse_args()


def main():
    cmdparser = OptionParser(option_class=MyOption)
    values, args = configOptions(cmdparser)
    if len(sys.argv) > 1:
        if values.config:
            parser = SafeConfigParser()
            try:
                parser.read(values.config)
            except ConfigParser.Error:
                print 'Bad config file!'
                sys.exit(1)
            config = values.config
            if values.outputdir=='/tmp/analysis':
                try:
                    outputdir = parser.get("IO", "OUTPUT_DATA_DIRECTORY")
                    values.outputdir = outputdir
                except ConfigParser.Error:
                    outputdir = values.outputdir
            if values.tmpdir=='/tmp':
                try:
                    tmpdir = parser.get("IO", "TMP_FILE_DIRECTORY")
                    values.tmpdir = tmpdir
                except ConfigParser.Error:
                    tmpdir = values.tmpdir
            if not values.honeypots:
                try:
                    honeypots = parser.get("IO", "HONEYPOTS")
                    honeypots = honeypots.split()
                    values.honeypots = honeypots
                except ConfigParser.Error:
                    print "Must specify honeypots!"
                    sys.exit(1)
            if not values.wordfile:
                try:
                    wordfile = parser.get("IO", "WORDFILE")
                    values.wordfile = wordfile
                except ConfigParser.Error:
                    values.wordfile = None
            if values.filename is None:
                try:
                    fn = parser.get("IO", "OUTPUTFILE")
                    values.filename = fn
                except ConfigParser.Error:
                    pass
        else:
            parser = None

        # pull in the values from the option parser
        options = values.__dict__
        
        if options['config'] is not None:
            if os.path.isfile(options['config']): 
                try:
                    for i in parser.items("OPTIONS"): 
                        if i[0] == 'irc_ports':
                            options[i[0]] = [ int(n) for n in i[1].split(',') ]
                        elif i[0] == 'irc_limit': 
                            options[i[0]] = int(i[1])
                        else:
                            options[i[0]] = i[1] 
                except ConfigParser.Error:
                    print "Problem with the config file! Check format and permissions"
                    sys.exit(1)
            else:
                print "Config file not found!"
                sys.exit(1)
        options["output_data_directory"] = values.outputdir
        options["tmp_file_directory"] = values.tmpdir

        if values.honeypots is None:
            print "No honeypots specified. Please use either -H or config file to specify honeypots.\n"
            sys.exit(2)
        hsingleton = HoneysnapSingleton.getInstance(options)
        if not os.path.exists(values.outputdir):
            make_dir(values.outputdir)
        if os.path.exists(values.outputdir):
            for i in options["honeypots"]:
                make_dir(options["output_data_directory"]+"/"+i)
        # by default treat args as files to be processed
        # handle multiple files being passed as args
        if len(args):
            for f in args:
                if os.path.exists(f) and os.path.isfile(f):
                    processFile(values.honeypots, f)
                else:
                    print "File not found: %s" % f
                    sys.exit(2)
        # -d was an option
        elif values.files:
            if os.path.exists(values.files) and os.path.isdir(values.files):
                for root, dirs, files in os.walk(values.files):
                    #print root, dirs, files
                    if fnmatch(root, values.mask):
                        # this root matches the mask function
                        # find all the log files
                        #f  = [j for j in files if fnmatch(j, "log*")]
                        f  = [j for j in files]
                        # process each log file
                        if len(f):
                            for i in f:
                                processFile(values.honeypots, root+"/"+i)
            else:
                print "File not found: %s" % values.files
                sys.exit(2)

        # no args indicating files, read from stdin
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
            processFile(values.honeypots, tmpf)
            # all done, delete the tmp file
            os.unlink(tmpf)

        cleanup(options)
    else:
        cmdparser.print_help()

if __name__ == "__main__":
    #import profile
    #profile.run('main()', 'mainprof')

    main()




