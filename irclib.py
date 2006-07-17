#
# Library for parsing IRC
#
# Copyright 2006 Arthur Clune, arthur@honeynet.org.uk
# All rights reserved.
#
# This code is released under the GNU General Public License
# version 2
#
# $Id$

import re
import exceptions
import os
import string
from datetime import datetime

__all__ = ['IRCMessageNotParsed', 'IRCLine', 'irc_from_pcap']

DEBUG = 0

irc_commands = [
    "ACTION",
    "ADMIN",
    "CNOTICE",
    "ERROR",
    "GLOBOPS",
    "INFO",
    "INVITE",
    "JOIN",
    "KICK",
    "LINKS",
    "LIST",
    "LUSERS",
    "MODE",
    "MOTD",
    "NAMES",
    "NICK",
    "NOTICE",
    "OPER",
    "PART",
    "PASS",
    "PING",
    "PONG",
    "PRIVMSG",
    "QUIT",
    "SCONNECT",
    "SQUIT",
    "STATS",
    "TIME",
    "TOPIC",
    "TRACE",
    "USER",
    "USERHOST",
    "USERS",
    "VERSION",
    "WALLOPS",
    "WELCOME",
    "WHO",
    "WHOIS",
    "WHOAS"
    ]


# Numeric table from python-irclib, and from Perl Net::IRC before that
numeric_events = {
    "001": "welcome",
    "002": "yourhost",
    "003": "created",
    "004": "myinfo",
    "005": "featurelist",  # XXX
    "200": "tracelink",
    "201": "traceconnecting",
    "202": "tracehandshake",
    "203": "traceunknown",
    "204": "traceoperator",
    "205": "traceuser",
    "206": "traceserver",
    "207": "traceservice",
    "208": "tracenewtype",
    "209": "traceclass",
    "210": "tracereconnect",
    "211": "statslinkinfo",
    "212": "statscommands",
    "213": "statscline",
    "214": "statsnline",
    "215": "statsiline",
    "216": "statskline",
    "217": "statsqline",
    "218": "statsyline",
    "219": "endofstats",
    "221": "umodeis",
    "231": "serviceinfo",
    "232": "endofservices",
    "233": "service",
    "234": "servlist",
    "235": "servlistend",
    "241": "statslline",
    "242": "statsuptime",
    "243": "statsoline",
    "244": "statshline",
    "250": "luserconns",
    "251": "luserclient",
    "252": "luserop",
    "253": "luserunknown",
    "254": "luserchannels",
    "255": "luserme",
    "256": "adminme",
    "257": "adminloc1",
    "258": "adminloc2",
    "259": "adminemail",
    "261": "tracelog",
    "262": "endoftrace",
    "263": "tryagain",
    "265": "n_local",
    "266": "n_global",
    "300": "none",
    "301": "away",
    "302": "userhost",
    "303": "ison",
    "305": "unaway",
    "306": "nowaway",
    "311": "whoisuser",
    "312": "whoisserver",
    "313": "whoisoperator",
    "314": "whowasuser",
    "315": "endofwho",
    "316": "whoischanop",
    "317": "whoisidle",
    "318": "endofwhois",
    "319": "whoischannels",
    "321": "liststart",
    "322": "list",
    "323": "listend",
    "324": "channelmodeis",
    "329": "channelcreate",
    "331": "notopic",
    "332": "currenttopic",
    "333": "topicinfo",
    "341": "inviting",
    "342": "summoning",
    "346": "invitelist",
    "347": "endofinvitelist",
    "348": "exceptlist",
    "349": "endofexceptlist",
    "351": "version",
    "352": "whoreply",
    "353": "namreply",
    "361": "killdone",
    "362": "closing",
    "363": "closeend",
    "364": "links",
    "365": "endoflinks",
    "366": "endofnames",
    "367": "banlist",
    "368": "endofbanlist",
    "369": "endofwhowas",
    "371": "info",
    "372": "motd",
    "373": "infostart",
    "374": "endofinfo",
    "375": "motdstart",
    "376": "endofmotd",
    "377": "motd2",        # 1997-10-16 -- tkil
    "381": "youreoper",
    "382": "rehashing",
    "384": "myportis",
    "391": "time",
    "392": "usersstart",
    "393": "users",
    "394": "endofusers",
    "395": "nousers",
    "401": "nosuchnick",
    "402": "nosuchserver",
    "403": "nosuchchannel",
    "404": "cannotsendtochan",
    "405": "toomanychannels",
    "406": "wasnosuchnick",
    "407": "toomanytargets",
    "409": "noorigin",
    "411": "norecipient",
    "412": "notexttosend",
    "413": "notoplevel",
    "414": "wildtoplevel",
    "421": "unknowncommand",
    "422": "nomotd",
    "423": "noadmininfo",
    "424": "fileerror",
    "431": "nonicknamegiven",
    "432": "erroneusnickname", # Thiss iz how its speld in thee RFC.
    "433": "nicknameinuse",
    "436": "nickcollision",
    "437": "unavailresource",  # "Nick temporally unavailable"
    "441": "usernotinchannel",
    "442": "notonchannel",
    "443": "useronchannel",
    "444": "nologin",
    "445": "summondisabled",
    "446": "usersdisabled",
    "451": "notregistered",
    "461": "needmoreparams",
    "462": "alreadyregistered",
    "463": "nopermforhost",
    "464": "passwdmismatch",
    "465": "yourebannedcreep", # I love this one...
    "466": "youwillbebanned",
    "467": "keyset",
    "471": "channelisfull",
    "472": "unknownmode",
    "473": "inviteonlychan",
    "474": "bannedfromchan",
    "475": "badchannelkey",
    "476": "badchanmask",
    "477": "nochanmodes",  # "Channel doesn't support modes"
    "478": "banlistfull",
    "481": "noprivileges",
    "482": "chanoprivsneeded",
    "483": "cantkillserver",
    "484": "restricted",   # Connection is restricted
    "485": "uniqopprivsneeded",
    "491": "nooperhost",
    "492": "noservicehost",
    "501": "umodeunknownflag",
    "502": "usersdontmatch",
}


# useful regexps from RFC 1459

# channel
channel_re = r'(?:&|#|$)(?:[^ ,\x07])+'
# nick
nick_re    = r'[a-zA-Z0-9\[\]\\`^{}_|-]+'
# user
user_re    = r'~?[^\s@]+'
# identify a host in standard DNS form. This regexp is a little approximate
# but then this field is often not a valid hostname anyway
host_re    = r'(?:(?:\d+\.\d+\.\d+\.\d+)|(?:[\w-]+\.[\w.-]+))'
# command = text e.g. PRIVMSG or 3 digit code
command_re = r'(?:(?:%s)|(?:\d\d\d))' % '|'.join(irc_commands)
#prefix = servername | nick | nick!user | nick!user@host
prefix_re  = r'(?:(?:(?:%s)!(?:%s)@(?:%s))|(?:(?:%s)!(?:%s))|(?:%s)|(?:%s))' % (nick_re, user_re, host_re, nick_re, user_re, host_re, nick_re)
# params are :(.*) or groups of ' ' separated params, repeated up to 15 times.
params_re  = r'(?:(?::[^\n\r\0]+)|(?:(?:[^:][^\0\r\n ]*)(?: [^\0\r\n ]+)*))'
# a message is an optional prefix, a command and the params
message_re = re.compile(r'(?::(?P<prefix>%s) )?(?P<command>%s) (?P<arguments>%s)' % (prefix_re, command_re, params_re))

# some helper functions

def _to_rfc1459_lower(text):
    """Return a lower case string, as per RFC1459. []\^ -> {}|~  """
    translation = string.maketrans(string.ascii_uppercase + "[]\\^",
                                          string.ascii_lowercase + "{}|~")
    return text.translate(translation)

def _to_textual_command(command):
    """replace numeric codes with text strings and uppercase everything"""
    if re.match(r'\d\d\d', command):
        if numeric_events.has_key(command):
                return numeric_events[command].upper()
        else:
            raise IRCMessageNotParsed, "Can't find command %s" % command
    return command.upper()

def _to_ascii(line):
    """Convert hex->ascii and remove non-printable chars"""
    i=0
    output=""
    while(i<len(line)):
        num = int(line[i:i+2], 16)
        if(31<num<127):
            output = output + chr(num)
        i = i+2
    return output

class IRCMessageNotParsed(Exception):
    """Raised on bad message or parser failure"""
    def __str__(self):
        return "Can't parse IRC message : %s" % self.text
    def __init__(self, text):
        self.text = text

class IRCLine:
    """Class to represent IRC traffic"""
    def __init__(self):   
        self.fromIP     = None
        self.toIP       = None
        self.timestamp  = None
        self.channel    = None
        self.fromNick   = None
        self.fromUser   = None
        self.fromHost   = None
        self.toNick     = None
        self.toUser     = None
        self.toHost     = None
        self.text       = None
        self.command    = None

    def __repr__(self):
        """Pretty-print"""
        string = str(self.timestamp)
        for item in ["fromIP", "toIP", "fromNick", "fromUser",
                     "fromHost", "command", "toNick", "toUser", "toHost", "channel", "text"]:
            if self.__dict__[item]:
                string = string + " " + self.__dict__[item]
        return string
        
    def parse(self, text):
        """Parse IRC line"""
        if DEBUG:
            print "Parsing ", text

        m = message_re.search(text)
        if m:
            if DEBUG:
                print "Message is ", m.group(0)
            # messages have an optional prefix
            if m.group("prefix"):
                if DEBUG:
                    print "Prefix is ", m.group("prefix")
                (self.fromNick, self.fromUser, self.fromHost) = self._parse_prefix(m.group("prefix"))
            # then a command
            if m.group("command"):
                if DEBUG:
                    print "Command is ", m.group("command")
                self.command = _to_textual_command(m.group("command"))
            else:
                raise IRCMessageNotParsed, text

            # then a set of parameters
            args = m.group("arguments")
            if DEBUG:
                print "Params are ", args

            # Some commands don't match the general pattern. Special case those there
            
            # text after NICK is a request for a nickname, not a recipient
            # similarly for USER
            if self.command == 'NICK' or self.command == "USER":
                self.text = args
                return

            # now the generic case: COMMAMD param1 param2 .....
            args = args.split(' ')
            (first, rest) = (args[0], args[1:])
            # first parameter can be a list of targets
            # BUG: we ignore ',' separate lists for now since we can't store multiple recipients
            # channel
            channel = re.match(r'(%s)' % channel_re, first)
            prefix  = re.match(r'(%s)' % prefix_re, first)
            if channel:
                # to a channel
                if DEBUG:
                    print "Found a channel :%s:" % channel.group(1)
                self.channel = channel.group(1)[1:]
                del args[0]
            elif prefix:
                # user, nick, host or combination thereof
                if DEBUG:
                    print "To Prefix is ", prefix
                (self.toNick, self.toUser, self.toHost) = self._parse_prefix(prefix.group(1))
                del args[0]

            if args:
                args = ' '.join(args)
                # if params start with a ':', we are done
                message = re.match(':(.*)', args)
                if message:
                    self.text = message.group(1)
                else:
                    # something else. Just shove it in text for now and finish
                    self.text = args
        else:
            raise IRCMessageNotParsed, text


    def _parse_prefix(self, prefix):
        """
        Parse a prefix. Return tuple of (Nick, User, Host).
        Some of these values may be None
        """
        r = re.search(r'^(%s)!(%s)@(%s)' % (nick_re, user_re, host_re), prefix)
        if r:
            return (_to_rfc1459_lower(r.group(1)), r.group(2), r.group(3))
        r = re.search(r'^(%s)!(%s)' % (nick_re, user_re), prefix)
        if r:
            return (_to_rfc1459_lower(r.group(1)), r.group(2), None)
        r = re.search(r'^(%s)' % host_re, prefix)
        if r:
            return (None, None, r.group(1))
        r = re.search(r'^(%s)' % nick_re, prefix)Enigmail
        if r:
            return (_to_rfc1459_lower(r.group(1)), None, None)
        raise IRCMessageNotParsed(prefix) 

class _IRCRaw:
    """Class to hold IP level information about an IRC packet"""
    def __init__(self):
        self.fromIP     = None
        self.toIP       = None
        self.timestamp  = None
        self.data       = ""

def irc_from_pcap(pcap_file, tethereal="tethereal", tethereal_opts=""):
    """
    Iterate over tethereal input, returning IRCLine objects

    tethereal = OS path to the tethereal executable
    tethereal opts = extra options to pass to tethereal e.g. "-d tcp.port=1042,irc"

    """
    # tethereal headline. This isn't quite right since we ignore TCP timeout/re-transmission notices and just merge them in
    headerline =  re.compile("^\s*\d+\s+(\d{4})-(\d\d)-(\d\d)\s+(\d\d):(\d\d):(\d\d)\.(\d+)\s+(\d+\.\d+\.\d+\.\d+) -> (\d+\.\d+\.\d+\.\d+)\s+IRC\s+")
    firstline=True
    rawirc=_IRCRaw()
    cmd = tethereal + " -tad -lnx " + tethereal_opts + " -R 'irc'  -r " + pcap_file
    f = os.popen(cmd)
    for line in f:
        # are we a headerline?
        if headerline.match(line):
            if not firstline:
                for subline in rawirc.data.split("0d0a"):
                    if not subline:
                        continue
                    irc = IRCLine()
                    text = _to_ascii(subline)
                    try:
                        irc.parse(text)
                    except IRCMessageNotParsed:
                        print "Can't parse line ", text
                        continue
                    irc.toIP = rawirc.toIP
                    irc.fromIP = rawirc.fromIP
                    irc.timestamp = rawirc.timestampEnigmail
                    yield irc
                rawirc = _IRCRaw()
            h = headerline.match(line)
            rawirc.fromIP  = h.group(8)
            rawirc.toIP    = h.group(9)
            rawirc.timestamp = datetime(int(h.group(1)), int(h.group(2)), int(h.group(3)),
                               int(h.group(4)), int(h.group(5)), int(h.group(6)),
                               int(h.group(7)))
            firstline = False
            continue
        newdata = line[6:53].replace(" ", "")
        rawirc.data = rawirc.data + newdata
    f.close()
    raise StopIteration
        

if __name__=="__main__":
    import sys
    if len(sys.argv) == 3:
        lines = irc_from_pcap(sys.argv[1], tethereal_opts=sys.argv[2])
    else:
        lines = irc_from_pcap(sys.argv[1])
    for line in lines:
        print line
