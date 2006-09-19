import os

def ipnum(ip) :
    "Return a numeric address for an ip string"
    v = 0L
    for x in ip.split(".") :
        v = (v << 8) | int(x);
    return v

def findName(filename, realname):
    head, tail = os.path.split(filename)
    newfn = head+'/'+realname+".1"
    while 1:
        if os.path.exists(newfn):
            newfn, ext = newfn.rsplit(".", 1)
            ext = int(ext)+1
            newfn = newfn + "." +str(ext)
        else:
            return newfn
            
def renameFile(state, realname):
    state.realname = realname
    newfn = findName(state.fname, realname)
    print "renaming %s to %s" %(state.fname, newfn)
    os.rename(state.fname, newfn)
    state.fname = newfn   
