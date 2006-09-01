def ipnum(ip) :
    "Return a numeric address for an ip string"
    v = 0L
    for x in ip.split(".") :
        v = (v << 8) | int(x);
    return v
