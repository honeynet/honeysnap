# caching decorator
# code from http://www.willmcgugan.com/2007/10/14/timed-caching-decorator/

from datetime import datetime, timedelta
from copy import deepcopy
from threading import RLock
 
def timed_cache(seconds=0, minutes=0, hours=0, days=0):
 
    time_delta = timedelta( seconds=seconds,
                            minutes=minutes,
                            hours=hours,
                            days=days )
 
    def decorate(f):
 
        f._lock = RLock()
        f._updates = {}
        f._results = {}
 
        def do_cache(*args, **kwargs):
 
            lock = f._lock
            lock.acquire()
 
            try:
                key = (args, tuple(sorted(kwargs.items(), key=lambda i:i[0])))
 
                updates = f._updates
                results = f._results
 
                t = datetime.now()
                updated = updates.get(key, t)                
 
                if key not in results or t-updated > time_delta:
                    # Calculate
                    updates[key] = t
                    result = f(*args, **kwargs)
                    results[key] = deepcopy(result)
                    return result
 
                else:
                    # Cache
                    return deepcopy(results[key])
 
            finally:
                lock.release()
 
        return do_cache
 
    return decorate
 
if __name__ == "__main__":
 
    import time
 
    class T(object):
 
        @timed_cache(seconds=2)
        def expensive_func(self, c):
            time.sleep(.2)
            return c            
 
    t = T ()
 
    for _ in xrange(30):
        time.sleep(.1)
        t1 = time.clock()
        print t.expensive_func('Calling expensive method')
        print "t - %i milliseconds"%int( (time.clock() - t1) * 1000. )


