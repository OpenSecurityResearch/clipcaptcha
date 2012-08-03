# Copyright (c) 2004-2011 Moxie Marlinspike

class DnsCache:    

    _instance          = None

	# initialize the cache instance variable to empty hash
    def __init__(self):
        self.cache = {}

	# Add a new record to dns cache
    def cacheResolution(self, host, address):
        self.cache[host] = address

	# return a cached address or 'None' if NONE IS PRESENT
    def getCachedAddress(self, host):
        if host in self.cache:
            return self.cache[host]

        return None

	# If the DnsCache._instance does not exist, create a new DnsCache and return that
	# If it exists, return the existing instance
    def getInstance():
        if DnsCache._instance == None:
            DnsCache._instance = DnsCache()

        return DnsCache._instance

    getInstance = staticmethod(getInstance)
