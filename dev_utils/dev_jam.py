from dataclasses import dataclass
import time
import random

from typing import Dict, Tuple
from sortedcontainers import SortedDict  # For maintaining an ordered structure

@dataclass
class CacheEntry:
    domain_name: str
    record_type: str
    ttl: int
    timestamp: float  # Time when the record was cached

class DNSCache:
    def __init__(self):
        # Key: (domain_name, record_type), Value: CacheEntry
        self.cache: Dict[Tuple[str, str], CacheEntry] = {}
        # For quick access to expiration times
        self.expiry_index = SortedDict()

    def add_record(self, domain_name: str, record_type: str, ttl: int):
        current_time = time.time()
        expiry_time = current_time + ttl

        # Update main cache
        key = (domain_name, record_type)
        if key in self.cache:
            # Remove old entry from the expiry index
            old_expiry = self.cache[key].timestamp + self.cache[key].ttl
            if old_expiry in self.expiry_index:
                self.expiry_index.pop(old_expiry)

        self.cache[key] = CacheEntry(domain_name, record_type, ttl, current_time)
        self.expiry_index[expiry_time] = key

    def refresh_cache(self):
        current_time = time.time()

        for expiry_time, key in list(self.expiry_index.items()):
            if expiry_time - current_time <= random.uniform(0.7, 0.9) * self.cache[key].ttl:
                domain_name, record_type = key
                ttl = self.cache[key].ttl

                print(f"Refreshing {domain_name} ({record_type}) before expiry.")
                self.add_record(domain_name, record_type, ttl)  # Simulate refresh

            # Remove expired records
            if expiry_time <= current_time:
                print(f"Removing expired record: {key}")
                del self.cache[key]
                self.expiry_index.pop(expiry_time)

    def get_record(self, domain_name: str, record_type: str):
        key = (domain_name, record_type)
        if key in self.cache:
            entry = self.cache[key]
            if time.time() < entry.timestamp + entry.ttl:
                return entry
            else:
                print(f"Record {domain_name} ({record_type}) has expired.")
        return None

    def display_cache(self):
        print("Current Cache:")
        for key, entry in self.cache.items():
            expiry = entry.timestamp + entry.ttl
            print(
                f"{key} -> TTL: {entry.ttl}, Expires at: {time.ctime(expiry)}"
            )
    def fetch_dns_data(self, url: str) -> None:
        response = requests.get(url)
        
        if response.status_code == 200:
            data = response.json() 

            for entry in data['responses']:
                records, timestamp = entry
                
                timestamp_float = time()  

                for record in records:
                    domain_name = record['name']
                    record_type = record['record_type']
                    ttl = record['ttl']

                    cache_entry = CacheEntry(domain_name, record_type, ttl, timestamp_float)
                    self.add_record(domain_name, record_type, ttl)


url = "http://localhost:3030/universe"
dns_cache = DNSCache()
dns_cache.fetch_dns_data(url)
dns_cache.add_record("domain1.name", "A", 600)
dns_cache.add_record("domain2.name", "A", 1800)
dns_cache.add_record("domain.name", "AAAA", 30)

dns_cache.display_cache()

# time.sleep(5)  # Simulate some delay
dns_cache.refresh_cache()
dns_cache.display_cache()

