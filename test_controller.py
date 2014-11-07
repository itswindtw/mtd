import unittest
from pox_ctrl import *

HOSTS = [IPAddr('100.0.0.7')]
NETWORKS = ['140.0.0.0/16',
            '150.0.0.0/8',
            '160.0.0.0/8',
            '170.0.0.0/8']

class MTDIPPrefixesTestCase(unittest.TestCase):
    def test_rand_ip_prefix(self):
        prefixes = MTDIPPrefixes(NETWORKS)
        print prefixes.rand_ip_prefix()
        print prefixes.rand_ip_prefix()
        print prefixes.rand_ip_prefix()

    def test_rand_ip_addr(self):
        prefixes = MTDIPPrefixes(NETWORKS)
        print prefixes.rand_ip_addr()
        print prefixes.rand_ip_addr()
        print prefixes.rand_ip_addr()

if __name__ == '__main__':
    unittest.main()
