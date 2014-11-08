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

    def test_contains(self):
        prefixes = MTDIPPrefixes(NETWORKS)
        self.assertTrue(IPAddr('140.0.0.3') in prefixes)
        self.assertTrue(IPAddr('140.0.8.3') in prefixes)
        self.assertFalse(IPAddr('180.0.8.3') in prefixes)

class MTDIPPrefixTestCase(unittest.TestCase):
    def test_contains(self):
        self.assertTrue(IPAddr('140.0.0.3') in MTDIPPrefix('140.0.0.0/8'))
        self.assertTrue(IPAddr('140.0.1.5') in MTDIPPrefix('140.0.0.0/8'))
        self.assertFalse(IPAddr('140.0.0.2') in MTDIPPrefix('140.0.0.0/32'))
        self.assertFalse(IPAddr('141.0.1.5') in MTDIPPrefix('140.0.0.0/8'))

if __name__ == '__main__':
    unittest.main()
