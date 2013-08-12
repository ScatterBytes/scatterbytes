import unittest
from ..validation import SecurePassword


class RandomPasswordTestCase(unittest.TestCase):

    def test_random_password(self):
        p = SecurePassword.generate_random_value()
        self.assertEqual(len(p), 16)
