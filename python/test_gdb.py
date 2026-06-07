import sys
import unittest
from tests.test_engines import TestQIHSEEngines
suite = unittest.TestSuite()
suite.addTest(TestQIHSEEngines('test_vector_db'))
unittest.TextTestRunner().run(suite)
