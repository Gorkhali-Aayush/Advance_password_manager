import classTest as funct
import unittest

class TestFunct(unittest.TestCase):
    def setUp(self):
        self.test_funct = funct.TestFunct()

    def test_add(self):
        self.assertEqual(self.test_funct.add(2, 3), 5)
        self.assertEqual(self.test_funct.add(-1, 1), 0)
        self.assertEqual(self.test_funct.add(0, 0), 0)

    def test_sub(self):
        self.assertEqual(self.test_funct.sub(5, 3), 2)
        self.assertEqual(self.test_funct.sub(0, 0), 0)
        self.assertEqual(self.test_funct.sub(-1, -1), 0)

    def test_div(self):
        self.assertEqual(self.test_funct.div(10, 2), 5)
        self.assertEqual(self.test_funct.div(9, 3), 3)
        with self.assertRaises(ZeroDivisionError):
            self.test_funct.div(5, 0)


if __name__ == '__main__':
    unittest.main()
