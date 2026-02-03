# import unittest
# def add(a,b):
#     return a + b

# class TestAddFunction(unittest.TestCase):
#     def test_add(self):
#         self.assertEqual(add(2, 3), 5)
#         self.assertTrue(add(0, 2) == 2)
#         self.assertRaises(TypeError, add, '2', 3)


# if __name__ == '__main__':
#     unittest.main()


class TestFunct:
    def add(self,a,b):
        return a + b    
    def sub(self,a,b):
        return a - b
    def div(self,a,b):
        return a / b

    
if __name__ == "__main__":
    t = TestFunct()
    print(t.add(2,3))
    print(t.sub(5,3))
    print(t.div(10,2))