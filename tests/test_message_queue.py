import unittest
from messaging_queue.message_queue import MessageQueue

class TestMessageQueue(unittest.TestCase):
    def test_enqueue_dequeue(self):
        q = MessageQueue()
        q.enqueue("msg1")
        q.enqueue("msg2")
        self.assertEqual(q.dequeue(), "msg1")
        self.assertEqual(q.dequeue(), "msg2")
        self.assertIsNone(q.dequeue())

if __name__ == '__main__':
    unittest.main()