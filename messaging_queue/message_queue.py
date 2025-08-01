class Node:
    def __init__(self, data: str):
        self.data = data
        self.next = None

class MessageQueue:
    def __init__(self):
        self.front = None
        self.rear = None

    def enqueue(self, data: str):
        new_node = Node(data)
        if self.rear:
            self.rear.next = new_node
        self.rear = new_node
        if not self.front:
            self.front = new_node

    def dequeue(self) -> str:
        if not self.front:
            return None
        result = self.front.data
        self.front = self.front.next
        if not self.front:
            self.rear = None
        return result

    def is_empty(self) -> bool:
        return self.front is None
