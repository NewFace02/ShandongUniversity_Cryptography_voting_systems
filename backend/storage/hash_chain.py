import hashlib
from typing import List

def sha256(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

class HashChain:
    def __init__(self):
        self.chain: List[str] = []

    def add_block(self, data: str):
        if not self.chain:
            prev_hash = "0" * 64
        else:
            prev_hash = self.chain[-1]

        block_hash = sha256(prev_hash + data)
        self.chain.append(block_hash)
        return block_hash

    def get_chain(self) -> List[str]:
        return self.chain

    def verify_chain(self, data_list: List[str]) -> bool:
        if len(data_list) != len(self.chain):
            return False

        prev_hash = "0" * 64
        for i, data in enumerate(data_list):
            expected_hash = sha256(prev_hash + data)
            if expected_hash != self.chain[i]:
                return False
            prev_hash = expected_hash
        return True
