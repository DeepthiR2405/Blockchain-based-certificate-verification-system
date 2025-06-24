import hashlib
import json
import time

class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_hashes = []
        self.create_block(previous_hash="0")  # Genesis block

    def create_block(self, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'hashes': self.pending_hashes,
            'previous_hash': previous_hash
        }
        block_hash = self.hash(block)
        block['block_hash'] = block_hash
        self.chain.append(block)
        self.pending_hashes = []  # Reset pending hashes after block is created
        return block

    def add_certificate_hash(self, cert_hash):
        self.pending_hashes.append(cert_hash)

    def mine_block(self):
        if not self.pending_hashes:
            return None  # Nothing to mine
        last_block = self.chain[-1]
        new_block = self.create_block(previous_hash=last_block['block_hash'])
        return new_block

    def is_valid_certificate(self, cert_hash):
        for block in self.chain:
            if cert_hash in block['hashes']:
                return True
        return False

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
