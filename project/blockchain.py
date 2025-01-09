import json
import os
import hashlib
import time

class Block:
    def __init__(self, data, previous_hash=""):
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = 0  # Nonce for proof-of-work
        self.timestamp = time.time()
        self.hash = ""

    def calculate_hash(self):
        block_string = f"{self.data}{self.previous_hash}{self.nonce}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self):
        return {
            "Data": self.data,
            "Previous hash": self.previous_hash,
            "Hash": self.hash
        }

class Blockchain:
    def __init__(self):
        self.chain = []
        self.load_from_file()
        if len(self.chain) == 0:
            # Create the genesis block if the chain is empty
            genesis = Block("Genesis Block", "")
            genesis.hash = genesis.calculate_hash()
            while not genesis.hash.startswith("00"):
                genesis.nonce += 1
                genesis.hash = genesis.calculate_hash()
            self.chain.append(genesis.to_dict())
            self.save_to_file()

    def new_block(self, data):
        # Get previous block's hash from the last block in chain
        prev_hash = self.chain[-1]["Hash"] if self.chain else ""

        new_block = Block(data, prev_hash)
        new_block.hash = new_block.calculate_hash()
        
        # Adjusted proof-of-work condition to require hash to start with "00"
        while not new_block.hash.startswith("00"):
            new_block.nonce += 1
            new_block.hash = new_block.calculate_hash()
        
        self.chain.append(new_block.to_dict())
        self.save_to_file()
        return new_block.hash

    def new_transaction(self, sender, recipient, amount):
        # Create block data
        data = f"{sender} sent {amount} to {recipient}"
        
        # Create new block and get its hash
        transaction_hash = self.new_block(data)
        
        return {
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
            'timestamp': time.time(),
            'transaction_id': transaction_hash
        }

    def save_to_file(self):
        # Clear existing data and save the current chain as an array of dictionaries
        with open('data/blockchain.json', 'w') as f:
            json.dump(self.chain, f, indent=4)

    def load_from_file(self):
        if os.path.exists('data/blockchain.json'):
            with open('data/blockchain.json', 'r') as f:
                try:
                    data = json.load(f)
                    self.chain = data if isinstance(data, list) else []
                except json.JSONDecodeError:
                    # If the file is empty or invalid, initialize with an empty chain
                    self.chain = []
        else:
            self.chain = []

    def get_chain(self):
        return self.chain


# import json
# import os
# import hashlib
# import time

# class Block:
#     def __init__(self, data, previous_hash=""):
#         self.data = data
#         self.previous_hash = previous_hash
#         self.timestamp = time.time()
#         self.hash = self.calculate_hash()

#     def calculate_hash(self):
#         block_string = f"{self.data}{self.previous_hash}{self.timestamp}"
#         return hashlib.sha256(block_string.encode()).hexdigest()

#     def to_dict(self):
#         return {
#             "Data": self.data,
#             "Previous hash": self.previous_hash,
#             "Hash": self.hash
#         }

# class Blockchain:
#     def __init__(self):
#         self.chain = []
#         self.load_from_file()
#         if len(self.chain) == 0:
#             # Create the genesis block if the chain is empty
#             genesis = Block("Genesis Block", "")
#             self.chain.append(genesis.to_dict())
#             self.save_to_file()

#     def new_block(self, data):
#         # Get previous block's hash from the last block in chain
#         prev_hash = self.chain[-1]["Hash"] if self.chain else ""

#         new_block = Block(data, prev_hash)
#         self.chain.append(new_block.to_dict())
#         self.save_to_file()
#         return new_block.hash

#     def new_transaction(self, sender, recipient, amount):
#         # Create block data
#         data = f"{sender} sent {amount} to {recipient}"
        
#         # Create new block and get its hash
#         transaction_hash = self.new_block(data)
        
#         return {
#             'sender': sender,
#             'recipient': recipient,
#             'amount': amount,
#             'timestamp': time.time(),
#             'transaction_id': transaction_hash
#         }

#     def save_to_file(self):
#         # Save the chain as an array of dictionaries
#         with open('data/blockchain.json', 'w') as f:
#             json.dump(self.chain, f, indent=4)

#     def load_from_file(self):
#         if os.path.exists('data/blockchain.json'):
#             with open('data/blockchain.json', 'r') as f:
#                 self.chain = json.load(f)
#         else:
#             self.chain = []
#     def get_chain(self):
#         return self.chain


# import json
# import os
# import hashlib
# import time

# class Block:
#     def __init__(self, data, previous_hash=""):
#         self.data = data
#         self.previous_hash = previous_hash
#         self.timestamp = time.time()
#         self.hash = self.calculate_hash()

#     def calculate_hash(self):
#         block_string = f"{self.data}{self.previous_hash}{self.timestamp}"
#         return hashlib.sha256(block_string.encode()).hexdigest()

#     def to_dict(self):
#         return {
#             "Data": self.data,
#             "Previous hash": self.previous_hash,
#             "Hash": self.hash
#         }

# class Blockchain:
#     def __init__(self):
#         self.chain = []
#         self.load_from_file()
#         if len(self.chain) == 0:
#             # Create the genesis block if the chain is empty
#             genesis = Block("Genesis Block", "1")
#             self.chain.append(genesis.to_dict())
#             self.save_to_file()

#     def new_block(self, data):
#         if len(self.chain) > 0:
#             prev_block = self.chain[-1]
#             if isinstance(prev_block, dict):
#                 prev_hash = prev_block.get("Hash", "1")
#             else:
#                 # If for some reason the block is not a dict, use a default hash
#                 prev_hash = "1"
#         else:
#             prev_hash = "1"

#         new_block = Block(data, prev_hash)
#         self.chain.append(new_block.to_dict())
#         self.save_to_file()
#         return new_block.hash

#     def new_transaction(self, sender, recipient, amount):
#         # Create block data
#         data = f"{sender} sent {amount} to {recipient}"
        
#         # Create new block and get its hash
#         transaction_hash = self.new_block(data)
        
#         return {
#             'sender': sender,
#             'recipient': recipient,
#             'amount': amount,
#             'timestamp': time.time(),
#             'transaction_id': transaction_hash
#         }

#     def save_to_file(self):
#         # Save the chain as an array of dictionaries
#         with open('data/blockchain.json', 'w') as f:
#             json.dump(self.chain, f, indent=4)

#     def load_from_file(self):
#         if os.path.exists('data/blockchain.json'):
#             with open('data/blockchain.json', 'r') as f:
#                 self.chain = json.load(f)
#         else:
#             self.chain = []

#     def get_chain(self):
#         return self.chain



# import json
# import os
# import hashlib
# import time

# class Block:
#     def __init__(self, data, previous_hash=""):
#         self.data = data
#         self.previous_hash = previous_hash
#         self.hash = self.calculate_hash()

#     def calculate_hash(self):
#         block_string = f"{self.data}{self.previous_hash}{time.time()}"
#         return hashlib.sha256(block_string.encode()).hexdigest()

#     def to_dict(self):
#         return {
#             "data": self.data,
#             "previous_hash": self.previous_hash,
#             "hash": self.hash
#         }

#     def __str__(self):
#         return f"Data: {self.data}\nPrevious hash: {self.previous_hash}\nHash: {self.hash}"

# class Blockchain:
#     def __init__(self):
#         self.chain = []
#         self.load_from_file()
#         if len(self.chain) == 0:
#             # Create the genesis block if the chain is empty
#             self.new_block("Genesis Block", "1")

#     def new_block(self, data, previous_hash):
#         # Calculate hash for the new block
#         block_string = f"{data}{previous_hash}{time.time()}"
#         current_hash = hashlib.sha256(block_string.encode()).hexdigest()
        
#         # Create block with the exact format shown
#         block = f"""Data: {data}
#                 Previous hash: {previous_hash}
#                 Hash: {current_hash}"""
        
#         # Add block to chain
#         self.chain.append(block)
#         self.save_to_file()
#         return current_hash

#     def new_transaction(self, sender, recipient, amount):
#         # Get previous block's hash
#         if len(self.chain) > 0:
#             prev_block = self.chain[-1]
#             # Extract hash from the last line of previous block
#             prev_hash = prev_block.split('\n')[-1].split(': ')[1]
#         else:
#             prev_hash = "1"

#         # Create block data
#         data = f"{sender} sent {amount} to {recipient}"
        
#         # Create new block
#         transaction_hash = self.new_block(data, prev_hash)
        
#         return {
#             'sender': sender,
#             'recipient': recipient,
#             'amount': amount,
#             'timestamp': time.time(),
#             'transaction_id': transaction_hash
#         }

#     def save_to_file(self):
#         # Save the chain exactly as formatted
#         with open('data/blockchain.json', 'w') as f:
#             json.dump(self.chain, f, indent=4)

#     def load_from_file(self):
#         if os.path.exists('data/blockchain.json'):
#             with open('data/blockchain.json', 'r') as f:
#                 self.chain = json.load(f)
#         else:
#             self.chain = []
#     def get_chain(self):
#         return self.chain


# import json
# import os
# import hashlib
# import time

# class Blockchain:
#     def __init__(self):
#         self.chain = []
#         self.current_transactions = []
#         self.load_from_file()
#         if len(self.chain) == 0:
#             # Create the genesis block if the chain is empty
#             self.new_block(previous_hash='1', proof=100)

#     def new_block(self, proof, previous_hash=None):
#         block = {
#             'index': len(self.chain) + 1,
#             'timestamp': time.time(),
#             'transactions': self.current_transactions,
#             'proof': proof,
#             'previous_hash': previous_hash or self.hash(self.chain[-1] if self.chain else None),
#         }
#         self.current_transactions = []
#         self.chain.append(block)
#         self.save_to_file()
#         return block

#     def new_transaction(self, sender, recipient, amount):
#         transaction = {
#             'sender': sender,
#             'recipient': recipient,
#             'amount': amount,
#             'timestamp': time.time(),
#             'transaction_id': self.generate_transaction_id(sender, recipient, amount)
#         }
#         self.current_transactions.append(transaction)
#         self.save_to_file()
#         return transaction

#     @property
#     def last_block(self):
#         return self.chain[-1] if self.chain else None

#     @staticmethod
#     def hash(block):
#         if block is None:
#             return hashlib.sha256(b'genesis').hexdigest()
#         block_string = json.dumps(block, sort_keys=True).encode()
#         return hashlib.sha256(block_string).hexdigest()

#     def generate_transaction_id(self, sender, recipient, amount):
#         transaction_string = f"{sender}{recipient}{amount}{time.time()}"
#         return hashlib.sha256(transaction_string.encode()).hexdigest()

#     def save_to_file(self):
#         data = {
#             'chain': self.chain,
#             'current_transactions': self.current_transactions
#         }
#         with open('data/blockchain.json', 'w') as f:
#             json.dump(data, f, indent=4)

#     def load_from_file(self):
#         if os.path.exists('data/blockchain.json'):
#             with open('data/blockchain.json', 'r') as f:
#                 data = json.load(f)
#                 if isinstance(data, dict):
#                     self.chain = data.get('chain', [])
#                     self.current_transactions = data.get('current_transactions', [])
#                 elif isinstance(data, list):
#                     self.chain = data
#                     self.current_transactions = []

# import hashlib
# import json
# import os
# from datetime import datetime

# class Block:
#     def __init__(self, data, prev_hash=""):
#         self.data = data
#         self.prev_hash = prev_hash
#         self.nonce = 0
#         self.timestamp = datetime.now().isoformat()
#         self.hash = self.calculate_hash()

#     def calculate_hash(self):
#         data = str(self.data) + self.prev_hash + str(self.nonce)
#         data = data.encode('utf-8')
#         return hashlib.sha256(data).hexdigest()

#     def to_dict(self):
#         return {
#             "data": self.data,
#             "prev_hash": self.prev_hash,
#             "nonce": self.nonce,
#             "timestamp": self.timestamp,
#             "hash": self.hash
#         }

# class Blockchain:
#     def __init__(self):
#         self.chain = []
#         self.current_transactions = []
        
#         # Ensure data directory exists
#         os.makedirs('data', exist_ok=True)
        
#         # Load existing chain or create genesis block
#         self.load_from_file()
#         if not self.chain:  # If chain is empty
#             genesis_block = Block("Genesis Block")
#             self.chain.append(genesis_block.to_dict())
#             self.save_to_file()

#     def generate_transaction_id(self, sender, recipient, amount):
#         timestamp = datetime.now().isoformat()
#         data = f"{sender}{recipient}{amount}{timestamp}"
#         return hashlib.sha256(data.encode('utf-8')).hexdigest()

#     def new_transaction(self, sender, recipient, amount):
#         # Ensure chain has at least genesis block
#         if not self.chain:
#             genesis_block = Block("Genesis Block")
#             self.chain.append(genesis_block.to_dict())
#             self.save_to_file()

#         transaction = {
#             'sender': sender,
#             'recipient': recipient,
#             'amount': amount,
#             'timestamp': datetime.now().isoformat(),
#             'transaction_id': self.generate_transaction_id(sender, recipient, amount)
#         }
        
#         # Add transaction to current transactions
#         self.current_transactions.append(transaction)
        
#         # Get previous block (now safe since we ensure chain has at least genesis block)
#         prev_block = self.chain[-1]
        
#         # Create new block with current transactions
#         new_block = Block(
#             data=json.dumps(self.current_transactions),
#             prev_hash=prev_block['hash']
#         )
        
#         # Add block to chain and clear current transactions
#         self.chain.append(new_block.to_dict())
#         self.current_transactions = []
        
#         # Save updated chain
#         self.save_to_file()
        
#         return transaction

#     def save_to_file(self):
#         try:
#             with open('data/blockchain.json', 'w') as f:
#                 json.dump(self.chain, f, indent=4)
#         except Exception as e:
#             print(f"Error saving blockchain: {e}")

#     def load_from_file(self):
#         try:
#             if os.path.exists('data/blockchain.json'):
#                 with open('data/blockchain.json', 'r') as f:
#                     self.chain = json.load(f)
#             else:
#                 self.chain = []
#         except Exception as e:
#             print(f"Error loading blockchain: {e}")
#             self.chain = []

#     def get_chain(self):
#         return self.chain