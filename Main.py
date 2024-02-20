import socket
import threading
import time
import hashlib
import json
from urllib.parse import urlparse
import time
import queue
import seal

class User:
    def __init__(self, username, password, age, income, credit_score, num_open_credit_accounts):
        self.username = username
        self.password = password
        self.age = age
        self.income = income
        self.credit_score = credit_score
        self.num_open_credit_accounts = num_open_credit_accounts

    def to_dict(self):
        return {
            "username": self.username,
            "password": self.password,
            "age": self.age,
            "income": self.income,
            "credit_score": self.credit_score,
            "num_open_credit_accounts": self.num_open_credit_accounts
        }

class LeaseContract:
    def __init__(self, lease_duration, lessee_address):
        self.lease_duration = lease_duration
        self.lessee_address = lessee_address
        self.start_time = time.time()

    def is_lease_active(self):
        return time.time() < self.start_time + self.lease_duration

    def get_lease_status(self):
        if self.is_lease_active():
            return "Active"
        else:
            return "Expired"

class Block:
    def __init__(self, index, previous_hash, timestamp, data, hash,contracts=None):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.hash = hash
        self.contracts = contracts if contracts else []

def calculate_hash(index, previous_hash, timestamp, data):
    value = str(index) + str(previous_hash) + str(timestamp) + str(data)
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

def append_new_block(inde,previous_hash, data,timesta):
    index = inde
    timestamp = timesta
    hash_value = calculate_hash(index, previous_hash, timestamp, data)
    return Block(index, previous_hash, timestamp, data, hash_value)

def create_new_block(previous_block, data):
    index = previous_block.index + 1
    timestamp = time.time()
    hash_value = calculate_hash(index, previous_block.hash, timestamp, data)
    return Block(index, previous_block.hash, timestamp, data, hash_value)
def create_genesis_block():
    return Block(0, "0", time.time(), "Genesis Block", calculate_hash(0, "0", time.time(), "Genesis Block"))

class Blockchain:

    def __init__(self):
        self.chain = [create_genesis_block()]
        self.nodes = {}
        self.pool = queue.Queue()
        self.lock = threading.Lock()
        self.users = {}
    
    def execute_block_contracts(self, block):
        for contract in block.contracts:
            contract.execute(block.data)

    def get_last_block(self):
        return self.chain[-1]
    
    def validate_transaction(self,Transaction):
        return True

    def validate_chain(self, remote_chain):
        return True

    def add_block(self, data, contracts=None):
        with self.lock:
            new_block = create_new_block(self.get_last_block(), data)
            if contracts:
                new_block.contracts.extend(contracts)
            self.chain.append(new_block)
            return new_block

    def add_node(self, address):
        parsed_url = urlparse(address)
        print(parsed_url)
        node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        node_id = len(self.nodes) + 1
        node.connect((address, 12345))
        print(f"Connected to node at {address}")
        self.nodes[node_id]= node
        client_handler = threading.Thread(target=handle_client, args=(node, address))
        client_handler.start()
        self.nodes.add(parsed_url.path)

    def connect_to_node(self, address):
        self.add_node(address)
        self.sync_nodes()

    def sync_nodes(self):
        for node in self.nodes:
            try:
                node.sendall(json.dumps({'type': 'sync', 'chain': [block.__dict__ for block in self.chain]}).encode('utf-8'))
            except socket.error as e:
                print(f"Failed to sync with node {node}: {e}")
                if e.errno == 10049:
                    print("Check if the IP address and port are correct.")
                elif e.errno == 10061:
                    print("Connection refused. Make sure the node is running and the port is open.")

    def sync_pools(self):
        def get_timestamp(obj):
            return  obj.timestamp
        while(True):
            self.pool.sort(key=get_timestamp)
    def create_user(self, username, password, age, income, credit_score, num_open_credit_accounts):
        if username in self.users:
            print("Username already exists. Please choose a different username.")
            return False
        else:
            user = User(username, password, age, income, credit_score, num_open_credit_accounts)
            self.users[username] = user
            print("User created successfully.")
            return True

    def login(self, username, password):
        if username in self.users:
            user = self.users[username]
            if user.password == password:
                print("Login successful!")
                return True
            else:
                print("Incorrect password. Please try again.")
                return False
        else:
            print("User does not exist. Please sign up.")
            return False           

blockchain = Blockchain()

def handle_client(conn, addr):
    with conn:
        while True:
            data = conn.recv(1024).decode('utf-8')
            #print(data)
            if not data:
                break
            message = json.loads(data)

            if message['type'] == 'transaction':
                transaction_data = message['data']
                contract_script = message.get('contract')
                
                if validate_transaction(transaction_data):
                    contracts = []
                    if contract_script:
                        contracts.append(LeaseContract(contract_script))
                    blockchain.add_block(transaction_data, contracts=contracts)
                    blockchain.sync_nodes()

            if message['type'] == 'sync':
                remote_chain = message['chain']
                if len(remote_chain) > len(blockchain.chain) and blockchain.validate_chain(remote_chain):
                    og_bc = len(blockchain.chain)
                    rc_bc = len(remote_chain)
                    excess_blks = remote_chain[og_bc:]
                    for blks in excess_blks:
                        ine = blks['index']
                        data = blks['data']
                        pre_hash =blks['previous_hash']
                        ts = blks['timestamp']
                        new_block = append_new_block(inde=ine,previous_hash=pre_hash,data=data,timesta=ts)
                        blockchain.chain.append(new_block)
                        blockchain.sync_nodes()
                print(f"Synchronized with {addr[0]}:{addr[1]}")
            elif message['type']=='syn':
                conn.sendall(json.dumps({'type': 'ack'}).encode('utf-8'))

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(('', 12346))
        server.listen(5)
        print("[*] Server listening on port 5001")
        while True:
            conn, addr = server.accept()
            print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")
            client_handler = threading.Thread(target=handle_client, args=(conn, addr))
            client_handler.start()

def start_miner():
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    age = int(input("Enter your age: "))
    income = float(input("Enter your income: "))
    credit_score = int(input("Enter your credit score: "))
    num_open_credit_accounts = int(input("Enter number of open credit accounts: "))

    # Create user
    blockchain.create_user(username, password, age, income, credit_score, num_open_credit_accounts)



def start_node():
    address = input("Enter node address to connect (e.g., localhost:5001): ")
    address = str(address)
    blockchain.connect_to_node(address)

def display_blocks():
    for block in blockchain.chain:
        print("Index:", block.index)
        print("Data:", block.data)
        print("Timestamp:", block.timestamp)
        print("Hash:", block.hash)
        print("Previous Hash:", block.previous_hash)
        for contract in block.contracts:
            if isinstance(contract, LeaseContract):
                print("Lease Contract Status:", contract.get_lease_status())
        print("----------------------------------------------")

if __name__ == '__main__':
    server_thread = threading.Thread(target=start_server)
    server_thread.start()
    while True:
        print("--------------------------------")
        print("1. Transaction")
        print("2. Display blocks")
        option = int(input("Enter your choice:"))
        if option == 1:
            start_miner()
        elif option == 2:
            display_blocks()
        else:
            print("Wrong Option Selected, retry!!")
