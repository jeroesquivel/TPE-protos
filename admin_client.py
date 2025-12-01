#!/usr/bin/env python3
import socket
import struct
import sys

ADMIN_VERSION = 0x01

CMD_GET_METRICS = 0x01
CMD_LIST_USERS = 0x02
CMD_ADD_USER = 0x03
CMD_DEL_USER = 0x04

STATUS_OK = 0x00
STATUS_ERROR = 0x01
STATUS_INVALID_CMD = 0x02
STATUS_USER_EXISTS = 0x03
STATUS_USER_NOT_FOUND = 0x04

def send_request(host, port, command, data=b''):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    
    request = struct.pack('!BBH', ADMIN_VERSION, command, len(data)) + data
    sock.sendall(request)
    
    header = sock.recv(4)
    if len(header) < 4:
        sock.close()
        return None
    
    version, status, length = struct.unpack('!BBH', header)
    
    response_data = b''
    while len(response_data) < length:
        chunk = sock.recv(length - len(response_data))
        if not chunk:
            break
        response_data += chunk
    
    sock.close()
    return status, response_data

def get_metrics(host='127.0.0.1', port=8080):
    print("=== GET METRICS ===")
    status, data = send_request(host, port, CMD_GET_METRICS)
    
    if status == STATUS_OK:
        total_conn = struct.unpack('!Q', data[0:8])[0]
        current_conn = struct.unpack('!Q', data[8:16])[0]
        bytes_trans = struct.unpack('!Q', data[16:24])[0]
        start_time = struct.unpack('!Q', data[24:32])[0]
        
        print(f"Total connections: {total_conn}")
        print(f"Current connections: {current_conn}")
        print(f"Bytes transferred: {bytes_trans}")
        print(f"Server start time: {start_time}")
    else:
        print(f"Error: status={status}")

def list_users(host='127.0.0.1', port=8080):
    print("\n=== LIST USERS ===")
    status, data = send_request(host, port, CMD_LIST_USERS)
    
    if status == STATUS_OK:
        count = data[0]
        print(f"Users: {count}")
        
        ptr = 1
        for i in range(count):
            username_len = data[ptr]
            ptr += 1
            username = data[ptr:ptr+username_len].decode('utf-8')
            ptr += username_len
            
            bytes_trans = struct.unpack('!Q', data[ptr:ptr+8])[0]
            ptr += 8
            total_conn = struct.unpack('!Q', data[ptr:ptr+8])[0]
            ptr += 8
            
            print(f"  - {username}: {total_conn} connections, {bytes_trans} bytes")
    else:
        print(f"Error: status={status}")

def add_user(username, password, host='127.0.0.1', port=8080):
    print(f"\n=== ADD USER: {username} ===")
    data = username.encode('utf-8') + b'\x00' + password.encode('utf-8') + b'\x00'
    status, _ = send_request(host, port, CMD_ADD_USER, data)
    
    if status == STATUS_OK:
        print("User added successfully")
    elif status == STATUS_USER_EXISTS:
        print("User already exists")
    else:
        print(f"Error: status={status}")

def del_user(username, host='127.0.0.1', port=8080):
    print(f"\n=== DELETE USER: {username} ===")
    data = username.encode('utf-8') + b'\x00'
    status, _ = send_request(host, port, CMD_DEL_USER, data)
    
    if status == STATUS_OK:
        print("User deleted successfully")
    elif status == STATUS_USER_NOT_FOUND:
        print("User not found")
    else:
        print(f"Error: status={status}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 admin_client.py metrics")
        print("  python3 admin_client.py users")
        print("  python3 admin_client.py add <username> <password>")
        print("  python3 admin_client.py del <username>")
        sys.exit(1)
    
    cmd = sys.argv[1]
    
    if cmd == 'metrics':
        get_metrics()
    elif cmd == 'users':
        list_users()
    elif cmd == 'add' and len(sys.argv) == 4:
        add_user(sys.argv[2], sys.argv[3])
    elif cmd == 'del' and len(sys.argv) == 3:
        del_user(sys.argv[2])
    else:
        print("Invalid command")
        sys.exit(1)