import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(15)
s.connect(("127.0.0.1", 1080))

# Handshake - pedir método 0x02 (auth)
s.sendall(b'\x05\x01\x02')
resp = s.recv(1024)
print(f"Handshake: {resp.hex()}")

# Auth - user:pass
username = b'user'
password = b'pass'
auth_msg = b'\x01' + bytes([len(username)]) + username + bytes([len(password)]) + password
s.sendall(auth_msg)
resp = s.recv(1024)
print(f"Auth response: {resp.hex()}")

# Request
s.sendall(b'\x05\x01\x00\x01' + bytes([142, 250, 185, 46]) + b'\x00\x50')
resp = s.recv(1024)
print(f"Request response: {resp.hex()}")

# HTTP GET
print("Sending HTTP GET...")
s.sendall(b'GET / HTTP/1.0\r\nHost: google.com\r\n\r\n')
print("Waiting for response...")
resp = s.recv(4096)
print(f"HTTP response ({len(resp)} bytes):")
print(resp[:200])
s.close()