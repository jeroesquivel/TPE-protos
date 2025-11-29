import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(15)
s.connect(('localhost', 1080))

s.send(b'\x05\x01\x00')
resp = s.recv(2)
print(f"Handshake: {resp.hex()}")

# Request CONNECT a 93.184.216.34:80 (example.com)
s.send(b'\x05\x01\x00\x01\x5d\xb8\xd8\x22\x00\x50')
resp = s.recv(1024)
print(f"Request response: {resp.hex()}")

# Si la conexión fue exitosa, enviar GET HTTP
print("Sending HTTP GET...")
s.send(b'GET / HTTP/1.0\r\nHost: example.com\r\n\r\n')

print("Waiting for response...")
resp = s.recv(4096)
print(f"HTTP response ({len(resp)} bytes):")
print(resp.decode('utf-8', errors='ignore')[:500])

s.close()