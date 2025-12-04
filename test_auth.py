import socket
import struct

s = socket.socket()
s.settimeout(2.0)
s.connect(('127.0.0.1', 8080))

username = b'admin'
password = b'1234'
auth_msg = struct.pack('BB', 0x01, len(username)) + username + struct.pack('B', len(password)) + password
s.send(auth_msg)

resp = s.recv(2)
version, status = struct.unpack('BB', resp)
print(f"Auth response: version={version}, status={status}")

if status == 0x00:
    print("Autenticacion exitosa\n")
    
    cmd = struct.pack('!BBH', 0x01, 0x01, 0)
    s.send(cmd)
    
    header = s.recv(4)
    version, status, length = struct.unpack('!BBH', header)
    print(f"Command response: version={version}, status={status}, length={length}")
    
    if length > 0:
        data = s.recv(length)
        total_conn, current_conn, bytes_trans, start_time = struct.unpack('!QQQQ', data)
        print(f"\n--- METRICS ---")
        print(f"Total connections: {total_conn}")
        print(f"Current connections: {current_conn}")
        print(f"Bytes transferred: {bytes_trans}")
        print(f"Server start time: {start_time}")
else:
    print("Autenticacion fallida")

s.close()
