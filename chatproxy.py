import socket
import select
import time
import threading
import struct
import random

class InstagramThrottlingProxy:
    def __init__(self, host='0.0.0.0', port=1080, username='admin', password='admin'):
        self.host = host
        self.port = port
        self.username = username
        self.password = password

    def handle_client(self, client_socket):
        try:
            # SOCKS5 greeting
            version, nmethods = struct.unpack("!BB", client_socket.recv(2))

            if version != 5:
                client_socket.close()
                return

            # Get available methods
            methods = []
            for _ in range(nmethods):
                methods.append(ord(client_socket.recv(1)))

            # Require username/password auth (method 2)
            if 2 not in methods:
                 client_socket.send(b'\x05\xff')  # No acceptable methods
                 client_socket.close()
                 return

            client_socket.send(b'\x05\x02')  # Choose username/password auth

            # Handle authentication
            if not self.authenticate(client_socket):
                 client_socket.close()
                 return

            # Get connection request
            version, cmd, _, addr_type = struct.unpack("!BBBB", client_socket.recv(4))

            if cmd != 1:  # Only CONNECT supported
                client_socket.send(b'\x05\x07\x00\x01' + b'\x00'*6)
                client_socket.close()
                return

            # Parse destination address
            if addr_type == 1:  # IPv4
                address = socket.inet_ntoa(client_socket.recv(4))
            elif addr_type == 3:  # Domain name
                domain_length = ord(client_socket.recv(1))
                address = client_socket.recv(domain_length).decode('utf-8')
            else:
                client_socket.send(b'\x05\x08\x00\x01' + b'\x00'*6)
                client_socket.close()
                return

            port = struct.unpack('!H', client_socket.recv(2))[0]

            # Check if this is Instagram traffic
            is_instagram = self.is_instagram_domain(address)

            if is_instagram:
                print(f"[THROTTLE] Instagram detected: {address}:{port}")
            else:
                print(f"[NORMAL] Connection to: {address}:{port}")

            # Connect to the target
            try:
                remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_socket.connect((address, port))

                # Send success response
                bind_address = remote_socket.getsockname()
                addr_bytes = socket.inet_aton(bind_address[0])
                port_bytes = struct.pack('!H', bind_address[1])

                client_socket.send(b'\x05\x00\x00\x01' + addr_bytes + port_bytes)

                # Start relaying with throttling if Instagram
                self.relay_traffic(client_socket, remote_socket, is_instagram)

            except Exception as e:
                print(f"[ERROR] Connection failed: {e}")
                client_socket.send(b'\x05\x05\x00\x01' + b'\x00'*6)
                client_socket.close()

        except Exception as e:
            print(f"[ERROR] Client handling error: {e}")
            try:
                client_socket.close()
            except:
                pass

    def authenticate(self, client_socket):
        """Handle username/password authentication"""
        try:
            version = ord(client_socket.recv(1))
            if version != 1:
                return False

            username_len = ord(client_socket.recv(1))
            username = client_socket.recv(username_len).decode('utf-8')

            password_len = ord(client_socket.recv(1))
            password = client_socket.recv(password_len).decode('utf-8')

            if username == self.username and password == self.password:
                client_socket.send(b'\x01\x00')  # Success
                print(f"[AUTH] Authentication successful for user: {username}")
                return True
            else:
                client_socket.send(b'\x01\x01')  # Failure
                print(f"[AUTH] Authentication failed for user: {username}")
                return False
        except:
            return False

    def is_instagram_domain(self, domain):
        """Check if domain is Instagram-related"""
        instagram_keywords = [
            'instagram.com',
            'cdninstagram.com',
            'fbcdn.net',  # Facebook CDN used by Instagram
            'ig.me',
            'instgrm.com'
        ]

        domain_lower = domain.lower()
        return any(keyword in domain_lower for keyword in instagram_keywords)

    def relay_traffic(self, client_socket, remote_socket, throttle):
        """Relay traffic between client and remote, with optional throttling"""

        if throttle:
            # Frustrating delays for Instagram
            self.throttled_relay(client_socket, remote_socket)
        else:
            # Normal speed for other traffic
            self.normal_relay(client_socket, remote_socket)

    def throttled_relay(self, client_socket, remote_socket):
        """Relay with aggressive throttling to make Instagram frustrating"""

        chunk_size = 512  # Very small chunks
        base_delay = 0.8  # Base delay between chunks (800ms)

        while True:
            try:
                readable, _, exceptional = select.select(
                    [client_socket, remote_socket], [],
                    [client_socket, remote_socket], 1
                )

                if exceptional:
                    break

                if client_socket in readable:
                    data = client_socket.recv(chunk_size)
                    if not data:
                        break

                    # Add random delay before sending to server
                    time.sleep(random.uniform(0.2, 0.5))
                    remote_socket.send(data)

                if remote_socket in readable:
                    data = remote_socket.recv(chunk_size)
                    if not data:
                        break

                    # Aggressive delay before sending to client
                    # This makes images/videos load painfully slow
                    delay = base_delay + random.uniform(0, 0.4)
                    time.sleep(delay)

                    client_socket.send(data)

            except Exception as e:
                print(f"[ERROR] Relay error: {e}")
                break

        try:
            client_socket.close()
            remote_socket.close()
        except:
            pass

    def normal_relay(self, client_socket, remote_socket):
        """Normal relay without throttling"""

        while True:
            try:
                readable, _, exceptional = select.select(
                    [client_socket, remote_socket], [],
                    [client_socket, remote_socket], 30
                )

                if exceptional:
                    break

                if client_socket in readable:
                    data = client_socket.recv(8192)
                    if not data:
                        break
                    remote_socket.send(data)

                if remote_socket in readable:
                    data = remote_socket.recv(8192)
                    if not data:
                        break
                    client_socket.send(data)

            except Exception as e:
                print(f"[ERROR] Relay error: {e}")
                break

        try:
            client_socket.close()
            remote_socket.close()
        except:
            pass

    def start(self):
        """Start the SOCKS5 proxy server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(200)

        print(f"[STARTED] Instagram Throttling SOCKS5 Proxy")
        print(f"[LISTENING] {self.host}:{self.port}")
        print(f"[AUTH] Username: {self.username}, Password: {self.password}")
        print(f"[INFO] Instagram traffic will be throttled")
        print(f"[INFO] All other traffic will pass normally")
        print("-" * 60)

        while True:
            try:
                client_socket, address = server_socket.accept()
                print(f"[CONNECTION] New connection from {address[0]}:{address[1]}")

                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket,)
                )
                client_thread.daemon = True
                client_thread.start()

            except KeyboardInterrupt:
                print("\n[SHUTDOWN] Server shutting down...")
                break
            except Exception as e:
                print(f"[ERROR] Accept error: {e}")

        server_socket.close()

if __name__ == '__main__':
    # Configuration
    PROXY_HOST = '0.0.0.0'  # Listen on all interfaces
    PROXY_PORT = 80       # SOCKS5 default port
    USERNAME = 'myuser'     # Change this!
    PASSWORD = 'mypass123'  # Change this!

    print("=" * 60)
    print("Instagram Throttling SOCKS5 Proxy")
    print("=" * 60)

    proxy = InstagramThrottlingProxy(
        host=PROXY_HOST,
        port=PROXY_PORT,
        username=USERNAME,
        password=PASSWORD
    )

    proxy.start()
