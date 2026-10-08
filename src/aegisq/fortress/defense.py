"""Fortress Defense Module — Network defense and honeypot capabilities."""

import asyncio
import socket
import threading
from typing import Any


class TarpitServer:
    """Network tarpit — slows down attackers by accepting connections and responding extremely slowly."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8080, delay: float = 10.0):
        self.host = host
        self.port = port
        self.delay = delay
        self.running = False
        self.connections: list[socket.socket] = []

    async def start(self):
        """Start the tarpit server."""
        self.running = True
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(100)
        server.setblocking(False)

        print(f"[+] Tarpit server listening on {self.host}:{self.port}")

        while self.running:
            try:
                client, addr = await asyncio.get_event_loop().sock_accept(server)
                print(f"[*] Tarpit: Connection from {addr[0]}:{addr[1]}")
                self.connections.append(client)
                asyncio.create_task(self._slow_respond(client, addr))
            except Exception:
                await asyncio.sleep(0.1)

    async def _slow_respond(self, client: socket.socket, addr: tuple):
        """Respond extremely slowly to waste attacker time."""
        try:
            # Send HTTP-like response one byte at a time
            response = b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n" + b"A" * 1000000
            for byte in response:
                await asyncio.sleep(self.delay)
                try:
                    client.send(bytes([byte]))
                except Exception:
                    break
        finally:
            client.close()
            if client in self.connections:
                self.connections.remove(client)

    def stop(self):
        """Stop the tarpit server."""
        self.running = False
        for conn in self.connections:
            try:
                conn.close()
            except Exception:
                pass
        self.connections.clear()


class HoneypotServer:
    """Simple honeypot — logs attacker activity."""

    def __init__(self, host: str = "0.0.0.0", port: int = 2222, banner: str = "SSH-2.0-OpenSSH_7.4"):
        self.host = host
        self.port = port
        self.banner = banner
        self.running = False
        self.log: list[dict] = []

    async def start(self):
        """Start the honeypot server."""
        self.running = True
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(10)
        server.setblocking(False)

        print(f"[+] Honeypot listening on {self.host}:{self.port}")

        while self.running:
            try:
                client, addr = await asyncio.get_event_loop().sock_accept(server)
                print(f"[*] Honeypot: Connection from {addr[0]}:{addr[1]}")
                self.log.append({"ip": addr[0], "port": addr[1], "action": "connect"})
                asyncio.create_task(self._handle_client(client, addr))
            except Exception:
                await asyncio.sleep(0.1)

    async def _handle_client(self, client: socket.socket, addr: tuple):
        """Handle honeypot client interaction."""
        try:
            # Send banner
            client.send(f"{self.banner}\r\n".encode())
            await asyncio.sleep(0.5)

            # Wait for input
            data = client.recv(1024)
            if data:
                print(f"[*] Honeypot: Received from {addr[0]}: {data.decode(errors='ignore')}")
                self.log.append({"ip": addr[0], "data": data.decode(errors='ignore')})

            # Send fake response
            client.send(b"Permission denied\r\n")
            await asyncio.sleep(0.2)
        except Exception:
            pass
        finally:
            client.close()

    def stop(self):
        """Stop the honeypot server."""
        self.running = False

    def get_log(self) -> list[dict]:
        """Get the honeypot activity log."""
        return self.log


async def run_defense_suite():
    """Run the full defense suite (tarpit + honeypot)."""
    tarpit = TarpitServer(port=8080)
    honeypot = HoneypotServer(port=2222)

    print("[!] Starting Fortress Defense Suite...")
    await asyncio.gather(tarpit.start(), honeypot.start())


if __name__ == "__main__":
    asyncio.run(run_defense_suite())
