#!/usr/bin/env python3
import asyncio
import websockets

SSH_HOST = "127.0.0.1"  # SSH server di localhost
SSH_PORT = 22           # Port SSH
LISTEN_HOST = "0.0.0.0" # Biar bisa diakses publik
LISTEN_PORT = 80        # Port WebSocket

async def handle_client(websocket, path):
    reader, writer = await asyncio.open_connection(SSH_HOST, SSH_PORT)
    async def ws_to_tcp():
        try:
            async for message in websocket:
                writer.write(message)
                await writer.drain()
        except:
            pass
        finally:
            writer.close()

    async def tcp_to_ws():
        try:
            while True:
                data = await reader.read(1024)
                if not data:
                    break
                await websocket.send(data)
        except:
            pass
        finally:
            await websocket.close()

    await asyncio.gather(ws_to_tcp(), tcp_to_ws())

start_server = websockets.serve(handle_client, LISTEN_HOST, LISTEN_PORT)

print(f"WS-SSH running on {LISTEN_HOST}:{LISTEN_PORT} -> {SSH_HOST}:{SSH_PORT}")
asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
