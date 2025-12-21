#!/usr/bin/env python3
"""Send inject.js to PS4 for execution"""
import asyncio
import pathlib
IP = "192.168.1.6"

import aioconsole
import websockets

PORT = "40404"
DELAY = 2

retry = True


async def send_file(ws: websockets.WebSocketClientProtocol, file_path: str):
    try:
        path = pathlib.Path(file_path)
        if not path.is_file():
            print(f"[!] File not found: {file_path}")
            return

        message = path.read_text("utf-8")
        await ws.send(message)

        print(f"[*] Sent {file_path} ({len(message)} bytes) to server")
    except Exception as e:
        print(f"[!] Failed to send file: {e}")


async def command(ws: websockets.WebSocketClientProtocol):
    while ws.open:
        cmd = await aioconsole.ainput()
        parts = cmd.split(maxsplit=1)

        if len(parts) == 2 and parts[0].lower() == "send":
            await send_file(ws, parts[1])        elif cmd.lower() in ("quit", "exit", "disconnect"):
            print("[*] Disconnecting...")
            await ws.close()
            global retry
            retry = False
            break
        else:
            print("[*] Unknown command. Use: send <path-to-file>")


async def receiver(ws: websockets.WebSocketClientProtocol):
    try:
        while ws.open:
            try:
                data = await asyncio.wait_for(ws.recv(), timeout=DELAY)
                if isinstance(data, str):
                    print(data)
            except asyncio.TimeoutError:
                pass
    except Exception as e:
        print(f"[!] {e}")


async def main():
    while retry:
        ws = None
        try:
            print(f"[*] Connecting to {IP}:{PORT}...")
            async with websockets.connect(f"ws://{IP}:{PORT}") as ws:
                print(f"[*] Connected to {IP}:{PORT} !!")
                receiver_task = asyncio.create_task(receiver(ws))
                command_task = asyncio.create_task(command(ws))

                await asyncio.wait(
                    [receiver_task, command_task],
                    return_when=asyncio.FIRST_COMPLETED,
                )
        except Exception as e:
            print("[!] Error:", e)
            print(f"[*] Retrying in {DELAY} seconds...")
            await asyncio.sleep(DELAY)
        finally:
            if hasattr(ws, "closed") and not ws.closed:
                await ws.close()


if __name__ == "__main__":
    asyncio.run(main())
