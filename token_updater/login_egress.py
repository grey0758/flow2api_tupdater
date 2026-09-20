"""Unix-socket to fixed TCP relay for a networkless login worker."""

import asyncio
import os
from pathlib import Path


SOCKET = Path(os.getenv("LOGIN_EGRESS_SOCKET", "/egress/proxy.sock"))
TARGET_HOST = os.getenv("LOGIN_EGRESS_HOST", "172.19.240.1")
TARGET_PORT = int(os.getenv("LOGIN_EGRESS_PORT", "18088"))


async def copy(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    finally:
        try:
            writer.write_eof()
        except (OSError, RuntimeError):
            pass


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection(TARGET_HOST, TARGET_PORT)
        tasks = [
            asyncio.create_task(copy(reader, upstream_writer)),
            asyncio.create_task(copy(upstream_reader, writer)),
        ]
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        upstream_writer.close()
        await upstream_writer.wait_closed()
    except Exception:
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def run() -> None:
    SOCKET.parent.mkdir(mode=0o770, parents=True, exist_ok=True)
    SOCKET.unlink(missing_ok=True)
    server = await asyncio.start_unix_server(handle, path=SOCKET)
    os.chmod(SOCKET, 0o660)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(run())
