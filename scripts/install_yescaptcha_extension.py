"""Install the pinned Chrome Web Store YesCaptcha CRX into VNC mount directories."""

import argparse
import base64
import hashlib
import io
import json
import os
import shutil
import struct
import tempfile
import zipfile
from pathlib import Path, PurePosixPath


EXTENSION_ID = "jiofmdifioeejeilfkpegipdjiopiekl"
VERSION = "1.4.7"
SHA256 = "be6034d83592293703861dec68ac26bd62cc0f5d435022152d4abc9e5242c6f3"


def _varint(data: bytes, offset: int) -> tuple[int, int]:
    value = shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7f) << shift
        if byte < 128:
            return value, offset
        shift += 7
        if shift > 63:
            break
    raise ValueError("invalid CRX header varint")


def _fields(data: bytes):
    offset = 0
    while offset < len(data):
        key, offset = _varint(data, offset)
        if key & 7 != 2:
            raise ValueError("unexpected CRX header field")
        length, offset = _varint(data, offset)
        field = data[offset:offset + length]
        if len(field) != length:
            raise ValueError("truncated CRX header")
        offset += length
        yield key >> 3, field


def _key_id(key: bytes) -> str:
    digest = hashlib.sha256(key).digest()[:16]
    return "".join(chr(97 + (byte >> 4)) + chr(97 + (byte & 15)) for byte in digest)


def read_verified_crx(path: Path) -> tuple[zipfile.ZipFile, bytes]:
    data = path.read_bytes()
    if len(data) > 10_000_000 or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError("YesCaptcha CRX does not match pinned SHA-256")
    if len(data) < 12 or data[:4] != b"Cr24" or struct.unpack_from("<I", data, 4)[0] != 3:
        raise ValueError("expected a CRX3 package")
    header_size = struct.unpack_from("<I", data, 8)[0]
    if header_size > 100_000 or 12 + header_size >= len(data):
        raise ValueError("invalid CRX3 header size")
    signing_keys = {}
    for field_number, proof in _fields(data[12:12 + header_size]):
        if field_number in {2, 3}:
            for nested_number, key in _fields(proof):
                if nested_number == 1:
                    signing_keys[_key_id(key)] = key
                    break
    if EXTENSION_ID not in signing_keys:
        raise ValueError("CRX signing identity differs from Chrome Web Store ID")
    archive = zipfile.ZipFile(io.BytesIO(data[12 + header_size:]))
    if archive.testzip() is not None:
        raise ValueError("CRX archive checksum failed")
    if sum(info.file_size for info in archive.infolist()) > 10_000_000:
        raise ValueError("CRX unpacked size exceeds limit")
    manifest = json.loads(archive.read("manifest.json"))
    if manifest.get("manifest_version") != 3 or manifest.get("version") != VERSION:
        raise ValueError("unexpected YesCaptcha manifest version")
    for info in archive.infolist():
        name = PurePosixPath(info.filename)
        if name.is_absolute() or ".." in name.parts or not name.parts:
            raise ValueError("unsafe CRX archive path")
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            raise ValueError("CRX archive contains a symlink")
    return archive, signing_keys[EXTENSION_ID]


def install(archive: zipfile.ZipFile, public_key: bytes, destination: Path) -> None:
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".yescaptcha-", dir=parent) as temp_name:
        stage = Path(temp_name) / "extension"
        stage.mkdir(mode=0o755)
        archive.extractall(stage)
        manifest = json.loads((stage / "manifest.json").read_text(encoding="utf-8"))
        manifest["key"] = base64.b64encode(public_key).decode("ascii")
        (stage / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False))
        for root, dirs, files in os.walk(stage):
            os.chmod(root, 0o755)
            for name in files:
                os.chmod(Path(root) / name, 0o644)
        if destination.exists():
            if destination.is_symlink() or not destination.is_dir():
                raise ValueError(f"destination is not a plain directory: {destination}")
            if any(item.name != ".gitkeep" for item in destination.iterdir()):
                old_manifest = destination / "manifest.json"
                if not old_manifest.is_file() or json.loads(old_manifest.read_text()).get("version") != VERSION:
                    raise ValueError(f"destination already contains a different extension: {destination}")
            shutil.rmtree(destination)
        stage.rename(destination)
    print(f"installed {EXTENSION_ID} {VERSION}: {destination}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("crx", type=Path)
    parser.add_argument("destinations", nargs="+", type=Path)
    args = parser.parse_args()
    archive, public_key = read_verified_crx(args.crx)
    for destination in args.destinations:
        install(archive, public_key, destination)


if __name__ == "__main__":
    main()
