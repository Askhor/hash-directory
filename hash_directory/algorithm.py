import hashlib
import logging
import os
from logging import Logger
from pathlib import Path

from colorama import Fore

from .hash_context import _parse_context, _HashContext

log: Logger = logging.getLogger("hash-directory")


def hash_directory(path: Path, hash_function=hashlib.sha256) -> str:
    return _parse_context(path, hash_function).hash(Path(os.curdir))


def _compare_at(path: Path, ctx: tuple[_HashContext, _HashContext]) -> int:
    log.debug(f"Comparing at {path}")
    difference_count = 0

    if not all(c.exists(path) for c in ctx):
        missing = [str(c) for c in ctx if not c.exists(path)]
        print(f"File missing in {Fore.RED}{", ".join(missing)}{Fore.RESET}: {Fore.BLUE}{path}")
        difference_count += 1
    else:
        assert all(c.exists(path) for c in ctx)
        hash_a, hash_b = ctx[0].hash(path), ctx[1].hash(path)

        if hash_a != hash_b:
            print(f"Files differ at {path}:\n{hash_a}\n{hash_b}")
            difference_count += 1

        files = tuple(sorted(set(ctx[0].filenames(path)) | set(ctx[1].filenames(path))))

        for filename in files:
            difference_count += _compare_at(path / filename, ctx)

    return difference_count


def compare_directories(a: Path, b: Path, hash_function=hashlib.sha256):
    log.debug(f"Comparing {a} to {b}")

    ctx = _parse_context(a, hash_function), _parse_context(b, hash_function)

    difference_count = _compare_at(Path(os.curdir), ctx)

    log.info(f"Directories differ at {difference_count} file(s)")
