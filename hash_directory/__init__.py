import argparse
import hashlib
import logging
from pathlib import Path

from hash_directory.terminal_formatting import parse_color
from hash_directory.version import program_version

log = logging.getLogger("hash-directory")
console = logging.StreamHandler()
log.addHandler(console)
log.setLevel(logging.DEBUG)
console.setFormatter(
    logging.Formatter(parse_color("{asctime} [ℂ3.{levelname:>5}ℂ.] ℂ4.{name}ℂ.: {message}"),
                      style="{", datefmt="%W %a %I:%M"))

PROGRAM_NAME = "hash-directory"


def hash_directory(path: Path, hash_function=hashlib.sha256):
    hasher = DirectoryHasher(hash_function=hash_function)
    return hasher.hash(path)


class DirectoryHasher:
    def __init__(self, hash_function=hashlib.sha256):
        self._hash_function = hash_function
        self._hashes = {}

    def _hash_file(self, path: Path):
        with open(path, "rb") as fp:
            return hashlib.file_digest(fp, self._hash_function).hexdigest()

    def _hash_dir(self, path: Path):
        the_hash = self._hash_function()

        for file in sorted(path.iterdir(), key=lambda p: p.name):
            the_hash.update(file.name)
            the_hash.update(self.hash(file))

        return the_hash.hexdigest()

    def hash(self, path: Path):
        path = path.resolve(strict=True)
        the_hash = None

        if path.is_file():
            the_hash = self._hash_file(path)
        else:
            the_hash = self._hash_dir(path)

        hashes[str(path)] = the_hash
        return the_hash


def command_entry_point():
    try:
        main()
    except KeyboardInterrupt:
        log.warning("Program was interrupted by user")


def main():
    parser = argparse.ArgumentParser(prog=PROGRAM_NAME,
                                     description="",
                                     allow_abbrev=True, add_help=True, exit_on_error=True)

    parser.add_argument('-v', '--verbose', action='store_true', help="Show more output")
    parser.add_argument("--version", action="store_true", help="Show the current version of the program")

    args = parser.parse_args()

    log.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    log.debug("Starting program...")

    if args.version:
        log.info(f"{PROGRAM_NAME} version {program_version}")
        return
