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
            the_hash.update(file.name.encode("utf-8"))
            the_hash.update(self.hash(file).encode("utf-8"))

        return the_hash.hexdigest()

    def hash(self, path: Path):
        log.debug(f"Generating hash for {path}")
        path = Path(path)
        path = path.resolve(strict=True)

        if path.is_file():
            the_hash = self._hash_file(path)
        else:
            the_hash = self._hash_dir(path)

        self._hashes[str(path)] = the_hash
        return the_hash

    def hash_overview(self, path: Path, _relative_to=None, _recursion_depth=0):
        path = Path(path)

        if _relative_to is None:
            _relative_to = path

        if path.is_file():
            return f"{path.relative_to(_relative_to)} \t{self.hash(path)}\n"
        else:
            output = ""
            for file in sorted(path.iterdir(), key=lambda p: p.name):
                output += self.hash_overview(file, _relative_to=_relative_to,
                                             _recursion_depth=_recursion_depth + 1)
            return output


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

    parser.add_argument("-o", "--overview", action="store_true", help="Show an overview of all hashes in directory")
    parser.add_argument("PATH", help="The directory to hash")

    args = parser.parse_args()

    log.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    log.debug("Starting program...")

    if args.version:
        log.info(f"{PROGRAM_NAME} version {program_version}")
        return

    if args.overview:
        print(DirectoryHasher().hash_overview(args.PATH))
    else:
        print(hash_directory(args.PATH))
