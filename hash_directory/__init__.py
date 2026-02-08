import argparse
import logging
from logging import Logger, StreamHandler
from pathlib import Path
from typing import TextIO

import colorama
from colorama import Fore

from hash_directory.algorithm import hash_directory, compare_directories
from hash_directory.hash_context import _DirectoryContext, _parse_context
from hash_directory.version import program_version

colorama.init(autoreset=True)

log: Logger = logging.getLogger("hash-directory")
console: StreamHandler[TextIO] = logging.StreamHandler()
log.addHandler(console)
log.setLevel(logging.DEBUG)
console.setFormatter(
    logging.Formatter(
        f"{{asctime}} [{Fore.YELLOW}{{levelname:>5}}{Fore.RESET}] {Fore.BLUE}{{name}}{Fore.RESET}: {{message}}",
        style="{", datefmt="W%W %a %I:%M"))

PROGRAM_NAME: str = "hash-directory"


def command_entry_point() -> None:
    try:
        main()
    except KeyboardInterrupt:
        log.warning("Program was interrupted by user")


def main() -> None:
    parser = argparse.ArgumentParser(prog=PROGRAM_NAME,
                                     description="A command line program (and python library) for hashing directories. Can also do hash-based comparisons between directories (like diff -qr).",
                                     allow_abbrev=True, add_help=True, exit_on_error=True)

    parser.add_argument('-v', '--verbose', action='store_true', help="Show more output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {program_version}")

    parser.add_argument("-o", "--overview", action="store_true", help="Show an overview of all hashes in directory")
    parser.add_argument("-c", "--compare", type=Path,
                        help="Compare the hashes of PATH and its subdirectories with COMPARE which is a directory "
                             f"or a path to a file containing output of {PROGRAM_NAME} -o")
    parser.add_argument("PATH", type=Path, help=f"The directory to hash "
                                                f"or path to a file containing output of {PROGRAM_NAME} -o")

    args = parser.parse_args()

    log.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    log.debug("Starting program...")

    if args.compare is not None:
        compare_directories(args.PATH, args.compare)
    elif args.overview:
        ctx = _parse_context(args.PATH)
        assert isinstance(ctx, _DirectoryContext)

        print(ctx.hash_overview())
    else:
        print(hash_directory(args.PATH))
