import abc
import hashlib
import logging
import os
import re
import sys
from abc import abstractmethod
from collections import defaultdict
from logging import Logger
from pathlib import Path
from typing import Iterable, Callable

import temp_text

log: Logger = logging.getLogger("hash-directory")

overview_line_re = re.compile(r"^((?:[^\\ ]|\\\\|\\ )+) \s*([a-zA-Z0-9]*)$", flags=re.MULTILINE)


class _HashContext(abc.ABC):
    @abstractmethod
    def exists(self, path: Path) -> bool:
        pass

    @abstractmethod
    def is_dir(self, path: Path) -> bool:
        pass

    @abstractmethod
    def hash(self, path: Path) -> str:
        pass

    def filenames(self, path: Path) -> list[str]:
        if not self.exists(path) or not self.is_dir(path):
            return []

        return list(sorted(self._filenames(path)))

    @abstractmethod
    def _filenames(self, path: Path) -> Iterable[str]:
        pass

    @abstractmethod
    def __str__(self) -> str:
        pass


class _DirectoryContext(_HashContext):
    def __init__(self, path: Path, hash_function: Callable = hashlib.sha256):
        self._path: Path = path
        self._hash_function: Callable = hash_function
        self._hashes: dict[str, str] = {}

    def exists(self, path: Path) -> bool:
        return (self._path / path).exists()

    def is_dir(self, path: Path) -> bool:
        return (self._path / path).is_dir()

    def hash(self, path: Path) -> str:
        temp_text.prnt(f"Hashing {path}")

        if self.is_dir(path):
            the_hash = self._hash_dir(path)
        else:
            the_hash = self._hash_file(path)

        self._hashes[str(path)] = the_hash
        return the_hash

    def _filenames(self, path: Path) -> Iterable[str]:
        for file in (self._path / path).iterdir():
            yield file.name

    def _hash_file(self, path: Path) -> str:
        with open(self._path / path, "rb") as fp:
            return hashlib.file_digest(fp, self._hash_function).hexdigest()

    def _hash_dir(self, path: Path) -> str:
        the_hash = self._hash_function()

        for filename in self.filenames(path):
            the_hash.update(filename.encode("utf-8"))
            the_hash.update(self.hash(path / filename).encode("utf-8"))

        return the_hash.hexdigest()

    def hash_overview(self, path: Path=Path(os.curdir), _recursion_depth=0) -> str:
        assert not path.is_absolute()
        assert self.exists(path)

        encoded_path = str(path).replace("\\", "\\\\").replace(" ", "\\ ")
        output = f"{encoded_path} \t{self.hash(path)}\n"

        for filename in self.filenames(path):
            output += self.hash_overview(path / filename, _recursion_depth + 1)

        return output

    def __str__(self):
        return str(self._path)


class _HashfileContext(_HashContext):
    def __init__(self, hashfile: Path, hashes: dict[str, str], children_map: defaultdict[str, list[str]]):
        self.hashfile: Path = hashfile
        self.hashes: dict[str, str] = hashes
        self.children_map: dict[str, list[str]] = children_map

    def exists(self, path: Path) -> bool:
        return str(path) in self.hashes

    def is_dir(self, path: Path) -> bool:
        return True

    def hash(self, path: Path) -> str:
        return self.hashes[str(path)]

    def _filenames(self, path: Path) -> Iterable[str]:
        return self.children_map[str(path)]

    def __str__(self):
        return f"data from {self.hashfile.name}"

    @classmethod
    def parse(cls, file: Path) -> '_HashfileContext':
        string = file.read_text()

        hashes: dict[str, str] = {}

        children_map: defaultdict[str, list] = defaultdict(lambda: list())

        for raw_path, the_hash in overview_line_re.findall(string):
            path = raw_path.replace(r"\ ", " ").replace(r"\\", "\\")
            hashes[path] = the_hash

            path_obj = Path(path)

            if path_obj.parent != path_obj:
                children_map[str(path_obj.parent)].append(path_obj.name)

        return _HashfileContext(file, hashes, children_map)


def _parse_context(path: Path, hash_function=hashlib.sha256) -> _HashContext:
    if not path.exists():
        log.error(f"File {path} does not exist")
        sys.exit(1)

    if path.is_dir():
        return _DirectoryContext(path, hash_function)
    else:
        return _HashfileContext.parse(path)
