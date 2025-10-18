# Hash Directory

A command line program (and python library) for hashing directories. Can also do hash-based comparisons between
directories (like diff -qr).

## Command line usage

```bash
hash-directory some/path
```

This will return the `sha-256` hash of `some/path`. For an explanation of how this is calculated go
to [hash_directory](#hash_directory).

### Hash overviews

```bash
hash-directory some/path -o
```

This generates a hash overview of this directory (or file).
This is simply file path and hash, one per line, one line for each file within the directory tree.

This looks something like this:
```
. blablablathsiisahash
./foo blablablathsiisahash
./foo/bar.txt blablablathsiisahash
```

This can be used when comparing directories by storing the output to a file. Example code for Linux:

```bash
hash-directory some/path -o > some.hash
```

### Comparing directories

```bash
hash-directory some/path -c another/path
```

This will compare the directories by first computing the hashes and then iterating of the directories to show the differences.

Now if you don't want to recalculate the hashes whenever comparing, then you can pass the output of [overviews](#hash-overviews)
as a file, like this:
```bash
hash-directory some.hash -c another.hash
# or
hash-directory some.hash -c another/path
```

## As Python library

Install it using `pip install hash-directory`.

And then import using `import hash_directory`

### Basic usage

```python
import hash_directory

hash_directory.hash_directory("some/path")
```

This will return the `sha-256` hash of `some/path`. For an explanation of how this is calculated go
to [hash_directory](#hash_directory).

### hash_directory

Parameters:

- path: The path to calculate the hash of
- hash_function (default=hashlib.sha256): A hash function from hashlib

For files (yes, this program of course also works on files) this is equivalent to
`hashlib.file_digest("some/path", "sha256").hexdigest()`.

For directories on the other hand, we first take all files inside this directory and sort them by file name.
Then for each file we update our running hash with the file name (encoded in utf-8) and then the file hash.

### Other functions and classes

For now just a simple list:

- compare_directories (function)
- DirectoryHasher     (class)