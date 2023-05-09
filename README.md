# BAZ - Basic Archiver with LZ file compression
                         
BAZ is a very basic archiver with TAR-like command line interface and Electron's ASAR-inspired header format.
It supports both ASAR format (directory is stored in ASCII JSON), and a related BSAR format (directory is 
stored in binary JSON). Both formats describe the same data, but BSON is a bit more compact and can be easily
traversed in memory, e.g. if just one file needs to be extracted.

BAZ is very easy to install; it only needs a C compiler and has no dependency on platform-specific building tools. 
There is no distributives or packages: just compile the source file with your favorite C compiler, link it with 
the standard C runtime libraries and be done with it. For some platforms, precompiled binaries are available 
(please see [releases](https://github.com/false-schemers/baz/releases)).

## Installation

Here's how you can compile BAZ on a unix box using GCC:

```
gcc -o baz [baz].c
```

Instructions for other compilers are similar (you may use Clang on Linux/Mac or CL on Windows). 
Please note that CL may issue warnings; we recommend to add `-D_CRT_SECURE_NO_WARNINGS` for Windows 
headers (unless you want to hear that `fopen` is no longer a reasonable way to open files).

The resulting executable has no dependencies (except C runtime) and can be run from any location.
If compiled statically, it can be easily moved between systems with the same ABI.

## Compression

Unlike its predecessor BAR, BAZ supports file-by-file compression. The supported compressed format is
raw DEFLATE stream. It has its own simple DEFLATE compressor; to use ZLib, one may compile it with
`-D USEZLIB` compile-time option. Zlib-based compression can produce smaller archives; to make them
even smaller, BAZ supports external compression with the help of Google Zopfli\*. If Zopfli is installed,
BAZ can be given `--zopfli=` run-time option with the number of Zofli iterations as argument. Please
note that bigger number means slower compression; Zopfli's default is 15.

\* [zopfli]: https://github.com/google/zopfli


## In-memory archives

In addition to ASAR/BSAR formats, BAZ supports creation of in-memory archives in a form of C code. These
archives can only be created by BAZ; in order to use them in an executable, an extractor needs to be written.
An example of such extractor can be seen in the WCPL's sources [l.c](https://raw.githubusercontent.com/false-schemers/wcpl/master/l.c);
the code in it supports both compressed and uncompressed files.

This form of archives can be created with the help of `-d` or `--format=cdump` options. In absence
of any format options, this form of an archive is used if the output file has `.c` or `.h` suffix.
Only creation mode is supported; when creating such an archive, a special care is taken if the output
file already exists: instead of overriding the entire file, BAZ just replaces the archive data
section of the code if it exiss, or adds such a section to the end of the file if it doesn't. 

## Commmand line interface

BAZ adheres to TAR's command line conventions:

```
baz: BAZ (Basic Archiver with Zlib-like compression) 1.00 built on May  9 2023
usage: baz [OPTION]... [FILE/DIR]...

Examples:
  baz -cf arch.bsar foo bar    # Create bsar archive from files foo and bar
  baz -cf arch.asar foo bar    # Create asar archive from files foo and bar
  baz -ocfz arch.baz dir       # Create bsar archive by compressing files in dir
  baz -dcfz arch.c dir         # Create C dump archive by compressing files in dir
  baz -tvf arch.bsar           # List all files in arch.bsar verbosely
  baz -xf arch.bsar foo bar    # Extract files foo and bar from arch.bsar
  baz -xf arch.bsar            # Extract all files from arch.bsar

Main operation mode:
  -c, --create                 Create a new archive
  -t, --list                   List the contents of an archive
  -x, --extract                Extract files from an archive

Operation modifiers:
  -f, --file=FILE              Use archive FILE (required in all modes)
  -k, --keep-old-files         Don't overwrite existing files when extracting
  -C, --directory=DIR          Use directory DIR for extracted files
  -O, --to-stdout              Extract files to standard output
  -X, --exclude-from=FILE      Exclude files via globbing patterns in FILE
  -z, --compress=DEFLATE       Compress files while creating the archive
  --exclude="PATTERN"          Exclude files, given as a globbing PATTERN
  --unpack="PATTERN"           Exclude files, but keep their info in archive
  --include-from=FILE          List/extract files via globbing patterns in FILE
  --include="PATTERN"          List/extract files, given as a globbing PATTERN
  --integrity=SHA256           Calculate or check file integrity info
  --zopfli=I                   Compress via external binary: zopfli --iI

Archive format selection:
  -b, --format=bsar            Create bsar archive independently of extension
  -o, --format=asar            Create asar archive even if extension is not .asar
  -d, --format=cdump           Create C dump even if extension is not .h or .c

File name matching options:
   --anchored                  Patterns match path
   --no-anchored               Patterns match file/directory name
   --wildcards                 Patterns are wildcards
   --no-wildcards              Patterns match verbatim

Informative output:
  -v, --verbose                Increase output verbosity
  -q, --quiet                  Suppress logging
  -h, --help                   Print this help, then exit

Note: when creating archives (-c), only the name of each argument file/dir
is stored in the archive, not a complete path to the argument file/dir.
Compressed .asar archives may be incompatible with other tools.
```

## Family

Please see [BAR](https://github.com/false-schemers/bar) repository for a smaller archiver with no support for compression.
