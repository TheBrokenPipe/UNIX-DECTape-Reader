# UNIX DECTape Reader
My parser for old UNIX tap(1) and tp(1) tape archives, cobbled together to extract the early UNIX DECtapes from Dennis Ritchie shared by Warren Toomey. Code is not great nor well documented, but it works™ and provides proper access mode conversion for tap(1) archives.

# Usage
```
TapeReader [-l] [-c] [-f format] [-e epoch] [-s slack-file] <tape-file> [tar-file]
    -l  List all files in the tape archive.
    -c  Convert the tape archive to POSIX.1-1988 USTAR tar(1) format.
    -u  Print usage information and block map of the tape.
    -r  Attempt to recognize and repair access mode of files written by tap(1) under UNIX V4 or later.
    -a  Convert from absolute paths to relative path and strip ./ from all paths.
    -s  Dump all slack space data and unused blocks to a tar(1) archive.
    -f  Specify the format of the tape archive. Valid formats are:
          TAP - tap(1) format created by UNIX V1 - V3
          TP  - tp(1) format created by UNIX V4 - V6
    -e  Specify the epoch for tap(1) archives. Valid epoches are:
          1970, 1971, 1972, 1973
```
