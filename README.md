gcloud-compute-ssh
==================

Patches to PuTTY for 'gcloud compute ssh' on Windows.

overview
========

Patch Windows PuTTY so that after
  copy pscp.exe scp.exe
  copy plink.exe ssh.exe
  copy pkeygen.exe ssh-keygen.exe
scp, ssh and ssh-keygen, from the command line, behave more like the OpenSsh
counterparts. Some behaviors are not covered -- mainly just enough to support
internal gcloud usage patterns.

details
=======

Changes fall into a few categories:
* Eliminate the low hanging fruit of the MSVC 32 and 64 bit warnings. Most of
  these involve mixed combinations of [unsigned] int, [unsigned] long, size_t,
  and ssize_t. Some only show up in 64 bit compiles. Other culprits are
  strcpy(), strcat(), and sprintf() into fixed size buffers - they are handled
  by a homebrew szprintf() that supports a clean sized buffer paradigm. *Much
  more work* is needed in this area. A lot of the (int) and (size_t) casts
  should be replaced by proper variable and function typing, but that would
  require a meticulous code walkthrough.
* Change cmdgen.c to generate pkeygen.exe which acts like ssh-keygen from the
  command line. Most of the changes are in this file. Major changes:
    - use windows libraries to generate cryptographic random data
    - output refactored to a loop that can generate more than one file
* Change the default TERM environment variable value passed to the server by
  plink to check the local TERM setting (instead of "xterm"). If TERM is not set
  then "dumb" is used. This gives the proper hint to remote .profiles to
  refrain from colorizing prompts and ls(1) output.
