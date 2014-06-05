Notes on 2014-05-04 putty-ssh-keygen.patch that adds a windows command line
pkeygen.exe.

Overview
--------

The command line test harness cmdgen.c was modified to implement pkeygen.

File Changes
------------

Makefile.vc (a generated file, change should really be in the build system)

- Added pkeygen.exe rules. 
- Generate pkeygen.obj from cmdgen.c with the PKEYGEN macro defined;
    this allows both pkeygen.obj and cmdgen.obj to exist in the same dir.

cmdgen.c

- Implements pkeygen when PKEYGEN is defined.
- Error message command identifier changed to get_command_name(argv).
- PuTTYGen -o option changed to -f to match ssh-keygen.
- ``-f foo'' generates foo, foo.pub and foo.ppk.

import.c

- sshcom_write() modified to handle NULL Comment.

putty.h

- Added PRIVATE_KEY_SUFFIX="ppk" macro.
- Added noise_crypto() common API to unify unix /dev/urandom and windows
    CryptGenRandom().
- Added askoverwite() for pkeygen ``overwrite(y/n)? '' prompt.
- Added int filename_has_suffix(const Filename *f, const char *suffix);
    that returns TRUE if filename ends with .<suffix>.
- Added char* get_command_name(argv) to return the command base name
    (sans .exe on windows).

ssh.h

- Changed key_type() prototype to: int key_type(Filename *filename);
    If filename has no .ppk suffix and filename.ppk exists then the
    filename is changed in-place to filename.ppk.  This allows the unix
    ``ssh -i foo'' to work the same on windows by picking up the .ppk
    file if it exists, which it will if pkeygen was the generator.

ssh.c

- Moved ``Reading private key file'' logevent after key_type().
- Added command_name = get_command_name(argv) and use command_name
    in diagnostics.

sshpubk.c

- Changed key_type() per ssh.h above.

unix/gtkdlg.c

- Added askoverwrite().

unix/uxcons.c

- Added askoverwrite().

unix/uxmisc.c

- Added filename_has_suffix() per putty.h.

windows/plink.c

- Added command_name = get_command_name(argv) and use command_name
    in diagnostics.

windows/pscp.c

- Added command_name = get_command_name(argv) and use command_name
    in diagnostics.

windows/wincons.c

- Added askoverwrite().
- Added is_interactive() (called in cmdgen.c).

windows/windlg.c

- Added askoverwrite().

windows/winmisc.c

- Added filename_has_suffix() per putty.h.
- Added static void filename_create_private(const Filename *filename); to
    implement f_open(filename, mode, TRUE) on windows. Sets the windows security
    permissions to read/write by owner only.
- Added f_open(const Filename *filename, char const *mode, int is_private);
    filename_create_private() handles is_private.

windows/winnoise.c

- Added int noise_crypto(char* buf, int len) and
    static int noise_probe(char* buf, int len) fallback - see putty.h.
- Refactored noise_get_heavy() to call noise_crypto().

windows/winpgen.c

- Changed to use PRIVATE_KEY_SUFFIX.

windows/winstuff.h

- Added some MSVC function macros, e.g., snprintf => sprintf_s.  These quashed
    a bunch of MSVC compiler complaints.  Not all sprintf() usage was converted;
    that would be a good OpenSource project.
- Changed f_open() from a macro to a function prototype - see windows/winmisc.c.
- Changed to use PRIVATE_KEY_SUFFIX.

*.[ch]

- Changed to silence *most* /D_CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES and
    /D_CRT_SECURE_NO_WARNINGS diagnostics.  ~100 strcpy() warnings remain - they
    require a bit of study.
- Changed to silence MSVC 64 bit diagnostics.  Most are from expressions with
    size_t sizeof() and size_t strlen() mixed with int variables.  It would be
    best to switch to size_t, but that requires more care than sprinkling (int)
    casts.
