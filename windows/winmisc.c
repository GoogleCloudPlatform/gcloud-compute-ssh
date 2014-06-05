/*
 * winmisc.c: miscellaneous Windows-specific things
 */

#include <stdio.h>
#include <stdlib.h>
#include "putty.h"
#include <security.h>

/*
 * runtime DLL API function state
 */
enum {
  MODULE_STATUS_required, /* API not checked yet */
  MODULE_STATUS_success,  /* API checked and present */
  MODULE_STATUS_error     /* API checked and not present */
};

OSVERSIONINFO osVersion;

char *platform_get_x_display(void) {
    /* We may as well check for DISPLAY in case it's useful. */
    return dupstr(getenv("DISPLAY"));
}

const char *platform_default_term(void) {
    const char* term = (const char*)dupstr(getenv("TERM"));
    if (term == NULL)
	term = "dumb";
    return term;
}

Filename *filename_from_str(const char *str)
{
    Filename *ret = snew(Filename);
    ret->path = dupstr(str);
    return ret;
}

Filename *filename_copy(const Filename *fn)
{
    return filename_from_str(fn->path);
}

const char *filename_to_str(const Filename *fn)
{
    return fn->path;
}

int filename_equal(const Filename *f1, const Filename *f2)
{
    return !strcmp(f1->path, f2->path);
}

int filename_is_null(const Filename *fn)
{
    return !*fn->path;
}

void filename_free(Filename *fn)
{
    sfree(fn->path);
    sfree(fn);
}

int filename_serialise(const Filename *f, void *vdata)
{
    char *data = (char *)vdata;
    int len = strlen(f->path) + 1;     /* include trailing NUL */
    if (data) {
        strcpy(data, f->path);
    }
    return len;
}

Filename *filename_deserialise(void *vdata, int maxsize, int *used)
{
    char *data = (char *)vdata;
    char *end;
    end = memchr(data, '\0', maxsize);
    if (!end)
        return NULL;
    end++;
    *used = (int)(end - data);
    return filename_from_str(data);
}

int filename_has_suffix(const Filename* filename, const char* suffix)
{
    char* s;
    s = strrchr(filename->path, '.');
    if (!s)
	return 0;
    return stricmp(s + 1, suffix) == 0;
}

#define NOTIFY_WIDTH    79	/* subtract 1 for nervous terminals */
#define NOTIFY_BORDER   '@'

/*
 * ssh-ish painfully obvious notification box, line by line
 * fmt==NULL prints head/tail border
 */
void notifyf(const char* fmt, ...)
{
    if (fmt) {
        char* txt;
	int len;
        va_list ap;
        va_start(ap, fmt);
        txt = dupvprintf(fmt, ap);
        va_end(ap);
	len = (int)strlen(txt);
	if (len > (NOTIFY_WIDTH - 2))
	    len = NOTIFY_WIDTH - 2;
	fprintf(stderr, "%c%*s%-.*s%*s%c\n", 
		NOTIFY_BORDER,
		(NOTIFY_WIDTH - len - 2) / 2, " ",
		len, txt,
		(NOTIFY_WIDTH - len - 1) / 2, " ",
		NOTIFY_BORDER);
	sfree(txt);
    } else {
	char buf[NOTIFY_WIDTH];
        memset(buf, NOTIFY_BORDER, sizeof(buf));
	fprintf(stderr, "%-.*s\n", sizeof(buf), buf);
    }
}

char* get_command_name(char** argv)
{
    char* b = argv[0];
    char* s = b;
    char* x = 0;
    int i;

    for (;;) {
        switch (*s++) {
          case '\0':
    	    break;
          case '/':
          case '\\':
    	    b = *s ? s : argv[0];
	    x = 0;
    	    continue;
          case '.':
    	    x = s;
    	    continue;
	  default:
	    continue;
        }
        break;
    }
    i = (x && stricmp(x, "exe") == 0) ? (int)(x - b - 1) : 0;
    x = dupstr(b);
    if (i)
	x[i] = 0;
#if defined PUTTY_INSTALLDIR_ONLY
    {
	/*
	 * PUTTY_INSTALLDIR_ONLY is of the form \some\path\
	 * the executable path must match *\some\path\executable-base-name
	 * if not then an unsupported warning is printed
	 */
        HMODULE hp = GetModuleHandle(NULL);
	char* dir = STR(PUTTY_INSTALLDIR_ONLY);
	int len = (int)strlen(dir);
	char* base;
	char* s;
        char path[MAX_PATH];
        GetModuleFileName(hp, path, sizeof(path));
	base = strrchr(path, '\\') + 1;
	for (s = path; s = strchr(s, '\\'); ++s) {
	    if (!strnicmp(s, dir, len) && (s + len) == base) {
		break;
	    }
	}
	if (!s) {
	    if (dir[0] == '\\')
		++dir;
	    s = strchr(dir, '\\');
	    len = s ? (int)(s - dir) : (int)strlen(dir);
	    notifyf(NULL);
	    notifyf("This %s executable is a %-.*s implementation detail.", x, len, dir);
	    notifyf("It may change or disappear completely in the next Cloud SDK release.");
	    notifyf("http://www.putty.org provides a complete ssh client package.");
	    notifyf(NULL);
        }
    }
#endif
    return x;
}

#ifndef NO_SECUREZEROMEMORY
/*
 * Windows implementation of smemclr (see misc.c) using SecureZeroMemory.
 */
void smemclr(void *b, size_t n) {
    if (b && n > 0)
        SecureZeroMemory(b, n);
}
#endif

char *get_username(void)
{
    DWORD namelen;
    char *user;
    int got_username = FALSE;
    DECL_WINDOWS_FUNCTION(static, BOOLEAN, GetUserNameExA,
			  (EXTENDED_NAME_FORMAT, LPSTR, PULONG));

    {
	static int tried_usernameex = FALSE;
	if (!tried_usernameex) {
	    /* Not available on Win9x, so load dynamically */
	    HMODULE secur32 = load_system32_dll("secur32.dll");
	    GET_WINDOWS_FUNCTION(secur32, GetUserNameExA);
	    tried_usernameex = TRUE;
	}
    }

    if (p_GetUserNameExA) {
	/*
	 * If available, use the principal -- this avoids the problem
	 * that the local username is case-insensitive but Kerberos
	 * usernames are case-sensitive.
	 */

	/* Get the length */
	namelen = 0;
	(void) p_GetUserNameExA(NameUserPrincipal, NULL, &namelen);

	user = snewn(namelen, char);
	got_username = p_GetUserNameExA(NameUserPrincipal, user, &namelen);
	if (got_username) {
	    char *p = strchr(user, '@');
	    if (p) *p = 0;
	} else {
	    sfree(user);
	}
    }

    if (!got_username) {
	/* Fall back to local user name */
	namelen = 0;
	if (GetUserName(NULL, &namelen) == FALSE) {
	    /*
	     * Apparently this doesn't work at least on Windows XP SP2.
	     * Thus assume a maximum of 256. It will fail again if it
	     * doesn't fit.
	     */
	    namelen = 256;
	}

	user = snewn(namelen, char);
	got_username = GetUserName(user, &namelen);
	if (!got_username) {
	    sfree(user);
	}
    }

    return got_username ? user : NULL;
}

#include <lm.h>

static int newver_module_status = MODULE_STATUS_required;

DECL_WINDOWS_FUNCTION(static, NET_API_STATUS, NetWkstaGetInfo,
                      (LPWSTR, DWORD, LPBYTE*));

static int oldver_module_status = MODULE_STATUS_required;

DECL_WINDOWS_FUNCTION(static, BOOL, GetVersionExA,
                      (LPOSVERSIONINFO));

BOOL init_winver(void)
{
    ZeroMemory(&osVersion, sizeof(osVersion));
    osVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    if (newver_module_status == MODULE_STATUS_required) {
	HMODULE newver_module;
        newver_module = load_system32_dll("netapi32.dll");
        GET_WINDOWS_FUNCTION(newver_module, NetWkstaGetInfo);
	newver_module_status = p_NetWkstaGetInfo ?
	        MODULE_STATUS_success : MODULE_STATUS_error;
    }
    if (newver_module_status == MODULE_STATUS_success) {
        LPWKSTA_INFO_102 pInfo = NULL;
        if (p_NetWkstaGetInfo(NULL, 102, (LPBYTE*)&pInfo) == NERR_Success) {
            osVersion.dwMajorVersion = pInfo->wki102_ver_major;
            osVersion.dwMinorVersion = pInfo->wki102_ver_minor;
	    return TRUE;
        }
        newver_module_status = MODULE_STATUS_error;
    }
    if (oldver_module_status == MODULE_STATUS_required) {
	HMODULE oldver_module;
        oldver_module = load_system32_dll("kernel32.dll");
        GET_WINDOWS_FUNCTION(oldver_module, GetVersionExA);
	oldver_module_status = p_GetVersionExA ?
	        MODULE_STATUS_success : MODULE_STATUS_error;
    }
    if (oldver_module_status == MODULE_STATUS_success)
	return p_GetVersionExA(&osVersion);
    return FALSE;
}

HMODULE load_system32_dll(const char *libname)
{
    /*
     * Wrapper function to load a DLL out of c:\windows\system32
     * without going through the full DLL search path. (Hence no
     * attack is possible by placing a substitute DLL earlier on that
     * path.)
     */
    static char *sysdir = NULL;
    char *fullpath;
    HMODULE ret;

    if (!sysdir) {
	int size = 0, len;
	do {
	    size = 3*size/2 + 512;
	    sysdir = sresize(sysdir, size, char);
	    len = GetSystemDirectory(sysdir, size);
	} while (len >= size);
    }

    fullpath = dupcat(sysdir, "\\", libname, NULL);
    ret = LoadLibrary(fullpath);
    sfree(fullpath);
    return ret;
}

/*
 * A tree234 containing mappings from system error codes to strings.
 */

struct errstring {
    int error;
    char *text;
};

static int errstring_find(void *av, void *bv)
{
    int *a = (int *)av;
    struct errstring *b = (struct errstring *)bv;
    if (*a < b->error)
        return -1;
    if (*a > b->error)
        return +1;
    return 0;
}
static int errstring_compare(void *av, void *bv)
{
    struct errstring *a = (struct errstring *)av;
    return errstring_find(&a->error, bv);
}

static tree234 *errstrings = NULL;

const char *win_strerror(int error)
{
    struct errstring *es;

    if (!errstrings)
        errstrings = newtree234(errstring_compare);

    es = find234(errstrings, &error, errstring_find);

    if (!es) {
        char msgtext[65536]; /* maximum size for FormatMessage is 64K */

        es = snew(struct errstring);
        es->error = error;
        if (!FormatMessage((FORMAT_MESSAGE_FROM_SYSTEM |
                            FORMAT_MESSAGE_IGNORE_INSERTS), NULL, error,
                           MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                           msgtext, lenof(msgtext)-1, NULL)) {
            szprintf(msgtext, sizeof(msgtext),
                    "(unable to format: FormatMessage returned %d)", 
                    error, GetLastError());
        } else {
            int len = strlen(msgtext);
            if (len > 0 && msgtext[len-1] == '\n')
                msgtext[len-1] = '\0';
        }
        es->text = dupprintf("Error %d: %s", error, msgtext);
        add234(errstrings, es);
    }

    return es->text;
}

#ifdef DEBUG
static FILE *debug_fp = NULL;
static HANDLE debug_hdl = INVALID_HANDLE_VALUE;
static int debug_got_console = 0;

void dputs(char *buf)
{
    DWORD dw;

    if (!debug_got_console) {
	if (AllocConsole()) {
	    debug_got_console = 1;
	    debug_hdl = GetStdHandle(STD_OUTPUT_HANDLE);
	}
    }
    if (!debug_fp) {
	debug_fp = fopen("debug.log", "w");
    }

    if (debug_hdl != INVALID_HANDLE_VALUE) {
	WriteFile(debug_hdl, buf, strlen(buf), &dw, NULL);
    }
    fputs(buf, debug_fp);
    fflush(debug_fp);
}
#endif

#ifdef MINEFIELD
/*
 * Minefield - a Windows equivalent for Electric Fence
 */

#define PAGESIZE 4096

/*
 * Design:
 * 
 * We start by reserving as much virtual address space as Windows
 * will sensibly (or not sensibly) let us have. We flag it all as
 * invalid memory.
 * 
 * Any allocation attempt is satisfied by committing one or more
 * pages, with an uncommitted page on either side. The returned
 * memory region is jammed up against the _end_ of the pages.
 * 
 * Freeing anything causes instantaneous decommitment of the pages
 * involved, so stale pointers are caught as soon as possible.
 */

static int minefield_initialised = 0;
static void *minefield_region = NULL;
static long minefield_size = 0;
static long minefield_npages = 0;
static long minefield_curpos = 0;
static unsigned short *minefield_admin = NULL;
static void *minefield_pages = NULL;

static void minefield_admin_hide(int hide)
{
    int access = hide ? PAGE_NOACCESS : PAGE_READWRITE;
    VirtualProtect(minefield_admin, minefield_npages * 2, access, NULL);
}

static void minefield_init(void)
{
    int size;
    int admin_size;
    int i;

    for (size = 0x40000000; size > 0; size = ((size >> 3) * 7) & ~0xFFF) {
	minefield_region = VirtualAlloc(NULL, size,
					MEM_RESERVE, PAGE_NOACCESS);
	if (minefield_region)
	    break;
    }
    minefield_size = size;

    /*
     * Firstly, allocate a section of that to be the admin block.
     * We'll need a two-byte field for each page.
     */
    minefield_admin = minefield_region;
    minefield_npages = minefield_size / PAGESIZE;
    admin_size = (minefield_npages * 2 + PAGESIZE - 1) & ~(PAGESIZE - 1);
    minefield_npages = (minefield_size - admin_size) / PAGESIZE;
    minefield_pages = (char *) minefield_region + admin_size;

    /*
     * Commit the admin region.
     */
    VirtualAlloc(minefield_admin, minefield_npages * 2,
		 MEM_COMMIT, PAGE_READWRITE);

    /*
     * Mark all pages as unused (0xFFFF).
     */
    for (i = 0; i < minefield_npages; i++)
	minefield_admin[i] = 0xFFFF;

    /*
     * Hide the admin region.
     */
    minefield_admin_hide(1);

    minefield_initialised = 1;
}

static void minefield_bomb(void)
{
    div(1, *(int *) minefield_pages);
}

static void *minefield_alloc(int size)
{
    int npages;
    int pos, lim, region_end, region_start;
    int start;
    int i;

    npages = (size + PAGESIZE - 1) / PAGESIZE;

    minefield_admin_hide(0);

    /*
     * Search from current position until we find a contiguous
     * bunch of npages+2 unused pages.
     */
    pos = minefield_curpos;
    lim = minefield_npages;
    while (1) {
	/* Skip over used pages. */
	while (pos < lim && minefield_admin[pos] != 0xFFFF)
	    pos++;
	/* Count unused pages. */
	start = pos;
	while (pos < lim && pos - start < npages + 2 &&
	       minefield_admin[pos] == 0xFFFF)
	    pos++;
	if (pos - start == npages + 2)
	    break;
	/* If we've reached the limit, reset the limit or stop. */
	if (pos >= lim) {
	    if (lim == minefield_npages) {
		/* go round and start again at zero */
		lim = minefield_curpos;
		pos = 0;
	    } else {
		minefield_admin_hide(1);
		return NULL;
	    }
	}
    }

    minefield_curpos = pos - 1;

    /*
     * We have npages+2 unused pages starting at start. We leave
     * the first and last of these alone and use the rest.
     */
    region_end = (start + npages + 1) * PAGESIZE;
    region_start = region_end - size;
    /* FIXME: could align here if we wanted */

    /*
     * Update the admin region.
     */
    for (i = start + 2; i < start + npages + 1; i++)
	minefield_admin[i] = 0xFFFE;   /* used but no region starts here */
    minefield_admin[start + 1] = region_start % PAGESIZE;

    minefield_admin_hide(1);

    VirtualAlloc((char *) minefield_pages + region_start, size,
		 MEM_COMMIT, PAGE_READWRITE);
    return (char *) minefield_pages + region_start;
}

static void minefield_free(void *ptr)
{
    int region_start, i, j;

    minefield_admin_hide(0);

    region_start = (char *) ptr - (char *) minefield_pages;
    i = region_start / PAGESIZE;
    if (i < 0 || i >= minefield_npages ||
	minefield_admin[i] != region_start % PAGESIZE)
	minefield_bomb();
    for (j = i; j < minefield_npages && minefield_admin[j] != 0xFFFF; j++) {
	minefield_admin[j] = 0xFFFF;
    }

    VirtualFree(ptr, j * PAGESIZE - region_start, MEM_DECOMMIT);

    minefield_admin_hide(1);
}

static int minefield_get_size(void *ptr)
{
    int region_start, i, j;

    minefield_admin_hide(0);

    region_start = (char *) ptr - (char *) minefield_pages;
    i = region_start / PAGESIZE;
    if (i < 0 || i >= minefield_npages ||
	minefield_admin[i] != region_start % PAGESIZE)
	minefield_bomb();
    for (j = i; j < minefield_npages && minefield_admin[j] != 0xFFFF; j++);

    minefield_admin_hide(1);

    return j * PAGESIZE - region_start;
}

void *minefield_c_malloc(size_t size)
{
    if (!minefield_initialised)
	minefield_init();
    return minefield_alloc(size);
}

void minefield_c_free(void *p)
{
    if (!minefield_initialised)
	minefield_init();
    minefield_free(p);
}

/*
 * realloc _always_ moves the chunk, for rapid detection of code
 * that assumes it won't.
 */
void *minefield_c_realloc(void *p, size_t size)
{
    size_t oldsize;
    void *q;
    if (!minefield_initialised)
	minefield_init();
    q = minefield_alloc(size);
    oldsize = minefield_get_size(p);
    memcpy(q, p, (oldsize < size ? oldsize : size));
    minefield_free(p);
    return q;
}

#endif				/* MINEFIELD */

#include <aclapi.h>
#include <sddl.h>

static int winsec_module_status = MODULE_STATUS_required;

DECL_WINDOWS_FUNCTION(static, BOOL, ConvertStringSidToSidA,
                      (LPCTSTR, PSID*));
DECL_WINDOWS_FUNCTION(static, DWORD, SetEntriesInAclA,
                      (ULONG, PEXPLICIT_ACCESS, PACL, PACL*));
DECL_WINDOWS_FUNCTION(static, BOOL, InitializeSecurityDescriptor,
                      (PSECURITY_DESCRIPTOR, DWORD));
DECL_WINDOWS_FUNCTION(static, BOOL, SetSecurityDescriptorDacl,
                      (PSECURITY_DESCRIPTOR, BOOL, PACL, BOOL));
DECL_WINDOWS_FUNCTION(static, BOOL, SetNamedSecurityInfoA,
                      (LPTSTR, SE_OBJECT_TYPE, SECURITY_INFORMATION, PSID, PSID, PACL, PACL));

static void filename_create_private(const Filename *filename)
{
    char* username;

    if (winsec_module_status == MODULE_STATUS_required) {
	HMODULE winsec_module;
        winsec_module = load_system32_dll("advapi32.dll");
        GET_WINDOWS_FUNCTION(winsec_module, ConvertStringSidToSidA);
        GET_WINDOWS_FUNCTION(winsec_module, SetEntriesInAclA);
        GET_WINDOWS_FUNCTION(winsec_module, InitializeSecurityDescriptor);
        GET_WINDOWS_FUNCTION(winsec_module, SetSecurityDescriptorDacl);
        GET_WINDOWS_FUNCTION(winsec_module, SetNamedSecurityInfoA);
	winsec_module_status = p_ConvertStringSidToSidA &&
	    p_SetEntriesInAclA && p_InitializeSecurityDescriptor &&
	    p_SetSecurityDescriptorDacl && p_SetNamedSecurityInfoA ?
	        MODULE_STATUS_success : MODULE_STATUS_error;
    }
    if (winsec_module_status != MODULE_STATUS_success)
	return;
    username = get_username();
    if (username != NULL) {
	SECURITY_DESCRIPTOR sd;
        EXPLICIT_ACCESS ea;
        PSID sid = NULL;
        PACL acl = NULL;

        ea.grfAccessMode = GRANT_ACCESS;
        ea.grfAccessPermissions = GENERIC_READ|GENERIC_WRITE;
        ea.grfInheritance = OBJECT_INHERIT_ACE|CONTAINER_INHERIT_ACE;
        ea.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
        ea.Trustee.pMultipleTrustee = NULL;
        ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;

        if (p_ConvertStringSidToSidA(username, &sid)) {
            ea.Trustee.ptstrName = sid;
            ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        } else {
            ea.Trustee.ptstrName = username;
            ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
        }
        if (p_SetEntriesInAclA(1, &ea, NULL, &acl) == ERROR_SUCCESS &&
	    p_InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) &&
	    p_SetSecurityDescriptorDacl(&sd, TRUE, acl, FALSE)) {
	    SECURITY_ATTRIBUTES sa;
	    HANDLE fh;
	    sa.nLength = sizeof(sa);
	    sa.lpSecurityDescriptor = &sd;
	    sa.bInheritHandle = FALSE;
	    fh = CreateFile(filename->path, GENERIC_READ|GENERIC_WRITE, 0,
			    &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	    if (fh != INVALID_HANDLE_VALUE) {
		CloseHandle(fh);
                p_SetNamedSecurityInfoA(filename->path, SE_FILE_OBJECT,
			               DACL_SECURITY_INFORMATION,
			               NULL, NULL, acl, NULL);
	    }
	}
        sfree(username);
        if (sid != NULL)
	    LocalFree(sid);
        if (acl != NULL)
	    LocalFree(acl);
    }
}

FILE *f_open(const Filename *filename, char const *mode, int is_private)
{
    if (is_private)
	filename_create_private(filename);
    return fopen(filename->path, mode);
}

FontSpec *fontspec_new(const char *name,
                        int bold, int height, int charset)
{
    FontSpec *f = snew(FontSpec);
    f->name = dupstr(name);
    f->isbold = bold;
    f->height = height;
    f->charset = charset;
    return f;
}
FontSpec *fontspec_copy(const FontSpec *f)
{
    return fontspec_new(f->name, f->isbold, f->height, f->charset);
}
void fontspec_free(FontSpec *f)
{
    sfree(f->name);
    sfree(f);
}
int fontspec_serialise(FontSpec *f, void *vdata)
{
    char *data = (char *)vdata;
    int len = strlen(f->name) + 1;     /* include trailing NUL */
    if (data) {
        strcpy(data, f->name);
        PUT_32BIT_MSB_FIRST(data + len, f->isbold);
        PUT_32BIT_MSB_FIRST(data + len + 4, f->height);
        PUT_32BIT_MSB_FIRST(data + len + 8, f->charset);
    }
    return len + 12;                   /* also include three 4-byte ints */
}
FontSpec *fontspec_deserialise(void *vdata, int maxsize, int *used)
{
    char *data = (char *)vdata;
    char *end;
    if (maxsize < 13)
        return NULL;
    end = memchr(data, '\0', maxsize-12);
    if (!end)
        return NULL;
    end++;
    *used = (int)(end - data + 12);
    return fontspec_new(data,
                        GET_32BIT_MSB_FIRST(end),
                        GET_32BIT_MSB_FIRST(end + 4),
                        GET_32BIT_MSB_FIRST(end + 8));
}
