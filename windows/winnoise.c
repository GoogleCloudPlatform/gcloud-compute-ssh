/*
 * Noise generation for PuTTY's cryptographic random number
 * generator.
 */

#include <stdio.h>

#include "putty.h"
#include "ssh.h"
#include "storage.h"

#include <wincrypt.h>

enum { MODULE_STATUS_required, MODULE_STATUS_success, MODULE_STATUS_error };

static int wincrypt_module_status = MODULE_STATUS_required;

DECL_WINDOWS_FUNCTION(static, BOOL, CryptAcquireContextA,
                      (HCRYPTPROV *, LPCTSTR, LPCTSTR, DWORD, DWORD));
DECL_WINDOWS_FUNCTION(static, BOOL, CryptGenRandom,
                      (HCRYPTPROV, DWORD, BYTE *));
DECL_WINDOWS_FUNCTION(static, BOOL, CryptReleaseContext,
                      (HCRYPTPROV, DWORD));

static int kernel32_module_status = MODULE_STATUS_required;

DECL_WINDOWS_FUNCTION(static, BOOL, QueryPerformanceCounter,
                      (LARGE_INTEGER*));
DECL_WINDOWS_FUNCTION(static, DWORD, GetTickCount,
                      (void));
DECL_WINDOWS_FUNCTION(static, DWORD, GetCurrentThreadId,
                      (void));
DECL_WINDOWS_FUNCTION(static, BOOL, GlobalMemoryStatusEx,
                      (LPMEMORYSTATUSEX));
DECL_WINDOWS_FUNCTION(static, void, GetSystemInfo,
                      (LPSYSTEM_INFO));
DECL_WINDOWS_FUNCTION(static, BOOL, GetDiskFreeSpace,
                      (LPCTSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD));
DECL_WINDOWS_FUNCTION(static, BOOL, GetProcessHandleCount,
                      (HANDLE, PDWORD));

#define MIXA(f, d, b, z, i)    \
    if (f) f(&d); i = mix((unsigned char*)&d, sizeof(d), (unsigned char*)b, z, i)
#define MIXR(f, d, b, z, i)    \
    if (f) d = f(); i = mix((unsigned char*)&d, sizeof(d), (unsigned char*)b, z, i)
#define MIX(d, b, z, i)    \
    i = mix((unsigned char*)&d, sizeof(d), (unsigned char*)b, z, i)

/*
 * Mix <data,data_size> into <buf,buf_size> at buf index i.
 * Next buf index returned.
 */
static int mix(const unsigned char* data, int data_size, unsigned char* buf, int buf_size, int i)
{
    int j;
    for (j = 0; j < data_size; ++j) {
	if (!(j & 0x7))
	    ++i;
        if (i >= buf_size)
            i = 0;
        buf[i] ^= data[j];
    }
    return i;
}

/*
 * noise_crypto() fallback -- not expected to be called on windows >= XP.
 */
static int noise_probe(char* buf, int len)
{
    int i = len;
    LARGE_INTEGER dl;
    MEMORYSTATUSEX dm;
    SYSTEM_INFO ds;
    DWORD dw, dw2, dw3, dw4;
    struct MD5Context md5c;
    unsigned char tmp[16];

    if (kernel32_module_status == MODULE_STATUS_required) {
	HMODULE kernel32_module;
        kernel32_module = load_system32_dll("kernel32.dll");
        GET_WINDOWS_FUNCTION(kernel32_module, QueryPerformanceCounter);
        GET_WINDOWS_FUNCTION(kernel32_module, GetTickCount);
        GET_WINDOWS_FUNCTION(kernel32_module, GlobalMemoryStatusEx);
        GET_WINDOWS_FUNCTION(kernel32_module, GetSystemInfo);
	kernel32_module_status = MODULE_STATUS_success;
    }
    MIXA(p_QueryPerformanceCounter, dl, buf, len, i);
    MIXR(p_GetTickCount, dw, buf, len, i);
    MIXR(p_GetCurrentThreadId, dw, buf, len, i);
    MIXA(p_GlobalMemoryStatusEx, dm, buf, len, i);
    MIXA(p_GetSystemInfo, ds, buf, len, i);
    if (p_GetDiskFreeSpace) {
        GetDiskFreeSpace("C:\\", &dw, &dw2, &dw3, &dw4);
        MIX(dw, buf, len, i);
        MIX(dw2, buf, len, i);
        MIX(dw3, buf, len, i);
        MIX(dw4, buf, len, i);
    }
    if (p_GetProcessHandleCount) {
        p_GetProcessHandleCount(GetCurrentProcess(), &dw);
        MIX(dw, buf, len, i);
    }
    Sleep((buf[0] & 0x7f) + 10);
    MIXR(p_GetTickCount, dw, buf, len, i);
    MIXA(p_QueryPerformanceCounter, dl, buf, len, i);

    /*
     * MD5 compensates for dead bytes in the high order parts of probed counters
     */
    MD5Init(&md5c);
    i = 0;
    while (i < len) {
	int j;
	int n = i + sizeof(tmp);
	if (n > len)
	    n = len;
	MD5Update(&md5c, (unsigned char*)buf + i, n);
	MD5Final(tmp, &md5c);
	for (j = 0; i < n; ++i, ++j)
	    buf[i] ^= tmp[j];
    }
    return 2;
}

/*
 * Someday windows might have \\?\GLOBALROOT\Device\urandom.
 */
int noise_crypto(char* buf, int len)
{
    if (len < 0)
	return 0;
    if (wincrypt_module_status == MODULE_STATUS_required) {
	HMODULE wincrypt_module;
        wincrypt_module = load_system32_dll("advapi32.dll");
        GET_WINDOWS_FUNCTION(wincrypt_module, CryptAcquireContextA);
        GET_WINDOWS_FUNCTION(wincrypt_module, CryptGenRandom);
        GET_WINDOWS_FUNCTION(wincrypt_module, CryptReleaseContext);
        wincrypt_module_status =
	    wincrypt_module && p_CryptAcquireContextA &&
            p_CryptGenRandom && p_CryptReleaseContext ?
		MODULE_STATUS_success : MODULE_STATUS_error;
    }
    if (wincrypt_module_status == MODULE_STATUS_success) {
        HCRYPTPROV crypto = 0;
	if (len == 0)
	    return 1;
        if (CryptAcquireContext(&crypto, 0, 0, PROV_RSA_FULL,
			        CRYPT_VERIFYCONTEXT|CRYPT_SILENT)) {
	    int success = 1;
            if (!CryptGenRandom(crypto, len, buf))
		success = 0;
            if (!CryptReleaseContext(crypto, 0))
                success = 0;
	    if (success)
		return 1;
        }
    }
    else if (len == 0)
	return 0;
    return noise_probe(buf, len);
}

/*
 * This function is called once, at PuTTY startup.
 */

void noise_get_heavy(void (*func) (void *, int))
{
    HANDLE srch;
    WIN32_FIND_DATA finddata;
    DWORD pid;
    char winpath[MAX_PATH + 3];
    BYTE buf[32];
    int pos;

    pos = GetWindowsDirectory(winpath, sizeof(winpath));
    szprintf(winpath + pos, sizeof(winpath) - pos, "\\*");
    srch = FindFirstFile(winpath, &finddata);
    if (srch != INVALID_HANDLE_VALUE) {
	do {
	    func(&finddata, sizeof(finddata));
	} while (FindNextFile(srch, &finddata));
	FindClose(srch);
    }

    pid = GetCurrentProcessId();
    func(&pid, sizeof(pid));

    if (noise_crypto(buf, sizeof(buf)))
        func(buf, sizeof(buf));

    read_random_seed(func);
    /* Update the seed immediately, in case another instance uses it. */
    random_save_seed();
}

void random_save_seed(void)
{
    int len;
    void *data;

    if (random_active) {
	random_get_savedata(&data, &len);
	write_random_seed(data, len);
	sfree(data);
    }
}

/*
 * This function is called every time the random pool needs
 * stirring, and will acquire the system time in all available
 * forms.
 */
void noise_get_light(void (*func) (void *, int))
{
    SYSTEMTIME systime;
    DWORD adjust[2];
    BOOL rubbish;

    GetSystemTime(&systime);
    func(&systime, sizeof(systime));

    GetSystemTimeAdjustment(&adjust[0], &adjust[1], &rubbish);
    func(&adjust, sizeof(adjust));
}

/*
 * This function is called on a timer, and it will monitor
 * frequently changing quantities such as the state of physical and
 * virtual memory, the state of the process's message queue, which
 * window is in the foreground, which owns the clipboard, etc.
 */
void noise_regular(void)
{
    HWND w;
    DWORD z;
    POINT pt;
    MEMORYSTATUS memstat;
    FILETIME times[4];

    w = GetForegroundWindow();
    random_add_noise(&w, sizeof(w));
    w = GetCapture();
    random_add_noise(&w, sizeof(w));
    w = GetClipboardOwner();
    random_add_noise(&w, sizeof(w));
    z = GetQueueStatus(QS_ALLEVENTS);
    random_add_noise(&z, sizeof(z));

    GetCursorPos(&pt);
    random_add_noise(&pt, sizeof(pt));

    GlobalMemoryStatus(&memstat);
    random_add_noise(&memstat, sizeof(memstat));

    GetThreadTimes(GetCurrentThread(), times, times + 1, times + 2,
		   times + 3);
    random_add_noise(&times, sizeof(times));
    GetProcessTimes(GetCurrentProcess(), times, times + 1, times + 2,
		    times + 3);
    random_add_noise(&times, sizeof(times));
}

/*
 * This function is called on every keypress or mouse move, and
 * will add the current Windows time and performance monitor
 * counter to the noise pool. It gets the scan code or mouse
 * position passed in.
 */
void noise_ultralight(unsigned long data)
{
    DWORD wintime;
    LARGE_INTEGER perftime;

    random_add_noise(&data, sizeof(DWORD));

    wintime = GetTickCount();
    random_add_noise(&wintime, sizeof(DWORD));

    if (QueryPerformanceCounter(&perftime))
	random_add_noise(&perftime, sizeof(perftime));
}
