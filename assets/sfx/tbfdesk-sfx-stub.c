/*
 * tbfdesk-sfx-stub.c -- the Windows half of the dashboard "one-file installer".
 *
 * The TBFDesk server staples this prebuilt stub in front of a real installer and a
 * per-device setup string, producing ONE double-clickable .exe:
 *
 *     [ this stub ][ installer.exe ][ setup bytes ][ setup name (utf8) ][ trailer ]
 *
 * Trailer, the last 28 bytes of the file, little-endian:
 *     char  magic[8]  = "TBFSFX01"
 *     u64   installer_len
 *     u64   setup_len
 *     u32   setup_name_len
 *
 * Trailing bytes after a PE image are an "overlay" the Windows loader ignores, so the
 * stub still runs normally; it then reads its own tail, carves the two blobs into a
 * fresh per-run temp dir, and runs
 *     installer.exe --silent-install --import-setup <setup>
 * passing the setup as a FILE (never on the command line -- a setup string carries the
 * device key, and every process can read another's argv). The embedded manifest asks for
 * requireAdministrator, so one UAC prompt at double-click elevates the whole chain and
 * --silent-install can create the service. The stub waits, cleans the temp dir up on
 * every exit path, and returns the installer's own exit code (0 ok, 1 install failed,
 * 2 a setup value was refused -- nothing installed).
 *
 * Build (reproducible, see build-stub.sh):
 *   x86_64-w64-mingw32-windres stub.rc stub_rc.o
 *   x86_64-w64-mingw32-gcc -municode -O2 -s tbfdesk-sfx-stub.c stub_rc.o \
 *       -o tbfdesk-sfx-stub.exe -mconsole -lkernel32 -luser32
 * The committed tbfdesk-sfx-stub.exe is what the server include_bytes!s; nothing is
 * cross-compiled at server build time.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TRAILER_LEN 28
static const char MAGIC[8] = { 'T','B','F','S','F','X','0','1' };

/* Wait for Enter only on a genuine double-click, so the freshly-spawned window stays up
 * for the user to read the result. Three conditions, all required:
 *   1. we have a console WINDOW at all;
 *   2. we are in an INTERACTIVE session (session != 0). A service or SYSTEM scheduled
 *      task runs in session 0, where that console still exists but NO ONE can press Enter
 *      — pausing there hangs the task forever (measured: a SYSTEM /tr <exe> task blocks
 *      indefinitely at getchar). This is why GetConsoleWindow()!=NULL alone is wrong.
 *   3. we are the SOLE process on that console (GetConsoleProcessList == 1), i.e. Windows
 *      allocated it for us. A shell launch (cmd/PowerShell/SSH) shares its console with
 *      the parent shell (count >= 2); that shell keeps its own window and already shows
 *      our output, so stealing its Enter would only be a nuisance.
 * A headless/RMM run (CreateProcess with CREATE_NO_WINDOW) has no console window and is
 * caught by (1). NB stdin being a char device is not a usable signal: NUL is one too. */
static void pause_if_interactive(void) {
    DWORD session = 0;
    DWORD pids[4];
    if (GetConsoleWindow() == NULL) return;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &session) || session == 0) return;
    if (GetConsoleProcessList(pids, 4) != 1) return;
    wprintf(L"Press Enter to close.\n");
    (void) getchar();
}

static int fail(const char *msg, int code) {
    fprintf(stderr, "TBFDesk one-file installer: %s\n", msg);
    pause_if_interactive();
    return code;
}

/* Copy `len` bytes from `h` at absolute `off` into a new file at `path`. */
static int carve(HANDLE h, long long off, unsigned long long len, const wchar_t *path) {
    HANDLE out = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE) return 0;
    LARGE_INTEGER pos; pos.QuadPart = off;
    if (!SetFilePointerEx(h, pos, NULL, FILE_BEGIN)) { CloseHandle(out); return 0; }
    static BYTE buf[1 << 20]; /* 1 MiB */
    unsigned long long left = len;
    int ok = 1;
    while (left > 0) {
        DWORD want = (DWORD)(left < sizeof(buf) ? left : sizeof(buf));
        DWORD got = 0, wrote = 0;
        if (!ReadFile(h, buf, want, &got, NULL) || got == 0) { ok = 0; break; }
        if (!WriteFile(out, buf, got, &wrote, NULL) || wrote != got) { ok = 0; break; }
        left -= got;
    }
    CloseHandle(out);
    return ok;
}

int wmain(void) {
    wchar_t self[MAX_PATH * 2];
    DWORD sn = GetModuleFileNameW(NULL, self, MAX_PATH * 2);
    if (sn == 0 || sn >= MAX_PATH * 2) return fail("cannot locate self", 10);

    HANDLE h = CreateFileW(self, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return fail("cannot open self", 10);

    LARGE_INTEGER size;
    if (!GetFileSizeEx(h, &size) || size.QuadPart < TRAILER_LEN) {
        CloseHandle(h); return fail("not a one-file installer", 11);
    }

    BYTE tr[TRAILER_LEN];
    LARGE_INTEGER pos; pos.QuadPart = size.QuadPart - TRAILER_LEN;
    DWORD got = 0;
    if (!SetFilePointerEx(h, pos, NULL, FILE_BEGIN) ||
        !ReadFile(h, tr, TRAILER_LEN, &got, NULL) || got != TRAILER_LEN) {
        CloseHandle(h); return fail("cannot read trailer", 11);
    }
    if (memcmp(tr, MAGIC, 8) != 0) {
        CloseHandle(h); return fail("no payload (not a one-file installer?)", 11);
    }

    unsigned long long inst_len = 0, setup_len = 0;
    unsigned int name_len = 0;
    memcpy(&inst_len, tr + 8, 8);
    memcpy(&setup_len, tr + 16, 8);
    memcpy(&name_len, tr + 24, 4);

    long long name_off  = size.QuadPart - TRAILER_LEN - (long long) name_len;
    long long setup_off = name_off - (long long) setup_len;
    long long inst_off  = setup_off - (long long) inst_len;
    if (inst_off < 0 || name_len == 0 || name_len > 400 ||
        inst_len == 0 || setup_len == 0) {
        CloseHandle(h); return fail("corrupt payload", 12);
    }

    /* setup file name (utf8 -> wide), sanitised to a bare file name */
    char *nameb = (char *) malloc(name_len + 1);
    if (!nameb) { CloseHandle(h); return fail("out of memory", 12); }
    pos.QuadPart = name_off;
    if (!SetFilePointerEx(h, pos, NULL, FILE_BEGIN) ||
        !ReadFile(h, nameb, name_len, &got, NULL) || got != name_len) {
        free(nameb); CloseHandle(h); return fail("cannot read setup name", 12);
    }
    nameb[name_len] = 0;
    for (unsigned int i = 0; i < name_len; i++) {
        char c = nameb[i];
        if (c == '\\' || c == '/' || c == ':') nameb[i] = '_';
    }
    wchar_t setupName[512];
    if (MultiByteToWideChar(CP_UTF8, 0, nameb, -1, setupName, 512) == 0) {
        wcscpy(setupName, L"client.tbfsetup");
    }
    free(nameb);

    /* fresh per-run temp dir under %TEMP% (ACL is already user-only there) */
    wchar_t tmp[MAX_PATH];
    DWORD tn = GetTempPathW(MAX_PATH, tmp);
    if (tn == 0 || tn >= MAX_PATH) { CloseHandle(h); return fail("no temp dir", 12); }
    wchar_t dir[MAX_PATH];
    _snwprintf(dir, MAX_PATH, L"%stbfdesk_sfx_%lu_%lu", tmp,
               GetCurrentProcessId(), GetTickCount());
    /* Must be a FRESH dir we create: under a SYSTEM/service launch %TEMP% is C:\Windows\Temp,
     * where a non-admin user can pre-create our name and plant files. Never reuse an existing
     * directory — treat ERROR_ALREADY_EXISTS as failure (the name carries pid+tick, so a real
     * collision is rare). */
    if (!CreateDirectoryW(dir, NULL)) {
        CloseHandle(h); return fail("cannot create a private temp dir", 12);
    }

    wchar_t instPath[MAX_PATH], setupPath[MAX_PATH];
    _snwprintf(instPath, MAX_PATH, L"%s\\tbfdesk-install.exe", dir);
    _snwprintf(setupPath, MAX_PATH, L"%s\\%s", dir, setupName);

    wprintf(L"Unpacking the TBFDesk installer...\n");
    int ok = carve(h, inst_off, inst_len, instPath) &&
             carve(h, setup_off, setup_len, setupPath);
    CloseHandle(h);
    if (!ok) {
        DeleteFileW(instPath); DeleteFileW(setupPath); RemoveDirectoryW(dir);
        return fail("cannot unpack payload", 12);
    }

    /* installer.exe --silent-install --import-setup "<setup file>" */
    wchar_t cmd[2048];
    _snwprintf(cmd, 2048, L"\"%s\" --silent-install --import-setup \"%s\"",
               instPath, setupPath);

    STARTUPINFOW si; ZeroMemory(&si, sizeof si); si.cb = sizeof si;
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof pi);
    wprintf(L"Installing TBFDesk and provisioning this computer...\n");
    DWORD code;
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        DeleteFileW(instPath); DeleteFileW(setupPath); RemoveDirectoryW(dir);
        return fail("cannot start the installer", 13);
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    /* best-effort cleanup -- the installer copied itself into Program Files already */
    DeleteFileW(instPath);
    DeleteFileW(setupPath);
    RemoveDirectoryW(dir);

    if (code == 0) {
        wprintf(L"Done. This computer is now installed and provisioned for TBFDesk.\n");
    } else if (code == 2) {
        wprintf(L"The setup string was refused -- nothing was installed (exit 2).\n");
    } else {
        wprintf(L"Installation failed (exit %lu).\n", code);
    }
    pause_if_interactive();
    return (int) code;
}
