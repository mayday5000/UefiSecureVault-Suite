/*
 * UsvAuthSet.c — tiny EFI helper for the OVMF .auth enrollment tests.
 *
 * efitools UpdateVars.efi is kept as a control, but its gnu-efi argsplit /
 * Print path is unreliable under the Debian EFI Shell (argc is often wrong
 * and Print emits a long U+AEAF run). This helper takes no argv: it reads
 * an ASCII cmds.txt next to itself (SET / DUMP lines) and reports ASCII
 * status on ConOut so the serial log is easy to assert.
 *
 * cmds.txt lines:
 *   SET  <PK|KEK|db|dbx>  <filename>
 *   DUMP <SetupMode|SecureBoot|PK|KEK|db|dbx>
 *   LOAD <filename>     LoadImage (and StartImage for Hello*.efi)
 * Blank lines and # comments are ignored.
 *
 * LoadImage is called with a FileDevicePath of the volume plus the file
 * buffer. OVMF's security hook returns EFI_INVALID_PARAMETER when FilePath
 * is NULL, even if SourceBuffer is set.
 */
#include <efi.h>
#include <efilib.h>

static EFI_GUID GV_GUID = {
    0x8BE4DF61, 0x93CA, 0x11d2,
    {0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C}
};
static EFI_HANDLE g_image;
static EFI_HANDLE g_fs_handle;

static EFI_GUID SIG_DB_GUID = {
    0xd719b2cb, 0x3d3a, 0x4596,
    {0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f}
};

#define AUTH_ATTR (EFI_VARIABLE_NON_VOLATILE \
    | EFI_VARIABLE_BOOTSERVICE_ACCESS \
    | EFI_VARIABLE_RUNTIME_ACCESS \
    | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)

static void say_ascii(const char *s)
{
    CHAR16 buf[320];
    UINTN i;
    for (i = 0; s[i] && i < 317; i++)
        buf[i] = (CHAR16)(UINT8)s[i];
    buf[i++] = L'\r';
    buf[i++] = L'\n';
    buf[i] = 0;
    ST->ConOut->OutputString(ST->ConOut, buf);
}

static char hexdigit(UINT8 v)
{
    v &= 0xF;
    return (char)((v < 10) ? ('0' + v) : ('a' + (v - 10)));
}

static void append_hex(char *out, UINTN *pos, UINTN cap, UINT64 value, UINTN width)
{
    char tmp[16];
    UINTN n = 0;
    do {
        tmp[n++] = hexdigit((UINT8)(value & 0xF));
        value >>= 4;
    } while (value && n < 16);
    while (n < width && n < 16)
        tmp[n++] = '0';
    while (n && *pos + 1 < cap)
        out[(*pos)++] = tmp[--n];
}

static int str_eq(const char *a, const char *b)
{
    while (*a && *b && *a == *b) {
        a++;
        b++;
    }
    return *a == 0 && *b == 0;
}


static const char *skip_ws(const char *s)
{
    while (*s == ' ' || *s == '\t' || *s == '\r')
        s++;
    return s;
}

static void token(const char **cursor, char *out, UINTN cap)
{
    const char *s = skip_ws(*cursor);
    UINTN n = 0;
    while (*s && *s != ' ' && *s != '\t' && *s != '\r' && *s != '\n' && n + 1 < cap)
        out[n++] = *s++;
    out[n] = 0;
    *cursor = s;
}

static EFI_GUID *guid_for(const char *name)
{
    if (str_eq(name, "PK") || str_eq(name, "KEK") ||
        str_eq(name, "SetupMode") || str_eq(name, "SecureBoot"))
        return &GV_GUID;
    if (str_eq(name, "db") || str_eq(name, "dbx") || str_eq(name, "dbt"))
        return &SIG_DB_GUID;
    return NULL;
}

static EFI_STATUS open_fs_handle(EFI_HANDLE dev, EFI_FILE_HANDLE *root)
{
    EFI_STATUS st;
    EFI_FILE_IO_INTERFACE *fs = NULL;

    st = BS->HandleProtocol(dev, &FileSystemProtocol, (void **)&fs);
    if (EFI_ERROR(st) || !fs)
        return st ? st : EFI_UNSUPPORTED;
    return fs->OpenVolume(fs, root);
}

static EFI_STATUS open_root(EFI_HANDLE image, EFI_FILE_HANDLE *root)
{
    EFI_STATUS st;
    EFI_LOADED_IMAGE *li = NULL;
    EFI_HANDLE *handles = NULL;
    UINTN count = 0, i;

    *root = NULL;
    g_fs_handle = NULL;
    st = BS->HandleProtocol(image, &LoadedImageProtocol, (void **)&li);
    if (!EFI_ERROR(st) && li && li->DeviceHandle) {
        st = open_fs_handle(li->DeviceHandle, root);
        if (!EFI_ERROR(st) && *root) {
            g_fs_handle = li->DeviceHandle;
            return EFI_SUCCESS;
        }
    }
    /* Fallback: first SimpleFileSystem volume that has cmds.txt. */
    st = BS->LocateHandleBuffer(ByProtocol, &FileSystemProtocol, NULL, &count, &handles);
    if (EFI_ERROR(st) || !handles)
        return st;
    st = EFI_NOT_FOUND;
    for (i = 0; i < count; i++) {
        EFI_FILE_HANDLE vol = NULL;
        EFI_FILE_HANDLE probe = NULL;
        if (EFI_ERROR(open_fs_handle(handles[i], &vol)) || !vol)
            continue;
        if (!EFI_ERROR(vol->Open(vol, &probe, L"cmds.txt", EFI_FILE_MODE_READ, 0))) {
            probe->Close(probe);
            *root = vol;
            g_fs_handle = handles[i];
            st = EFI_SUCCESS;
            break;
        }
        vol->Close(vol);
    }
    if (handles)
        FreePool(handles);
    return st;
}

static EFI_STATUS read_file(EFI_FILE_HANDLE root, const char *name, void **buf, UINTN *size)
{
    EFI_STATUS st;
    EFI_FILE_HANDLE file = NULL;
    CHAR16 wname[128];
    UINTN i;
    EFI_FILE_INFO *info;
    UINTN info_sz;

    for (i = 0; name[i] && i < 126; i++)
        wname[i] = (CHAR16)(UINT8)name[i];
    wname[i] = 0;

    st = root->Open(root, &file, wname, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(st))
        return st;

    info_sz = SIZE_OF_EFI_FILE_INFO + 256;
    info = AllocateZeroPool(info_sz);
    if (!info) {
        file->Close(file);
        return EFI_OUT_OF_RESOURCES;
    }
    st = file->GetInfo(file, &gEfiFileInfoGuid, &info_sz, info);
    if (EFI_ERROR(st)) {
        FreePool(info);
        file->Close(file);
        return st;
    }
    *size = (UINTN)info->FileSize;
    FreePool(info);
    *buf = AllocateZeroPool(*size ? *size : 1);
    if (!*buf) {
        file->Close(file);
        return EFI_OUT_OF_RESOURCES;
    }
    st = file->Read(file, size, *buf);
    file->Close(file);
    return st;
}

static void do_set(EFI_FILE_HANDLE root, const char *var, const char *file)
{
    EFI_GUID *guid = guid_for(var);
    void *buf = NULL;
    UINTN size = 0;
    EFI_STATUS st;
    CHAR16 wvar[32];
    UINTN i;
    char line[280];
    UINTN p = 0;
    const char *s;
    const char *pre = "USV_STATUS SET ";

    if (!guid) {
        say_ascii("USV_STATUS SET unknown-var");
        return;
    }
    for (i = 0; var[i] && i < 30; i++)
        wvar[i] = (CHAR16)(UINT8)var[i];
    wvar[i] = 0;

    st = read_file(root, file, &buf, &size);
    if (EFI_ERROR(st) || !buf) {
        p = 0;
        s = "USV_STATUS SET ";
        while (*s) line[p++] = *s++;
        s = var;
        while (*s) line[p++] = *s++;
        line[p++] = ' ';
        s = file;
        while (*s) line[p++] = *s++;
        s = " open 0x";
        while (*s) line[p++] = *s++;
        append_hex(line, &p, sizeof(line), (UINT64)st, 8);
        line[p] = 0;
        say_ascii(line);
        if (buf)
            FreePool(buf);
        return;
    }
    st = RT->SetVariable(wvar, guid, AUTH_ATTR, size, buf);
    FreePool(buf);

    p = 0;
    for (s = pre; *s && p + 1 < sizeof(line); )
        line[p++] = *s++;
    for (s = var; *s && p + 1 < sizeof(line); )
        line[p++] = *s++;
    if (p + 1 < sizeof(line))
        line[p++] = ' ';
    for (s = file; *s && p + 1 < sizeof(line); )
        line[p++] = *s++;
    if (p + 3 < sizeof(line)) {
        line[p++] = ' ';
        line[p++] = '0';
        line[p++] = 'x';
    }
    append_hex(line, &p, sizeof(line), (UINT64)st, 8);
    line[p] = 0;
    say_ascii(line);
}

static void do_dump(const char *var)
{
    EFI_GUID *guid = guid_for(var);
    CHAR16 wvar[32];
    UINTN i, size = 0;
    EFI_STATUS st;
    UINT8 *buf;
    char line[280];
    UINTN p = 0;
    const char *s;

    if (!guid) {
        say_ascii("USV_DUMP unknown-var");
        return;
    }
    for (i = 0; var[i] && i < 30; i++)
        wvar[i] = (CHAR16)(UINT8)var[i];
    wvar[i] = 0;
    size = 0;
    st = RT->GetVariable(wvar, guid, NULL, &size, NULL);
    if (st != EFI_BUFFER_TOO_SMALL) {
        p = 0;
        s = "USV_DUMP ";
        while (*s) line[p++] = *s++;
        s = var;
        while (*s) line[p++] = *s++;
        s = " missing 0x";
        while (*s) line[p++] = *s++;
        append_hex(line, &p, sizeof(line), (UINT64)st, 8);
        line[p] = 0;
        say_ascii(line);
        return;
    }
    buf = AllocateZeroPool(size);
    if (!buf) {
        say_ascii("USV_DUMP oom");
        return;
    }
    st = RT->GetVariable(wvar, guid, NULL, &size, buf);
    p = 0;
    s = "USV_DUMP ";
    while (*s) line[p++] = *s++;
    s = var;
    while (*s) line[p++] = *s++;
    s = " size=";
    while (*s) line[p++] = *s++;
    append_hex(line, &p, sizeof(line), (UINT64)size, 1);
    s = " 0x";
    while (*s) line[p++] = *s++;
    append_hex(line, &p, sizeof(line), (UINT64)st, 8);
    s = " data=";
    while (*s) line[p++] = *s++;
    for (i = 0; i < size && i < 16 && p + 2 < sizeof(line); i++) {
        line[p++] = hexdigit(buf[i] >> 4);
        line[p++] = hexdigit(buf[i]);
    }
    line[p] = 0;
    say_ascii(line);
    FreePool(buf);
}


static void emit_status(const char *op, const char *a, const char *b, EFI_STATUS st)
{
    char line[280];
    UINTN p = 0;
    const char *s;
    const char *pre = "USV_STATUS ";
    for (s = pre; *s && p + 1 < sizeof(line); )
        line[p++] = *s++;
    for (s = op; *s && p + 1 < sizeof(line); )
        line[p++] = *s++;
    if (a && *a) {
        if (p + 1 < sizeof(line))
            line[p++] = ' ';
        for (s = a; *s && p + 1 < sizeof(line); )
            line[p++] = *s++;
    }
    if (b && *b) {
        if (p + 1 < sizeof(line))
            line[p++] = ' ';
        for (s = b; *s && p + 1 < sizeof(line); )
            line[p++] = *s++;
    }
    if (p + 3 < sizeof(line)) {
        line[p++] = ' ';
        line[p++] = '0';
        line[p++] = 'x';
    }
    append_hex(line, &p, sizeof(line), (UINT64)st, 8);
    line[p] = 0;
    say_ascii(line);
}

static int looks_like_hello(const char *file)
{
    const char *base = file;
    const char *p;
    for (p = file; *p; p++) {
        if (*p == '\\' || *p == '/')
            base = p + 1;
    }
    return (base[0] == 'H' || base[0] == 'h')
        && (base[1] == 'e' || base[1] == 'E')
        && (base[2] == 'l' || base[2] == 'L')
        && (base[3] == 'l' || base[3] == 'L')
        && (base[4] == 'o' || base[4] == 'O');
}

static void ascii_to_path(const char *name, CHAR16 *out, UINTN cap)
{
    UINTN i = 0, j = 0;
    if (cap < 2) {
        if (cap)
            out[0] = 0;
        return;
    }
    if (name[0] != '\\' && name[0] != '/')
        out[j++] = L'\\';
    for (i = 0; name[i] && j + 1 < cap; i++, j++) {
        char c = name[i];
        out[j] = (CHAR16)(UINT8)((c == '/') ? '\\' : c);
    }
    out[j] = 0;
}

static UINTN dp_size(EFI_DEVICE_PATH *dp)
{
    UINTN n = 0;
    if (!dp)
        return 0;
    while (!IsDevicePathEnd(dp)) {
        UINTN l = DevicePathNodeLength(dp);
        if (l < 4)
            break;
        n += l;
        dp = NextDevicePathNode(dp);
    }
    return n + sizeof(EFI_DEVICE_PATH);
}

static EFI_DEVICE_PATH *make_file_dp(CHAR16 *wname, int with_device)
{
    UINTN name_len = 0, file_node_size, prefix = 0, total;
    EFI_DEVICE_PATH *dev = NULL;
    EFI_DEVICE_PATH *out;
    FILEPATH_DEVICE_PATH *fp;
    EFI_DEVICE_PATH *end;

    while (wname[name_len])
        name_len++;
    file_node_size = SIZE_OF_FILEPATH_DEVICE_PATH + (name_len + 1) * sizeof(CHAR16);

    if (with_device && g_fs_handle) {
        EFI_STATUS st;
        st = BS->HandleProtocol(g_fs_handle, &DevicePathProtocol, (void **)&dev);
        if (EFI_ERROR(st))
            dev = NULL;
    }
    if (dev) {
        UINTN sz = dp_size(dev);
        if (sz >= sizeof(EFI_DEVICE_PATH))
            prefix = sz - sizeof(EFI_DEVICE_PATH);
    }
    total = prefix + file_node_size + sizeof(EFI_DEVICE_PATH);
    out = AllocateZeroPool(total);
    if (!out)
        return NULL;
    if (prefix && dev)
        CopyMem(out, dev, prefix);
    fp = (FILEPATH_DEVICE_PATH *)((UINT8 *)out + prefix);
    fp->Header.Type = MEDIA_DEVICE_PATH;
    fp->Header.SubType = MEDIA_FILEPATH_DP;
    SetDevicePathNodeLength(&fp->Header, file_node_size);
    CopyMem(fp->PathName, wname, (name_len + 1) * sizeof(CHAR16));
    end = (EFI_DEVICE_PATH *)((UINT8 *)fp + file_node_size);
    SetDevicePathEndNode(end);
    return out;
}

static int is_invalid_param(EFI_STATUS st)
{
    return EFI_ERROR(st) && ((st & 0xFF) == (EFI_INVALID_PARAMETER & 0xFF));
}

static void emit_try(const char *file, const char *how, EFI_STATUS st)
{
    emit_status("LOAD_TRY", file, how, st);
}

static void do_load(EFI_FILE_HANDLE root, const char *file)
{
    EFI_STATUS st = EFI_INVALID_PARAMETER;
    void *buf = NULL;
    UINTN size = 0;
    EFI_HANDLE loaded = NULL;
    EFI_DEVICE_PATH *full = NULL;
    EFI_DEVICE_PATH *bare = NULL;
    CHAR16 wname[160];

    st = read_file(root, file, &buf, &size);
    if (EFI_ERROR(st) || !buf) {
        emit_status("LOAD", file, NULL, st);
        if (buf)
            FreePool(buf);
        return;
    }

    ascii_to_path(file, wname, 160);
    /* Build the path ourselves. libefi FileDevicePath may be a different ABI
       than this image (we compile with GNU_EFI_USE_MS_ABI). */
    full = make_file_dp(wname, 1);
    bare = make_file_dp(wname, 0);

    /* Prefer FilePath + SourceBuffer (OVMF's security hook wants a path). */
    if (full) {
        st = BS->LoadImage(FALSE, g_image, full, buf, size, &loaded);
        emit_try(file, "full+buf", st);
    }
    if (is_invalid_param(st) && full) {
        st = BS->LoadImage(FALSE, g_image, full, NULL, 0, &loaded);
        emit_try(file, "full", st);
    }
    if (is_invalid_param(st) && bare) {
        st = BS->LoadImage(FALSE, g_image, bare, buf, size, &loaded);
        emit_try(file, "bare+buf", st);
    }
    if (is_invalid_param(st) && full) {
        st = BS->LoadImage(TRUE, g_image, full, buf, size, &loaded);
        emit_try(file, "boot+full+buf", st);
    }
    /* Some firmware returns ACCESS_DENIED (0x0f) rather than
       SECURITY_VIOLATION (0x1a) for an unsigned image. Record it as-is. */
    emit_status("LOAD", file, NULL, st);

    /* Start Hello*.efi so the serial log shows USV_HELLO_OK. Never start
       EFI/BOOT/BOOTX64.EFI (the Shell) or this helper will not return. */
    if (!EFI_ERROR(st) && loaded && looks_like_hello(file)) {
        EFI_STATUS st2;
        st2 = BS->StartImage(loaded, NULL, NULL);
        emit_status("START", file, NULL, st2);
        if (EFI_ERROR(st2))
            BS->UnloadImage(loaded);
    } else if (!EFI_ERROR(st) && loaded) {
        BS->UnloadImage(loaded);
    }

    if (full)
        FreePool(full);
    if (bare)
        FreePool(bare);
    FreePool(buf);
}

static void run_cmds(EFI_FILE_HANDLE root, char *text, UINTN size)
{
    UINTN i = 0;
    while (i < size) {
        char line[200];
        UINTN n = 0;
        const char *cur;
        char op[16], a[64], b[96];

        while (i < size && text[i] != '\n' && n + 1 < sizeof(line)) {
            if (text[i] != '\r')
                line[n++] = text[i];
            i++;
        }
        if (i < size && text[i] == '\n')
            i++;
        line[n] = 0;
        cur = skip_ws(line);
        if (*cur == 0 || *cur == '#')
            continue;
        token(&cur, op, sizeof(op));
        token(&cur, a, sizeof(a));
        token(&cur, b, sizeof(b));
        if (str_eq(op, "SET"))
            do_set(root, a, b);
        else if (str_eq(op, "DUMP"))
            do_dump(a);
        else if (str_eq(op, "LOAD"))
            do_load(root, a[0] ? a : b);
        else
            say_ascii("USV_STATUS unknown-op");
    }
}

/*
 * efi_main is deliberately not EFIAPI: Debian gnu-efi _entry calls it
 * SysV. GNU_EFI_USE_MS_ABI still applies to EFI_BOOT_SERVICES /
 * EFI_RUNTIME_SERVICES function pointers. A prior EFIAPI efi_main left
 * g_image / ImageHandle unset, so LoadImage always returned
 * EFI_INVALID_PARAMETER.
 */
EFI_STATUS
efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_FILE_HANDLE root = NULL;
    void *cmds = NULL;
    UINTN size = 0;
    EFI_STATUS st;

    InitializeLib(ImageHandle, SystemTable);
    g_image = ImageHandle;
    say_ascii("USV_AUTHSET_START");
    st = open_root(ImageHandle, &root);
    if (EFI_ERROR(st) || !root) {
        char line[64];
        UINTN p = 0;
        const char *s = "USV_AUTHSET_NO_VOLUME 0x";
        while (*s) line[p++] = *s++;
        append_hex(line, &p, sizeof(line), (UINT64)st, 8);
        line[p] = 0;
        say_ascii(line);
        return st;
    }
    st = read_file(root, "cmds.txt", &cmds, &size);
    if (EFI_ERROR(st) || !cmds) {
        say_ascii("USV_AUTHSET_NO_CMDS");
        return st;
    }
    run_cmds(root, (char *)cmds, size);
    FreePool(cmds);
    say_ascii("USV_AUTHSET_DONE");
    return EFI_SUCCESS;
}
