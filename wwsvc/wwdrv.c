/* wwdrv.c -- WaterWall driver channel implementation. */
#include "wwdrv.h"
#include <string.h>
#include <stdlib.h>

void ripemd160(const uint8_t *msg, size_t len, uint8_t out[20]);

static uint32_t ld32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void st32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xff); p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff); p[3] = (uint8_t)((v >> 24) & 0xff);
}
static uint8_t nibswap(uint8_t b) { return (uint8_t)(((b >> 4) | (b << 4)) & 0xff); }

/* --- device open --- */
HANDLE drv_open_host(void)
{
    return CreateFileA("\\\\.\\Global\\WWHost", 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0x80, NULL);
}

HANDLE drv_open_kernel(void)
{
    return CreateFileA("\\\\.\\wwkernel", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
}

HANDLE drv_open_kernel_overlapped(void)
{
    return CreateFileA("\\\\.\\wwkernel", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED, NULL);
}

/* --- registration channel --- */
int drv_cmd1(HANDLE h, DWORD *d0, DWORD *d1)
{
    uint8_t out[8];
    DWORD ret = 0;
    memset(out, 0, sizeof(out));
    BOOL ok = DeviceIoControl(h, 1, NULL, 0, out, sizeof(out), &ret, NULL);
    if (d0) *d0 = ld32(out);
    if (d1) *d1 = ld32(out + 4);
    return (ok && ret >= 4 && ld32(out) == 0x139) ? 1 : 0;
}

static DWORD build_handshake(uint8_t *buf, DWORD pid, const wchar_t *exename)
{
    memcpy(buf, WW_MAGIC_W, 16);
    memcpy(buf + 0x10, &pid, 4);
    size_t n = wcslen(exename) + 1;
    memcpy(buf + 0x14, exename, n * 2);
    return (DWORD)(0x14 + n * 2);
}

int drv_register(HANDLE h, DWORD pid, const wchar_t *exename)
{
    uint8_t in[512], out[0x40];
    DWORD inlen = build_handshake(in, pid, exename);
    DWORD ret = 0;
    memset(out, 0, sizeof(out));
    BOOL ok = DeviceIoControl(h, 3, in, inlen, out, sizeof(out), &ret, NULL);
    return (ok && ret == 0x12 && memcmp(out, WW_MAGIC_W, 16) == 0) ? 1 : 0;
}

int drv_deregister(HANDLE h, DWORD pid, const wchar_t *exename)
{
    uint8_t in[512], out[0x40];
    DWORD inlen = build_handshake(in, pid, exename);
    DWORD ret = 0;
    memset(out, 0, sizeof(out));
    BOOL ok = DeviceIoControl(h, 5, in, inlen, out, sizeof(out), &ret, NULL);
    return (ok && ret == 0x12 && memcmp(out, WW_MAGIC_W, 16) == 0) ? 1 : 0;
}

int drv_read_flags(HANDLE h, DWORD *flags)
{
    DWORD out = 0, ret = 0;
    BOOL ok = DeviceIoControl(h, 0x1e, NULL, 0, (uint8_t *)&out, 4, &ret, NULL);
    if (ok && ret >= 4) { *flags = out; return 1; }
    return 0;
}

int drv_send_verb(HANDLE h, const wchar_t *verb)
{
    wchar_t buf[0x101];
    uint8_t out[0x40];
    DWORD ret = 0;
    size_t n = wcslen(verb);
    if (8 + n + 1 > 0x101) return 0;
    memcpy(buf, WW_MAGIC_W, 16);
    memcpy(buf + 8, verb, (n + 1) * 2);
    memset(out, 0, sizeof(out));
    BOOL ok = DeviceIoControl(h, 0x18, (uint8_t *)buf, (DWORD)((8 + n + 1) * 2),
                              out, sizeof(out), &ret, NULL);
    return (ok && ret == 0x12 && memcmp(out, WW_MAGIC_W, 16) == 0) ? 1 : 0;
}

int drv_send_whitelist(HANDLE h, const uint8_t *list, DWORD len)
{
    DWORD ret = 0;
    if (len > 5000) return 0;
    BOOL ok = DeviceIoControl(h, 0x26, (void *)list, len, NULL, 0, &ret, NULL);
    return ok ? 1 : 0;
}

int drv_enum_usb(HANDLE h, uint8_t *out, DWORD out_cap, DWORD *ret_len)
{
    DWORD ret = 0;
    memset(out, 0, out_cap);
    BOOL ok = DeviceIoControl(h, 0x27, NULL, 0, out, out_cap, &ret, NULL);
    if (!ok) return 0;
    if (ret_len) *ret_len = ret;
    return 1;
}

/* --- 0x22e000 encoding --- */
DWORD drv_encode_msg(const uint8_t *payload, DWORD payload_len,
                     uint8_t *out, uint8_t tid_low)
{
    DWORD total = 0x18 + payload_len;
    uint8_t *p1 = (uint8_t *)malloc(payload_len ? payload_len : 1);
    uint8_t digest[20];
    DWORD o;
    if (!p1) return 0;
    for (DWORD j = 0; j < payload_len; j++)
        p1[j] = (uint8_t)(payload[j] ^ (tid_low ^ (j & 0xff)));
    ripemd160(p1, payload_len, digest);
    st32(out, total);
    memcpy(out + 4, digest, 20);
    o = 0;
    while (o + 4 <= payload_len) {
        uint32_t k = ld32(digest + (o % 20));
        uint32_t w = ld32(p1 + o);
        w ^= (k >> 4 & 0x0f0f0f0f) ^ ((k & 0x0f0f0f0f) << 4);
        st32(out + 0x18 + o, w);
        o += 4;
    }
    while (o < payload_len) { out[0x18 + o] = (uint8_t)(p1[o] ^ nibswap(digest[o % 20])); o++; }
    free(p1);
    return total;
}

/* --- injection control channel --- */
int drv_get_entry(HANDLE h, DWORD index, uint8_t *out, DWORD out_cap,
                  DWORD *entry_len)
{
    uint8_t payload[4];
    uint8_t *msg = NULL;
    DWORD total, ret = 0;
    BOOL ok;
    uint8_t tid = (uint8_t)(GetCurrentThreadId() & 0xff);

    st32(payload, index);
    msg = (uint8_t *)malloc(0x18 + 4);
    if (!msg) return 0;
    total = drv_encode_msg(payload, 4, msg, tid);
    memset(out, 0, out_cap);
    ok = DeviceIoControl(h, 0x22e010, msg, total, out, out_cap, &ret, NULL);
    free(msg);
    if (!ok || ret < 4) return 0;
    *entry_len = ld32(out);
    if (*entry_len == 0 || *entry_len > out_cap) return 0;
    return 1;
}

int drv_wait_once(ww_waiter_t *w)
{
    /* payload = [key DWORD][continue BYTE][inner entry message]
     * NOTE: continue is ONE byte (offset 4), inner starts at offset 5.
     * (An earlier build used a DWORD continue + inner at offset 8; the
     * driver then read the inner total as 0xB8000000 and rejected the
     * request with STATUS_UNSUCCESSFUL / err 31 on every attempt.) */
    DWORD payload_len = 5 + w->entry_len;
    uint8_t *payload = (uint8_t *)malloc(payload_len);
    uint8_t *msg = NULL;
    uint8_t outbuf[20];
    DWORD total, ret = 0;
    OVERLAPPED ov;
    BOOL ok;
    DWORD wait_r;
    HANDLE events[2];
    int result = 0;

    if (!payload) return 0;
    st32(payload, w->key);
    payload[4] = 1; /* continue (single byte) */
    memcpy(payload + 5, w->entry, w->entry_len);

    msg = (uint8_t *)malloc(0x18 + payload_len);
    if (!msg) { free(payload); return 0; }
    total = drv_encode_msg(payload, payload_len, msg,
                           (uint8_t)(GetCurrentThreadId() & 0xff));
    free(payload);

    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!ov.hEvent) { free(msg); return 0; }
    memset(outbuf, 0, sizeof(outbuf));

    ok = DeviceIoControl(w->hKrn, 0x22e014, msg, total, outbuf, sizeof(outbuf),
                         &ret, &ov);
    free(msg);
    if (!ok && GetLastError() != ERROR_IO_PENDING) {
        CloseHandle(ov.hEvent);
        return 0;
    }
    /* wait for the notification or for the stop signal */
    events[0] = ov.hEvent;
    events[1] = w->hStop;
    wait_r = WaitForMultipleObjects(2, events, FALSE, INFINITE);
    if (wait_r == WAIT_OBJECT_0 + 1) {
        /* asked to stop: cancel the pending IRP and wait for it to finish */
        CancelIoEx(w->hKrn, &ov);
        WaitForSingleObject(ov.hEvent, 5000);
        CloseHandle(ov.hEvent);
        return -1;
    }
    if (wait_r != WAIT_OBJECT_0) {
        CloseHandle(ov.hEvent);
        return 0;
    }
    /* completed: read the result */
    {
        DWORD got = 0;
        if (!GetOverlappedResult(w->hKrn, &ov, &got, FALSE) || got < 20) {
            CloseHandle(ov.hEvent);
            return 0;
        }
    }
    for (int i = 0; i < 5; i++) w->out5[i] = ld32(outbuf + i * 4);
    result = 1;
    CloseHandle(ov.hEvent);
    return result;
}
