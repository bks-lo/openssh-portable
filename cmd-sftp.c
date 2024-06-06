#include "cmd-sftp.h"
#include "sftp.h"
#include "log.h"
#include "sshbuf.h"
#include "cmd-common.h"
#include <string.h>

#pragma pack(1)
typedef struct sftp_head_st
{
    uint32_t  dlen;
    uint8_t   type;
    uint32_t  id;
} __attribute__((packed)) sftp_head_st;
#pragma pack()


struct proxy_sftp_st
{
    uint8_t enable;         // 是否启用这个cache结构
    char *buf;              // 缓存空间，已经为下一个分包，开辟好了空间，下个分包到达后直接填充
    void *cmd_cb;           // 缓存数据包的处理函数，为空 代表 不关心接下来的缓存内容，所以不用缓存数据，只用记录偏移就可以。
    int tlen;               // buf的空间大小
    int offset;             // 当前已缓存的偏移
    int needlen;            // 需要下一个分包的长度 = tlen - offset
    int id;                 // 第一包解析出的 id
};

proxy_sftp_st *proxy_sftp_pd_create()
{
    proxy_sftp_st *sftp_pd = xmalloc(sizeof(proxy_sftp_st));
    memset(sftp_pd, 0, sizeof(proxy_sftp_st));

    return sftp_pd;
}

void *proxy_sftp_pd_destroy(void *private_data)
{
    proxy_sftp_st *sftp_pd = (proxy_sftp_st *)private_data;
    if (sftp_pd == NULL)
        return ;

    if (sftp_pd->buf) {
        free(sftp_pd);
    }

    free(sftp_pd);
}

typedef int (*sftp_cmd_cb)(Channel *c, const char *data, int dlen, int id);

/* handle handles */
typedef struct Handle Handle;
struct Handle {
    int use;
    int flags;
    char *name;
    u_int64_t bytes_read, bytes_write;
    int next_unused;
};

enum {
    HANDLE_UNUSED,
    HANDLE_DIR,
    HANDLE_FILE
};

static Handle *handles = NULL;
static u_int num_handles = 0;
static int first_unused_handle = -1;

static void handle_unused(int i)
{
    handles[i].use = HANDLE_UNUSED;
    handles[i].next_unused = first_unused_handle;
    first_unused_handle = i;
}

static int
handle_new(int use, const char *name, int flags)
{
    int i;

    if (first_unused_handle == -1) {
        if (num_handles + 1 <= num_handles)
            return -1;
        num_handles++;
        handles = xreallocarray(handles, num_handles, sizeof(Handle));
        handle_unused(num_handles - 1);
    }

    i = first_unused_handle;
    first_unused_handle = handles[i].next_unused;

    handles[i].use = use;
    handles[i].flags = flags;
    handles[i].name = xstrdup(name);
    handles[i].bytes_read = handles[i].bytes_write = 0;

    return i;
}

static int
handle_is_ok(int i, int type)
{
    return i >= 0 && (u_int)i < num_handles && handles[i].use == type;
}

static int
handle_to_string(int handle, u_char **stringp, int *hlenp)
{
    if (stringp == NULL || hlenp == NULL)
        return -1;
    *stringp = xmalloc(sizeof(int32_t));
    put_u32(*stringp, handle);
    *hlenp = sizeof(int32_t);
    return 0;
}

static int
handle_from_string(const u_char *handle, u_int hlen)
{
    int val;

    if (hlen != sizeof(int32_t))
        return -1;
    val = get_u32(handle);
    if (handle_is_ok(val, HANDLE_FILE) ||
        handle_is_ok(val, HANDLE_DIR))
        return val;
    return -1;
}

static char *
handle_to_name(int handle)
{
    if (handle_is_ok(handle, HANDLE_DIR)||
        handle_is_ok(handle, HANDLE_FILE))
        return handles[handle].name;
    return NULL;
}


static int
handle_to_flags(int handle)
{
    if (handle_is_ok(handle, HANDLE_FILE))
        return handles[handle].flags;
    return 0;
}

static void
handle_update_read(int handle, ssize_t bytes)
{
    if (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
        handles[handle].bytes_read += bytes;
}

static void
handle_update_write(int handle, ssize_t bytes)
{
    if (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
        handles[handle].bytes_write += bytes;
}

static u_int64_t
handle_bytes_read(int handle)
{
    if (handle_is_ok(handle, HANDLE_FILE))
        return (handles[handle].bytes_read);
    return 0;
}

static u_int64_t
handle_bytes_write(int handle)
{
    if (handle_is_ok(handle, HANDLE_FILE))
        return (handles[handle].bytes_write);
    return 0;
}

static int
handle_close(int handle)
{
    int ret = -1;

    if (handle_is_ok(handle, HANDLE_FILE)) {
        ret = 0;
        free(handles[handle].name);
        handle_unused(handle);
    } else if (handle_is_ok(handle, HANDLE_DIR)) {
        ret = 0;
        free(handles[handle].name);
        handle_unused(handle);
    } else {
        errno = ENOENT;
    }
    return ret;
}

static int get_handle(const char *buf, int len, int *hp)
{
    u_char *handle;
    char *out_s;
    int out_l;

    PKT_GET_LEN4_STRING(out_s, out_l, buf, len, -1);
    handle = xmalloc(out_l + 1);
    memcpy(handle, out_s, out_l);
    out_s[out_l] = 0;

    *hp = -1;
    if (out_l < 256)
        *hp = handle_from_string(handle, out_l);
    free(handle);
    return 0;
}

/**
 * \brief 判断是否为sftp报文，不支持分包及合包的情况
 *
 * \param [in] buf
 * \param [in] len
 * \return int 0：非sftp报文  1：sftp报文
 */
int is_sftp_pkt(const char *buf, int len)
{
    size_t tlen = (size_t)len;
    const char *data = buf;
    int offset = 0;

    if (tlen < sizeof(sftp_head_st)) {
        return 0;
    }

    sftp_head_st *head = (sftp_head_st *)(data + offset);
    head->dlen = ntohl(head->dlen);

    if (tlen != head->dlen + sizeof(uint32_t)) {
        return 0;
    }

    switch (head->type) {
    case SSH2_FXP_INIT:
    case SSH2_FXP_OPEN:
    case SSH2_FXP_CLOSE:
    case SSH2_FXP_READ:
    case SSH2_FXP_WRITE:
    case SSH2_FXP_LSTAT:
    case SSH2_FXP_FSTAT:
    case SSH2_FXP_SETSTAT:
    case SSH2_FXP_FSETSTAT:
    case SSH2_FXP_OPENDIR:
    case SSH2_FXP_READDIR:
    case SSH2_FXP_REMOVE:
    case SSH2_FXP_MKDIR:
    case SSH2_FXP_RMDIR:
    case SSH2_FXP_REALPATH:
    case SSH2_FXP_STAT:
    case SSH2_FXP_RENAME:
    case SSH2_FXP_READLINK:
    case SSH2_FXP_SYMLINK:
    case SSH2_FXP_VERSION:
    case SSH2_FXP_STATUS:
    case SSH2_FXP_HANDLE:
    case SSH2_FXP_DATA:
    case SSH2_FXP_NAME:
    case SSH2_FXP_ATTRS:
    case SSH2_FXP_EXTENDED:
    case SSH2_FXP_EXTENDED_REPLY:
        return 1;
    default:
        return 0;
    }

}

int is_sftp_version_type(const char *buf, int len)
{
    size_t tlen = (size_t)len;
    const char *data = buf;
    int offset = 0;
    int dlen = 0;

    if (tlen < sizeof(sftp_head_st)) {
        return 0;
    }

    sftp_head_st *head = (sftp_head_st *)(data + offset);
    dlen = ntohl(head->dlen);

    if (tlen != dlen + sizeof(uint32_t)) {
        return 0;
    }

    if (head->type == SSH2_FXP_VERSION) {
        return 1;
    } else {
        return 0;
    }
}

/**
 * \brief 获取sftp 头部信息
 *
 * \param [in] buf  数据包内容
 * \param [in|out] pktlen 数据包长度，返回去掉头部的数据包长度
 * \param [out] pdulen   数据包内容长度，（已去掉头部的数据包内容长度），
 *                      如果没有分包， pktlen == pdulen, 如果分包 pktlen < pdulen
 * \param [out] ptype   数据包类型
 * \return const char*  成功：返回去掉头部的数据包内容，失败：NULL
 *
 * in : buf pktlen
 * out: buf pktlen pdulen type id
 */
const char *sftp_head_info(const char *buf, int *pktlen, sftp_head_st *sftph)
{
    const char *data = buf;
    size_t tlen = (size_t)*pktlen;
    int offset = 0;
    int dlen = 0;
    int dlen_min = (int)(sizeof(uint32_t) + sizeof(uint8_t));

    //debug_p("sftp_head_info: len=%d, sizeof(sftp_head_st)=%d", tlen, sizeof(sftp_head_st));
    if (tlen < sizeof(sftp_head_st)) {
        error_p("sftp_head_info: tlen=%d < sizeof(sftp_head_st)=%d", tlen, sizeof(sftp_head_st));
        return NULL;
    }

    sftp_head_st *head = (sftp_head_st *)(data + offset);
    dlen = ntohl(head->dlen);

    //debug_p("sftp_head_info: sftp_head_st {.dlen=%d, .type=%u}", dlen, head->type);
    if (dlen <= dlen_min) {
        error_p("sftp_head_info: dlen=%d <= dlen_min=%d", dlen, dlen_min);
        return NULL;
    }


    /* sftp pkt struct ：4B data_len + data[data_len]
       sftp data struct: 1B type + 4B id + data[data_len - 5B]
    */

    /* Remove the head structure */
    data += sizeof(sftp_head_st);
    tlen -= sizeof(sftp_head_st);
    dlen -= dlen_min;
    //debug_p("sftp_head_info: tlen=%d, dlen=%d", tlen, dlen);

    if (pktlen != NULL)
        *pktlen = tlen;

    sftph->dlen = dlen;
    sftph->type = head->type;
    sftph->id   = ntohl(head->id);

    return data;
}

int sftp_open(Channel *c, const u_char *buf, int len, int id)
{
    size_t tlen = (size_t)len;
    const char *data = buf;
    uint32_t fn_len = 0;
    char file_tmp[512] = {0};
    proxy_info_st *pinfo = c->proxy_info;
    const char *str = NULL;
    uint32_t flags = 0;

    PKT_GET_LEN4_STRING(str, fn_len, data, tlen, -1);
    snprintf(file_tmp, sizeof(file_tmp), "%.*s", fn_len, str);

    /* flags u32 */
    PKT_GET_U32(flags, data, tlen, -1);

    if ((flags & SSH2_FXF_READ) && (flags & SSH2_FXF_WRITE)) {
        debug_p("sftp open file: flags=0x%x, read|write", flags);
    } else if (flags & SSH2_FXF_READ) {
        debug_p("sftp open file: flags=0x%x, read", flags);
    } else if (flags & SSH2_FXF_WRITE) {
        debug_p("sftp open file: flags=0x%x, write", flags);
    }

    if (flags & SSH2_FXF_APPEND) {
        debug_p("sftp open file: flags=0x%x, append", flags);
    }

    if (flags & SSH2_FXF_CREAT) {
        debug_p("sftp open file: flags=0x%x, creat", flags);
    }

    if (flags & SSH2_FXF_TRUNC) {
        debug_p("sftp open file: flags=0x%x, trunc", flags);
    }

    if (flags & SSH2_FXF_EXCL) {
        debug_p("sftp open file: flags=0x%x, excl", flags);
    }

    int handle = handle_new(HANDLE_FILE, file_tmp, flags);

    // 转码
    // 组装还原文件路径
    // 判断是否可以传输文件

    char log[1024] = {0};
    snprintf(log, sizeof(log), "open file[%s] handle[%d]", file_tmp, handle);
    debug_p("log===> %s", log);
    cmd_log_send(c, log, (int)strlen(log));
    return 0;
}

int sftp_open_dir(Channel *c, const char *buf, int len, int id)
{
    int dlen = 0;
    const char *dirname = NULL;
    PKT_GET_LEN4_STRING(dirname, dlen, buf, len, -1);

    debug_p("opendir \"%s\"", dirname);
    int handle = handle_new(HANDLE_DIR, dirname, 0);
    cmd_log_send(c, dirname, strlen(dirname));
    return 0;
}

int sftp_write(Channel *c, const char *buf, int len, int id)
{
    int handle = 0;
    if (get_handle(buf, len, &handle) != 0) {
        error_p("get_handle failed");
        return -1;
    }

    const u_char *fname = handle_to_name(handle);
    debug_p("write file [%s]", fname);

    cmd_log_send(c, fname, strlen(fname));
    return 0;
}

static int sftp_read(Channel *c, const char *buf, int len, int id)
{
    int handle = 0;
    if (get_handle(buf, len, &handle) != 0) {
        error_p("get_handle failed");
        return -1;
    }

    const u_char *fname = handle_to_name(handle);
    if (fname == NULL) {
        error_p("handle_to_name failed");
        return -1;
    }

    debug_p("read file [%s]", fname);
    cmd_log_send(c, fname, strlen(fname));
    return 0;
}

static int sftp_close(Channel *c, const char *buf, int len, int id)
{
    int handle = 0;
    if (get_handle(buf, len, &handle) != 0) {
        error_p("get_handle failed");
        return -1;
    }

     if (handle_close(handle) != 0) {
        error_p("handle_close failed");
        return -1;
    }

    cmd_log_send(c, NULL, 0);
    return 0;
}

static int sftp_remove(Channel *c, const char *buf, int len, int id)
{
    int flen = 0;
    const char *fname = NULL;

    PKT_GET_LEN4_STRING(fname, flen, buf, len, -1);
    debug_p("request %u: remove file [%s]", id, fname);

    cmd_log_send(c, fname, strlen(fname));
    return 0;
}

static int sftp_mkdir(Channel *c, const char *buf, int len, int id)
{
    int flen = 0;
    const char *fname = NULL;
    PKT_GET_LEN4_STRING(fname, flen, buf, len, -1);

    debug_p("request %u: mkdir [%s]", id, fname);
    cmd_log_send(c, fname, strlen(fname));
    return 0;
}

static int sftp_rmdir(Channel *c, const char *buf, int len, int id)
{
    int flen = 0;
    const char *fname = NULL;
    PKT_GET_LEN4_STRING(fname, flen, buf, len, -1);

    debug_p("request %u: rmdir [%s]", id, fname);
    cmd_log_send(c, fname, strlen(fname));
    return 0;
}

static int sftp_rename(Channel *c, const char *buf, int len, int id)
{
    int oldlen = 0;
    int newlen = 0;
    const char *oldpath = NULL;
    const char *newpath = NULL;
    PKT_GET_LEN4_STRING(oldpath, oldlen, buf, len, -1);
    PKT_GET_LEN4_STRING(newpath, newlen, buf, len, -1);

    debug_p("rename old \"%s\" new \"%s\"", oldpath, newpath);
    cmd_log_send(c, newpath, strlen(newpath));
    return 0;
}

static int sftp_readdir(Channel *c, const char *buf, int len)
{
    int handle = 0;
    if (get_handle(buf, len, &handle) != 0) {
        error_p("get_handle failed");
        return -1;
    }

    const char *dirname = handle_to_name(handle);
    debug_p("readdir dirname \"%s\"", dirname);
    return 0;
}
sftp_cmd_cb sftp_reqst_handler_get(uint8_t type)
{
    sftp_cmd_cb ret = NULL;
    switch (type) {
    case SSH2_FXP_OPEN:
        ret = sftp_open;
        break;
    case SSH2_FXP_WRITE:
        ret = sftp_write;
        break;
    case SSH2_FXP_CLOSE:
        ret = sftp_close;
        break;
    case SSH2_FXP_REMOVE:
        ret = sftp_remove;
        break;
    case SSH2_FXP_MKDIR:
        ret = sftp_mkdir;
        break;
    case SSH2_FXP_RMDIR:
        ret = sftp_rmdir;
        break;
    case SSH2_FXP_RENAME:
        ret = sftp_rename;
        break;
    case SSH2_FXP_OPENDIR:
        ret = sftp_open_dir;
        break;
    case SSH2_FXP_READDIR:
        ret = sftp_readdir;
        break;
    case SSH2_FXP_READ:
        ret = sftp_read;
        break;
    default:
        break;
    }

    return ret;
}

#if 0
/* 进入函数前需确保 dlen 是合法的，函数内部不做校验 */
static int sftp_reqst_part_handle(Channel *c, uint8_t type, const char *data, int dlen)
{
    int ret = 0;
    switch (type) {
    case SSH2_FXP_OPEN:
        ret = sftp_open(c, data, dlen);
        /* code */
        break;
    case SSH2_FXP_WRITE:
        /* code */
        break;
    case SSH2_FXP_CLOSE:
        /* code */
        break;
    case SSH2_FXP_REMOVE:
        /* code */
        break;
    case SSH2_FXP_MKDIR:
        /* code */
        break;
    case SSH2_FXP_RMDIR:
        /* code */
        break;
    case SSH2_FXP_RENAME:
        /* code */
        break;
    case SSH2_FXP_OPENDIR:
        ret = sftp_open_dir(c, data, dlen);
        break;
    case SSH2_FXP_READDIR:
        /* code */
        break;

    default:
        break;
    }

    return ret;
}
#endif

static int sftp_cache_destroy(proxy_sftp_st *cache)
{
    cache->enable = 0;
    if (cache->buf) {
        free(cache->buf);
        cache->buf = NULL;
    }
    cache->cmd_cb = NULL;
    cache->tlen = 0;
    cache->offset = 0;
    cache->needlen = 0;
    return 0;
}

static int sftp_cache_init(proxy_sftp_st *cache, const char *data, int dlen, int left, int id, sftp_cmd_cb cmd_cb)
{
    if (dlen <= left) {
        cache->enable = 0;
        return 0;
    }

    if (cache->buf) {
        sftp_cache_destroy(cache);
    }

    cache->enable = 1;
    cache->id = id;
    if (cmd_cb) {
        cache->buf = (char *)malloc(dlen);
        cache->cmd_cb = cmd_cb;
        cache->tlen = dlen;
        cache->offset = left;
        cache->needlen = dlen - left;
        memcpy(cache->buf, data, dlen);
    } else {
        cache->buf = NULL;
        cache->cmd_cb = NULL;
        cache->tlen = 0;
        cache->offset = 0;
        cache->needlen = dlen - left;
    }
    return 1;
}

static const char *sftp_cache_merge(Channel *c, const char *buf, int *plen)
{
    int nlen = 0;
    int len = *plen;
    proxy_sftp_st *cache = (proxy_sftp_st *)c->proxy_data;
    sftp_cmd_cb cmd_cb = (sftp_cmd_cb)cache->cmd_cb;
    if (cache->enable == 0) {
        return buf;
    }

    /* 需要的长度 大于等于 当前包，整包缓存 */
    if (cache->needlen >= len) {
        *plen = 0;
        cache->needlen -= len;
        if (cmd_cb != NULL) {
            memcpy(cache->buf + cache->offset, buf, len);
            cache->offset += len;
        }
        return NULL;
    } else {    /* 需要长度 小于 当前包，处理缓存内容，并更新包起始 和 剩余长度*/
        nlen = cache->needlen;
        *plen = len - nlen;
        if (cmd_cb != NULL) {
            memcpy(cache->buf + cache->offset, buf, nlen);
            cmd_cb(c, cache->buf, cache->tlen, cache->id);
        }
        sftp_cache_destroy(cache);
        return buf + nlen;
    }
}


/**
 * \brief
 *
 * \param [in|out] c
 * \param [in|out] buf
 * \param [in|out] len
 * \return int  0:继续发送此包，-1：阻断此包   1：缓存此包不发送，待后续发送
 */
int sftp_reqst_handle(Channel *c, const u_char *buf, int len)
{
    const u_char *data = buf;
    int tlen = len;
    int left = 0;
    sftp_cmd_cb cmd_cb = NULL;
    sftp_head_st sftph = {0};
    proxy_sftp_st *sftp_pd = (proxy_sftp_st *)c->proxy_data;

    data = sftp_cache_merge(c, data, &tlen);
    if (data == NULL) {
        return 0;
    }

    left = tlen;
    while (left) {
        data = sftp_head_info(data, &left, &sftph);
        if (data == NULL) {
            return -1;
        }

        cmd_cb = sftp_reqst_handler_get(sftph.type);
        if (cmd_cb == NULL) {
            return 0;
        }

        /* cache */
        if (sftp_cache_init(sftp_pd, data, sftph.dlen, left, sftph.id, cmd_cb)) {
            return 1;
        }

        cmd_cb(c, data, sftph.dlen, sftph.id);
        left -= sftph.dlen;
        data += sftph.dlen;
    }
    return 0;
}

int cmd_sftp_login_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    if (is_sftp_version_type(buf, len)) {
        c->proxy_state = PROXY_STATE_CMD;
        debug_p("login success");
    }
    return 0;
}


#define SFTP_PROXY_DIRECT 0

int cmd_sftp_wfd_handle(struct ssh *ssh, Channel *c, const u_char *buf, int len)
{
#if SFTP_PROXY_DIRECT
    return 0;
#endif

    if (c->proxy_state != PROXY_STATE_CMD) {
        return 0;
    }

    return sftp_reqst_handle(c, buf, len);
}

int cmd_sftp_rfd_handle(struct ssh *ssh, Channel *c, const u_char *buf, int len)
{
#if SFTP_PROXY_DIRECT
    return 0;
#endif

    switch (c->proxy_state) {
    case PROXY_STATE_LOGIN:
        cmd_sftp_login_handle(ssh, c, buf, len);
        break;
    case PROXY_STATE_CMD:
        break;
    default:
        break;
    }

    return 0;
}

#ifdef UNITTEST_CMD_SFTP
#include "./tests/cmd-sftp-test.c"
#endif