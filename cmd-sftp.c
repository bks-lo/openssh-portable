#include "cmd-sftp.h"
#include "sftp.h"
#include "log.h"
#include "sshbuf.h"

#pragma pack(1)
typedef struct sftp_head_st
{
    uint32_t  dlen;
    uint8_t   type;
    uint32_t  id;
} __attribute__((packed)) sftp_head_st;
#pragma pack()

typedef int (*sftp_cmd_cb)(Channel *c, const char *data, int dlen);

/**
 * \brief 判断是否为sftp报文，不支持分包及合包的情况
 *
 * \param [in] buf
 * \param [in] len
 * \return int 0：非sftp报文  1：sftp报文
 */
int is_sftp_pkt(const char *buf, int len)
{
    int tlen = len;
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
    int tlen = len;
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
 * \param [in|out] plen 数据包长度，返回去掉头部的数据包长度
 * \param [out] pdlen   数据包内容长度，（已去掉头部的数据包内容长度）
 * \param [out] ptype   数据包类型
 * \return const char*  成功：返回去掉头部的数据包内容，失败：NULL
 */
const char *sftp_head_info(const char *buf, int *plen, int *pdlen, uint8_t *ptype)
{
    const char *data = buf;
    int tlen = *plen;
    int offset = 0;
    int dlen = 0;
    int dlen_min = sizeof(uint32_t) + sizeof(uint8_t);

    //debug_p("sftp_head_info: len=%d, sizeof(sftp_head_st)=%d", tlen, sizeof(sftp_head_st));
    if (tlen < sizeof(sftp_head_st)) {
        return NULL;
    }

    sftp_head_st *head = (sftp_head_st *)(data + offset);
    dlen = ntohl(head->dlen);

    //debug_p("sftp_head_info: sftp_head_st {.dlen=%d, .type=%u}", dlen, head->type);
    if (dlen < dlen_min) {
        return NULL;
    }


    /* sftp pkt struct ：4B data_len + data[data_len]
       sftp data struct: 1B type + 4B id + data[data_len - 5B]
    */

#if 0
    if (tlen < dlen + sizeof(uint32_t)) {
        debug3("need cache, sftp tlen[%d] < dlen[%d]", tlen, dlen);
        return 0;
    }
#endif

    /* Remove the head structure */
    data += sizeof(sftp_head_st);
    tlen -= sizeof(sftp_head_st);
    dlen -= dlen_min;
    //debug_p("sftp_head_info: tlen=%d, dlen=%d", tlen, dlen);

    if (plen != NULL)
        *plen = tlen;

    if (pdlen != NULL)
        *pdlen = dlen;

    if (ptype != NULL)
        *ptype = head->type;

    return data;
}

int sftp_open(Channel *c, const char *buf, int len)
{
    int tlen = len;
    const char *data = buf;
    uint32_t fn_len = 0;
    char file_tmp[512] = {0};

    if (tlen < sizeof(uint32_t)) {
        error("need cache, sftp tlen[%d] < sizeof(uint32_t)", tlen);
        return 0;
    }

    fn_len = PEEK_U32(data);
    data += sizeof(uint32_t);
    tlen -= sizeof(uint32_t);

    if (tlen < fn_len) {
        error("need cache, sftp tlen[%d] < fn_len[%d]", tlen, fn_len);
        return 0;
    }

    snprintf(file_tmp, sizeof(file_tmp), "%.*s", fn_len, data);
    debug_p("sftp open file: %s", file_tmp);
    cmd_log_send(c, file_tmp, strlen(file_tmp));
    return 0;
}

int sftp_open_dir(Channel *c, const char *buf, int len)
{
    if (sizeof(int) >= len) {
        return 0;
    }

    int dir_len = PEEK_U32(buf);
    if (dir_len + sizeof(int) != len) {
        debug_p("dir len[%d] != buf len[%d]", dir_len, len - sizeof(int));
        return 0;
    }
    buf += sizeof(int);
    len -= sizeof(int);

    const char *dir = buf;
    debug_p("dir = %s", dir);
    cmd_log_send(c, dir, strlen(dir));
    return 0;
}

int sftp_write(Channel *c, const char *buf, int len)
{
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
        break;
    case SSH2_FXP_REMOVE:
        break;
    case SSH2_FXP_MKDIR:
        break;
    case SSH2_FXP_RMDIR:
        break;
    case SSH2_FXP_RENAME:
        break;
    case SSH2_FXP_OPENDIR:
        ret = sftp_open_dir;
        break;
    case SSH2_FXP_READDIR:
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

static int sftp_cache_destroy(sftp_cache_st *cache)
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

static int sftp_cache_init(sftp_cache_st *cache, const char *data, int dlen, int left, sftp_cmd_cb cmd_cb)
{
    if (dlen <= left) {
        cache->enable = 0;
        return 0;
    }

    if (cache->buf) {
        sftp_cache_destroy(cache);
    }

    cache->enable = 1;
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
    int ret = 0;
    int nlen = 0;
    int len = *plen;
    sftp_cache_st *cache = &(c->sftp_cache);
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
            cmd_cb(c, cache->buf, cache->tlen);
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
int sftp_reqst_handle(Channel *c, const char *buf, int len)
{
    const char *data = buf;
    int tlen = len;
    int dlen = 0;
    int left = 0;
    int ret = 0;
    uint8_t type = 0;
    sftp_cmd_cb cmd_cb = NULL;

    data = sftp_cache_merge(c, data, &tlen);
    if (data == NULL) {
        return 0;
    }

    left = tlen;
    while (left) {
        data = sftp_head_info(data, &left, &dlen, &type);
        if (data == NULL) {
            return -1;
        }

        cmd_cb = sftp_reqst_handler_get(type);
        /* cache */
        if (sftp_cache_init(&(c->sftp_cache), data, dlen, left, cmd_cb)) {
            return 1;
        }
        if (cmd_cb)
            cmd_cb(c, data, dlen);

        left -= dlen;
        data += dlen;
    }
    return 0;
}

int cmd_sftp_wfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    if (c->proxy_state != PROXY_STATE_CMD) {
        return 0;
    }

    return sftp_reqst_handle(c, buf, len);
}

int cmd_sftp_login_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    if (is_sftp_version_type(buf, len)) {
        c->proxy_state = PROXY_STATE_CMD;
        debug_p("login success");
    }
    return 0;
}

int cmd_sftp_rfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
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