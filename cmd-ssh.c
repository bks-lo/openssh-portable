#include <string.h>
#include <linux/types.h>
#include <stdbool.h>
#include "includes.h"
#include "openbsd-compat/sys-queue.h"
#include "channels.h"
#include "log.h"
#include "sshbuf.h"
#include "cmd-ssh.h"
#include "cmd-common.h"
#include "xmalloc.h"

static struct uni_pagedict *dflt;

/* 取unicode 编码的最高5位 idx[15 ~ 11]*/
#define UNI_DIR(uni)        ((unsigned short)((((unsigned short)uni) & ((unsigned short)0xf800)) >> 11))

/* 取unicode 编码的中间5位 idx[10 ~ 6]*/
#define UNI_ROW(uni)        ((unsigned short)((((unsigned short)uni) & ((unsigned short)0x07c0)) >> 6))

/* 取unicode 编码的最低6位 idx[5 ~ 0]*/
#define UNI_GLYPH(uni)      ((unsigned short)((((unsigned short)uni) & ((unsigned short)0x003f))))

/* 拼凑 还原 unicode */
#define UNI(dir, row, glyph)	(((unsigned short)((((unsigned short)dir) & ((unsigned short)0x001f)) << 11)) | \
                                 ((unsigned short)((((unsigned short)row) & ((unsigned short)0x001f)) << 6)) | \
                                 ((unsigned short)((((unsigned short)glyph) & ((unsigned short)0x003f)))))

unsigned char dfont_unicount[256] =
{
	  1,   1,   1,   1,   2,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   2,
	  2,   2,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   2,   1,   1,   1,   1,   2,
	  1,   1,   1,   1,   2,   2,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   5,   1,   2,   2,   4,   1,   1,
	  1,   5,   1,   2,   1,   1,   1,   5,
	  1,   1,   2,   1,   1,   4,   1,   1,
	  1,   2,   1,   1,   1,   1,   1,   3,
	  1,   2,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   2,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  2,   2,   1,   1,   2,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   2,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   2,   1,   1,   1,   1,   2,   1,
	  2,   1,   2,   2,   1,   2,   2,   1,
	  1,   1,   1,   1,   1,   1,   1,   1,
	  1,   1,   1,   1,   1,   1,   2,   1
};

unsigned short dfont_unitable[303] =
{
	0x0000, 0x263a, 0x263b, 0x2665, 0x2666, 0x25c6, 0x2663, 0x2660,
	0x2022, 0x25d8, 0x25cb, 0x25d9, 0x2642, 0x2640, 0x266a, 0x266b,
	0x263c, 0x00a4, 0x25b6, 0x25ba, 0x25c0, 0x25c4, 0x2195, 0x203c,
	0x00b6, 0x00a7, 0x25ac, 0x21a8, 0x2191, 0x2193, 0x2192, 0x2190,
	0x221f, 0x2194, 0x25b2, 0x25bc, 0x0020, 0x0021, 0x0022, 0x00a8,
	0x0023, 0x0024, 0x0025, 0x0026, 0x0027, 0x00b4, 0x0028, 0x0029,
	0x002a, 0x002b, 0x002c, 0x00b8, 0x002d, 0x00ad, 0x002e, 0x002f,
	0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,
	0x0038, 0x0039, 0x003a, 0x003b, 0x003c, 0x003d, 0x003e, 0x003f,
	0x0040, 0x0041, 0x00c0, 0x00c1, 0x00c2, 0x00c3, 0x0042, 0x0043,
	0x00a9, 0x0044, 0x00d0, 0x0045, 0x00c8, 0x00ca, 0x00cb, 0x0046,
	0x0047, 0x0048, 0x0049, 0x00cc, 0x00cd, 0x00ce, 0x00cf, 0x004a,
	0x004b, 0x212a, 0x004c, 0x004d, 0x004e, 0x004f, 0x00d2, 0x00d3,
	0x00d4, 0x00d5, 0x0050, 0x0051, 0x0052, 0x00ae, 0x0053, 0x0054,
	0x0055, 0x00d9, 0x00da, 0x00db, 0x0056, 0x0057, 0x0058, 0x0059,
	0x00dd, 0x005a, 0x005b, 0x005c, 0x005d, 0x005e, 0x005f, 0x23bd,
	0xf804, 0x0060, 0x0061, 0x00e3, 0x0062, 0x0063, 0x0064, 0x0065,
	0x0066, 0x0067, 0x0068, 0x0069, 0x006a, 0x006b, 0x006c, 0x006d,
	0x006e, 0x006f, 0x00f5, 0x0070, 0x0071, 0x0072, 0x0073, 0x0074,
	0x0075, 0x0076, 0x0077, 0x0078, 0x00d7, 0x0079, 0x00fd, 0x007a,
	0x007b, 0x007c, 0x00a6, 0x007d, 0x007e, 0x2302, 0x00c7, 0x00fc,
	0x00e9, 0x00e2, 0x00e4, 0x00e0, 0x00e5, 0x00e7, 0x00ea, 0x00eb,
	0x00e8, 0x00ef, 0x00ee, 0x00ec, 0x00c4, 0x00c5, 0x212b, 0x00c9,
	0x00e6, 0x00c6, 0x00f4, 0x00f6, 0x00f2, 0x00fb, 0x00f9, 0x00ff,
	0x00d6, 0x00dc, 0x00a2, 0x00a3, 0x00a5, 0x20a7, 0x0192, 0x00e1,
	0x00ed, 0x00f3, 0x00fa, 0x00f1, 0x00d1, 0x00aa, 0x00ba, 0x00bf,
	0x2310, 0x00ac, 0x00bd, 0x00bc, 0x00a1, 0x00ab, 0x00bb, 0x2591,
	0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555,
	0x2563, 0x2551, 0x2557, 0x255d, 0x255c, 0x255b, 0x2510, 0x2514,
	0x2534, 0x252c, 0x251c, 0x2500, 0x253c, 0x255e, 0x255f, 0x255a,
	0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256c, 0x2567, 0x2568,
	0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256b, 0x256a,
	0x2518, 0x250c, 0x2588, 0x2584, 0x258c, 0x2590, 0x2580, 0x03b1,
	0x03b2, 0x00df, 0x0393, 0x03c0, 0x03a3, 0x03c3, 0x00b5, 0x03bc,
	0x03c4, 0x03a6, 0x00d8, 0x0398, 0x03a9, 0x2126, 0x03b4, 0x00f0,
	0x221e, 0x03c6, 0x00f8, 0x03b5, 0x2208, 0x2229, 0x2261, 0x00b1,
	0x2265, 0x2264, 0x2320, 0x2321, 0x00f7, 0x2248, 0x00b0, 0x2219,
	0x00b7, 0x221a, 0x207f, 0x00b2, 0x25a0, 0xfffd, 0x00a0
};

static int login_ok_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    //snprintf(c->prompt, sizeof(c->prompt), "%s", buf);
    c->proxy_state = PROXY_STATE_CMD;
    return 0;
}

static int cmd_reset(cmd_t *pcmd)
{
    pcmd->char_state = ESnormal;
    pcmd->cmd_state  = CSnone;
    pcmd->key_state  = KSnone;
    sshbuf_reset(pcmd->cmd_buf);
    sshbuf_reset(pcmd->rsp_buf);
    return 0;
}

#define E_TABSZ         256
#define MAX_NR_CONSOLES	63	/* serial lines start at 64 */
static enum translation_map inv_translate[MAX_NR_CONSOLES];

static unsigned short translations[][E_TABSZ] = {
  /* 8-bit Latin-1 mapped to Unicode -- trivial mapping */
  [LAT1_MAP] = {
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007,
    0x0008, 0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x000e, 0x000f,
    0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017,
    0x0018, 0x0019, 0x001a, 0x001b, 0x001c, 0x001d, 0x001e, 0x001f,
    0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027,
    0x0028, 0x0029, 0x002a, 0x002b, 0x002c, 0x002d, 0x002e, 0x002f,
    0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,
    0x0038, 0x0039, 0x003a, 0x003b, 0x003c, 0x003d, 0x003e, 0x003f,
    0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,
    0x0048, 0x0049, 0x004a, 0x004b, 0x004c, 0x004d, 0x004e, 0x004f,
    0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057,
    0x0058, 0x0059, 0x005a, 0x005b, 0x005c, 0x005d, 0x005e, 0x005f,
    0x0060, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,
    0x0068, 0x0069, 0x006a, 0x006b, 0x006c, 0x006d, 0x006e, 0x006f,
    0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077,
    0x0078, 0x0079, 0x007a, 0x007b, 0x007c, 0x007d, 0x007e, 0x007f,
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,
    0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x008d, 0x008e, 0x008f,
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,
    0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,
    0x00a0, 0x00a1, 0x00a2, 0x00a3, 0x00a4, 0x00a5, 0x00a6, 0x00a7,
    0x00a8, 0x00a9, 0x00aa, 0x00ab, 0x00ac, 0x00ad, 0x00ae, 0x00af,
    0x00b0, 0x00b1, 0x00b2, 0x00b3, 0x00b4, 0x00b5, 0x00b6, 0x00b7,
    0x00b8, 0x00b9, 0x00ba, 0x00bb, 0x00bc, 0x00bd, 0x00be, 0x00bf,
    0x00c0, 0x00c1, 0x00c2, 0x00c3, 0x00c4, 0x00c5, 0x00c6, 0x00c7,
    0x00c8, 0x00c9, 0x00ca, 0x00cb, 0x00cc, 0x00cd, 0x00ce, 0x00cf,
    0x00d0, 0x00d1, 0x00d2, 0x00d3, 0x00d4, 0x00d5, 0x00d6, 0x00d7,
    0x00d8, 0x00d9, 0x00da, 0x00db, 0x00dc, 0x00dd, 0x00de, 0x00df,
    0x00e0, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5, 0x00e6, 0x00e7,
    0x00e8, 0x00e9, 0x00ea, 0x00eb, 0x00ec, 0x00ed, 0x00ee, 0x00ef,
    0x00f0, 0x00f1, 0x00f2, 0x00f3, 0x00f4, 0x00f5, 0x00f6, 0x00f7,
    0x00f8, 0x00f9, 0x00fa, 0x00fb, 0x00fc, 0x00fd, 0x00fe, 0x00ff
  },
  /* VT100 graphics mapped to Unicode */
  [GRAF_MAP] = {
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007,
    0x0008, 0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x000e, 0x000f,
    0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017,
    0x0018, 0x0019, 0x001a, 0x001b, 0x001c, 0x001d, 0x001e, 0x001f,
    0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027,
    0x0028, 0x0029, 0x002a, 0x2192, 0x2190, 0x2191, 0x2193, 0x002f,
    0x2588, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,
    0x0038, 0x0039, 0x003a, 0x003b, 0x003c, 0x003d, 0x003e, 0x003f,
    0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,
    0x0048, 0x0049, 0x004a, 0x004b, 0x004c, 0x004d, 0x004e, 0x004f,
    0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057,
    0x0058, 0x0059, 0x005a, 0x005b, 0x005c, 0x005d, 0x005e, 0x00a0,
    0x25c6, 0x2592, 0x2409, 0x240c, 0x240d, 0x240a, 0x00b0, 0x00b1,
    0x2591, 0x240b, 0x2518, 0x2510, 0x250c, 0x2514, 0x253c, 0x23ba,
    0x23bb, 0x2500, 0x23bc, 0x23bd, 0x251c, 0x2524, 0x2534, 0x252c,
    0x2502, 0x2264, 0x2265, 0x03c0, 0x2260, 0x00a3, 0x00b7, 0x007f,
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,
    0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x008d, 0x008e, 0x008f,
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,
    0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,
    0x00a0, 0x00a1, 0x00a2, 0x00a3, 0x00a4, 0x00a5, 0x00a6, 0x00a7,
    0x00a8, 0x00a9, 0x00aa, 0x00ab, 0x00ac, 0x00ad, 0x00ae, 0x00af,
    0x00b0, 0x00b1, 0x00b2, 0x00b3, 0x00b4, 0x00b5, 0x00b6, 0x00b7,
    0x00b8, 0x00b9, 0x00ba, 0x00bb, 0x00bc, 0x00bd, 0x00be, 0x00bf,
    0x00c0, 0x00c1, 0x00c2, 0x00c3, 0x00c4, 0x00c5, 0x00c6, 0x00c7,
    0x00c8, 0x00c9, 0x00ca, 0x00cb, 0x00cc, 0x00cd, 0x00ce, 0x00cf,
    0x00d0, 0x00d1, 0x00d2, 0x00d3, 0x00d4, 0x00d5, 0x00d6, 0x00d7,
    0x00d8, 0x00d9, 0x00da, 0x00db, 0x00dc, 0x00dd, 0x00de, 0x00df,
    0x00e0, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5, 0x00e6, 0x00e7,
    0x00e8, 0x00e9, 0x00ea, 0x00eb, 0x00ec, 0x00ed, 0x00ee, 0x00ef,
    0x00f0, 0x00f1, 0x00f2, 0x00f3, 0x00f4, 0x00f5, 0x00f6, 0x00f7,
    0x00f8, 0x00f9, 0x00fa, 0x00fb, 0x00fc, 0x00fd, 0x00fe, 0x00ff
  },
  /* IBM Codepage 437 mapped to Unicode */
  [IBMPC_MAP] = {
    0x0000, 0x263a, 0x263b, 0x2665, 0x2666, 0x2663, 0x2660, 0x2022,
    0x25d8, 0x25cb, 0x25d9, 0x2642, 0x2640, 0x266a, 0x266b, 0x263c,
    0x25b6, 0x25c0, 0x2195, 0x203c, 0x00b6, 0x00a7, 0x25ac, 0x21a8,
    0x2191, 0x2193, 0x2192, 0x2190, 0x221f, 0x2194, 0x25b2, 0x25bc,
    0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027,
    0x0028, 0x0029, 0x002a, 0x002b, 0x002c, 0x002d, 0x002e, 0x002f,
    0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,
    0x0038, 0x0039, 0x003a, 0x003b, 0x003c, 0x003d, 0x003e, 0x003f,
    0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,
    0x0048, 0x0049, 0x004a, 0x004b, 0x004c, 0x004d, 0x004e, 0x004f,
    0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057,
    0x0058, 0x0059, 0x005a, 0x005b, 0x005c, 0x005d, 0x005e, 0x005f,
    0x0060, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,
    0x0068, 0x0069, 0x006a, 0x006b, 0x006c, 0x006d, 0x006e, 0x006f,
    0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077,
    0x0078, 0x0079, 0x007a, 0x007b, 0x007c, 0x007d, 0x007e, 0x2302,
    0x00c7, 0x00fc, 0x00e9, 0x00e2, 0x00e4, 0x00e0, 0x00e5, 0x00e7,
    0x00ea, 0x00eb, 0x00e8, 0x00ef, 0x00ee, 0x00ec, 0x00c4, 0x00c5,
    0x00c9, 0x00e6, 0x00c6, 0x00f4, 0x00f6, 0x00f2, 0x00fb, 0x00f9,
    0x00ff, 0x00d6, 0x00dc, 0x00a2, 0x00a3, 0x00a5, 0x20a7, 0x0192,
    0x00e1, 0x00ed, 0x00f3, 0x00fa, 0x00f1, 0x00d1, 0x00aa, 0x00ba,
    0x00bf, 0x2310, 0x00ac, 0x00bd, 0x00bc, 0x00a1, 0x00ab, 0x00bb,
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556,
    0x2555, 0x2563, 0x2551, 0x2557, 0x255d, 0x255c, 0x255b, 0x2510,
    0x2514, 0x2534, 0x252c, 0x251c, 0x2500, 0x253c, 0x255e, 0x255f,
    0x255a, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256c, 0x2567,
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256b,
    0x256a, 0x2518, 0x250c, 0x2588, 0x2584, 0x258c, 0x2590, 0x2580,
    0x03b1, 0x00df, 0x0393, 0x03c0, 0x03a3, 0x03c3, 0x00b5, 0x03c4,
    0x03a6, 0x0398, 0x03a9, 0x03b4, 0x221e, 0x03c6, 0x03b5, 0x2229,
    0x2261, 0x00b1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00f7, 0x2248,
    0x00b0, 0x2219, 0x00b7, 0x221a, 0x207f, 0x00b2, 0x25a0, 0x00a0
  },
  /* User mapping -- default to codes for direct font mapping */
  [USER_MAP] = {
    0xf000, 0xf001, 0xf002, 0xf003, 0xf004, 0xf005, 0xf006, 0xf007,
    0xf008, 0xf009, 0xf00a, 0xf00b, 0xf00c, 0xf00d, 0xf00e, 0xf00f,
    0xf010, 0xf011, 0xf012, 0xf013, 0xf014, 0xf015, 0xf016, 0xf017,
    0xf018, 0xf019, 0xf01a, 0xf01b, 0xf01c, 0xf01d, 0xf01e, 0xf01f,
    0xf020, 0xf021, 0xf022, 0xf023, 0xf024, 0xf025, 0xf026, 0xf027,
    0xf028, 0xf029, 0xf02a, 0xf02b, 0xf02c, 0xf02d, 0xf02e, 0xf02f,
    0xf030, 0xf031, 0xf032, 0xf033, 0xf034, 0xf035, 0xf036, 0xf037,
    0xf038, 0xf039, 0xf03a, 0xf03b, 0xf03c, 0xf03d, 0xf03e, 0xf03f,
    0xf040, 0xf041, 0xf042, 0xf043, 0xf044, 0xf045, 0xf046, 0xf047,
    0xf048, 0xf049, 0xf04a, 0xf04b, 0xf04c, 0xf04d, 0xf04e, 0xf04f,
    0xf050, 0xf051, 0xf052, 0xf053, 0xf054, 0xf055, 0xf056, 0xf057,
    0xf058, 0xf059, 0xf05a, 0xf05b, 0xf05c, 0xf05d, 0xf05e, 0xf05f,
    0xf060, 0xf061, 0xf062, 0xf063, 0xf064, 0xf065, 0xf066, 0xf067,
    0xf068, 0xf069, 0xf06a, 0xf06b, 0xf06c, 0xf06d, 0xf06e, 0xf06f,
    0xf070, 0xf071, 0xf072, 0xf073, 0xf074, 0xf075, 0xf076, 0xf077,
    0xf078, 0xf079, 0xf07a, 0xf07b, 0xf07c, 0xf07d, 0xf07e, 0xf07f,
    0xf080, 0xf081, 0xf082, 0xf083, 0xf084, 0xf085, 0xf086, 0xf087,
    0xf088, 0xf089, 0xf08a, 0xf08b, 0xf08c, 0xf08d, 0xf08e, 0xf08f,
    0xf090, 0xf091, 0xf092, 0xf093, 0xf094, 0xf095, 0xf096, 0xf097,
    0xf098, 0xf099, 0xf09a, 0xf09b, 0xf09c, 0xf09d, 0xf09e, 0xf09f,
    0xf0a0, 0xf0a1, 0xf0a2, 0xf0a3, 0xf0a4, 0xf0a5, 0xf0a6, 0xf0a7,
    0xf0a8, 0xf0a9, 0xf0aa, 0xf0ab, 0xf0ac, 0xf0ad, 0xf0ae, 0xf0af,
    0xf0b0, 0xf0b1, 0xf0b2, 0xf0b3, 0xf0b4, 0xf0b5, 0xf0b6, 0xf0b7,
    0xf0b8, 0xf0b9, 0xf0ba, 0xf0bb, 0xf0bc, 0xf0bd, 0xf0be, 0xf0bf,
    0xf0c0, 0xf0c1, 0xf0c2, 0xf0c3, 0xf0c4, 0xf0c5, 0xf0c6, 0xf0c7,
    0xf0c8, 0xf0c9, 0xf0ca, 0xf0cb, 0xf0cc, 0xf0cd, 0xf0ce, 0xf0cf,
    0xf0d0, 0xf0d1, 0xf0d2, 0xf0d3, 0xf0d4, 0xf0d5, 0xf0d6, 0xf0d7,
    0xf0d8, 0xf0d9, 0xf0da, 0xf0db, 0xf0dc, 0xf0dd, 0xf0de, 0xf0df,
    0xf0e0, 0xf0e1, 0xf0e2, 0xf0e3, 0xf0e4, 0xf0e5, 0xf0e6, 0xf0e7,
    0xf0e8, 0xf0e9, 0xf0ea, 0xf0eb, 0xf0ec, 0xf0ed, 0xf0ee, 0xf0ef,
    0xf0f0, 0xf0f1, 0xf0f2, 0xf0f3, 0xf0f4, 0xf0f5, 0xf0f6, 0xf0f7,
    0xf0f8, 0xf0f9, 0xf0fa, 0xf0fb, 0xf0fc, 0xf0fd, 0xf0fe, 0xf0ff
  }
};

unsigned short *set_translate(enum translation_map m, struct vc_data *vc)
{
	inv_translate[vc->vc_num] = m;
	return translations[m];
}

/* is this char_state an ANSI control string? */
static int ansi_control_string(unsigned int char_state)
{
	if (char_state == ESosc || char_state == ESapc || char_state == ESpm || char_state == ESdcs)
		return 1;
	return 0;
}

static void set_origin(struct vc_data *vc)
{
	vc->vc_origin = (unsigned long)vc->vc_screenbuf;
	vc->vc_visible_origin = vc->vc_origin;
	vc->vc_scr_end = vc->vc_origin + vc->vc_screenbuf_size;
	vc->vc_pos = vc->vc_origin + vc->vc_size_row * vc->state.y + 2 * vc->state.x;
}

static void gotoxy(struct vc_data *vc, int new_x, int new_y)
{
	int min_y, max_y;

	if (new_x < 0)
		vc->state.x = 0;
	else {
		if ((unsigned int)new_x >= vc->vc_cols)
			vc->state.x = vc->vc_cols - 1;
		else
			vc->state.x = new_x;
	}

 	if (vc->vc_decom) {
		min_y = vc->vc_top;
		max_y = vc->vc_bottom;
	} else {
		min_y = 0;
		max_y = vc->vc_rows;
	}
	if (new_y < min_y)
		vc->state.y = min_y;
	else if (new_y >= max_y)
		vc->state.y = max_y - 1;
	else
		vc->state.y = new_y;
	vc->vc_pos = vc->vc_origin + vc->state.y * vc->vc_size_row +
		(vc->state.x << 1);
	vc->vc_need_wrap = 0;
}

/*  */
static void save_cur(struct vc_data *vc)
{
	memcpy(&vc->saved_state, &vc->state, sizeof(vc->state));
}

static unsigned int **vc_uniscr_alloc(unsigned int cols, unsigned int rows)
{
	unsigned int **uni_lines;
	void *p;
	unsigned int memsize, i, col_size = cols * sizeof(**uni_lines);

	/* allocate everything in one go */
	memsize = col_size * rows;
	memsize += rows * sizeof(*uni_lines);
	uni_lines = xcalloc(1, memsize);
	if (!uni_lines)
		return NULL;

	/* initial line pointers */
	p = uni_lines + rows;
	for (i = 0; i < rows; i++) {
		uni_lines[i] = p;
		p += col_size;
	}

	return uni_lines;
}

static void vc_uniscr_free(unsigned int **uni_lines)
{
	free(uni_lines);
}

static void vc_uniscr_set(struct vc_data *vc, unsigned int **new_uni_lines)
{
	vc_uniscr_free(vc->vc_uni_lines);
	vc->vc_uni_lines = new_uni_lines;
}

static void vc_uniscr_putc(struct vc_data *vc, unsigned int uc)
{
	if (vc->vc_uni_lines)
		vc->vc_uni_lines[vc->state.y][vc->state.x] = uc;
}

static void vc_uniscr_insert(struct vc_data *vc, unsigned int nr)
{
	if (vc->vc_uni_lines) {
		unsigned int *ln = vc->vc_uni_lines[vc->state.y];
		unsigned int x = vc->state.x, cols = vc->vc_cols;

		memmove(&ln[x + nr], &ln[x], (cols - x - nr) * sizeof(*ln));
		memset(&ln[x], ' ', nr);
	}
}

static void vc_uniscr_delete(struct vc_data *vc, unsigned int nr)
{
	if (vc->vc_uni_lines) {
		unsigned int *ln = vc->vc_uni_lines[vc->state.y];
		unsigned int x = vc->state.x, cols = vc->vc_cols;

		memcpy(&ln[x], &ln[x + nr], (cols - x - nr) * sizeof(*ln));
		memset(&ln[cols - nr], ' ', nr);
	}
}

static void vc_uniscr_clear_line(struct vc_data *vc, unsigned int x, unsigned int nr)
{
	if (vc->vc_uni_lines)
		memset(&vc->vc_uni_lines[vc->state.y][x], ' ', nr);
}

static void vc_uniscr_clear_lines(struct vc_data *vc, unsigned int y, unsigned int nr)
{
	if (vc->vc_uni_lines)
		while (nr--)
			memset(vc->vc_uni_lines[y++], ' ', vc->vc_cols);
}

#define VC_MAXCOL (32767)
#define VC_MAXROW (32767)
#define VC_MALLOC_SIZE_MAX  (1 << 22)
int vc_do_resize(struct vc_data *vc, unsigned int cols, unsigned int lines)
{
    unsigned int new_cols, new_rows, new_row_size, new_screen_size;
    unsigned int **new_uniscr = NULL;
    unsigned short *oldscreen, *newscreen;

    if (!vc) {
        return -1;
    }

    if (cols > VC_MAXCOL || lines > VC_MAXROW) {
        return -EINVAL;
    }

    new_cols = (cols ? cols : vc->vc_cols);
    new_rows = (lines ? lines : vc->vc_rows);
    new_row_size = new_cols << 1;
    new_screen_size = new_row_size * new_rows;

    if (new_cols == vc->vc_cols && new_rows == vc->vc_rows) {
        return 0;
    }

    if (new_screen_size > VC_MALLOC_SIZE_MAX || !new_screen_size) {
        return -1;
    }

    newscreen = xcalloc(1, new_screen_size);
    if (!newscreen)
        return -ENOMEM;

    new_uniscr = vc_uniscr_alloc(new_cols, new_rows);
    if (!new_uniscr) {
        free(newscreen);
        return -ENOMEM;
    }

    vc->vc_rows = new_rows;
    vc->vc_cols = new_cols;
    vc->vc_size_row = new_row_size;
    vc->vc_screenbuf_size = new_screen_size;
    vc_uniscr_set(vc, new_uniscr);

    if (vc->vc_screenbuf)
        free(vc->vc_screenbuf);
    vc->vc_screenbuf = newscreen;
    vc->vc_screenbuf_size = new_screen_size;
    set_origin(vc);
    vc->vc_top = 0;
    vc->vc_bottom = vc->vc_rows;
    gotoxy(vc, vc->state.x, vc->state.y);
    save_cur(vc);
    return 0;
}

static inline int vc_translate_ascii(const struct vc_data *vc, int c)
{
	if (1) {
		if (vc->vc_toggle_meta)
			c |= 0x80;

		return vc->vc_translate[c];
	}

	return c;
}

/* 过滤掉utf8 字符中的坏点 */
static inline int vc_sanitize_unicode(const int c)
{
	if ((c >= 0xd800 && c <= 0xdfff) || c == 0xfffe || c == 0xffff)
		return 0xfffd;

	return c;
}

/* utf8 编码格式：：
码点的位数	码点起值	码点终值	字节序列	   Byte 1		Byte 2		Byte 3		Byte 4		Byte 5		Byte 6
7			U+0000		U+007F		1			0xxxxxxx
11			U+0080		U+07FF		2			110xxxxx	10xxxxxx
16			U+0800		U+FFFF		3			1110xxxx	10xxxxxx	10xxxxxx
21			U+10000		U+1FFFFF	4			11110xxx	10xxxxxx	10xxxxxx	10xxxxxx
26			U+200000	U+3FFFFFF	5			111110xx	10xxxxxx	10xxxxxx	10xxxxxx	10xxxxxx
31			U+4000000	U+7FFFFFFF	6			1111110x	10xxxxxx	10xxxxxx	10xxxxxx	10xxxxxx	10xxxxxx
*/
static int vc_translate_unicode(struct vc_data *vc, int c, bool *rescan)
{
    /* 每种长度的utf8编码最大值 */
    static const unsigned int utf8_length_changes[] = {
        0x0000007f, 0x000007ff, 0x0000ffff,
        0x001fffff, 0x03ffffff, 0x7fffffff
    };

    /* 收到了utf8 除起始字节以外的字节 */
    if ((c & 0xc0) == 0x80) {
        /* Unexpected continuation byte? */
        if (!vc->vc_utf_count)
            return 0xfffd;

        vc->vc_utf_char = (vc->vc_utf_char << 6) | (c & 0x3f);
        vc->vc_npar++;
        if (--vc->vc_utf_count)
            goto need_more_bytes;

        /* Got a whole character */
        c = vc->vc_utf_char;
        /* Reject overlong sequences */
        if (c <= utf8_length_changes[vc->vc_npar - 1] ||
                c > utf8_length_changes[vc->vc_npar])
            return 0xfffd;

        return vc_sanitize_unicode(c);
    }

    /* 在期望获取到utf8后续字节的状态下，收到了一个普通的ascII码，
       清理掉之前的utf8状态缓存，并将这个ascii码，重新带入到外层的逻辑中 */
    if (vc->vc_utf_count) {
        /* Continuation byte expected */
        *rescan = true;
        vc->vc_utf_count = 0;
        return 0xfffd;
    }

    /* Nothing to do if an ASCII byte was received */
    if (c <= 0x7f)
        return c;

    /* First byte of a multibyte sequence received */
    vc->vc_npar = 0;
    if ((c & 0xe0) == 0xc0) {
        vc->vc_utf_count = 1;
        vc->vc_utf_char = (c & 0x1f);
    } else if ((c & 0xf0) == 0xe0) {
        vc->vc_utf_count = 2;
        vc->vc_utf_char = (c & 0x0f);
    } else if ((c & 0xf8) == 0xf0) {
        vc->vc_utf_count = 3;
        vc->vc_utf_char = (c & 0x07);
    } else if ((c & 0xfc) == 0xf8) {
        vc->vc_utf_count = 4;
        vc->vc_utf_char = (c & 0x03);
    } else if ((c & 0xfe) == 0xfc) {
        vc->vc_utf_count = 5;
        vc->vc_utf_char = (c & 0x01);
    } else {
        /* 254 and 255 are invalid */
        return 0xfffd;
    }

need_more_bytes:
    return -1;
}

static int vc_translate(struct vc_data *vc, int *c, bool *rescan)
{
	/* Do no translation at all in control states */
	if (vc->vc_state != ESnormal)
		return *c;

	if (vc->vc_utf && !vc->vc_disp_ctrl)
		return *c = vc_translate_unicode(vc, *c, rescan);

	/* no utf or alternate charset mode */
	return vc_translate_ascii(vc, *c);
}

/* for absolute user moves, when decom is set */
static void gotoxay(struct vc_data *vc, int new_x, int new_y)
{
	gotoxy(vc, new_x, vc->vc_decom ? (vc->vc_top + new_y) : new_y);
}

struct interval {
	uint32_t first;
	uint32_t last;
};

#define ARRAY_SIZE(arr)     (sizeof(arr)/sizeof(arr[0]))

static int ucs_cmp(const void *key, const void *elt)
{
	uint32_t ucs = *(uint32_t *)key;
	struct interval e = *(struct interval *) elt;

	if (ucs > e.last)
		return 1;
	else if (ucs < e.first)
		return -1;
	return 0;
}

typedef int (*cmp_func_t)(const void *a, const void *b);

static int is_double_width(uint32_t ucs)
{
	static const struct interval double_width[] = {
		{ 0x1100, 0x115F }, { 0x2329, 0x232A }, { 0x2E80, 0x303E },
		{ 0x3040, 0xA4CF }, { 0xAC00, 0xD7A3 }, { 0xF900, 0xFAFF },
		{ 0xFE10, 0xFE19 }, { 0xFE30, 0xFE6F }, { 0xFF00, 0xFF60 },
		{ 0xFFE0, 0xFFE6 }, { 0x20000, 0x2FFFD }, { 0x30000, 0x3FFFD }
	};
	if (ucs < double_width[0].first || ucs > double_width[ARRAY_SIZE(double_width) - 1].last)
		return 0;

	return bsearch(&ucs, double_width, ARRAY_SIZE(double_width),
			sizeof(struct interval), ucs_cmp) != NULL;
}

#define UNI_DIRECT_BASE 0xF000	/* start of Direct Font Region */
#define UNI_DIRECT_MASK 0x01FF	/* Direct Font Region bitmask */
int conv_uni_to_pc(struct vc_data *conp, long ucs)
{
    struct uni_pagedict *dict;
	unsigned short **dir, *row, glyph;

	/* Only 16-bit codes supported at this time */
	if (ucs > 0xffff)
		return -4;		/* Not found */
	else if (ucs < 0x20)
		return -1;		/* Not a printable character */
	else if (ucs == 0xfeff || (ucs >= 0x200b && ucs <= 0x200f))
		return -2;			/* Zero-width space */
	/*
	 * UNI_DIRECT_BASE indicates the start of the region in the User Zone
	 * which always has a 1:1 mapping to the currently loaded font.  The
	 * UNI_DIRECT_MASK indicates the bit span of the region.
	 */
	else if ((ucs & ~UNI_DIRECT_MASK) == UNI_DIRECT_BASE)
		return ucs & UNI_DIRECT_MASK;

    dict = *conp->uni_pagedict_loc;
	if (!dict)
		return -3;

	dir = dict->uni_pgdir[UNI_DIR(ucs)];
	if (!dir)
		return -4;

	row = dir[UNI_ROW(ucs)];
	if (!row)
		return -4;

	glyph = row[UNI_GLYPH(ucs)];
	if (glyph >= MAX_GLYPH)
		return -4;

    //debug_p("ucs=0x%x, glyph=0x%x\n", ucs, glyph);
	return glyph;
}

static void cmd_char_handle(cmd_t *pcmd, int ch)
{
    if (ansi_control_string(pcmd->char_state) && ch >= 8 && ch <= 13) {
        return;
    }

    switch (ch) {
    case 0:
        return;
    case 7:             /* bell键 */
        if (ansi_control_string(pcmd->char_state)) {
            pcmd->char_state = ESnormal;
        }
    case 8:             /* 普通的退格键 */
        return;
    case 9:
        return;
    case 10:
    case 13:
        debug_p("cmd: %s", sshbuf_ptr(pcmd->cmd_buf));
        pcmd->cmd_state = CSrespd;
        return;
    case 11:
    case 12:
        return;
    case 14:
        return;
    case 15:
        return;
    case 24:
    case 26:
        pcmd->char_state = ESnormal;
        return;
    case 27:
        pcmd->char_state = ESesc;
        return;
    case ';':
        return;
    case '|':
        return;
    case '&':
        return;
    case 127:
        return;
    case 128+27:
        pcmd->char_state = ESsquare;
        return;
    }

    switch (pcmd->char_state) {
    case ESesc:
        pcmd->char_state = ESnormal;

        switch (ch) {
        case '[':
            pcmd->char_state = ESsquare;
            return;
        case ']':
            pcmd->char_state = ESnonstd;
            return;
        case '_':
            pcmd->char_state = ESapc;
            return;
        case '^':
            pcmd->char_state = ESpm;
            return;
        case '%':
            pcmd->char_state = ESpercent;
            return;
        case '(':
            pcmd->char_state = ESsetG0;
            return;
        case ')':
            pcmd->char_state = ESsetG1;
            return;
        case '#':
            pcmd->char_state = EShash;
            return;
        case 'P':
            pcmd->char_state = ESdcs;
            return;
        case 'E':
        case 'M':
        case 'D':
        case 'H':
        case 'Z':
        case '7':
        case '8':
        case 'c':
        case '>':
        case '=':
            return;
        }

        return;
    case ESnonstd:
        if (ch == 'P') {
            pcmd->char_state = ESpalette;
        } else if (ch == 'R') {
            pcmd->char_state = ESnormal;
        } else if (ch >= '0' && ch <= '9') {
            pcmd->char_state = ESosc;
        } else {
            pcmd->char_state = ESnormal;
        }
        return;
    case ESpalette:
        pcmd->char_state = ESnormal;
        return;
    case ESsquare:
        pcmd->char_state = ESgetpars;
        if (ch == '[') {
            pcmd->char_state = ESfunckey;
            return;
        }

        switch (ch) {
        case '?':
			return;
        case '>':
            return;
        case '=':
            return;
        case '<':
            return;
        }
        // fallthrough;
    case ESgetpars:

        pcmd->char_state = ESnormal;
        switch (ch) {
        case 'h':
            /* code */
            return;
        case 'l':
            return;
        case 'c':
            return;
        case 'm':
            return;
        case 'n':
            return;
        }

        switch (ch) {
        case 'G':
        case '`':
            /* code */
            return;
        case 'A':
            pcmd->key_state = KSup;
            pcmd->cmd_state = CSfindrespd;
            debug_p("up");
            return;
        case 'B':
        case 'e':
            debug_p("down");
            return;
        case 'C':
        case 'a':
            debug_p("right");
            return;
        case 'D':
            debug_p("left");
            return;
        case 'E':
            return;
        case 'F':
            return;
        case 'd':
            return;
        case 'H':
        case 'f':
            return;
        case 'J':
            return;
        case 'K':
            return;
        case 'L':
            return;
        case 'M':
            return;
        case 'P':
            return;
        case 'c':
            return;
        case 'g':
            return;
        case 'm':
            return;
        case 'q':
            return;
        case 'r':
            return;
        case 's':
            return;
        case 'u':
            return;
        case 'X':
            return;
        case '@':
            return;
        case ']':
            return;
        }

        return;
    case EScsiignore:
        if (ch >= 20 && ch <= 0x3f)
			return;
		pcmd->char_state = ESnormal;
		return;
    case ESpercent:
        pcmd->char_state = ESnormal;
        switch (ch) {
        case '@':
            /* code */
            return;
        case 'G':
        case '8':
            return;
        }

        return;
    case ESfunckey:
        pcmd->char_state = ESnormal;
        return;
    case EShash:
        pcmd->char_state = ESnormal;
        if (ch == '8') {
        }
        return;
    case ESsetG0:
        pcmd->char_state = ESnormal;
        return;
    case ESsetG1:
        pcmd->char_state = ESnormal;
        return;
    case ESapc:
    case ESosc:
    case ESpm:
    case ESdcs:
        return;
    default:
        pcmd->char_state = ESnormal;
        sshbuf_put_u8(pcmd->cmd_buf, (uint8_t)ch);
    }
}

#define BIT(nr)			(((unsigned int)1) << (nr))
#define BIT_ULL(nr)		(((unsigned long)1) << (nr))
static bool vc_is_control(struct vc_data *vc, int tc, int c)
{
	/*
	 * A bitmap for codes <32. A bit of 1 indicates that the code
	 * corresponding to that bit number invokes some special action (such
	 * as cursor movement) and should not be displayed as a glyph unless
	 * the disp_ctrl mode is explicitly enabled.
	 */
	static const unsigned int CTRL_ACTION = 0x0d00ff81;
	/* Cannot be overridden by disp_ctrl */
	static const unsigned int CTRL_ALWAYS = 0x0800f501;

	if (vc->vc_state != ESnormal)
		return true;

	if (!tc)
		return true;

	/*
	 * If the original code was a control character we only allow a glyph
	 * to be displayed if the code is not normally used (such as for cursor
	 * movement) or if the disp_ctrl mode has been explicitly enabled.
	 * Certain characters (as given by the CTRL_ALWAYS bitmap) are always
	 * displayed as control characters, as the console would be pretty
	 * useless without them; to display an arbitrary font position use the
	 * direct-to-font zone in UTF-8 mode.
	 */
	if (c < 32) {
		if (vc->vc_disp_ctrl)
			return CTRL_ALWAYS & BIT(c);
		else
			return vc->vc_utf || (CTRL_ACTION & BIT(c));
	}

	if (c == 127 && !vc->vc_disp_ctrl)
		return true;

	if (c == 128 + 27)
		return true;

	return false;
}

static inline void bs(struct vc_data *vc)
{
	if (vc->state.x) {
		vc->vc_pos -= 2;
		vc->state.x--;
		vc->vc_need_wrap = 0;
	}
}

static inline void cr(struct vc_data *vc)
{
	vc->vc_pos -= vc->state.x << 1;
	vc->vc_need_wrap = vc->state.x = 0;
}

static void lf(struct vc_data *vc)
{
    /* don't scroll if above bottom of scrolling region, or
	 * if below scrolling region
	 */
	if (vc->state.y + 1 == vc->vc_bottom) {
        debug_p("y at bottom");
        // con_scroll(vc, vc->vc_top, vc->vc_bottom, SM_UP, 1);
    }
	else if (vc->state.y < vc->vc_rows - 1) {
		vc->state.y++;
		vc->vc_pos += vc->vc_size_row;
	}
	vc->vc_need_wrap = 0;
	//notify_write(vc, '\n');
}

static inline void del(struct vc_data *vc)
{
	/* ignored */
}

static void ri(struct vc_data *vc)
{
	/* don't scroll if below top of scrolling region, or
	 * if above scrolling region
	 */
	if (vc->state.y == vc->vc_top) {
        debug_p("y at top");
		//con_scroll(vc, vc->vc_top, vc->vc_bottom, SM_DOWN, 1);
    }
	else if (vc->state.y > 0) {
		vc->state.y--;
		vc->vc_pos -= vc->vc_size_row;
	}
	vc->vc_need_wrap = 0;
}

static inline unsigned char vc_invert_attr(const struct vc_data *vc)
{
	return vc->vc_attr ^ 0x08;
}

static int vc_con_write_normal(struct vc_data *vc, int tc, int c)
{
    int next_c;
    unsigned char width = 1;
    unsigned char vc_attr = vc->vc_attr;
    bool inverse = false;
    unsigned short himask = vc->vc_hi_font_mask;
    unsigned short charmask = himask ? 0x1ff : 0xff;

    if (vc->vc_utf && !vc->vc_disp_ctrl && is_double_width(c)) {
        width = 2;
    }

    tc = conv_uni_to_pc(vc, tc);
    if (tc & ~charmask) {
		if (tc == -1 || tc == -2)
			return -1; /* nothing to display */

		/* Glyph not found */
		if ((!vc->vc_utf || vc->vc_disp_ctrl || c < 128) && !(c & ~charmask)) {
			tc = c;
		} else {
			/*
			 * Display U+FFFD. If it's not found, display an inverse
			 * question mark.
			 */
			tc = conv_uni_to_pc(vc, 0xfffd);
			if (tc < 0) {
				inverse = true;
				tc = conv_uni_to_pc(vc, '?');
				if (tc < 0)
					tc = '?';

                vc_attr = vc_invert_attr(vc);
			}
		}
	}

	next_c = c;
	while (1) {
		if (vc->vc_need_wrap || vc->vc_decim) {
			//con_flush(vc, draw);
        }
		if (vc->vc_need_wrap) {
			cr(vc);
			lf(vc);
		}
		if (vc->vc_decim) {
            vc_uniscr_insert(vc, 1);
        }

        //debug_p("%c", next_c);
        vc_uniscr_putc(vc, next_c);

        if (himask) {
            tc = ((tc & 0x100) ? himask : 0) | (tc &  0xff);
        }
        tc |= (vc_attr << 8) & ~himask;

        /*
		vc_uniscr_putc(vc, next_c);

		scr_writew(tc, (unsigned short *)vc->vc_pos);

		if (con_should_update(vc) && draw->x < 0) {
			draw->x = vc->state.x;
			draw->from = vc->vc_pos;
		}
        */

		if (vc->state.x == vc->vc_cols - 1) {
			vc->vc_need_wrap = vc->vc_decawm;
		} else {
			vc->state.x++;
		}

		if (!--width)
			break;

		/* A space is printed in the second column */
		tc = conv_uni_to_pc(vc, ' ');
		if (tc < 0)
			tc = ' ';
		next_c = ' ';
	}
	//notify_write(vc, c);

    /*
	if (inverse)
		con_flush(vc, draw);
    */
	return 0;
}

/* console_lock is held */
static void restore_cur(struct vc_data *vc)
{
	memcpy(&vc->state, &vc->saved_state, sizeof(vc->state));

	gotoxy(vc, vc->state.x, vc->state.y);
	vc->vc_translate = set_translate(vc->state.Gx_charset[vc->state.charset],
			vc);
	vc->vc_need_wrap = 0;
}

int hex_to_bin(unsigned char ch)
{
	unsigned char cu = ch & 0xdf;
	return -1 +
		((ch - '0' +  1) & (unsigned)((ch - '9' - 1) & ('0' - 1 - ch)) >> 8) +
		((cu - 'A' + 11) & (unsigned)((cu - 'F' - 1) & ('A' - 1 - cu)) >> 8);
}

enum { EPecma = 0, EPdec, EPeq, EPgt, EPlt};

/* console_lock is held */
static void set_mode(struct vc_data *vc, int on_off)
{
	int i;

	for (i = 0; i <= vc->vc_npar; i++)
		if (vc->vc_priv == EPdec) {
			switch(vc->vc_par[i]) {	/* DEC private modes set/reset */
			case 1:			/* Cursor keys send ^[Ox/^[[x */
				break;
			case 3:	/* 80/132 mode switch unimplemented */
				break;
			case 5:			/* Inverted screen on/off */
				if (vc->vc_decscnm != on_off) {
					vc->vc_decscnm = on_off;
                    /*
					invert_screen(vc, 0,
							vc->vc_screenbuf_size,
							false);
					update_attr(vc);
                    */
				}
				break;
			case 6:			/* Origin relative/absolute */
				vc->vc_decom = on_off;
				gotoxay(vc, 0, 0);
				break;
			case 7:			/* Autowrap on/off */
				vc->vc_decawm = on_off;
				break;
			case 8:			/* Autorepeat on/off */
                /*
				if (on_off)
					set_kbd(vc, decarm);
				else
					clr_kbd(vc, decarm);
                */
				break;
			case 9:
				vc->vc_report_mouse = on_off ? 1 : 0;
				break;
			case 25:		/* Cursor on/off */
				vc->vc_deccm = on_off;
				break;
			case 1000:
				vc->vc_report_mouse = on_off ? 2 : 0;
				break;
			}
		} else {
			switch(vc->vc_par[i]) {	/* ANSI modes set/reset */
			case 3:			/* Monitor (display ctrls) */
				vc->vc_disp_ctrl = on_off;
				break;
			case 4:			/* Insert Mode on/off */
				vc->vc_decim = on_off;
				break;
			case 20:		/* Lf, Enter == CrLf/Lf */
                /*
				if (on_off)
					set_kbd(vc, lnm);
				else
					clr_kbd(vc, lnm);
                */
				break;
			}
		}
}

static void csi_J(struct vc_data *vc, int vpar)
{
	unsigned int count;
	unsigned short * start;

	switch (vpar) {
		case 0:	/* erase from cursor to end of display */
			vc_uniscr_clear_line(vc, vc->state.x, vc->vc_cols - vc->state.x);
			vc_uniscr_clear_lines(vc, vc->state.y + 1, vc->vc_rows - vc->state.y - 1);
			count = (vc->vc_scr_end - vc->vc_pos) >> 1;
			start = (unsigned short *)vc->vc_pos;
			break;
		case 1:	/* erase from start to cursor */
			vc_uniscr_clear_line(vc, 0, vc->state.x + 1);
			vc_uniscr_clear_lines(vc, 0, vc->state.y);
			count = ((vc->vc_pos - vc->vc_origin) >> 1) + 1;
			start = (unsigned short *)vc->vc_origin;
			break;
		case 3: /* include scrollback */
			//flush_scrollback(vc);
			//// fallthrough;
		case 2: /* erase whole display */
			vc_uniscr_clear_lines(vc, 0, vc->vc_rows);
			count = vc->vc_cols * vc->vc_rows;
			start = (unsigned short *)vc->vc_origin;
			break;
		default:
			return;
	}

	vc->vc_need_wrap = 0;
}

static void csi_K(struct vc_data *vc, int vpar)
{
	unsigned int count;
	unsigned short *start = (unsigned short *)vc->vc_pos;
	int offset;

	switch (vpar) {
		case 0:	/* erase from cursor to end of line */
			offset = 0;
			count = vc->vc_cols - vc->state.x;
			break;
		case 1:	/* erase from start of line to cursor */
			offset = -vc->state.x;
			count = vc->state.x + 1;
			break;
		case 2: /* erase whole line */
			offset = -vc->state.x;
			count = vc->vc_cols;
			break;
		default:
			return;
	}
	vc_uniscr_clear_line(vc, vc->state.x + offset, count);
	//scr_memsetw(start + offset, vc->vc_video_erase_char, 2 * count);
	vc->vc_need_wrap = 0;
}

/* console_lock is held */
static void csi_L(struct vc_data *vc, unsigned int nr)
{
	if (nr > vc->vc_rows - vc->state.y)
		nr = vc->vc_rows - vc->state.y;
	else if (!nr)
		nr = 1;

    //con_scroll(vc, vc->state.y, vc->vc_bottom, SM_DOWN, nr);
	vc->vc_need_wrap = 0;
}

/* console_lock is held */
static void csi_M(struct vc_data *vc, unsigned int nr)
{
	if (nr > vc->vc_rows - vc->state.y)
		nr = vc->vc_rows - vc->state.y;
	else if (!nr)
		nr=1;

    //con_scroll(vc, vc->state.y, vc->vc_bottom, SM_UP, nr);
	vc->vc_need_wrap = 0;
}

/* console_lock is held */
static void csi_P(struct vc_data *vc, unsigned int nr)
{
    if (nr > vc->vc_cols - vc->state.x)
        nr = vc->vc_cols - vc->state.x;
    else if (!nr)
        nr = 1;

    vc_uniscr_delete(vc, nr);
}

/* erase the following vpar positions */
static void csi_X(struct vc_data *vc, unsigned int vpar)
{					  /* not vt100? */
	unsigned int count;

	if (!vpar)
		vpar++;

    unsigned int xs = vc->vc_cols - vc->state.x;
    count = (vpar <= xs) ? vpar : xs;

	vc_uniscr_clear_line(vc, vc->state.x, count);
	vc->vc_need_wrap = 0;
}

/* console_lock is held */
static void csi_at(struct vc_data *vc, unsigned int nr)
{
    if (nr > vc->vc_cols - vc->state.x)
        nr = vc->vc_cols - vc->state.x;
    else if (!nr)
        nr = 1;

    vc_uniscr_insert(vc, nr);
}

static void vc_setGx(struct vc_data *vc, unsigned int which, int c)
{
	unsigned char *charset = &vc->state.Gx_charset[which];

	switch (c) {
	case '0':
		*charset = GRAF_MAP;
		break;
	case 'B':
		*charset = LAT1_MAP;
		break;
	case 'U':
		*charset = IBMPC_MAP;
		break;
	case 'K':
		*charset = USER_MAP;
		break;
	}

	if (vc->state.charset == which)
		vc->vc_translate = set_translate(*charset, vc);
}


#define CUR_MAKE(size, change, set)	((size) | ((change) << 8) |	((set) << 16))

/* console_lock is held */
static void do_con_trol(struct vc_data *vc, int c)
{
	/*
	 *  Control characters can be used in the _middle_
	 *  of an escape sequence, aside from ANSI control strings.
	 */
	if (ansi_control_string(vc->vc_state) && c >= 8 && c <= 13)
		return;
	switch (c) {
	case 0:
		return;
	case 7:
		if (ansi_control_string(vc->vc_state))
			vc->vc_state = ESnormal;
		return;
	case 8:
		bs(vc);
		return;
	case 9:
		debug_p("tab key");
		return;
	case 10: case 11: case 12:
		debug_p("\\n, and fallthrough");
		// fallthrough;
	case 13:
        debug_p("\\r");
		cr(vc);
		return;
	case 14:
		vc->state.charset = 1;
		vc->vc_translate = set_translate(vc->state.Gx_charset[1], vc);
		vc->vc_disp_ctrl = 1;
		return;
	case 15:
		vc->state.charset = 0;
		vc->vc_translate = set_translate(vc->state.Gx_charset[0], vc);
		vc->vc_disp_ctrl = 0;
		return;
	case 24: case 26:
		vc->vc_state = ESnormal;
		return;
	case 27:
		vc->vc_state = ESesc;
		return;
	case 127:
		del(vc);
		return;
	case 128+27:
		vc->vc_state = ESsquare;
		return;
	}
	switch(vc->vc_state) {
	case ESesc:
		vc->vc_state = ESnormal;
		switch (c) {
		case '[':
			vc->vc_state = ESsquare;
			return;
		case ']':
			vc->vc_state = ESnonstd;
			return;
		case '_':
			vc->vc_state = ESapc;
			return;
		case '^':
			vc->vc_state = ESpm;
			return;
		case '%':
			vc->vc_state = ESpercent;
			return;
		case 'E':
			cr(vc);
			lf(vc);
			return;
		case 'M':
			ri(vc);
			return;
		case 'D':
			lf(vc);
			return;
		case 'H':
			/*
            if (vc->state.x < VC_TABSTOPS_COUNT)
				set_bit(vc->state.x, vc->vc_tab_stop);
            */
			return;
		case 'P':
			vc->vc_state = ESdcs;
			return;
		case 'Z':
			//respond_ID(tty);
			return;
		case '7':
			save_cur(vc);
			return;
		case '8':
			restore_cur(vc);
			return;
		case '(':
			vc->vc_state = ESsetG0;
			return;
		case ')':
			vc->vc_state = ESsetG1;
			return;
		case '#':
			vc->vc_state = EShash;
			return;
		case 'c':
			//reset_terminal(vc, 1);
			return;
		case '>':  /* Numeric keypad */
			//clr_kbd(vc, kbdapplic);
			return;
		case '=':  /* Appl. keypad */
			//set_kbd(vc, kbdapplic);
			return;
		}
		return;
	case ESnonstd:
		if (c=='P') {   /* palette escape sequence */
			for (vc->vc_npar = 0; vc->vc_npar < NPAR; vc->vc_npar++)
				vc->vc_par[vc->vc_npar] = 0;
			vc->vc_npar = 0;
			vc->vc_state = ESpalette;
			return;
		} else if (c=='R') {   /* reset palette */
			//reset_palette(vc);
			vc->vc_state = ESnormal;
		} else if (c>='0' && c<='9')
			vc->vc_state = ESosc;
		else
			vc->vc_state = ESnormal;
		return;
	case ESpalette:
		if (isxdigit(c)) {
			vc->vc_par[vc->vc_npar++] = hex_to_bin(c);
			if (vc->vc_npar == 7) {
				int i = vc->vc_par[0] * 3, j = 1;
				vc->vc_palette[i] = 16 * vc->vc_par[j++];
				vc->vc_palette[i++] += vc->vc_par[j++];
				vc->vc_palette[i] = 16 * vc->vc_par[j++];
				vc->vc_palette[i++] += vc->vc_par[j++];
				vc->vc_palette[i] = 16 * vc->vc_par[j++];
				vc->vc_palette[i] += vc->vc_par[j];
				//set_palette(vc);
				vc->vc_state = ESnormal;
			}
		} else
			vc->vc_state = ESnormal;
		return;
	case ESsquare:
		for (vc->vc_npar = 0; vc->vc_npar < NPAR; vc->vc_npar++)
			vc->vc_par[vc->vc_npar] = 0;
		vc->vc_npar = 0;
		vc->vc_state = ESgetpars;
		if (c == '[') { /* Function key */
			vc->vc_state=ESfunckey;
			return;
		}
		switch (c) {
		case '?':
			vc->vc_priv = EPdec;
			return;
		case '>':
			vc->vc_priv = EPgt;
			return;
		case '=':
			vc->vc_priv = EPeq;
			return;
		case '<':
			vc->vc_priv = EPlt;
			return;
		}
		vc->vc_priv = EPecma;
		// fallthrough;
	case ESgetpars:
		if (c == ';' && vc->vc_npar < NPAR - 1) {
			vc->vc_npar++;
			return;
		} else if (c>='0' && c<='9') {
			vc->vc_par[vc->vc_npar] *= 10;
			vc->vc_par[vc->vc_npar] += c - '0';
			return;
		}
		if (c >= 0x20 && c <= 0x3f) { /* 0x2x, 0x3a and 0x3c - 0x3f */
			vc->vc_state = EScsiignore;
			return;
		}
		vc->vc_state = ESnormal;
		switch(c) {
		case 'h':
			if (vc->vc_priv <= EPdec)
				set_mode(vc, 1);
			return;
		case 'l':
			if (vc->vc_priv <= EPdec)
				set_mode(vc, 0);
			return;
		case 'c':
			if (vc->vc_priv == EPdec) {
				if (vc->vc_par[0])
					vc->vc_cursor_type =
						CUR_MAKE(vc->vc_par[0],
							 vc->vc_par[1],
							 vc->vc_par[2]);
				else
					vc->vc_cursor_type = 2;
				return;
			}
			break;
		case 'm':
			if (vc->vc_priv == EPdec) {
				//clear_selection();
				if (vc->vc_par[0])
					vc->vc_complement_mask = vc->vc_par[0] << 8 | vc->vc_par[1];
				else
					vc->vc_complement_mask = vc->vc_s_complement_mask;
				return;
			}
			break;
		case 'n':
			if (vc->vc_priv == EPecma) {
                /*
				if (vc->vc_par[0] == 5)
					status_report(tty);
				else if (vc->vc_par[0] == 6)
					cursor_report(vc, tty);
                */
			}
			return;
		}
		if (vc->vc_priv != EPecma) {
			vc->vc_priv = EPecma;
			return;
		}
		switch(c) {
		case 'G': case '`':
			if (vc->vc_par[0])
				vc->vc_par[0]--;
			gotoxy(vc, vc->vc_par[0], vc->state.y);
			return;
		case 'A':
			if (!vc->vc_par[0])
				vc->vc_par[0]++;
			gotoxy(vc, vc->state.x, vc->state.y - vc->vc_par[0]);
			return;
		case 'B': case 'e':
			if (!vc->vc_par[0])
				vc->vc_par[0]++;
			gotoxy(vc, vc->state.x, vc->state.y + vc->vc_par[0]);
			return;
		case 'C': case 'a':
			if (!vc->vc_par[0])
				vc->vc_par[0]++;
			gotoxy(vc, vc->state.x + vc->vc_par[0], vc->state.y);
			return;
		case 'D':
			if (!vc->vc_par[0])
				vc->vc_par[0]++;
			gotoxy(vc, vc->state.x - vc->vc_par[0], vc->state.y);
			return;
		case 'E':
			if (!vc->vc_par[0])
				vc->vc_par[0]++;
			gotoxy(vc, 0, vc->state.y + vc->vc_par[0]);
			return;
		case 'F':
			if (!vc->vc_par[0])
				vc->vc_par[0]++;
			gotoxy(vc, 0, vc->state.y - vc->vc_par[0]);
			return;
		case 'd':
			if (vc->vc_par[0])
				vc->vc_par[0]--;
			gotoxay(vc, vc->state.x ,vc->vc_par[0]);
			return;
		case 'H': case 'f':
			if (vc->vc_par[0])
				vc->vc_par[0]--;
			if (vc->vc_par[1])
				vc->vc_par[1]--;
			gotoxay(vc, vc->vc_par[1], vc->vc_par[0]);
			return;
		case 'J':
			csi_J(vc, vc->vc_par[0]);
			return;
		case 'K':
			csi_K(vc, vc->vc_par[0]);
			return;
		case 'L':
			csi_L(vc, vc->vc_par[0]);
			return;
		case 'M':
			csi_M(vc, vc->vc_par[0]);
			return;
		case 'P':
			csi_P(vc, vc->vc_par[0]);
			return;
		case 'c':
            /*
			if (!vc->vc_par[0])
				respond_ID(tty);
            */
			return;
		case 'g':
            /*
			if (!vc->vc_par[0] && vc->state.x < VC_TABSTOPS_COUNT)
				set_bit(vc->state.x, vc->vc_tab_stop);
			else if (vc->vc_par[0] == 3)
				bitmap_zero(vc->vc_tab_stop, VC_TABSTOPS_COUNT);
            */
			return;
		case 'm':
			//csi_m(vc);
			return;
		case 'q': /* DECLL - but only 3 leds */
			/* map 0,1,2,3 to 0,1,2,4 */
            /*
			if (vc->vc_par[0] < 4)
				vt_set_led_state(vc->vc_num,
					    (vc->vc_par[0] < 3) ? vc->vc_par[0] : 4);
            */
			return;
		case 'r':
			if (!vc->vc_par[0])
				vc->vc_par[0]++;
			if (!vc->vc_par[1])
				vc->vc_par[1] = vc->vc_rows;
			/* Minimum allowed region is 2 lines */
			if (vc->vc_par[0] < vc->vc_par[1] &&
			    vc->vc_par[1] <= vc->vc_rows) {
				vc->vc_top = vc->vc_par[0] - 1;
				vc->vc_bottom = vc->vc_par[1];
				gotoxay(vc, 0, 0);
			}
			return;
		case 's':
			save_cur(vc);
			return;
		case 'u':
			restore_cur(vc);
			return;
		case 'X':
			csi_X(vc, vc->vc_par[0]);
			return;
		case '@':
			csi_at(vc, vc->vc_par[0]);
			return;
		case ']': /* setterm functions */
			// setterm_command(vc);
			return;
		}
		return;
	case EScsiignore:
		if (c >= 20 && c <= 0x3f)
			return;
		vc->vc_state = ESnormal;
		return;
	case ESpercent:
		vc->vc_state = ESnormal;
		switch (c) {
		case '@':  /* defined in ISO 2022 */
			vc->vc_utf = 0;
			return;
		case 'G':  /* prelim official escape code */
		case '8':  /* retained for compatibility */
			vc->vc_utf = 1;
			return;
		}
		return;
	case ESfunckey:
		vc->vc_state = ESnormal;
		return;
	case EShash:
		vc->vc_state = ESnormal;
		if (c == '8') {
			/* DEC screen alignment test. kludge :-) */
			vc->vc_video_erase_char = (vc->vc_video_erase_char & 0xff00) | 'E';
			csi_J(vc, 2);
			vc->vc_video_erase_char = (vc->vc_video_erase_char & 0xff00) | ' ';
			//do_update_region(vc, vc->vc_origin, vc->vc_screenbuf_size / 2);
		}
		return;
	case ESsetG0:
		vc_setGx(vc, 0, c);
		vc->vc_state = ESnormal;
		return;
	case ESsetG1:
		vc_setGx(vc, 1, c);
		vc->vc_state = ESnormal;
		return;
	case ESapc:
		return;
	case ESosc:
		return;
	case ESpm:
		return;
	case ESdcs:
		return;
	default:
		vc->vc_state = ESnormal;
	}
}

static int do_con_write(struct vc_data *vc, const unsigned char *buf, int count)
{
    int c, tc, n = 0;
    unsigned int currcons;
    bool rescan;
    int orig;

    while (count) {
        orig = *buf;
        buf++;
        n++;
        count--;
rescan_last_byte:
        c = orig;
        rescan = false;

        tc = vc_translate(vc, &c, &rescan);
        if (tc == -1) {
            continue;
        }

        if (vc_is_control(vc, tc, c)) {
            //con_flush(vc, &draw);
            do_con_trol(vc, orig);
            continue;
        }

        if (vc_con_write_normal(vc, tc, c) < 0)
            continue;

        if (rescan)
            goto rescan_last_byte;
    }

    int i = 0;
    for (; i < vc->state.x; ++i) {
        debug_p("vc_uni_lines=%c", (char)(vc->vc_uni_lines[vc->state.y][i]));
    }
    debug_p("len = %u\n", vc->state.x);

    return n;
}

static struct vc_data *vc_data_creat()
{
    struct vc_data *vc = xcalloc(1, sizeof(struct vc_data));
    return vc;
}

/* console_lock is held (except via vc_init()) */
static void reset_terminal(struct vc_data *vc)
{
	unsigned int i;

	vc->vc_top		= 0;
	vc->vc_bottom		= vc->vc_rows;
	vc->vc_state		= ESnormal;
	vc->vc_priv		= EPecma;
	vc->vc_translate	= set_translate(LAT1_MAP, vc);
	vc->state.Gx_charset[0]	= LAT1_MAP;
	vc->state.Gx_charset[1]	= GRAF_MAP;
	vc->state.charset	= 0;
	vc->vc_need_wrap	= 0;
	vc->vc_report_mouse	= 0;
	vc->vc_utf          = true;
	vc->vc_utf_count	= 0;

	vc->vc_disp_ctrl	= 0;
	vc->vc_toggle_meta	= 0;

	vc->vc_decscnm		= 0;
	vc->vc_decom		= 0;
	vc->vc_decawm		= 1;
	vc->vc_deccm		= 1;
	vc->vc_decim		= 0;

	vc->vc_cursor_type = 2;
	vc->vc_complement_mask = vc->vc_s_complement_mask;

	gotoxy(vc, 0, 0);
	save_cur(vc);
}

static void con_release_unimap(struct uni_pagedict *dict)
{
	unsigned int d, r;

	if (dict == dflt)
		dflt = NULL;

	for (d = 0; d < UNI_DIRS; d++) {
		unsigned short **dir = dict->uni_pgdir[d];
		if (dir != NULL) {
			for (r = 0; r < UNI_DIR_ROWS; r++)
				free(dir[r]);
			free(dir);
		}
		dict->uni_pgdir[d] = NULL;
	}

	for (r = 0; r < ARRAY_SIZE(dict->inverse_translations); r++) {
		free(dict->inverse_translations[r]);
		dict->inverse_translations[r] = NULL;
	}

	free(dict->inverse_trans_unicode);
	dict->inverse_trans_unicode = NULL;
}

void con_free_unimap(struct vc_data *vc)
{
	struct uni_pagedict *p;

	p = *vc->uni_pagedict_loc;
	if (!p)
		return;
	*vc->uni_pagedict_loc = NULL;
	if (--p->refcount)
		return;
	con_release_unimap(p);
	free(p);
}

int con_set_default_unimap(struct vc_data *vc);
static void vc_data_init(struct vc_data *vc)
{
    int j, k;
    vc->vc_num = 0;
    if (vc->uni_pagedict_loc)
        con_free_unimap(vc);
    vc->uni_pagedict_loc = &vc->uni_pagedict;
    vc->uni_pagedict = NULL;

    vc->vc_hi_font_mask = 0;
    vc->vc_complement_mask = 0;
    vc->vc_can_do_color = 0;
    vc->vc_cur_blink_ms = 0;
    if (!vc->vc_complement_mask)
        vc->vc_complement_mask = vc->vc_can_do_color ? 0x7700 : 0x0800;
    vc->vc_s_complement_mask = vc->vc_complement_mask;
    vc->vc_size_row = vc->vc_cols << 1;
    vc->vc_screenbuf_size = vc->vc_rows * vc->vc_size_row;

    con_set_default_unimap(vc);

    vc->vc_screenbuf = xmalloc(vc->vc_screenbuf_size);

    vc->vc_pos = vc->vc_origin;
    vc->vc_mode = 0;
	vc->vt_newvt = -1;

    reset_terminal(vc);
}

static int con_allocate_new(struct vc_data *vc)
{
	struct uni_pagedict *new, *old = *vc->uni_pagedict_loc;

	new = xcalloc(1, sizeof(*new));
	if (!new)
		return -ENOMEM;

	new->refcount = 1;
	*vc->uni_pagedict_loc = new;

	if (old)
		old->refcount--;

	return 0;
}

/* Caller must hold the lock */
static int con_do_clear_unimap(struct vc_data *vc)
{
	struct uni_pagedict *old = *vc->uni_pagedict_loc;

	if (!old || old->refcount > 1)
		return con_allocate_new(vc);

	old->sum = 0;
	con_release_unimap(old);

	return 0;
}

static int con_insert_unipair(struct uni_pagedict *p, u_short unicode, u_short fontpos)
{
	unsigned short **dir, *row;
	unsigned int n;

	n = UNI_DIR(unicode);
	dir = p->uni_pgdir[n];
	if (!dir) {
		dir = p->uni_pgdir[n] = xcalloc(UNI_DIR_ROWS, sizeof(*dir));
		if (!dir)
			return -ENOMEM;
	}

	n = UNI_ROW(unicode);
	row = dir[n];
	if (!row) {
		row = dir[n] = xmalloc(UNI_ROW_GLYPHS * sizeof(*row));
		if (!row)
			return -ENOMEM;
		/* No glyphs for the characters (yet) */
		memset(row, 0xff, UNI_ROW_GLYPHS * sizeof(*row));
	}

	row[UNI_GLYPH(unicode)] = fontpos;

	p->sum += (fontpos << 20U) + unicode;

	return 0;
}

static void set_inverse_transl(struct vc_data *conp, struct uni_pagedict *dict, enum translation_map m)
{
	unsigned short *t = translations[m];
	unsigned char *inv;

	if (!dict)
		return;
	inv = dict->inverse_translations[m];

	if (!inv) {
		inv = dict->inverse_translations[m] = xmalloc(MAX_GLYPH);
		if (!inv)
			return;
	}
	memset(inv, 0, MAX_GLYPH);

    unsigned int ch = 0;
	for (; ch < ARRAY_SIZE(translations[m]); ch++) {
		int glyph = conv_uni_to_pc(conp, t[ch]);
		if (glyph >= 0 && glyph < MAX_GLYPH && inv[glyph] < 32) {
			/* prefer '-' above SHY etc. */
			inv[glyph] = ch;
		}
	}
}

static void set_inverse_trans_unicode(struct uni_pagedict *dict)
{
	unsigned int d, r, g;
	unsigned short *inv;

	if (!dict)
		return;

	inv = dict->inverse_trans_unicode;
	if (!inv) {
		inv = dict->inverse_trans_unicode = xmalloc(MAX_GLYPH * sizeof(*inv));
		if (!inv)
			return;
	}
	memset(inv, 0, MAX_GLYPH * sizeof(*inv));

	for (d = 0; d < UNI_DIRS; d++) {
		unsigned short **dir = dict->uni_pgdir[d];
		if (!dir)
			continue;
		for (r = 0; r < UNI_DIR_ROWS; r++) {
			unsigned short *row = dir[r];
			if (!row)
				continue;
			for (g = 0; g < UNI_ROW_GLYPHS; g++) {
				unsigned short glyph = row[g];
				if (glyph < MAX_GLYPH && inv[glyph] < 32)
					inv[glyph] = UNI(d, r, g);
			}
		}
	}
}

int con_set_default_unimap(struct vc_data *vc)
{
	struct uni_pagedict *dict;
	unsigned int fontpos, count;
	int err = 0, err1;
	unsigned short *dfont;

	if (dflt) {
		dict = *vc->uni_pagedict_loc;
		if (dict == dflt)
			return 0;

		dflt->refcount++;
		*vc->uni_pagedict_loc = dflt;
		if (dict && !--dict->refcount) {
			con_release_unimap(dict);
			free(dict);
		}
		return 0;
	}

	/* The default font is always 256 characters */

	err = con_do_clear_unimap(vc);
	if (err)
		return err;

	dict = *vc->uni_pagedict_loc;
	dfont = dfont_unitable;

	for (fontpos = 0; fontpos < 256U; fontpos++)
		for (count = dfont_unicount[fontpos]; count; count--) {
			err1 = con_insert_unipair(dict, *(dfont++), fontpos);
			if (err1)
				err = err1;
		}

    enum translation_map m = FIRST_MAP;
	for (; m <= LAST_MAP; m++)
		set_inverse_transl(vc, dict, m);
	set_inverse_trans_unicode(dict);
	dflt = dict;
	return err;
}

static int wfd_cmd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{

}

static int rfd_respd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    cmd_t *pcmd = &(c->cmd);

#if 0

    if (pcmd->cmd_state != CSrespd) {
        return 0;
    }

    int i = 0;
    for (; i < len; ++i) {
        ch = (int)buf[i];


    }
#endif

#if 0
    switch (pcmd->cmd_state) {
    case CSrespd:
        if (strcmp(c->prompt, buf) == 0) {

        }
        sshbuf_put_string(pcmd->cmd_buf, buf, len);
        break;
    case CSfindrespd:
        sshbuf_put_string(pcmd->cmd_buf, buf, len);
        break;
    default:
        break;
    }
#endif

    int ch = 0;
    int i = 0;
    for (; i < len; ++i) {
        ch = (int)buf[i];
        //cmd_char_handle(pcmd, ch);
    }

    return 0;
}

int cmd_ssh_wfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    #if 1
    //TODO 当sftp登录成功时没有任何明确标记，导致被这个逻辑阻断，先注释掉
    if (c->proxy_state != PROXY_STATE_CMD) {
        return 0;
    }
    #endif

    proxy_info_st *pinfo = &(c->proxy_info);
    switch (pinfo->pt) {
    case PT_SFTP:
        //sftp_reqst_handle(c, buf, len);
        break;
    default:
        //wfd_cmd_handle(ssh, c, buf, len);
        break;
    }

    return 0;
}

int cmd_ssh_rfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len)
{
    switch (c->proxy_state) {
    case PROXY_STATE_LOGIN:
        login_handle(ssh, c, buf, len);
        break;
    case PROXY_STATE_LOGIN_OK:
        login_ok_handle(ssh, c, buf, len);
        break;
    case PROXY_STATE_CMD:
        rfd_respd_handle(ssh, c, buf, len);
        break;
    case PROXY_STATE_LOGIN_FAILED:
        fatal("login failed");  /* exit */
        break;
    default:
        break;
    }

    return 0;
}


#ifdef UNITTEST_CMD_SSH
#include "./tests/cmd-ssh-test.c"
#endif