#ifndef __CMD_SSH_H__
#define __CMD_SSH_H__

#include <stdbool.h>
#include "sshbuf.h"

#define NPAR 16
#define VC_TABSTOPS_COUNT	256U
#define MAX_GLYPH 512		/* Max possible glyph value */

enum vc_intensity {
	VCI_HALF_BRIGHT,
	VCI_NORMAL,
	VCI_BOLD,
	VCI_MASK = 0x3,
};

struct vc_state {
	unsigned int	x, y;

	unsigned char	color;

	unsigned char	Gx_charset[2];
	unsigned int	charset		: 1;

	/* attribute flags */
	enum vc_intensity intensity;
	bool		italic;
	bool		underline;
	bool		blink;
	bool		reverse;
};

enum translation_map {
	LAT1_MAP,
	GRAF_MAP,
	IBMPC_MAP,
	USER_MAP,

	FIRST_MAP = LAT1_MAP,
	LAST_MAP = USER_MAP,
};

#define UNI_DIRS	32U
#define UNI_DIR_ROWS	32U
#define UNI_ROW_GLYPHS	64U
struct uni_pagedict {
	unsigned short		**uni_pgdir[UNI_DIRS];
	unsigned long	refcount;
	unsigned long	sum;
	unsigned char	*inverse_translations[LAST_MAP + 1];
	unsigned short		*inverse_trans_unicode;
};

struct vc_data {

	struct vc_state state, saved_state;

	unsigned short	vc_num;			/* Console number */
	unsigned int	vc_cols;		/* [#] Console size */
	unsigned int	vc_rows;
	unsigned int	vc_size_row;		/* Bytes per row */
	unsigned int	vc_scan_lines;		/* # of scan lines */
	unsigned int	vc_cell_height;		/* CRTC character cell height */
	unsigned long	vc_origin;		/* [!] Start of real screen */
	unsigned long	vc_scr_end;		/* [!] End of real screen */
	unsigned long	vc_visible_origin;	/* [!] Top of visible window */
	unsigned int	vc_top, vc_bottom;	/* Scrolling region */
	unsigned short	*vc_screenbuf;		/* In-memory character/attribute buffer */
	unsigned int	vc_screenbuf_size;
	unsigned char	vc_mode;		/* KD_TEXT, ... */
	/* attributes for all characters on screen */
	unsigned char	vc_attr;		/* Current attributes */
	unsigned char	vc_def_color;		/* Default colors */
	unsigned char	vc_ulcolor;		/* Color for underline mode */
	unsigned char   vc_itcolor;
	unsigned char	vc_halfcolor;		/* Color for half intensity mode */
	/* cursor */
	unsigned int	vc_cursor_type;
	unsigned short	vc_complement_mask;	/* [#] Xor mask for mouse pointer */
	unsigned short	vc_s_complement_mask;	/* Saved mouse pointer mask */
	unsigned long	vc_pos;			/* Cursor address */
	/* fonts */
	unsigned short	vc_hi_font_mask;	/* [#] Attribute set for upper 256 chars of font or 0 if not supported */
	//struct console_font vc_font;		/* Current VC font set */
	unsigned short	vc_video_erase_char;	/* Background erase character */
	/* VT terminal data */
	unsigned int	vc_state;		/* Escape sequence parser state */
	unsigned int	vc_npar,vc_par[NPAR];	/* Parameters of current escape sequence */
	/* data for manual vt switching */
	// struct vt_mode	vt_mode;
	// struct pid 	*vt_pid;
	int		vt_newvt;
	//wait_queue_head_t paste_wait;
	/* mode flags */
	unsigned int	vc_disp_ctrl	: 1;	/* Display chars < 32? */
	unsigned int	vc_toggle_meta	: 1;	/* Toggle high bit? */
	unsigned int	vc_decscnm	: 1;	/* Screen Mode */
	unsigned int	vc_decom	: 1;	/* Origin Mode */
	unsigned int	vc_decawm	: 1;	/* Autowrap Mode */
	unsigned int	vc_deccm	: 1;	/* Cursor Visible */
	unsigned int	vc_decim	: 1;	/* Insert Mode */
	/* misc */
	unsigned int	vc_priv		: 3;
	unsigned int	vc_need_wrap	: 1;
	unsigned int	vc_can_do_color	: 1;
	unsigned int	vc_report_mouse : 2;
    unsigned int    bracketed_paste : 1;
	unsigned char	vc_utf		: 1;	/* Unicode UTF-8 encoding */
	unsigned char	vc_utf_count;
	int	            vc_utf_char;
	//DECLARE_BITMAP(vc_tab_stop, VC_TABSTOPS_COUNT);	/* Tab stops. 256 columns. */
	unsigned char   vc_palette[16*3];       /* Colour palette for VGA+ */
	unsigned short  *vc_translate;
	unsigned int    vc_resize_user;         /* resize request from user */
	unsigned int	vc_bell_pitch;		/* Console bell pitch */
	unsigned int	vc_bell_duration;	/* Console bell duration */
	unsigned short	vc_cur_blink_ms;	/* Cursor blink duration */
	//struct vc_data **vc_display_fg;		/* [!] Ptr to var holding fg console for this display */
	struct uni_pagedict *uni_pagedict;
	struct uni_pagedict **uni_pagedict_loc; /* [!] Location of uni_pagedict variable for this console */
	unsigned int    **vc_uni_lines;			/* unicode screen content */
    unsigned int    *line;
    struct sshbuf   *buf;
    struct sshbuf   *prompt;
	/* additional information is in vt_kern.h */
};

int cmd_ssh_rfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len);

int cmd_ssh_wfd_handle(struct ssh *ssh, Channel *c, const char *buf, int len);

#endif