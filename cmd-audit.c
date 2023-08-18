#include "cmd-audit.h"

typedef enum login_state_t
{
    LOGIN_STATE_NONE = 0,
    LOGIN_STATE_SUCCESS,
    LOGIN_STATE_FAIL,
    LOGIN_STATE_MAX
} login_state_t;

typedef enum read_state_t
{
    READ_STATE_NONE = 0,
    READ_STATE_SUCCESS,
    READ_STATE_FAIL,
    READ_STATE_MAX
} read_state_t;

typedef enum write_state_t
{
    WRITE_STATE_NONE = 0,
    WRITE_STATE_SUCCESS,
    WRITE_STATE_FAIL,
    WRITE_STATE_MAX
} write_state_t;

typedef enum terminal_type_t
{
    TERMINAL_TYPE_AAA = 0
} terminal_type_t;

typedef struct aaa
{
    terminal_type_t     ter_type;           /**< */
    login_state_t       login_state;        /**< */
    read_state_t        read_state;
    write_state_t       write_state;

} aaa;