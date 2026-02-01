#ifndef DISTRIBUTIONVC_COMMON_H
#define DISTRIBUTIONVC_COMMON_H

#include <stdint.h>

/* Protocol constants */
#define DVC_SERVER_PORT 12345
#define DVC_RELAY_BASE_PORT 13000
#define DVC_MAX_DATA_SIZE 2048
#define DVC_MAX_SERVERS 10

/* Message types */
#define DVC_MSG_DATA 0x01
#define DVC_MSG_ACK 0x02
#define DVC_MSG_RESULT 0x03
#define DVC_MSG_EXIT 0xFFFFFFFF

/* Client types */
#define DVC_CLIENT_TYPE_RECEIVER 1
#define DVC_CLIENT_TYPE_DATASERVER 2

/* Return codes */
#define DVC_OK 0
#define DVC_ERROR -1
#define DVC_ERROR_INVALID_DATA -2
#define DVC_ERROR_TLS_FAILED -3

#endif /* DISTRIBUTIONVC_COMMON_H */
