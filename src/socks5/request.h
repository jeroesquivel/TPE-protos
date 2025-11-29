#ifndef REQUEST_H
#define REQUEST_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "../utils/buffer.h"
#include "../utils/selector.h"

enum request_state {
    REQUEST_VERSION,
    REQUEST_CMD,
    REQUEST_RSV,
    REQUEST_ATYP,
    REQUEST_DSTADDR,
    REQUEST_DSTPORT,
    REQUEST_DONE,
    REQUEST_ERROR,
};

enum request_reply {
    REQUEST_REPLY_SUCCESS = 0x00,
    REQUEST_REPLY_FAILURE = 0x01,
    REQUEST_REPLY_CONNECTION_NOT_ALLOWED = 0x02,
    REQUEST_REPLY_NETWORK_UNREACHABLE = 0x03,
    REQUEST_REPLY_HOST_UNREACHABLE = 0x04,
    REQUEST_REPLY_CONNECTION_REFUSED = 0x05,
    REQUEST_REPLY_TTL_EXPIRED = 0x06,
    REQUEST_REPLY_COMMAND_NOT_SUPPORTED = 0x07,
    REQUEST_REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 0x08,
};

#define ADDRESS_TYPE_IPV4 0x01
#define ADDRESS_TYPE_DOMAIN 0x03
#define ADDRESS_TYPE_IPV6 0x04
#define REQUEST_COMMAND_CONNECT 0x01
#define IPV4_LENGTH 4
#define IPV6_LENGTH 16

struct request_parser {
    enum request_state state;
    uint8_t command;
    uint8_t address_type;
    uint8_t dst_addr[256];
    uint8_t dst_addr_length;
    uint16_t dst_port;
    uint8_t bytes_read;
};

void request_read_init(const unsigned state, struct selector_key *key);
unsigned request_read(struct selector_key *key);
unsigned request_write(struct selector_key *key);
unsigned request_connect(struct selector_key *key);
unsigned request_dns(struct selector_key *key);

void request_parser_init(struct request_parser *parser);
enum request_state request_parser_consume(struct request_parser *parser, buffer *b);
bool request_parser_is_done(const struct request_parser *parser);
bool request_parser_has_error(const struct request_parser *parser);
bool request_build_response(const struct request_parser *parser, buffer *buf, uint8_t reply_code);

#endif
