#ifndef ADMIN_COMMANDS_H
#define ADMIN_COMMANDS_H

#include "admin_protocol.h"
#include <stdbool.h>

bool admin_command_requires_admin(uint8_t command);

void admin_process_get_metrics(struct admin_response *response);

void admin_process_list_users(struct admin_response *response);

void admin_process_add_user(struct admin_response *response, const char *data);

void admin_process_del_user(struct admin_response *response, const char *data);

void admin_process_list_connections(struct admin_response *response);

void admin_process_change_password(struct admin_response *response, const char *data);

void admin_process_change_role(struct admin_response *response, const char *data);

#endif
