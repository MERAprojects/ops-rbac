/*
 * Copyright (C) 2016 Hewlett Packard Enterprise Development LP
 * All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License"); you may
 *   not use this file except in compliance with the License. You may obtain
 *   a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *   License for the specific language governing permissions and limitations
 *   under the License.
 *
 * File: rbac.h
 *
 * Purpose: To add declarations required for call the RBAC API's
 *
 */
#ifndef RBAC_H
#define RBAC_H
#include <stdbool.h>

#define RBAC_MAX_NUM_PERMISSIONS                5
#define RBAC_MAX_PERMISSION_NAME_LEN            25
#define RBAC_MAX_ROLE_NAME_LEN                  20

#define RBAC_ROLE_ROOT                          "root"
#define RBAC_ROLE_ADMIN                         "ops_admin"
#define RBAC_ROLE_NETOP                         "ops_netop"
#define RBAC_ROLE_NONE                          "none"

#define RBAC_READ_SWITCH_CONFIG                 "READ_SWITCH_CONFIG"
#define RBAC_WRITE_SWITCH_CONFIG                "WRITE_SWITCH_CONFIG"
#define RBAC_SYS_MGMT                           "SYS_MGMT"

#define BASE_10                                 10
#define RADIUS                                  "RADIUS"
#define TACACS                                  "TACACS"
#define PRIV_LVL_ENV                            "PRIV_LVL"
#define AUTH_METHOD_ENV                         "AUTH_MODE"

typedef struct {
  char name[RBAC_MAX_ROLE_NAME_LEN];
} rbac_role_t;

typedef struct {
  int count;
  char name[RBAC_MAX_NUM_PERMISSIONS][RBAC_MAX_PERMISSION_NAME_LEN];
} rbac_permissions_t;

enum resource_type_e {
    VTY_SH,
    ADMIN_CMDS
};

enum privilege_level_e {
    PRIV_LVL_0,
    OPERATOR_LVL,      /* Read-only role */
    PRIV_LVL_2,        /* Placeholders for new roles */
    PRIV_LVL_3,
    PRIV_LVL_4,
    PRIV_LVL_5,
    PRIV_LVL_6,
    PRIV_LVL_7,
    PRIV_LVL_8,
    PRIV_LVL_9,
    PRIV_LVL_10,
    PRIV_LVL_11,
    PRIV_LVL_12,
    PRIV_LVL_13,
    NETOP_LVL,          /* Netop role */
    ADMIN_LVL           /* Admin role */
};

enum radius_priv_lvl_e {
    ADMINISTRATIVE = 6,  /* Access to privileged commands */
    NAS_PROMPT           /* Access to non-privileged commands */
};

#ifdef __cplusplus
extern "C" {
#endif
extern bool rbac_check_user_permission(const char *username, const char *permissions);
extern bool rbac_get_user_permissions(const char *username, rbac_permissions_t *permissions);
extern bool rbac_get_user_role(const char *username, rbac_role_t *role);
extern bool rbac_is_remote_user_permitted(long privilege, enum resource_type_e);
extern bool rbac_is_local_user_permitted(char * username, enum resource_type_e);
extern long rbac_radius_to_switch_privilege(long privilege);
extern long rbac_get_remote_user_privilege(char *username, const char * auth_mode, long privilege);
extern bool rbac_is_user_permitted(char * username, enum resource_type_e);
extern bool rbac_string_to_long(long *result, const char * str, int base);
#ifdef __cplusplus
}
#endif

#endif /* RBAC_H */
