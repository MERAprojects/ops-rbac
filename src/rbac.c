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
 * File: rbac.c
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stdbool.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <errno.h>
#include <rbac.h>
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(rbac);

#define ALLOW_ROOT_ROLE

/*
 * Local functions to support the public API.
 */
bool
get_rbac_role(const char *username, rbac_role_t *role)
{
   int      i;
   int      result = 0;;
   gid_t    *groups = NULL;
   int      ngroups=20;
   struct   passwd *pw;
   struct   group *g;

   if ((username == NULL) || (role == NULL))
   {
      return(false);
   }

   pw = getpwnam(username);
   if (pw == NULL)
   {
      /* No user */
      strncpy(role->name, RBAC_ROLE_NONE, sizeof (rbac_role_t));
      return(true);
   }

   role->name[0] = (char) 0;
   groups = (gid_t *) malloc (ngroups * sizeof(gid_t));
   if (groups == NULL)
   {
      return(false);
   }

   result = getgrouplist(username, pw->pw_gid, groups, &ngroups);
   if (result < 0)
   {
      free(groups);
      return(false);
   }

#ifdef ALLOW_ROOT_ROLE
   /*
    * First check for root role.
    */
   for (i = 0; i < ngroups; i++)
   {
      g = getgrgid(groups[i]);
      if (strncmp(g->gr_name, RBAC_ROLE_ROOT, RBAC_MAX_ROLE_NAME_LEN) == 0)
      {
         strncpy(role->name, RBAC_ROLE_ROOT, sizeof (rbac_role_t));
         free(groups);
         return(true);
      }
   }
#endif

   /*
    * Next check for admin role.
    */
   for (i = 0; i < ngroups; i++)
   {
      g = getgrgid(groups[i]);
      if (strncmp(g->gr_name, RBAC_ROLE_ADMIN, RBAC_MAX_ROLE_NAME_LEN) == 0)
      {
         strncpy(role->name, RBAC_ROLE_ADMIN, sizeof (rbac_role_t));
         free(groups);
         return(true);
      }
   }

   /*
    * Finally check for netop role.
    */
   for (i = 0; i < ngroups; i++)
   {
      g = getgrgid(groups[i]);
      if (strncmp(g->gr_name, RBAC_ROLE_NETOP, RBAC_MAX_ROLE_NAME_LEN) == 0)
      {
         strncpy(role->name, RBAC_ROLE_NETOP, sizeof (rbac_role_t));
         free(groups);
         return(true);
      }
   }

   strncpy(role->name, RBAC_ROLE_NONE, RBAC_MAX_ROLE_NAME_LEN);
   free(groups);
   return(true);
}

bool
get_rbac_permissions(const char *username, rbac_permissions_t *permissions)
{
   bool          result;
   rbac_role_t   role;

   if ((username == NULL) || (permissions == NULL))
   {
       return(false);
   }

   /*
    * Get the user's role.
    */
   permissions->count = 0;
   result =  get_rbac_role(username, &role);
   if (result == false)
   {
      return(false);
   }

#ifdef ALLOW_ROOT_ROLE
   if (strncmp(role.name, RBAC_ROLE_ROOT, RBAC_MAX_ROLE_NAME_LEN) == 0)
   {
      permissions->count = 3;
      strcpy(permissions->name[0], RBAC_SYS_MGMT);
      strcpy(permissions->name[1], RBAC_READ_SWITCH_CONFIG);
      strcpy(permissions->name[2], RBAC_WRITE_SWITCH_CONFIG);
      return(true);
   }
#endif

   if (strncmp(role.name, RBAC_ROLE_ADMIN, RBAC_MAX_ROLE_NAME_LEN) == 0)
   {
      permissions->count = 1;
      strcpy(permissions->name[0], RBAC_SYS_MGMT);
      return(true);
   }

   if (strncmp(role.name, RBAC_ROLE_NETOP, RBAC_MAX_ROLE_NAME_LEN) == 0)
   {
      permissions->count = 2;
      strcpy(permissions->name[0], RBAC_READ_SWITCH_CONFIG);
      strcpy(permissions->name[1], RBAC_WRITE_SWITCH_CONFIG);
      return(true);
   }

   permissions->count = 0;
   return(true);

}

/*
 * externally callable functions
 */

/*
 * Check if user has rights to a permission
 *
 * Returns true the specified user has rights to this permission,
 * otherwise returns false.
 */
bool
rbac_check_user_permission(const char *username, const char *permission)
{
    rbac_permissions_t     permissions;
    bool                   result;
    int                    i;

    if ((username == NULL) || (permission == NULL))
    {
       return(false);
    }

   result = get_rbac_permissions(username, &permissions);
   if (result == false)
   {
      return(false);
   }

   for (i = 0; i < permissions.count; i++)
   {
       if (strncmp(permissions.name[i], permission,
                            RBAC_MAX_PERMISSION_NAME_LEN) == 0)
       {
       return(true);
       }
   }
   return(false);
}

/*
 * Returns the users list of permissions.
 *
 * Returns true if if rbac_permissions_t structure contains the
 * users permissions, otherwise returns false.
 */
bool
rbac_get_user_permissions(const char *username, rbac_permissions_t *permissions)
{
    bool   result;
    if ((username == NULL) || (permissions == NULL))
    {
       return(false);
    }

   result = get_rbac_permissions(username, permissions);
   return(result);
}

/*
 * Returns the role of the specified user.
 *
 * Returns true if if rbac_role_t structure contains the
 * role string, otherwise returns false.
 */
bool
rbac_get_user_role(const char *username, rbac_role_t *role)
{
    bool     result;

    if ((username == NULL) || (role == NULL))
    {
       return(false);
    }
    result = get_rbac_role(username, role);
    return(result);
}

/*
 * Function       : rbac_is_remote_user_permitted
 * Responsibility : Checks if at privilege level 'privilege',
 *                  'resource' can be accessed or not.
 * Parameters     : long privilege           - (0 to 15)
 *                : resource_type_e resource - VTY_SH/ADMIN_CMDS
 * Return         : 'true' if resource is permitted for the privilege
 *                  level 'privilege' and 'false' if not.
 */
bool
rbac_is_remote_user_permitted(long privilege, enum resource_type_e resource)
{

    switch (resource) {
        case VTY_SH:
            return ((privilege >= OPERATOR_LVL) &&
                    (privilege <= NETOP_LVL)) ? true: false;
        case ADMIN_CMDS:
            return privilege == ADMIN_LVL ? true: false;
        default:
            return false;
    }
}

/*
 * Function       : rbac_is_local_user_permitted
 * Responsibility : Checks if user 'username' has access to 'resource'
 * Parameters     : char * username
 *                : resource_type_e resource - VTY_SH/ADMIN_CMDS
 * Return         : 'true' if user 'username' has access to 'resource'
 *                  and 'false' if not.
 */
bool
rbac_is_local_user_permitted(char * username, enum resource_type_e resource)
{

    switch(resource) {
        case VTY_SH:
            if (rbac_check_user_permission(username, RBAC_READ_SWITCH_CONFIG)
                 || rbac_check_user_permission(username,
                                               RBAC_WRITE_SWITCH_CONFIG)) {
                return true;
            }
            break;
        case ADMIN_CMDS:
            if (rbac_check_user_permission(username, RBAC_SYS_MGMT)) {
                return true;
            }
            break;
    }
    return false;
}

/*
 * Function       : rbac_radius_to_switch_privilege
 * Responsibility : Maps privilege level value from RADIUS
 *                  to privilege level understood by the switch.
 * RADIUS privilege level ADMINISTRATIVE (6) -> ADMIN_LVL    (15)
 * RADIUS privilege level NAS_PROMPT     (7) -> OPERATOR_LVL (1)
 * Parameters     : long privilege
 * Return         : switch privilege level
 */

long
rbac_radius_to_switch_privilege(long privilege)
{
    if (privilege == ADMINISTRATIVE) {
        return ADMIN_LVL;
    } else {
        return OPERATOR_LVL;
    }
}

/*
 * Function       : rbac_get_remote_user_privilege
 * Responsibility : Returns switch privilege level of remote user 'username'
 *                  based on 'auth_mode' and 'privilege' set by RADIUS/TACACS.
 * Parameters     : char * username
 *                  const char *auth_mode: RADIUS/TACACS
 *                  long privilege       : Privilege level set by RADIUS/TACACS
 * Return         : switch privilege level
 */
long
rbac_get_remote_user_privilege(char *username, const char * auth_mode,
                               long privilege)
{
    /* RADIUS Authenticated user */
    if (!strncmp(auth_mode, RADIUS, strlen(RADIUS))) {
        long switch_priv = rbac_radius_to_switch_privilege(privilege);
         VLOG_INFO("RADIUS authenticated user %s with privilege %ld\n",
                    username, switch_priv);
         return switch_priv;
    /* TACACS Authenticated user */
    } else {
        VLOG_INFO("TACACS authenticated user %s with privilege %ld\n",
                   username, privilege);
        return privilege;
    }
}

/*
 * Function       : rbac_string_to_long
 * Responsibility : Converts 'str' string to long and is stored in 'result'
 * Parameters     : long * result    - holds the converted string
 *                : const char * str - string to be converted to long
 *                : int base         - base to use for the conversion
 * Return         : 'true' on success and 'false' on failure
 */
bool
rbac_string_to_long(long *result, const char * str, int base)
{
    char *end;
    errno = 0;

    *result = strtol(str, &end, base);

    if ((errno == ERANGE && (*result == LONG_MAX || *result == LONG_MIN))
        || (errno != 0 && *result == 0)) {
        VLOG_ERR("Error while converting %s to long: Out of range\n",str);
        return false;
    }

    if (end == str) {
        VLOG_ERR("Error while converting %s to long: No digits were found\n",
                  str);
        return false;
    }

    if (*end != '\0') {
        VLOG_ERR("Error while converting %s to long: "
                 "Further characters after number %s \n",
                  str, end);
        return false;
    }

    VLOG_INFO("String %s was converted to %ld\n", str, *result);
    return true;
}

/*
 * Function       : rbac_is_user_permitted
 * Responsibility : Checks if user 'username' has access to 'resource'
 * Parameters     : char * username
 *                : resource_type_e resource - VTYSH/ADMIN_CMDS
 * Return         : 'true' if user 'username' has access to 'resource'
 *                  and 'false' if not.
 */

bool
rbac_is_user_permitted(char * username, enum resource_type_e resource)
{
    const char *auth_mode = getenv(AUTH_METHOD_ENV);

    /* Use RBAC when AUTH_METHOD ENV is not set. Locally authenticated user */
    if (auth_mode == NULL) {
        VLOG_INFO("AUTH_METHOD ENV = NULL\n");
        return rbac_is_local_user_permitted(username, resource);
    } else {
        /* Remote Authenticated user */
        long privilege;
        const char *priv_lvl = getenv(PRIV_LVL_ENV);

        if (priv_lvl != NULL) {
            VLOG_INFO("PRIV_LVL ENV = %s\n", getenv(PRIV_LVL_ENV));
            if (rbac_string_to_long(&privilege, priv_lvl, BASE_10)) {
                /* Get privilege level of remote RADIUS/TACACS user */
                long priv = rbac_get_remote_user_privilege(username,
                                                           auth_mode,
                                                           privilege);
                return rbac_is_remote_user_permitted(priv, resource);
            } else {
                VLOG_ERR("Conversion from %s to long failed for user %s\n",
                      priv_lvl, username);
                return false;
            }
        } else {
            VLOG_INFO("Privilege level = NULL\n");
            return false;
        }
    }
}
