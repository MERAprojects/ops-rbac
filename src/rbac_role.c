/*
 * Copyright (C) 2016 Hewlett-Packard Development Company, L.P.
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
#include <rbac.h>

void
usage() {
   printf("\n");
   printf("rbac_role <username> - returns the rbac_role \n");
   printf("rbac_role -p <username> - returns the list of permissions for this user \n");
   printf("rbac_role -c <permission> <username> - returns 'true' of 'false' depending\n");
   printf("if the user has rights to use this permission.\n");
   printf("\n");
}

/*
 * rbac_role support the following syntax
 *
 *    rbac_role <username> - returns the rbac_role
 *    rbac_role -p <username> - returns the list of permissions for this user
 *    rbac_role -c <permission> <username> - returns "true" or "false" depending if the user
 *                 has rights to use this permission.
 */
int
main (int argc, char *argv[]) {

   int                   i;
   bool                  result;
   rbac_role_t           role;
   rbac_permissions_t    permissions;

   switch (argc) {
       case 1:   usage();
                 break;
       case 2:   result = rbac_get_user_role((const char *) argv[1], &role);
                 if (result) {
                    printf("%s\n", role.name);
                    }
                 break;
       case 3:   if (strcmp(argv[1], "-p") != 0) {
                    usage();
                    return(0);
                    }
                  result = rbac_get_user_permissions((const char *) argv[2], &permissions);
                  if (result) {
                     for (i = 0; i < permissions.count; i++) {
                         printf("%s ", permissions.name[i]);
                         }
                         printf("\n");
                     }
                 break;
       case 4:   if (strcmp(argv[1], "-c") != 0) {
                    usage();
                    return(0);
                    }
                  result = rbac_check_user_permission((const char *) argv[3], (const char *) argv[2]);
                  if (result) {
                     printf("true\n");
                     }
                  else {
                     printf("false\n");
                     }
                 break;
       default:  usage();
                 break;
    }
   return 0;
}
