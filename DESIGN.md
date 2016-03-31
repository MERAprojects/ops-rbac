High-level design of ops-rbac
=============================
Role-Based Access Control (RBAC) is a method for allowing or restricting an authenticated user access to resources based on a role the user has been assigned. Roles are assigned to the user when the user's account is created.

In OpenSwitch we will be using these roles to restrict a user's access to configuration information and system password administration by granting each role a pre-defined list of permissions.

## References
