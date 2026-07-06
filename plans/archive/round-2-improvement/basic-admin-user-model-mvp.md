# Basic Admin User Model (MVP)

## Goal

The initial version supports **multiple administrator accounts** without
Role-Based Access Control (RBAC).

All administrator accounts have the same permission level:

-   **Role = Admin**

RBAC can be introduced in a future release without changing the
authentication or 2FA flow.

------------------------------------------------------------------------

## Data Model

``` text
AdminUser
├── id
├── username
├── password_hash
├── totp_secret
├── totp_enabled
├── recovery_code_hashes
├── created_at
└── updated_at
```

Optional (future-proof):

``` text
AdminUser
├── id
├── username
├── password_hash
├── totp_secret
├── totp_enabled
├── recovery_code_hashes
├── role = Admin
├── created_at
└── updated_at
```

Currently, every account has the same role:

  Username   Role
  ---------- -------
  alice      Admin
  bob        Admin
  charlie    Admin

------------------------------------------------------------------------

## Login Flow

``` text
Username
Password
      │
Password Correct?
      │
      ▼
TOTP Enabled?
      │
 ┌────┴────┐
 │         │
No        Yes
 │         │
Enrollment  Enter OTP
Required       │
 │             ▼
Setup 2FA   Verify OTP
 │             │
 └──────┬──────┘
        ▼
   Admin Dashboard
```

------------------------------------------------------------------------

## Benefits

-   Each administrator has an individual account.
-   Each administrator enrolls their own Google Authenticator.
-   Each administrator has their own recovery codes.
-   Audit logs identify the individual administrator performing each
    action.
-   No RBAC complexity in the MVP.
-   Ready for future RBAC expansion if required.

------------------------------------------------------------------------

## Future Expansion

RBAC can be added later by introducing additional roles such as:

-   SuperAdmin
-   Admin
-   Operator
-   ReadOnly

The authentication flow remains unchanged because authentication
(identity verification) and authorization (permissions) are separated.
