# Oktopus REST API Reference

## Overview

Oktopus exposes two REST API services:

| Service | Default Port | Base Path |
|---------|-------------|-----------|
| Controller | `8000` | `/api/` |
| TaaS (Test-as-a-Service) | `8001` | `/api/taas/` |

**Protocol**: HTTP/HTTPS  
**Content-Type**: `application/json` (unless noted otherwise)  
**Request Timeout**: 30 seconds

---

## Authentication

All endpoints (unless marked **No auth**) require a JWT token passed as a raw value in the `Authorization` header:

```
Authorization: <jwt_token>
```

Tokens are obtained via [`PUT /api/auth/login`](#put-apiauthlogin) and expire after **24 hours**.

### Common Error Responses

| Status | Meaning |
|--------|---------|
| `400` | Invalid request body or parameters |
| `401` | Missing or invalid token |
| `403` | Insufficient permissions (not admin) |
| `404` | Resource not found |
| `409` | Conflict (resource already exists) |
| `500` | Internal server error |
| `503` | Device offline or unavailable |

---

## Controller Service

### Authentication

#### `PUT /api/auth/login`

Authenticate and receive a JWT token. **No auth required.**

**Request**
```json
{
  "email": "user@example.com",
  "password": "secret"
}
```

**Response `200`**
```
"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

---

#### `POST /api/auth/register`

Register a new user. **Admin only.**

**Request**
```json
{
  "email": "newuser@example.com",
  "name": "New User",
  "password": "password123",
  "phone": "+1234567890"
}
```

**Response `200`** — No body.

---

#### `POST /api/auth/admin/register`

Register an admin user. No auth required when no admin exists yet; admin auth required thereafter.

**Request**
```json
{
  "email": "admin@example.com",
  "name": "Admin",
  "password": "adminpass"
}
```

**Response `200`** — No body. Returns `403` if an admin already exists and the request is unauthenticated.

---

#### `GET /api/auth/admin/exists`

Check whether an admin user has been created. **No auth required.**

**Response `200`**
```
true
```

---

#### `DELETE /api/auth/delete/{user}`

Delete a user by email. Admins may delete any user; normal users may only delete themselves.

| Path param | Description |
|------------|-------------|
| `user` | Email address of the user to delete |

**Response `200`** — No body.

---

#### `PUT /api/auth/password`

Change a user's password. The requesting user's email and new password are supplied in the body.

**Request**
```json
{
  "email": "user@example.com",
  "password": "newpassword"
}
```

**Response `204`** — No body. Password must be at least 8 characters (`400` otherwise).

---

### Users

#### `GET /api/users`

List all users. **Admin only.**

**Response `200`**
```json
[
  {
    "_id": "507f1f77bcf86cd799439011",
    "email": "user@example.com",
    "name": "User Name",
    "level": 0,
    "phone": "",
    "createdAt": "15/04/2026"
  }
]
```

`level`: `0` = normal user, `1` = admin. Passwords are never returned.

---

### Devices

#### `GET /api/device`

List devices with optional filtering and pagination.

**Query parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `id` | string | — | Return a single device by serial number |
| `page_number` | integer | `0` | Zero-based page number |
| `page_size` | integer | `20` | Results per page (max `50`) |
| `status` | integer | — | Filter by status: `0`=offline, `1`=associating, `2`=online |
| `statusOrder` | string | `asc` | Sort direction: `asc` or `desc` |
| `vendor` | string | — | Filter by vendor |
| `version` | string | — | Filter by software version |
| `model` | string | — | Filter by model |
| `type` | string | — | Filter by product class |
| `alias` | string | — | Filter by alias |

**Response `200`**
```json
{
  "pages": 3,
  "page": 0,
  "size": 20,
  "total": 42,
  "devices": [
    {
      "SN": "sn-12345",
      "Alias": "My Router",
      "Model": "CPE-100",
      "ProductClass": "Router",
      "Vendor": "Acme",
      "Version": "1.2.3",
      "Status": 2,
      "mqtt": 1,
      "stomp": 0,
      "websockets": 0,
      "cwmp": 0,
      "webpa": 0
    }
  ]
}
```

Returns `404` when no devices match.

---

#### `DELETE /api/device`

Delete one or more devices.

**Query parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Comma-separated serial numbers (required) |

**Response `200`**
```json
{
  "number_of_deleted_devices": 2
}
```

---

#### `PUT /api/device/alias`

Set a human-readable alias for a device.

**Query parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Device serial number (required) |

**Request body** — Raw string, max 50 characters (not JSON-encoded):
```
My Living Room Router
```

**Response `200`** — No body.

---

#### `GET /api/device/filterOptions`

Return distinct values for device filter dropdowns.

**Response `200`**
```json
{
  "models": ["CPE-100", "CPE-200"],
  "productClasses": ["Router", "Gateway"],
  "vendors": ["Acme", "Globex"],
  "versions": ["1.2.3", "2.0.0"]
}
```

---

#### `GET /api/device/auth`

Retrieve stored device credentials (username/password pairs). **Admin only.**

**Query parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Device serial number — omit to return all |

**Response `200`**
```json
{
  "sn-12345": "device-password",
  "sn-67890": "another-password"
}
```

---

#### `POST /api/device/auth`

Create device credentials. **Admin only.**

**Request**
```json
{
  "id": "sn-12345",
  "password": "device-password"
}
```

**Response `200`** — No body. Returns `409` if credentials already exist for this device.

---

#### `DELETE /api/device/auth`

Delete device credentials. **Admin only.**

**Query parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Device serial number (required) |

**Response `200`** — No body.

---

### Message Templates

#### `GET /api/device/message`

Retrieve message templates.

**Query parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Return a single template by name |
| `type` | string | Filter by type: `cwmp` or `usp` |

**Response `200`**
```json
[
  {
    "name": "reboot",
    "type": "usp",
    "value": "{...}"
  }
]
```

When `name` is specified, the raw template content is returned instead of the array.

---

#### `POST /api/device/message/{type}`

Create a new message template.

| Path param | Description |
|------------|-------------|
| `type` | `cwmp` or `usp` |

**Query parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Template name (required) |

**Request body** — Template content (XML for CWMP, JSON for USP).

**Response `204`** — No body.

---

#### `PUT /api/device/message`

Update an existing template.

**Query parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Template name (required) |

**Request body** — New template content.

**Response `204`** — No body.

---

#### `DELETE /api/device/message`

Delete a message template.

**Query parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Template name (required) |

**Response `204`** — No body.

---

### USP Device Commands

All USP endpoints share the same path structure and response conventions:

```
PUT /api/device/{sn}/{mtp}/<action>
```

| Path param | Description |
|------------|-------------|
| `sn` | Device serial number |
| `mtp` | Transport protocol: `mqtt`, `ws`, `stomp`, `webpa`, or `any` |

All return `503` when the device is offline.

---

#### `PUT /api/device/{sn}/{mtp}/get`

Send a USP Get message to retrieve parameter values.

**Request**
```json
{
  "param_paths": ["Device.DeviceInfo.", "Device.LocalAgent.EndpointID"],
  "max_depth": 1
}
```

**Response `200`** — USP GetResp JSON.

---

#### `PUT /api/device/{sn}/{mtp}/set`

Send a USP Set message to update parameter values.

**Request**
```json
{
  "update_objs": [
    {
      "obj_path": "Device.LocalAgent.Controller.1.",
      "param_settings": {
        "Alias": "my-controller"
      }
    }
  ]
}
```

**Response `200`** — USP SetResp JSON.

---

#### `PUT /api/device/{sn}/{mtp}/add`

Send a USP Add message to create object instances.

**Request**
```json
{
  "create": [
    {
      "obj_path": "Device.LocalAgent.Subscription.",
      "param_settings": {
        "NotifType": "ValueChange",
        "ReferenceList": "Device.LocalAgent.EndpointID"
      }
    }
  ]
}
```

**Response `200`** — USP AddResp JSON.

---

#### `PUT /api/device/{sn}/{mtp}/del`

Send a USP Delete message to remove object instances.

**Request**
```json
{
  "obj_paths": ["Device.LocalAgent.Subscription.1."]
}
```

**Response `200`** — USP DeleteResp JSON.

---

#### `PUT /api/device/{sn}/{mtp}/operate`

Send a USP Operate message to invoke a command.

**Request**
```json
{
  "command": "Device.Reboot()",
  "command_key": "my-key",
  "send_resp": true,
  "input_args": {}
}
```

**Response `200`** — USP OperateResp JSON.

---

#### `PUT /api/device/{sn}/{mtp}/parameters`

Retrieve supported data model parameters (GetSupportedDM).

**Request**
```json
{
  "obj_paths": ["Device.DeviceInfo."],
  "first_level_only": true,
  "return_commands": true,
  "return_events": true,
  "return_params": true
}
```

**Response `200`** — USP GetSupportedDmResp JSON.

---

#### `PUT /api/device/{sn}/{mtp}/instances`

Retrieve object instances (GetInstances).

**Request**
```json
{
  "obj_paths": ["Device.LocalAgent.Controller."],
  "first_level_only": false
}
```

**Response `200`** — USP GetInstancesResp JSON.

---

#### `PUT /api/device/{sn}/{mtp}/fw_update`

Trigger a firmware update via USP Operate.

**Request**
```json
{
  "url": "http://fileserver/firmware-v2.bin"
}
```

**Response `200`** — USP OperateResp JSON. Returns `500` if the device has only one firmware partition.

---

#### `PUT /api/device/{sn}/{mtp}/generic`

Send a raw USP message (ProtoBuf encoded as JSON).

**Request** — Full USP message object (header + body).

**Response `200`** — Raw USP response JSON.

---

#### `GET /api/device/{sn}/wifi` / `PUT /api/device/{sn}/wifi`

Get or set WiFi configuration for a device.

**Response `200`** — WiFi configuration object. Returns `503` if device is offline.

---

### CWMP Device Commands

#### `PUT /api/device/cwmp/{sn}/generic`

Send a raw SOAP/CWMP message to a TR-069 device.

| Path param | Description |
|------------|-------------|
| `sn` | Device serial number |

**Request body** — SOAP/XML CWMP message.

**Response `200`** — SOAP/XML CWMP response.

Specific CWMP convenience endpoints follow the same pattern and accept SOAP bodies:

| Endpoint | Description |
|----------|-------------|
| `PUT /api/device/cwmp/{sn}/getParameterNames` | GetParameterNames |
| `PUT /api/device/cwmp/{sn}/getParameterValues` | GetParameterValues |
| `PUT /api/device/cwmp/{sn}/getParameterAttributes` | GetParameterAttributes |
| `PUT /api/device/cwmp/{sn}/setParameterValues` | SetParameterValues |
| `PUT /api/device/cwmp/{sn}/addObject` | AddObject |
| `PUT /api/device/cwmp/{sn}/deleteObject` | DeleteObject |

---

### Dashboard Info

#### `GET /api/info/general`

Aggregated dashboard statistics.

**Response `200`**
```json
{
  "mqttRtt": "3.4ms",
  "websocketsRtt": "1.2ms",
  "stompRtt": "0s",
  "webpaRtt": "0s",
  "acsRtt": "0s",
  "statusCount": {
    "online": 5,
    "offline": 2
  },
  "vendorsCount": [
    { "vendor": "Acme", "count": 4 }
  ],
  "productClassCount": [
    { "productClass": "Router", "count": 3 }
  ]
}
```

---

#### `GET /api/info/vendors`

Device counts grouped by vendor.

**Response `200`**
```json
[
  { "vendor": "Acme", "count": 4 }
]
```

---

#### `GET /api/info/device_class`

Device counts grouped by product class.

**Response `200`**
```json
[
  { "productClass": "Router", "count": 3 }
]
```

---

#### `GET /api/info/status`

Online/offline device counts.

**Response `200`**
```json
{
  "online": 5,
  "offline": 2
}
```

---

## TaaS Service

The TaaS service runs TP-469 USP conformance tests against a target device via the Controller API.

### Test Catalogue

#### `GET /api/taas/tests`

List all registered test cases.

**Query parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `section` | integer | Filter by section number |
| `mtp` | string | Filter by MTP (`mqtt`, `ws`, `stomp`, etc.) |

**Response `200`**
```json
[
  {
    "id": "1.1",
    "section": 1,
    "name": "Add message with allow_partial false, single object, required parameters succeed",
    "purpose": "Verify USP Add creates an object when all required params are provided.",
    "disabled": false,
    "mtps": [],
    "tags": ["add"]
  }
]
```

`disabled: true` means the test is skipped by default and must be explicitly selected by ID to run (e.g., the Reboot tests `1.61` and `1.62`).

---

### Test Runs

#### `POST /api/taas/runs`

Start a new test run. Tests execute asynchronously; the run ID is returned immediately.

**Request**
```json
{
  "name": "My Test Run",
  "device_id": "sn-12345",
  "mtp": "mqtt",
  "controller_url": "http://controller:8000",
  "controller_token": "<jwt>",
  "sections": [1, 6],
  "test_ids": [],
  "config": {
    "multi_instance_object": "Device.LocalAgent.Subscription.",
    "required_param": "NotifType",
    "required_param_value": "ValueChange",
    "writable_param_path": "Device.LocalAgent.EndpointID",
    "readable_param_path": "Device.DeviceInfo.Manufacturer",
    "get_instances_object": "Device.LocalAgent.Controller.",
    "get_supported_dm_object": "Device.DeviceInfo.",
    "invalid_path": "Device.Bogus.",
    "reboot_command": "Device.Reboot()"
  }
}
```

**Field notes**

| Field | Required | Description |
|-------|----------|-------------|
| `device_id` | Yes | Device serial number |
| `mtp` | Yes | `mqtt`, `ws`, `stomp`, or `webpa` |
| `controller_url` | Yes | URL reachable from TaaS container |
| `controller_token` | Yes | Valid controller JWT |
| `sections` | No | Section numbers to run; empty = all non-disabled tests |
| `test_ids` | No | Explicit test IDs; overrides `sections`; required to run disabled tests |
| `config` | No | Override default data model paths used by tests |

**Response `202`**
```json
{
  "run_id": "69df8131b8fb05154ccf32df"
}
```

---

#### `GET /api/taas/runs`

List recent test runs.

**Query parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | `50` | Max runs to return |

**Response `200`**
```json
[
  {
    "id": "69df8131b8fb05154ccf32df",
    "name": "My Test Run",
    "device_id": "sn-12345",
    "mtp": "mqtt",
    "start_time": "2026-04-15T12:14:41Z",
    "end_time": "2026-04-15T12:16:42Z",
    "status": "completed",
    "summary": {
      "total": 39,
      "passed": 19,
      "failed": 17,
      "errored": 2,
      "skipped": 1
    },
    "results": [
      {
        "test_id": "1.1",
        "test_name": "Add message with allow_partial false...",
        "section": 1,
        "status": "pass",
        "start_time": "2026-04-15T12:14:41Z",
        "end_time": "2026-04-15T12:14:41Z",
        "note": "",
        "steps": [
          {
            "description": "AddResp received",
            "status": "pass",
            "detail": "created_obj_results: ..."
          }
        ]
      }
    ]
  }
]
```

`status` values: `running`, `completed`.  
Result `status` values: `pass`, `fail`, `error`, `skip`.

---

#### `GET /api/taas/runs/{id}`

Get a single test run by ID.

| Path param | Description |
|------------|-------------|
| `id` | Run ID returned by `POST /api/taas/runs` |

**Response `200`** — Same structure as a single item from the list endpoint. Returns `404` if not found.

---

#### `DELETE /api/taas/runs/{id}`

Delete a test run.

| Path param | Description |
|------------|-------------|
| `id` | Run ID |

**Response `200`**
```json
{
  "deleted": "69df8131b8fb05154ccf32df"
}
```

Returns `404` if not found.
