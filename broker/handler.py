"""Credential broker Lambda: user token -> per-user S3 Files mount credentials.

Invoked (lambda:InvokeFunction) by the root gateway inside the microVM with
the user's Cognito ACCESS token -- the same token AgentCore Runtime already
validated at the front door. The broker never trusts the caller (the runtime
execution role is readable by any code in the VM), only the token:

  1. Verify the token: Cognito GetUser proves signature / expiry / revocation,
     then check iss == our user pool, client_id == our app client.
  2. Look the user up in the mapping table (written at onboarding by
     scripts/manage_users.py, the stand-in for an upstream onboarding system). No
     record, or status != active -> refuse. The broker never creates access
     points, so it holds no S3 Files control-plane permission at all.
  3. AssumeRole SessionMountRole with a session policy that only allows
     mounting THAT access point. Role chaining caps it at 1 h; the gateway
     re-calls this function to rotate before expiry.

Event:  {"token": "<cognito access token>"}
Return: {"username", "fileSystemId", "accessPointId", "accessPointArn", "rootPath",
         "posixUid", "posixGid", "userKey", "status", "credentials": {...}}
        or {"error": "..."}

Env: FILE_SYSTEM_ID, SESSION_MOUNT_ROLE_ARN, USER_POOL_ID, USER_POOL_CLIENT_ID,
     USER_TABLE, ACCOUNT_ID, CRED_TTL_SECONDS (default 3600).
"""

import base64
import hashlib
import json
import os

import boto3

REGION = os.environ["AWS_REGION"]
FILE_SYSTEM_ID = os.environ["FILE_SYSTEM_ID"]
SESSION_MOUNT_ROLE_ARN = os.environ["SESSION_MOUNT_ROLE_ARN"]
USER_POOL_ID = os.environ["USER_POOL_ID"]
USER_POOL_CLIENT_ID = os.environ["USER_POOL_CLIENT_ID"]
ACCOUNT_ID = os.environ["ACCOUNT_ID"]
USER_TABLE = os.environ["USER_TABLE"]
CRED_TTL = int(os.environ.get("CRED_TTL_SECONDS", "3600"))
ISSUER = f"https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}"

_cognito = boto3.client("cognito-idp", region_name=REGION)
_ddb = boto3.client("dynamodb", region_name=REGION)
_sts = boto3.client("sts", region_name=REGION)


class Unauthorized(Exception):
    pass


def _claims(token: str) -> dict:
    """Decode the JWT payload. Only trusted AFTER GetUser has verified it."""
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except Exception:
        raise Unauthorized("malformed token")


def verify_user(token: str) -> str:
    """Return the Cognito `sub` of a valid access token from OUR pool/client."""
    try:
        user = _cognito.get_user(AccessToken=token)
    except _cognito.exceptions.NotAuthorizedException:
        raise Unauthorized("token invalid, expired or revoked")
    # GetUser accepts a valid token from ANY user pool, so pin the issuer.
    claims = _claims(token)
    if claims.get("iss") != ISSUER:
        raise Unauthorized("token not issued by this user pool")
    if claims.get("client_id") != USER_POOL_CLIENT_ID or claims.get("token_use") != "access":
        raise Unauthorized("token not issued to this app client")
    attrs = {a["Name"]: a["Value"] for a in user["UserAttributes"]}
    return attrs["sub"]


def user_key(sub: str) -> str:
    # Hash, not the raw id: no special characters reach the path, and two
    # ids can never collapse into the same directory.
    return hashlib.sha256(sub.encode()).hexdigest()


def _ap_arn(ap_id: str) -> str:
    return f"arn:aws:s3files:{REGION}:{ACCOUNT_ID}:file-system/{FILE_SYSTEM_ID}/access-point/{ap_id}"


def lookup_storage(sub: str) -> dict:
    """The user's storage record, created at onboarding (never here)."""
    item = _ddb.get_item(TableName=USER_TABLE, Key={"sub": {"S": sub}}, ConsistentRead=True).get("Item")
    if not item:
        raise Unauthorized("no storage provisioned for this user")
    rec = {k: next(iter(v.values())) for k, v in item.items()}
    if rec.get("status") != "active":
        raise Unauthorized(f"user storage is {rec.get('status')}")
    if rec["userKey"] != user_key(sub) or rec["fileSystemId"] != FILE_SYSTEM_ID:
        raise Unauthorized("storage record does not match this user")
    return rec


def session_policy(ap_arn: str) -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "MountThisUsersAccessPointOnly",
                "Effect": "Allow",
                "Action": ["s3files:ClientMount", "s3files:ClientWrite"],
                "Resource": "*",
                "Condition": {"StringEquals": {"s3files:AccessPointArn": ap_arn}},
            },
            {
                "Sid": "EfsCompatThisUsersAccessPointOnly",
                "Effect": "Allow",
                "Action": ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"],
                "Resource": "*",
                "Condition": {"StringEquals": {"elasticfilesystem:AccessPointArn": ap_arn}},
            },
            {
                "Sid": "DiscoverMountTargets",
                "Effect": "Allow",
                "Action": "elasticfilesystem:DescribeMountTargets",
                "Resource": "*",
            },
        ],
    })


def mint_credentials(key: str, ap_id: str) -> dict:
    creds = _sts.assume_role(
        RoleArn=SESSION_MOUNT_ROLE_ARN,
        RoleSessionName=f"user-{key[:32]}",  # shows up in CloudTrail
        Policy=session_policy(_ap_arn(ap_id)),
        DurationSeconds=CRED_TTL,
    )["Credentials"]
    return {
        "AccessKeyId": creds["AccessKeyId"],
        "SecretAccessKey": creds["SecretAccessKey"],
        "SessionToken": creds["SessionToken"],
        "Expiration": creds["Expiration"].isoformat(),
    }


def broker(token: str) -> dict:
    rec = lookup_storage(verify_user(token))
    ap_id = rec["accessPointId"]
    return {
        "username": rec["username"],
        "fileSystemId": FILE_SYSTEM_ID,
        "accessPointId": ap_id,
        "accessPointArn": _ap_arn(ap_id),
        "rootPath": rec["rootPath"],
        "posixUid": int(rec["posixUid"]),
        "posixGid": int(rec["posixGid"]),
        "userKey": rec["userKey"],
        "status": rec["status"],
        "credentials": mint_credentials(rec["userKey"], ap_id),
    }


def handler(event, context):
    token = event.get("token") if isinstance(event, dict) else None
    if not token:
        return {"error": "unauthorized: missing token"}
    try:
        result = broker(token)
        print(json.dumps({"event": "minted", "userKey": result["userKey"],
                          "accessPointId": result["accessPointId"],
                          "expiration": result["credentials"]["Expiration"]}))
        return result
    except Unauthorized as e:
        print(json.dumps({"event": "rejected", "reason": str(e)}))
        return {"error": f"unauthorized: {e}"}
