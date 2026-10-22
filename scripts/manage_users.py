"""User onboarding / storage management -- the upstream control plane.

Plays the upstream onboarding system: when a user is created, the control plane
(never the container, never the broker) creates the user's S3 Files access
point and records the user -> access point mapping. Run with admin
credentials from outside the microVM.

  python3 scripts/manage_users.py add alice [--password P]   # Cognito user + AP + mapping
  python3 scripts/manage_users.py list
  python3 scripts/manage_users.py show alice
  python3 scripts/manage_users.py disable alice   # broker stops minting -> next mount/rotation fails
  python3 scripts/manage_users.py enable alice
  python3 scripts/manage_users.py remove alice [--purge-data]   # AP + mapping + Cognito user

Env: STACK_NAME (default s3files-user), REGION (default us-west-2).
"""

import argparse
import hashlib
import os
import secrets
import string
import sys
import time
from datetime import datetime, timezone

import boto3

STACK = os.environ.get("STACK_NAME", "s3files-user")
REGION = os.environ.get("REGION", "us-west-2")
POSIX_UID = POSIX_GID = 1000  # must equal the agent's uid in the container

_cfn = boto3.client("cloudformation", region_name=REGION)
OUT = {o["OutputKey"]: o["OutputValue"] for o in _cfn.describe_stacks(StackName=STACK)["Stacks"][0]["Outputs"]}
POOL, FS_ID, TABLE, BUCKET = OUT["UserPoolId"], OUT["FileSystemId"], OUT["UserStorageTableName"], OUT["DataBucketName"]

idp = boto3.client("cognito-idp", region_name=REGION)
s3files = boto3.client("s3files", region_name=REGION)
ddb = boto3.resource("dynamodb", region_name=REGION).Table(TABLE)


def user_key(sub: str) -> str:
    return hashlib.sha256(sub.encode()).hexdigest()  # same derivation as the broker


def _sub(username: str) -> str:
    attrs = idp.admin_get_user(UserPoolId=POOL, Username=username)["UserAttributes"]
    return next(a["Value"] for a in attrs if a["Name"] == "sub")


def _record(username: str) -> dict | None:
    return ddb.get_item(Key={"sub": _sub(username)}, ConsistentRead=True).get("Item")


def create_access_point(key: str, username: str) -> str:
    try:
        ap_id = s3files.create_access_point(
            fileSystemId=FS_ID,
            clientToken=key,  # idempotent: re-running add never creates a second AP
            posixUser={"uid": POSIX_UID, "gid": POSIX_GID},
            rootDirectory={
                "path": f"/users/{key}",
                "creationPermissions": {"ownerUid": POSIX_UID, "ownerGid": POSIX_GID, "permissions": "700"},
            },
            tags=[{"key": "user-key", "value": key}, {"key": "username", "value": username}],
        )["accessPointId"]
    except s3files.exceptions.ConflictException as e:
        ap_id = e.response.get("resourceId") or sys.exit(f"conflict without resourceId: {e}")
    for _ in range(60):
        if s3files.get_access_point(accessPointId=ap_id).get("lifeCycleState", "available") == "available":
            break
        time.sleep(2)
    return ap_id


def add(username: str, password: str | None) -> dict:
    password = password or "Aa1#" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    try:
        idp.admin_create_user(UserPoolId=POOL, Username=username, MessageAction="SUPPRESS")
    except idp.exceptions.UsernameExistsException:
        pass
    idp.admin_set_user_password(UserPoolId=POOL, Username=username, Password=password, Permanent=True)
    sub = _sub(username)
    key = user_key(sub)
    ap_id = create_access_point(key, username)
    item = {
        "sub": sub, "username": username, "userKey": key,
        "fileSystemId": FS_ID, "accessPointId": ap_id, "rootPath": f"/users/{key}",
        "posixUid": POSIX_UID, "posixGid": POSIX_GID, "status": "active",
        "createdAt": datetime.now(timezone.utc).isoformat(),
    }
    ddb.put_item(Item=item)
    return {**item, "password": password}


def set_status(username: str, status: str) -> None:
    ddb.update_item(Key={"sub": _sub(username)}, UpdateExpression="SET #s = :s",
                    ExpressionAttributeNames={"#s": "status"}, ExpressionAttributeValues={":s": status},
                    ConditionExpression="attribute_exists(#s)")


def remove(username: str, purge_data: bool) -> None:
    rec = _record(username)
    if rec:
        s3files.delete_access_point(accessPointId=rec["accessPointId"])
        ddb.delete_item(Key={"sub": rec["sub"]})
        if purge_data:
            bucket = boto3.resource("s3", region_name=REGION).Bucket(BUCKET)
            bucket.object_versions.filter(Prefix=rec["rootPath"].lstrip("/") + "/").delete()
    idp.admin_delete_user(UserPoolId=POOL, Username=username)


def main() -> None:
    p = argparse.ArgumentParser(description="用户开户与存储映射管理（模拟上游控制面）")
    sp = p.add_subparsers(dest="cmd", required=True)
    a = sp.add_parser("add"); a.add_argument("username"); a.add_argument("--password")
    sp.add_parser("list")
    for c in ("show", "disable", "enable"):
        sp.add_parser(c).add_argument("username")
    r = sp.add_parser("remove"); r.add_argument("username"); r.add_argument("--purge-data", action="store_true")
    args = p.parse_args()

    if args.cmd == "add":
        rec = add(args.username, args.password)
        print(f"已开通：{rec['username']} / {rec['password']}")
        print(f"  accessPoint={rec['accessPointId']}  rootPath={rec['rootPath']}")
    elif args.cmd == "list":
        items = ddb.scan()["Items"]
        print(f"{'username':<16}{'status':<10}{'accessPointId':<26}rootPath")
        for i in sorted(items, key=lambda x: x["username"]):
            print(f"{i['username']:<16}{i['status']:<10}{i['accessPointId']:<26}{i['rootPath']}")
    elif args.cmd == "show":
        rec = _record(args.username)
        print(rec or "（未开通存储）")
    elif args.cmd in ("disable", "enable"):
        set_status(args.username, "disabled" if args.cmd == "disable" else "active")
        print(f"{args.username} -> {'disabled' if args.cmd == 'disable' else 'active'}")
    elif args.cmd == "remove":
        remove(args.username, args.purge_data)
        print(f"已删除 {args.username}" + ("（含 S3 数据）" if args.purge_data else "（S3 数据保留）"))


if __name__ == "__main__":
    main()
