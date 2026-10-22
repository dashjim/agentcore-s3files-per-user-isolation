#!/bin/bash
# Tear everything down: access points -> broker -> buckets -> infra stack -> network stack.
set -uo pipefail
STACK_NAME="${STACK_NAME:-s3files-user}"
REGION="${REGION:-us-west-2}"
export AWS_REGION="$REGION" AWS_DEFAULT_REGION="$REGION"

out() {
  aws cloudformation describe-stacks --stack-name "$1" \
    --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue" --output text 2>/dev/null
}

# Per-user access points are created by the broker, not CFN; the file system
# cannot be deleted while they exist.
FS_ID=$(out "$STACK_NAME" FileSystemId)
if [[ -n "$FS_ID" && "$FS_ID" != "None" ]]; then
  echo ">>> 删除用户 access points..."
  for AP in $(aws s3files list-access-points --file-system-id "$FS_ID" \
                --query 'accessPoints[].accessPointId' --output text); do
    aws s3files delete-access-point --access-point-id "$AP" && echo "  deleted $AP"
  done
fi

echo ">>> 删除 broker Lambda..."
aws lambda delete-function --function-name "${STACK_NAME}-broker" 2>/dev/null || true

empty_bucket() {
  local b="$1"; [[ -z "$b" || "$b" == "None" ]] && return
  echo ">>> 清空桶 $b ..."
  aws s3 rm "s3://$b" --recursive >/dev/null 2>&1 || true
  while :; do
    local batch
    batch=$(aws s3api list-object-versions --bucket "$b" --max-items 500 --output json \
      --query '{Objects: [Versions[].{Key:Key,VersionId:VersionId}, DeleteMarkers[].{Key:Key,VersionId:VersionId}][]}')
    [[ "$(echo "$batch" | python3 -c 'import sys,json;print(len(json.load(sys.stdin).get("Objects") or []))')" == "0" ]] && break
    aws s3api delete-objects --bucket "$b" --delete "$batch" >/dev/null
  done
}
empty_bucket "$(out "$STACK_NAME" DataBucketName)"
empty_bucket "$(out "$STACK_NAME" FrontendBucketName)"

echo ">>> 删除基础设施栈 $STACK_NAME ..."
aws cloudformation delete-stack --stack-name "$STACK_NAME"
aws cloudformation wait stack-delete-complete --stack-name "$STACK_NAME" || {
  echo "!!! 栈删除失败：Runtime 的 VPC ENI 释放可能较慢，稍后重跑本脚本即可"; exit 1; }

if aws cloudformation describe-stacks --stack-name "${STACK_NAME}-net" >/dev/null 2>&1; then
  echo ">>> 删除测试 VPC 栈 ${STACK_NAME}-net ..."
  aws cloudformation delete-stack --stack-name "${STACK_NAME}-net"
  aws cloudformation wait stack-delete-complete --stack-name "${STACK_NAME}-net"
fi
echo ">>> 完成"
