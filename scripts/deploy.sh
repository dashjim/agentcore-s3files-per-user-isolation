#!/bin/bash
# One-shot deploy: network (optional) -> infra (CFN) -> broker Lambda ->
# agent image -> AgentCore Runtime (CFN) -> frontend (S3 + CloudFront).
# Re-run to update; it is idempotent.
#
#   REGION=us-west-2 bash scripts/deploy.sh                 # creates a test VPC
#   VPC_ID=vpc-.. SUBNET_A=subnet-.. SUBNET_B=subnet-.. bash scripts/deploy.sh
set -euo pipefail
cd "$(dirname "$0")/.."

STACK_NAME="${STACK_NAME:-s3files-user}"
REGION="${REGION:-us-west-2}"
CRED_TTL_SECONDS="${CRED_TTL_SECONDS:-3600}"
export AWS_REGION="$REGION" AWS_DEFAULT_REGION="$REGION"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
BROKER_FN="${STACK_NAME}-broker"

out() {  # out <stack> <OutputKey>
  aws cloudformation describe-stacks --stack-name "$1" \
    --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue" --output text 2>/dev/null || true
}

# ── 1. Network (only when no VPC is given) ──
if [[ -z "${VPC_ID:-}" ]]; then
  echo ">>> [1/6] 部署测试 VPC（NAT + 2 个私有子网）..."
  aws cloudformation deploy --template-file infra/network.yaml --stack-name "${STACK_NAME}-net" --no-fail-on-empty-changeset
  VPC_ID=$(out "${STACK_NAME}-net" VpcId)
  SUBNET_A=$(out "${STACK_NAME}-net" PrivateSubnetA)
  SUBNET_B=$(out "${STACK_NAME}-net" PrivateSubnetB)
fi
: "${SUBNET_A:?SUBNET_A not set}" "${SUBNET_B:?SUBNET_B not set}"

deploy_infra() {  # deploy_infra <image-uri or empty>
  aws cloudformation deploy --template-file infra/infra.yaml --stack-name "$STACK_NAME" \
    --capabilities CAPABILITY_NAMED_IAM --no-fail-on-empty-changeset \
    --parameter-overrides VpcId="$VPC_ID" PrivateSubnetA="$SUBNET_A" PrivateSubnetB="$SUBNET_B" ImageUri="$1"
}

# ── 2. Infra, keeping whatever image the runtime currently runs ──
echo ">>> [2/6] 部署基础设施（S3 Files / Cognito / IAM / ECR / 前端）..."
CURRENT_IMAGE=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" \
  --query "Stacks[0].Parameters[?ParameterKey=='ImageUri'].ParameterValue" --output text 2>/dev/null || true)
[[ "$CURRENT_IMAGE" == "None" ]] && CURRENT_IMAGE=""
deploy_infra "$CURRENT_IMAGE"

FS_ID=$(out "$STACK_NAME" FileSystemId)
ECR_REPO=$(out "$STACK_NAME" EcrRepositoryUri)

# ── 3. Broker Lambda (create or update) ──
echo ">>> [3/6] 部署 broker Lambda..."
rm -f /tmp/${BROKER_FN}.zip && (cd broker && zip -q /tmp/${BROKER_FN}.zip handler.py)
BROKER_ENV="Variables={FILE_SYSTEM_ID=$FS_ID,SESSION_MOUNT_ROLE_ARN=$(out "$STACK_NAME" SessionMountRoleArn),USER_POOL_ID=$(out "$STACK_NAME" UserPoolId),USER_POOL_CLIENT_ID=$(out "$STACK_NAME" UserPoolClientId),USER_TABLE=$(out "$STACK_NAME" UserStorageTableName),ACCOUNT_ID=$ACCOUNT_ID,CRED_TTL_SECONDS=$CRED_TTL_SECONDS}"
if aws lambda get-function --function-name "$BROKER_FN" >/dev/null 2>&1; then
  aws lambda update-function-code --function-name "$BROKER_FN" --zip-file "fileb:///tmp/${BROKER_FN}.zip" >/dev/null
  aws lambda wait function-updated --function-name "$BROKER_FN"
  aws lambda update-function-configuration --function-name "$BROKER_FN" --environment "$BROKER_ENV" >/dev/null
else
  aws lambda create-function --function-name "$BROKER_FN" --runtime python3.12 --architectures arm64 \
    --handler handler.handler --role "$(out "$STACK_NAME" BrokerRoleArn)" \
    --zip-file "fileb:///tmp/${BROKER_FN}.zip" --timeout 30 --memory-size 256 --environment "$BROKER_ENV" >/dev/null
fi
aws lambda wait function-updated --function-name "$BROKER_FN"

# ── 4. Agent image (ARM64) ──
TAG="v$(date +%Y%m%d%H%M%S)"
echo ">>> [4/6] 构建并推送镜像 ${ECR_REPO}:${TAG} ..."
aws ecr get-login-password | docker login --username AWS --password-stdin "${ECR_REPO%%/*}" >/dev/null
docker build --platform linux/arm64 -f container/Dockerfile -t "${ECR_REPO}:${TAG}" .
docker push "${ECR_REPO}:${TAG}" >/dev/null

# ── 5. Runtime (PlatformVersion V2, VPC, JWT authorizer) ──
echo ">>> [5/6] 创建/更新 AgentCore Runtime..."
deploy_infra "${ECR_REPO}:${TAG}"
RUNTIME_ARN=$(out "$STACK_NAME" AgentRuntimeArn)

# ── 6. Frontend ──
echo ">>> [6/6] 发布前端..."
FRONTEND_BUCKET=$(out "$STACK_NAME" FrontendBucketName)
cat > /tmp/${STACK_NAME}-config.js <<EOF
window.APP_CONFIG = {
  region: "$REGION",
  userPoolId: "$(out "$STACK_NAME" UserPoolId)",
  userPoolClientId: "$(out "$STACK_NAME" UserPoolClientId)",
  runtimeArn: "$RUNTIME_ARN",
};
EOF
aws s3 cp /tmp/${STACK_NAME}-config.js "s3://$FRONTEND_BUCKET/config.js" --content-type application/javascript >/dev/null
aws s3 sync frontend/ "s3://$FRONTEND_BUCKET/" --exclude "config*.js" --delete >/dev/null

echo
echo "完成。"
echo "  前端地址:     $(out "$STACK_NAME" FrontendUrl)"
echo "  Runtime ARN:  $RUNTIME_ARN"
echo "  开通用户:     python3 scripts/manage_users.py add alice"
