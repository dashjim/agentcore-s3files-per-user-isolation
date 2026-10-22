FROM public.ecr.aws/amazonlinux/amazonlinux:2023

# amazon-efs-utils: mount.s3files + efs-proxy + watchdog (uses the SYSTEM
# python3, which needs botocore to read the awsprofile credentials).
# python3.11: gateway + agent.
RUN dnf install -y --setopt=install_weak_deps=False \
        amazon-efs-utils python3.11 python3.11-pip python3-pip shadow-utils procps-ng && \
    python3 -m pip install --no-cache-dir botocore && \
    # /sys is read-only in the microVM: stop the watchdog retrying read_ahead_kb every second
    sed -i 's/^optimize_readahead = true/optimize_readahead = false/' /etc/amazon/efs/efs-utils.conf /etc/amazon/efs/s3files-utils.conf && \
    dnf clean all && rm -rf /var/cache/dnf

COPY container/requirements.txt /app/requirements.txt
RUN pip3.11 install --no-cache-dir -r /app/requirements.txt

# The non-root identity the agent runs as; must equal the access point posixUser.
ARG AGENT_UID=1000
RUN groupadd -g ${AGENT_UID} agent && useradd -u ${AGENT_UID} -g ${AGENT_UID} -m -d /home/agent agent && \
    mkdir -p /mnt/user /root/.aws && chmod 700 /root /root/.aws

COPY container/gateway.py container/agent_app.py container/entrypoint.sh /app/
RUN chmod 755 /app/entrypoint.sh && chmod 644 /app/*.py

EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
