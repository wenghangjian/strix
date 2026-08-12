FROM python@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b AS builder

RUN rm -rf \
      /usr/local/bin/2to3* \
      /usr/local/bin/idle* \
      /usr/local/bin/pip* \
      /usr/local/bin/pydoc* \
      /usr/local/lib/python3.12/ensurepip \
      /usr/local/lib/python3.12/idlelib \
      /usr/local/lib/python3.12/site-packages/pip* \
      /usr/local/lib/python3.12/site-packages/setuptools* \
      /usr/local/lib/python3.12/site-packages/pkg_resources

FROM gcr.io/distroless/base-debian12@sha256:63f52bd27b6aa6555f5d56500b70d7bb0afe51c654905be88a2c1cf967a77b1a

ARG WORKER_SOURCE_DIGEST

COPY --from=builder /usr/local /usr/local
COPY --from=builder /lib/x86_64-linux-gnu/libbz2.so.1.0 /lib/x86_64-linux-gnu/libbz2.so.1.0
COPY --from=builder /lib/x86_64-linux-gnu/libcrypto.so.3 /lib/x86_64-linux-gnu/libcrypto.so.3
COPY --from=builder /lib/x86_64-linux-gnu/libgcc_s.so.1 /lib/x86_64-linux-gnu/libgcc_s.so.1
COPY --from=builder /lib/x86_64-linux-gnu/liblzma.so.5 /lib/x86_64-linux-gnu/liblzma.so.5
COPY --from=builder /lib/x86_64-linux-gnu/libssl.so.3 /lib/x86_64-linux-gnu/libssl.so.3
COPY --from=builder /lib/x86_64-linux-gnu/libz.so.1 /lib/x86_64-linux-gnu/libz.so.1
COPY --from=worker_deps / /opt/firmware-worker/site-packages
COPY strix/__init__.py /app/strix/__init__.py
COPY strix/domains/__init__.py /app/strix/domains/__init__.py
COPY strix/domains/product_security/firmware/errors.py /app/strix/domains/product_security/firmware/errors.py
COPY strix/domains/product_security/firmware/protocol /app/strix/domains/product_security/firmware/protocol
COPY strix/domains/product_security/firmware/worker /app/strix/domains/product_security/firmware/worker

ENV PYTHONHASHSEED=0 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app:/opt/firmware-worker/site-packages \
    STRIX_FIRMWARE_WORKER_BUILD_ID=${WORKER_SOURCE_DIGEST} \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

LABEL org.opencontainers.image.title="Strix firmware worker" \
      org.opencontainers.image.source="https://github.com/usestrix/strix" \
      io.strix.firmware.worker.source-digest="${WORKER_SOURCE_DIGEST}" \
      io.strix.firmware.worker.protocol-version="1.0" \
      io.strix.firmware.worker.manifest-schema="p2a-manifest-1"

WORKDIR /work
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/python3.12", "-m", "strix.domains.product_security.firmware.worker"]
