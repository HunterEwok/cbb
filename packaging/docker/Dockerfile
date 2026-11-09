# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# The cbb image: the static cbb of a release, the programs beside it, and
# nothing else.
# context.sh lays out the build context; see README.md here.
FROM scratch
ARG TARGETARCH
ARG TARGETVARIANT
COPY --chown=65532:65532 rootfs/ /
COPY bin-${TARGETARCH}${TARGETVARIANT}/ /usr/local/bin/
USER 65532:65532
# The service then makes no group and takes no admin key: their keys would
# be in a file in the volume (README.md here, "Keys").
ENV CBB_CONTAINER=docker
VOLUME /var/lib/cbb
ENTRYPOINT ["/usr/local/bin/cbb"]
CMD ["service"]
