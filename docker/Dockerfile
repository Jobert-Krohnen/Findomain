# The release workflow stages the binaries under bin/<arch>/ straight from the
# build that produced the release assets, so the image carries exactly the
# version being released and nothing is downloaded at build time.
#
# To build by hand, put a static musl binary at docker/bin/amd64/findomain
# (and docker/bin/arm64/findomain for a multi-arch image) and run:
#
#   docker build -f docker/Dockerfile docker/
#
# docker run --rm edu4rdshl/findomain -t example.com
FROM alpine:latest
ARG TARGETARCH
LABEL maintainers="wfnintr@null.net,edu4rdshl@protonmail.com"
WORKDIR /opt/findomain
# A static musl binary needs nothing installed on top of alpine, and the CA
# bundle the TLS stack reads ships with the base image. No RUN step means the
# arm64 image builds on an amd64 runner without emulation.
COPY --chmod=755 bin/${TARGETARCH}/findomain /usr/bin/findomain
ENTRYPOINT ["findomain"]
