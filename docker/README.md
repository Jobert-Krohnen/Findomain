# Findomain Docker image

The published image is `edu4rdshl/findomain`, built for `linux/amd64` and
`linux/arm64`. Every stable release pushes it under two tags, `latest` and the
release version, so a deployment can pin one:

```
docker pull edu4rdshl/findomain:latest
docker run --rm edu4rdshl/findomain:latest -t example.com
```

The working directory inside the container is `/opt/findomain`. Bind mount a
host directory there to hand Findomain a configuration file and to keep what
it writes with `-o` or `-u` after the container is gone:

```
docker run --rm -v "$(pwd):/opt/findomain" edu4rdshl/findomain:latest \
  -c config.toml -t example.com -u results.txt
```

The default SQLite database lands in that same directory as `findomain.db`,
so monitoring runs keep their history across containers through the mount.

The image carries the same static binaries that the release ships as
`findomain-linux.zip` and `findomain-aarch64-musl.zip`, dropped on top of
Alpine. Nothing is downloaded while the image builds, so it always matches the
release it was built with.

## Building it yourself

The Dockerfile expects one static musl binary per architecture under
`bin/<arch>/`, using Docker's architecture names. Stage the ones you need and
build from this directory:

```
mkdir -p bin/amd64 bin/arm64
cp /path/to/x86_64-unknown-linux-musl/release/findomain  bin/amd64/findomain
cp /path/to/aarch64-unknown-linux-musl/release/findomain bin/arm64/findomain
docker build -f Dockerfile -t findomain .
```

For a single architecture, stage only that one and build with `--platform`,
for instance `--platform linux/amd64`. For a multi-arch image use buildx with
`--platform linux/amd64,linux/arm64`; the Dockerfile has no `RUN` step, so the
foreign architecture builds without emulation.

The binaries must be the musl builds: the glibc ones in `findomain-aarch64.zip`
and `findomain-armv7.zip` do not run on Alpine.

## Rebuilding a published release

The `Build Docker images` workflow, run by hand from the Actions tab, takes a
release tag, fetches its binaries and pushes the image again. It is there for
the day the base image needs refreshing without cutting a new release.
