# Wagie releases

This repository publishes verified Wagie OCI images to Docker Hub, then verified
downloads and image evidence as immutable GitHub releases. Releases use exact
version tags; published assets and container tags are never replaced.

## What is published

Version `1.2.3` publishes `1.2.3` to `wagiedev/wagied`,
`wagiedev/wagied-headquarters` and `wagiedev/wagied-runner`, and
`1.2.3-toolchains` to `wagiedev/wagied-runner`, each with `linux/amd64` and
`linux/arm64`. No mutable aliases are published. Every destination repository is
public and enforces immutable tags matching this exact rule:

```text
^[0-9]+\.[0-9]+\.[0-9]+(-toolchains)?$
```

The receiver authenticates that exact policy and proves all four destination
tags absent before the first upload.

Publication requires a fresh version tag and the first workflow attempt. An
existing tag or release causes failure. Failed drafts require administrator
review before another release is attempted.

## How releases are verified

The eight required dispatch coordinates include `container_artifact_id` and
`container_artifact_digest`, identifying the `container-release` artifact from
the same live source release run and first attempt as `distribution-release`.
The source's `container_build` and `seal_containers` jobs must have succeeded.
Its input lock is fetched from the authenticated source commit; the receiver
uses its own OCI verifier and verifies the source's Sigstore signature before
exposing the Docker Hub token on a distribution runner. It never executes
transferred code or images. Skopeo copies the complete OCI graphs while
preserving digests, and the receiver reads back every index and platform
manifest to compare exact bytes.

Only successful publication of all four images enables GitHub release
publication. The additional `containers_<version>.tar.gz` release asset contains
the signed `images.json`, Sigstore bundle, reviewed input lock, eight SPDX SBOMs,
and eight test records. It excludes OCI blobs, which remain in Docker Hub under
the signed digests. The evidence archive receives a public GitHub attestation
and immutable asset readback alongside the existing 35 native assets.

Registry and GitHub publication are separate operations. A partial failure
stops the release, leaves any published immutable versions intact, and requires
investigation followed by a fresh version; retries do not adopt or overwrite
existing artifacts. Environment approval delays count against the source's
handoff deadline.

GitHub Actions carries transfer receipts capped at 1 MiB, retained for one day.
The binary, OCI and evidence files travel through the private NUC object store;
the receiver checks their identity, SHA256, size and mode against the authenticated
receipt before applying the existing release and signature policies. The store
expires objects after one day and enforces a 128 GiB bucket quota.

Configure `WAGIE_ARTIFACT_ENDPOINT`, `WAGIE_ARTIFACT_BUCKET` and
`WAGIE_ARTIFACT_CA_CERT` as repository variables, plus
`WAGIE_ARTIFACT_ACCESS_KEY_ID` and `WAGIE_ARTIFACT_SECRET_ACCESS_KEY` as secrets.
The distribution key reads the source prefix and reads/writes its own prefix;
it cannot write source objects or administer the store. The runners require the
AWS CLI and a route to the HTTPS endpoint. A probe checks this before publication.

No App used by this workflow has Workflows write, Administration write, or
access to repository secrets; jobs request only the permissions needed for their
step. The Docker Hub username is fixed in reviewed receiver code, so there is no
username variable, password login, or alternate registry destination, and the
source repository never receives the registry token.

## Validation

CI and publication use the `self-hosted, wagie-distribution` runner pool. Each
NUC runs a separate Compose service with its own container workspace and no
shared build caches or host Docker socket. Compose restarts the container after
each ephemeral runner registration completes; the container filesystem is
reused between jobs.

Run `make test` with Python 3.12+, Bash 5.2+ and ShellCheck 0.9.0. The validation
script downloads and verifies actionlint 1.7.12 when it is not already installed.
Tests use local fixtures and do not publish releases.

`make test-registry` additionally requires Docker and Skopeo and starts a
disposable loopback-only registry to verify real multiarch copying and digest
readback. It uses synthetic tiny OCI images and a mock Docker Hub policy API;
no Docker Hub credentials or public publication are used.

GitHub documents [immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
and [release integrity verification](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/verify-release-integrity).
Docker documents [immutable tags](https://docs.docker.com/docker-hub/repos/manage/hub-images/immutable-tags/)
and the [Hub repository API](https://docs.docker.com/reference/api/hub/latest/).
