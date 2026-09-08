#!/usr/bin/env python3

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PUBLISH = ROOT / ".github" / "workflows" / "publish-wagie.yml"
POLICY = ROOT / "scripts" / "release_policy.py"
PUBLISHER = ROOT / "scripts" / "publish.sh"
EXPECTED_INPUTS = {
    "source_repository",
    "source_run_id",
    "source_sha",
    "tag",
    "source_artifact_id",
    "source_artifact_digest",
    "container_artifact_id",
    "container_artifact_digest",
}


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def section(text, start, end=None):
    begin = text.index(start)
    finish = text.index(end, begin) if end is not None else len(text)
    return text[begin:finish]


def run_blocks(text):
    lines = text.splitlines()
    result = []
    index = 0
    while index < len(lines):
        match = re.match(r"^(\s*)run:\s*(.*)$", lines[index])
        if match is None:
            index += 1
            continue
        indent = len(match.group(1))
        body = [match.group(2)]
        index += 1
        while index < len(lines):
            line = lines[index]
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                break
            body.append(line)
            index += 1
        result.append("\n".join(body))
    return result


def main():
    workflow = PUBLISH.read_text(encoding="utf-8")
    publisher = PUBLISHER.read_text(encoding="utf-8")

    trigger = section(workflow, "on:\n", "\npermissions:")
    require("  workflow_dispatch:\n" in trigger, "publisher must use workflow_dispatch")
    for forbidden in ("push:", "pull_request:", "schedule:", "repository_dispatch:", "workflow_call:"):
        require(forbidden not in trigger, f"publisher exposes forbidden trigger {forbidden}")
    inputs = {
        match.group(1)
        for match in re.finditer(r"^      ([a-z_]+):\n        required: true\n        type: string$", trigger, re.MULTILINE)
    }
    require(inputs == EXPECTED_INPUTS, "publisher dispatch input surface drifted")
    require(
        "source_run_attempt" not in workflow + publisher,
        "publisher retains a source rerun coordinate",
    )

    for block in run_blocks(workflow):
        require("${{ inputs." not in block, "workflow input is interpolated directly into a shell")

    actor = workflow.index("name: Authenticate the handoff actor")
    reader = workflow.index("name: Mint source-only read authority")
    require(actor < reader, "handoff actor must be authenticated before source access")
    require("test \"$GITHUB_ACTOR\" = \"$EXPECTED_HANDOFF_ACTOR\"" in workflow, "exact handoff actor gate is missing")
    for gate in (
        'test "$GITHUB_TRIGGERING_ACTOR" = "$EXPECTED_HANDOFF_ACTOR"',
        'test "$GITHUB_RUN_ATTEMPT" = 1',
        'test "$GITHUB_REPOSITORY" = wagiedev/distribution',
        'test "$GITHUB_EVENT_NAME" = workflow_dispatch',
        'test "$GITHUB_REF" = refs/heads/master',
    ):
        require(gate in workflow, f"handoff context gate is missing: {gate}")
    require("WAGIE_HANDOFF_APP_ACTOR" in workflow, "handoff actor setup is not locked")
    policy_gate = workflow.index("name: Authenticate destination tip and immutable policy before write authority")
    writer = workflow.index("name: Mint destination-only release authority")
    require(policy_gate < writer, "destination policy must be authenticated before write authority is minted")

    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    require("branches: [master]" in ci, "CI must cover the default branch")
    for document in (workflow, ci):
        runners = re.findall(r"^    runs-on: (.+)$", document, re.MULTILINE)
        require(runners and all(runner == "ubuntu-24.04" for runner in runners), "authority and validation jobs require fresh hosted runners")
    require("refs/heads/main" not in workflow and "commits/main" not in workflow + publisher, "receiver retains an obsolete branch")
    require("done < <(python3" not in workflow, "verification must check manifest enumeration before entering its loop")

    timeouts = [int(value) for value in re.findall(r"^    timeout-minutes: ([0-9]+)$", workflow, re.MULTILINE)]
    require(timeouts == [25, 60, 25], "receiver timeout budgets must cover authentication, image promotion and downloads")

    image_job = section(workflow, "  publish_images:\n", "  publish:\n")
    native_job = section(workflow, "  publish:\n")
    require("needs: [authenticate, publish_images]" in native_job, "native publication must require image publication success")
    require("environment: docker-release" in image_job, "Docker Hub authority requires docker-release environment")
    require("name: Authenticate and reverify OCI bytes before Docker Hub authority" in image_job, "image verifier is missing")
    require(image_job.index("scripts/oci_policy.py verify") < image_job.index("DOCKERHUB_TOKEN:"), "OCI policy must pass before Docker Hub authority")
    require(image_job.index("cosign verify-blob") < image_job.index("DOCKERHUB_TOKEN:"), "source OCI signature must pass before Docker Hub authority")
    require(workflow.count("secrets.DOCKERHUB_TOKEN") == 1, "Docker Hub PAT must be isolated to one publishing step")
    require("source_reader" not in image_job and "WAGIE_RELEASE_WRITER" not in image_job, "image publisher has unrelated authority")
    require("contents/distribution/image-inputs.env?ref=$SOURCE_SHA" in workflow, "OCI input policy must come from the authenticated source commit")
    for invariant in ("published-container-evidence", "--container-evidence", "scripts/oci_policy.py verify-evidence", "needs.publish_images.outputs.evidence_artifact_digest"):
        require(invariant in native_job, "image evidence is not bound into native publication: " + invariant)
    image_publisher = (ROOT / "scripts" / "publish_images.py").read_text(encoding="utf-8")
    for invariant in ('USERNAME = "wagiedev"', '"--preserve-digests"', '"--all"', '"MANIFEST_UNKNOWN"', '"docker-content-digest"', '"immutable_tags_settings"'):
        require(invariant in image_publisher, "image publication invariant is missing: " + invariant)
    for forbidden in ("docker run", "docker build", "docker load", "--dest-tls-verify=false", "--format", "--dest-compress"):
        require(forbidden not in image_job + image_publisher, "receiver must only copy exact verified OCI bytes: " + forbidden)

    require("permissions: {}" in workflow, "publisher must deny ambient permissions")
    require("permission-actions: read" in workflow, "source reader lacks Actions read")
    require("permission-contents: read" in workflow, "source reader lacks Contents read")
    require("permission-administration: read" in workflow, "writer cannot authenticate immutable policy")
    require("permission-contents: write" in workflow, "release writer lacks exact mutation authority")
    require("permission-workflows:" not in workflow, "no App may receive Workflows permission")
    require("permission-administration: write" not in workflow, "no App may mutate repository administration")
    app_scopes = re.findall(r"^          owner: (.+)\n          repositories: (.+)$", workflow, re.MULTILINE)
    require(
        app_scopes == [("Savid", "wagie"), ("wagiedev", "distribution"), ("wagiedev", "distribution")],
        "App installation scopes must bind the source reader to Savid/wagie and destination authority to wagiedev/distribution",
    )

    for match in re.finditer(r"^\s*-?\s*uses:\s*([^\s#]+)", workflow, re.MULTILINE):
        action = match.group(1)
        require(re.search(r"@[0-9a-f]{40}$", action) is not None, f"action is not pinned by commit: {action}")

    for required in (
        "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6",
        "gh release verify \"$TAG\"",
        "gh release verify-asset",
        "immutable-releases",
        "digest-mismatch: error",
        "--repo wagiedev/distribution",
        "--signer-workflow wagiedev/distribution/.github/workflows/publish-wagie.yml",
        "--source-ref refs/heads/master",
        "-R wagiedev/distribution",
    ):
        require(required in workflow or required in publisher, f"missing publication invariant: {required}")

    require("--clobber" not in workflow + publisher, "release assets may not be overwritten")
    require("gh release upload" not in publisher, "publisher must not resolve its draft by tag for upload")
    require("scripts/upload_asset.py" in publisher and '--release-id "$release_id"' in publisher, "publisher does not upload to its exact created release ID")
    for forbidden in ("gh release delete", "delete-asset", "--cleanup-tag"):
        require(forbidden not in workflow + publisher, f"publisher contains destructive recovery: {forbidden}")
    require(
        "releases?per_page=100" in publisher
        and "all(.[]; type == \"object\" and (.tag_name | type == \"string\"))" in publisher
        and "any(.[]; .tag_name == $tag)" in publisher,
        "publisher does not enumerate and refuse published or draft releases",
    )
    require("expect_absent" in publisher, "publisher does not refuse an existing tag")
    require('"repos/$DESTINATION_REPOSITORY/git/refs"' in publisher, "publisher does not atomically create its tag")
    require("refs/tags/$TAG" in publisher and '.object.type == "commit"' in publisher, "publisher does not bind the fresh tag to a commit")
    require("commits/master" in publisher and 'test "$destination_tip" = "$GITHUB_SHA"' in publisher, "publisher does not bind the live receiver tip")
    require(".immutable == true" in publisher, "publisher does not require immutable readback")
    require("for _ in {1..12}" in workflow and 'test "$verified" = true' in workflow, "release-attestation retry is not bounded and fail closed")
    require(
        publisher.count('make_latest:"false"') == 2,
        "draft creation and publication must both refuse the mutable latest pointer",
    )

    policy_source = POLICY.read_text(encoding="utf-8")
    require("source_run_attempt" not in policy_source, "policy retains a source rerun coordinate")
    require("SOURCE_REPOSITORY = \"Savid/wagie\"" in policy_source, "source authority drifted")
    require("DESTINATION_REPOSITORY = \"wagiedev/distribution\"" in policy_source, "destination authority drifted")
    require("readonly DESTINATION_REPOSITORY=wagiedev/distribution" in publisher, "publisher destination authority drifted")


if __name__ == "__main__":
    main()
