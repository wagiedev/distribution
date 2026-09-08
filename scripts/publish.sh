#!/usr/bin/env bash

set -euo pipefail

readonly DESTINATION_REPOSITORY=wagiedev/distribution
readonly API_VERSION=2026-03-10
readonly TRANSFER_ROOT=${1:?verified transfer root is required}
readonly CONTAINER_EVIDENCE=${2:?verified container evidence archive is required}

: "${GH_TOKEN:?destination release token is required}"
: "${TAG:?release tag is required}"
: "${SOURCE_REPOSITORY:?source repository is required}"
: "${SOURCE_RUN_ID:?source run ID is required}"
: "${SOURCE_SHA:?source SHA is required}"
: "${SOURCE_ARTIFACT_ID:?source artifact ID is required}"
: "${SOURCE_ARTIFACT_DIGEST:?source artifact digest is required}"
: "${CONTAINER_ARTIFACT_ID:?container artifact ID is required}"
: "${CONTAINER_ARTIFACT_DIGEST:?container artifact digest is required}"
: "${GITHUB_SHA:?receiver SHA is required}"
: "${GITHUB_REPOSITORY:?receiver repository is required}"

test "$GITHUB_REPOSITORY" = "$DESTINATION_REPOSITORY"
[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]]

python3 scripts/release_policy.py validate-inputs \
  --source-repository "$SOURCE_REPOSITORY" \
  --source-run-id "$SOURCE_RUN_ID" \
  --source-sha "$SOURCE_SHA" \
  --tag "$TAG" \
  --source-artifact-id "$SOURCE_ARTIFACT_ID" \
  --source-artifact-digest "$SOURCE_ARTIFACT_DIGEST" \
  --container-artifact-id "$CONTAINER_ARTIFACT_ID" \
  --container-artifact-digest "$CONTAINER_ARTIFACT_DIGEST"
python3 scripts/release_policy.py verify-transfer \
  --root "$TRANSFER_ROOT" \
  --source-repository "$SOURCE_REPOSITORY" \
  --source-sha "$SOURCE_SHA" \
  --tag "$TAG"
test "$(basename -- "$CONTAINER_EVIDENCE")" = "containers_${TAG#v}.tar.gz"
test -f "$CONTAINER_EVIDENCE"
test ! -L "$CONTAINER_EVIDENCE"

destination_tip=$(gh api -H "X-GitHub-Api-Version: $API_VERSION" \
  "repos/$DESTINATION_REPOSITORY/commits/master" --jq .sha)
test "$destination_tip" = "$GITHUB_SHA"

releases=$(gh api --paginate -H "X-GitHub-Api-Version: $API_VERSION" \
  "repos/$DESTINATION_REPOSITORY/releases?per_page=100" --jq '.[]' | jq -s '.')
jq -e 'type == "array" and all(.[]; type == "object" and (.tag_name | type == "string"))' \
  <<<"$releases" >/dev/null
if jq -e --arg tag "$TAG" 'any(.[]; .tag_name == $tag)' <<<"$releases" >/dev/null; then
  echo "release $TAG already exists; refusing adoption or overwrite" >&2
  exit 1
fi

expect_absent() {
  local endpoint=$1
  local label=$2
  local response status
  set +e
  response=$(gh api --include -H "X-GitHub-Api-Version: $API_VERSION" "$endpoint" 2>&1)
  status=$?
  set -e
  if (( status == 0 )); then
    echo "$label already exists; refusing adoption or overwrite" >&2
    exit 1
  fi
  if ! grep -Eq '^HTTP/[^ ]+ 404( |$)' <<<"$response"; then
    echo "could not prove $label absent" >&2
    printf '%s\n' "$response" >&2
    exit 1
  fi
}

expect_absent "repos/$DESTINATION_REPOSITORY/git/ref/tags/$TAG" "tag $TAG"

staging=$(mktemp -d)
trap 'rm -rf -- "$staging"' EXIT

jq -n --arg ref "refs/tags/$TAG" --arg sha "$GITHUB_SHA" \
  '{ref:$ref,sha:$sha}' > "$staging/tag.json"
gh api --method POST -H "X-GitHub-Api-Version: $API_VERSION" \
  "repos/$DESTINATION_REPOSITORY/git/refs" \
  --input "$staging/tag.json" > "$staging/created-tag.json"
jq -e --arg ref "refs/tags/$TAG" --arg sha "$GITHUB_SHA" '
  .ref == $ref and .object.type == "commit" and .object.sha == $sha
' "$staging/created-tag.json" >/dev/null

jq -n \
  --arg tag "$TAG" \
  --arg target "$GITHUB_SHA" \
  --arg source "$SOURCE_REPOSITORY@$SOURCE_SHA" \
  --arg run "https://github.com/$SOURCE_REPOSITORY/actions/runs/$SOURCE_RUN_ID/attempts/1" \
  --arg artifact "$SOURCE_ARTIFACT_ID" \
  --arg digest "$SOURCE_ARTIFACT_DIGEST" \
  --arg container_artifact "$CONTAINER_ARTIFACT_ID" \
  --arg container_digest "$CONTAINER_ARTIFACT_DIGEST" \
  '{tag_name:$tag,target_commitish:$target,name:$tag,draft:true,prerelease:false,
    generate_release_notes:false,make_latest:"false",
    body:("Source: `"+$source+"`\n\nSource workflow: "+$run+"\n\nSealed transfer artifact: `"+$artifact+"` (`sha256:"+$digest+"`)\n\nSealed container artifact: `"+$container_artifact+"` (`sha256:"+$container_digest+"`)\n\nThe containers evidence archive contains the signed exact Docker Hub index and platform digests, input lock, tests and SPDX SBOMs.\n")}' \
  > "$staging/create.json"

gh api --method POST -H "X-GitHub-Api-Version: $API_VERSION" \
  "repos/$DESTINATION_REPOSITORY/releases" \
  --input "$staging/create.json" > "$staging/created.json"
release_id=$(jq -er '.id | select(type == "number" and . > 0 and floor == .)' \
  "$staging/created.json")

while IFS= read -r asset; do
  python3 scripts/upload_asset.py \
    --release-id "$release_id" \
    --asset "$TRANSFER_ROOT/assets/$asset" \
    --name "$asset" > "$staging/upload-$asset.json"
done < <(python3 scripts/release_policy.py list-assets --tag "$TAG")
python3 scripts/upload_asset.py \
  --release-id "$release_id" \
  --asset "$CONTAINER_EVIDENCE" \
  --name "containers_${TAG#v}.tar.gz" > "$staging/upload-containers.json"

gh api -H "X-GitHub-Api-Version: $API_VERSION" \
  "repos/$DESTINATION_REPOSITORY/releases/$release_id" > "$staging/draft.json"
python3 scripts/release_policy.py verify-release-readback \
  --release "$staging/draft.json" \
  --root "$TRANSFER_ROOT" \
  --tag "$TAG" \
  --release-id "$release_id" \
  --receiver-sha "$GITHUB_SHA" \
  --container-evidence "$CONTAINER_EVIDENCE" \
  --phase draft

tag_sha=$(gh api -H "X-GitHub-Api-Version: $API_VERSION" \
  "repos/$DESTINATION_REPOSITORY/git/ref/tags/$TAG" --jq .object.sha)
test "$tag_sha" = "$GITHUB_SHA"

jq -n '{draft:false,make_latest:"false"}' > "$staging/publish.json"
gh api --method PATCH -H "X-GitHub-Api-Version: $API_VERSION" \
  "repos/$DESTINATION_REPOSITORY/releases/$release_id" \
  --input "$staging/publish.json" > "$staging/published.json"

for _ in {1..30}; do
  gh api -H "X-GitHub-Api-Version: $API_VERSION" \
    "repos/$DESTINATION_REPOSITORY/releases/$release_id" > "$staging/readback.json"
  if jq -e '.draft == false and .immutable == true' "$staging/readback.json" >/dev/null; then
    break
  fi
  sleep 2
done

python3 scripts/release_policy.py verify-release-readback \
  --release "$staging/readback.json" \
  --root "$TRANSFER_ROOT" \
  --tag "$TAG" \
  --release-id "$release_id" \
  --receiver-sha "$GITHUB_SHA" \
  --container-evidence "$CONTAINER_EVIDENCE" \
  --phase published

tag_sha=$(gh api -H "X-GitHub-Api-Version: $API_VERSION" \
  "repos/$DESTINATION_REPOSITORY/git/ref/tags/$TAG" --jq .object.sha)
test "$tag_sha" = "$GITHUB_SHA"
