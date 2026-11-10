"""Reapply placer-labs fork changes onto upstream's .github/workflows/pipeline.yml.

Usage, after merging upstream:
  git show origin/main:.github/workflows/pipeline.yml > /tmp/pipeline.up.yml
  python3 scripts/placer/fork_pipeline.py /tmp/pipeline.up.yml .github/workflows/pipeline.yml
Every replacement must match the expected number of times, so an upstream
change that moves a target fails loudly instead of being silently skipped.
"""

import re
import sys

src, dst = sys.argv[1], sys.argv[2]
text = open(src).read()


def sub(pattern, repl, count, flags=0, literal=False):
    global text
    if literal:
        n = text.count(pattern)
        new = text.replace(pattern, repl)
    else:
        new, n = re.subn(pattern, repl, text, flags=flags)
    if n != count:
        sys.exit(f"expected {count} match(es), got {n}: {pattern[:80]!r}")
    text = new


UPSTREAM_ONLY = "github.repository == 'langfuse/langfuse'"

# Run on our line.
sub(
    '      - "v3" # OSS maintenance branch — releases are cut from it like from main\n',
    '      - "v3" # OSS maintenance branch — releases are cut from it like from main\n'
    '      - "placer/main" # this fork\'s line: upstream main plus our changes\n',
    1,
    literal=True,
)

# GitHub-hosted runners instead of Blacksmith.
sub(r"blacksmith-\d+vcpu-ubuntu-2404-arm", "ubuntu-24.04-arm", 3)
sub(
    "runs-on: ${{ matrix.deploy-mode == '-redis-cluster' && 'blacksmith-16vcpu-ubuntu-2404' || 'blacksmith-8vcpu-ubuntu-2404' }}",
    "runs-on: ubuntu-24.04",
    1,
    literal=True,
)
# Pinned to the OS upstream's runners use: ubuntu-latest moves ahead of
# tooling support (Playwright had no browsers for 26.04 when it rolled out).
sub(r"blacksmith-\d+vcpu-ubuntu-2404", "ubuntu-24.04", 31)

# Plain buildx instead of the Blacksmith builder (test jobs; the release job is
# rewritten below).
sub(
    r"      - name: Setup Blacksmith Builder\n"
    r"        uses: useblacksmith/setup-docker-builder@\S+ # v2\.0\.1\n"
    r"        with:\n"
    r"          cache-key: langfuse/test-[^\n]+\n",
    "      - name: Setup Docker Buildx\n"
    "        uses: docker/setup-buildx-action@37fe631027851001ddb9b187196cc803df7f5f0e # v4.3.0\n",
    3,
)

# GitHub-hosted runners have 4 vCPUs; size vitest to them.
sub('      VITEST_MAX_WORKERS: "12"\n      NODE_ENV: test\n',
    '      VITEST_MAX_WORKERS: "4"\n      NODE_ENV: test\n', 1, literal=True)
sub("      VITEST_MAX_WORKERS: ${{ matrix.deploy-mode == '-redis-cluster' && '8' || '4' }}\n",
    '      VITEST_MAX_WORKERS: "4"\n', 1, literal=True)

# One database and deploy-mode combination.
sub(
    '        postgres-version: [15]\n        deploy-mode: ["", "-azure", "-redis-cluster"]\n',
    "        # 17 is the compose default and the version this fork runs; upstream's\n"
    "        # extra leg is compatibility coverage it does not need.\n"
    "        postgres-version: [17]\n"
    "        # The -azure and -redis-cluster topologies are not deployed here, and\n"
    "        # nothing in this fork's delta is specific to either.\n"
    '        deploy-mode: [""]\n',
    2,
    literal=True,
)

# Jobs that need upstream-only secrets or cover components this fork does not
# deploy (AI gateway, FIPS hosts). A skipped job does not fail all-ci-passed.
sub(
    "    if: ${{ !cancelled() && (startsWith(github.ref, 'refs/tags/') || ((github.event_name != 'push' || needs.pre-job.outputs.should_skip != 'true') && (needs.llm-connections-filter.outputs.changed == 'true' || github.event_name == 'workflow_dispatch'))) }}\n",
    "    # Calls the real providers with the LANGFUSE_LLM_CONNECTION_* secrets, which\n"
    "    # only the upstream repository holds.\n"
    f"    if: ${{{{ !cancelled() && {UPSTREAM_ONLY} && (startsWith(github.ref, 'refs/tags/') || ((github.event_name != 'push' || needs.pre-job.outputs.should_skip != 'true') && (needs.llm-connections-filter.outputs.changed == 'true' || github.event_name == 'workflow_dispatch'))) }}}}\n",
    1,
    literal=True,
)
sub(
    "    if: ${{ !cancelled() && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository) && (startsWith(github.ref, 'refs/tags/') || ((github.event_name != 'push' || needs.pre-job.outputs.should_skip != 'true') && (needs.ai-gateway-filter.outputs.changed == 'true' || github.event_name == 'workflow_dispatch'))) }}\n",
    "    # The AI gateway is not deployed by this fork, and the test needs the\n"
    "    # upstream-only LLM provider secrets.\n"
    f"    if: ${{{{ !cancelled() && {UPSTREAM_ONLY} && (startsWith(github.ref, 'refs/tags/') || ((github.event_name != 'push' || needs.pre-job.outputs.should_skip != 'true') && (needs.ai-gateway-filter.outputs.changed == 'true' || github.event_name == 'workflow_dispatch'))) }}}}\n",
    1,
    literal=True,
)
for job, why in (
    ("tests-ai-gateway", "The AI gateway is not deployed by this fork."),
    ("tests-fips", "This fork does not run on FIPS hosts."),
):
    sub(
        rf"(  {job}:\n(?:(?!\n  [a-z]).)*?)\n    if: \$\{{\{{ !cancelled\(\) && ",
        rf"\1\n    # {why}\n    if: ${{{{ !cancelled() && {UPSTREAM_ONLY} && ",
        1,
        flags=re.S,
    )

# label-cursor-prs.yml is dropped as an upstream-only workflow; drop its test.
sub(
    "      - name: cursor PR label tests\n"
    "        run: node --test scripts/github/label-cursor-prs.test.mjs\n",
    "",
    1,
    literal=True,
)

# Slack alerts only when the webhook secret exists.
for step_title in ('"❌ CI failed on', '"❌ Docker release failed on'):
    sub(
        "      - name: Notify Slack\n"
        "        uses: ./.github/actions/notify-slack-failure\n"
        "        with:\n"
        f"          message: {step_title}",
        "      - name: Notify Slack\n"
        "        if: env.SLACK_WEBHOOK != ''\n"
        "        uses: ./.github/actions/notify-slack-failure\n"
        "        with:\n"
        f"          message: {step_title}",
        1,
        literal=True,
    )
for job in ("notify-ci-failure", "notify-docker-image-release"):
    sub(
        f"  {job}:\n",
        f"  {job}:\n    env:\n      SLACK_WEBHOOK: ${{{{ secrets.SLACK_CI_FAILURE_WORKFLOW_WEBHOOK_URL }}}}\n",
        1,
        literal=True,
    )

# --- Release: publish web and worker to ghcr.io/placer-labs on tags and on
# every push to our line, built on the public UBI bases.
RELEASE_REF = "(startsWith(github.ref, 'refs/tags/') || github.ref == 'refs/heads/placer/main')"
sub(
    "    if: always() && needs.all-ci-passed.outputs.success == 'true' && github.event_name == 'push' && startsWith(github.ref, 'refs/tags/')\n"
    '    environment: "protected branches"\n',
    "    # Tags cut a pinned release; pushes to our line publish the moving\n"
    "    # placer-main tag that deployments track by digest, so a merge is enough to\n"
    "    # ship and nobody has to hand-cut a version.\n"
    f"    if: always() && needs.all-ci-passed.outputs.success == 'true' && github.event_name == 'push' && {RELEASE_REF}\n",
    1,
    literal=True,
)
sub(
    "    if: always() && needs.build-docker-image-release.result == 'success' && github.event_name == 'push' && startsWith(github.ref, 'refs/tags/')\n"
    '    environment: "protected branches"\n',
    f"    if: always() && needs.build-docker-image-release.result == 'success' && github.event_name == 'push' && {RELEASE_REF}\n",
    1,
    literal=True,
)
sub(
    "    if: ${{ !cancelled() && github.event_name == 'push' && startsWith(github.ref, 'refs/tags/') && (contains(needs.*.result, 'failure') || contains(needs.*.result, 'cancelled')) }}\n",
    f"    if: ${{{{ !cancelled() && github.event_name == 'push' && {RELEASE_REF} && (contains(needs.*.result, 'failure') || contains(needs.*.result, 'cancelled')) }}}}\n",
    1,
    literal=True,
)

# No AI gateway image.
sub(
    r"          # The gateway crate is its own build context \(ai-gateway/\.dockerignore\)\.\n"
    r"(          - component: ai-gateway\n(?:            [^\n]+\n)+){2}",
    "",
    1,
)
sub(
    r"    # publish-docker-image-release is gated on this whole matrix succeeding, so\n"
    r"(    #[^\n]*\n)*"
    r"    continue-on-error: \$\{\{ matrix\.component == 'ai-gateway' \}\}\n",
    "",
    1,
)
sub("          - component: ai-gateway\n            image_name: ai-gateway\n", "", 1, literal=True)

# No Docker Hub.
sub(
    r"      - name: Log in to Docker Hub\n"
    r"        uses: docker/login-action@\S+ # v4\.6\.0\n"
    r"        with:\n"
    r"          username: \$\{\{ secrets\.DOCKERHUB_USERNAME \}\}\n"
    r"          password: \$\{\{ secrets\.DOCKERHUB_TOKEN \}\}\n",
    "",
    2,
)
sub(
    r"      - name: Build and push image by digest to Docker Hub .*?\n(?=      - name: Record pushed digests\n)",
    "",
    1,
    flags=re.S,
)
sub(
    r"      - name: Record pushed digests\n.*?\n(?=  publish-docker-image-release:\n)",
    "      - name: Record pushed digests\n"
    "        env:\n"
    "          DIGEST_GHCR: ${{ steps.build-ghcr.outputs.digest }}\n"
    "          PLATFORM_TAG: ${{ matrix.platform_tag }}\n"
    "        run: |\n"
    '          if [ -z "$DIGEST_GHCR" ]; then\n'
    '            echo "Missing registry digest output"\n'
    "            exit 1\n"
    "          fi\n"
    "\n"
    '          mkdir -p "$RUNNER_TEMP/digests"\n'
    "          printf '%s\\\\n' \"$DIGEST_GHCR\" > \"$RUNNER_TEMP/digests/${PLATFORM_TAG}.txt\"\n"
    "      - name: Upload release digests\n"
    "        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n"
    "        with:\n"
    "          name: release-digests-${{ matrix.component }}-${{ matrix.platform_tag }}\n"
    "          path: ${{ runner.temp }}/digests/${{ matrix.platform_tag }}.txt\n"
    "          if-no-files-found: error\n"
    "\n",
    1,
    flags=re.S,
)
sub(
    r"      - name: Extract metadata \(tags\) for Docker Hub\n.*?\n(?=      - name: Publish multi-platform manifest to GitHub Container Registry\n)",
    "",
    1,
    flags=re.S,
)
sub(
    r"      - name: Publish multi-platform manifest to Docker Hub\n.*?\n(?=  notify-docker-image-release:\n)",
    "      - name: Inspect published manifest\n"
    "        run: |\n"
    "          ghcr_first_tag=\"$(printf '%s\\\\n' \"${STEPS_META_GHCR_OUTPUTS_TAGS}\" | sed -n '1p')\"\n"
    '          docker buildx imagetools inspect "$ghcr_first_tag"\n'
    "        env:\n"
    "          STEPS_META_GHCR_OUTPUTS_TAGS: ${{ steps.meta-ghcr.outputs.tags }}\n"
    "\n",
    1,
    flags=re.S,
)
sub('"$RUNNER_TEMP"/digests/ghcr/*.txt', '"$RUNNER_TEMP"/digests/*.txt', 1, literal=True)
sub("            langfuse/${{ matrix.image_name }}\n", "", 1, literal=True)
sub("ghcr.io/langfuse/", "ghcr.io/placer-labs/", 4, literal=True)
sub(
    "            type=raw,value=latest,enable=${{ startsWith(github.ref, 'refs/tags/v4') && !contains(github.ref, '-rc') }}\n",
    "",
    2,
    literal=True,
)

# Public UBI bases instead of Iron Bank, which needs credentials we do not hold.
sub(
    r"      # Released images always build on the Iron Bank bases\..*?\n(?=      # build-push-action v2 requires this step)",
    "      # Iron Bank needs registry credentials this fork does not hold; release on\n"
    "      # Red Hat's public UBI9, the same content and the Dockerfiles' defaults.\n"
    "      - name: Resolve base images\n"
    "        id: bases\n"
    "        run: |\n"
    '          echo "base=registry.access.redhat.com/ubi9/ubi:9.8" >> "$GITHUB_OUTPUT"\n'
    '          echo "micro=registry.access.redhat.com/ubi9/ubi-micro:9.8" >> "$GITHUB_OUTPUT"\n',
    1,
    flags=re.S,
)
sub(
    r"      # build-push-action v2 requires this step;.*?          nofallback: \"true\"\n",
    "      - name: Setup Docker Buildx\n"
    "        uses: docker/setup-buildx-action@37fe631027851001ddb9b187196cc803df7f5f0e # v4.3.0\n",
    1,
    flags=re.S,
)
sub(
    "        uses: useblacksmith/build-push-action@fb9e3e6a9299c78462bfadd0d93352c316adc9b8 # v2.2.0\n",
    "        uses: docker/build-push-action@263435318d21b8e681c14492fe198d362a7d2c83 # v6.18.0\n",
    1,
    literal=True,
)

# Link the GHCR packages to this repository rather than langfuse/langfuse.
sub(
    '            cat .github/image-labels/common.txt ".github/image-labels/${COMPONENT}.txt"\n',
    '            cat .github/image-labels/common.txt ".github/image-labels/${COMPONENT}.txt" \\\n'
    '              | grep -v "^org.opencontainers.image.source="\n'
    '            echo "org.opencontainers.image.source=${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}"\n',
    1,
    literal=True,
)

for leftover in ("blacksmith", "DOCKERHUB_USERNAME:", "dockerhub", "ironbank/redhat", "ghcr.io/langfuse/"):
    if leftover in text and not (leftover == "blacksmith" and "Blacksmith deadline_exceeded" in text and text.count("blacksmith") == text.count("Blacksmith deadline_exceeded")):
        lines = [l for l in text.splitlines() if leftover in l]
        print(f"note: {leftover!r} still present: {lines[:3]}")

open(dst, "w").write(text)
print("ok")
