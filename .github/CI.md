# Alliance CI

The Alliance fork uses Blacksmith Ubuntu 24.04 runners for Linux builds and tests.
Small orchestration jobs continue to use GitHub-hosted runners. Rust jobs use 8, 16,
or 32 vCPUs according to the existing workload tiers; Docker release builds use
8 vCPUs and hybrid image builds use 16 vCPUs. macOS coverage remains unchanged.

## Runner access and caches

The Blacksmith GitHub App must have access to `madara-alliance/sequencer` in the
organization's installation settings. Copying workflows from upstream does not
copy its Namespace runner access. Jobs that stay queued without a runner require
checking the app's repository access and organization runner policy.

`bootstrap` installs Rust before restoring dependencies with `Swatinem/rust-cache`.
Python downloads and cross-job image/digest handoffs use `actions/cache@v5`, which
Blacksmith routes to its cache backend. Hybrid tests build local Docker archives
and import them into k3d; they do not require the upstream Namespace registry.
Handoff keys include the run ID and commit SHA so retrying only failed jobs can
reuse successful producers from the same run. A missing handoff fails the consumer.

## Upstream-only test data and publication

Ordinary builds and tests run without upstream cloud credentials. The following
additional checks or publications require access to private upstream GCS buckets:

- Blockifier reexecution fixtures: `SA_REEXECUTION_ARTIFACTS_READ_ACCESS_KEY`.
- Transaction prover RPC fixtures: `SA_STARKNET_OS_RUNNER_ARTIFACTS`.
- Committer regression fixtures and benchmarks: `COMMITER_PRODUCTS_EXT_WRITER_JSON`.
- Native artifact publication: `SA_NATIVE_BLOCKIFIER_ARTIFACTS_BUCKET_WRITER_ACCESS_KEY`.
- Committer/OS CLI publication: `COMMITER_PRODUCTS_EXT_WRITER_JSON`.

When a fixture secret is absent, its download and fixture-dependent tests are
skipped and the job summary records the missing coverage; ordinary tests still run.
Missing publication credentials skip only the GCS upload and are also reported.
Committer benchmarks are opt-in on the fork through the repository variable
`ENABLE_COMMITTER_BENCHMARKS=true` and require the committer fixture secret.
Fork nightly matrices target `dev`; release images publish under the fork's GHCR
namespace. Scheduled workflows still follow GitHub's default-branch rules.

## Workflow validation

From the repository root, run:

```sh
actionlint -shellcheck= -pyflakes=
git diff --check
```

The actionlint configuration lists the supported Blacksmith runner labels. Linux
build and test results must be checked on the PR; local workflow validation does
not establish that the Rust test suite passed.
