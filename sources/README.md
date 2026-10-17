# Upstream discovery and license decisions

The executable seed list is `uvault.sources.seed_packages()`. It includes Unity
registry seeds, common OpenUPM runtimes, pinned GitHub-tag families, NuGet runtime
packages, and explicit reference/restricted/unavailable records. Seeds are entry
points rather than an ecosystem completeness claim.

OpenUPM discovery resolves a commit and enumerates its entire recursive Git tree.
If GitHub reports truncation, discovery walks the relevant non-recursive subtrees.
The contents endpoint's 1,000-item response is never used for coverage. Every
definition is retained with its immutable blob SHA and definition URL, including
pending or failed metadata tasks. Registry adapters retain every listed version;
GitHub adapters follow all tag pages and pin each tag to its commit SHA.

`python -m uvault.harvest --help` provides standalone discovery, resumable
metadata/collection, and coverage commands. `metadata --refresh` adds upstream
versions and variants while preserving prior artifact hashes and license evidence.
`--retry-failed` retries failed requests without converting HTTP errors into
claims that a package has no source. The root pipeline uses package shards as its
single task state and is the publication writer.

The version policy selects 3–5 real releases with semantic ordering, observed
target versions, compatible neighbors, stable releases, and another available
major. All available observed targets bypass the default count. Missing targets
remain explicit; unselected versions remain metadata and pending tasks.

License decisions apply to the observed version and archive, never an entire
family. Archive-root grant texts, nested licenses, NOTICE files, NuGet nuspec
metadata, detected native SDK binaries, and suspicious bundled component paths
are inspected. A wrapper's MIT license does not grant rights to Steam/native SDK
payloads. Proprietary, custom, missing, mixed, or unrecognized grants retain an
official/reference/unresolved disposition and are not published automatically.

Some OpenUPM archives omit the root license. Only a matching package manifest's
full immutable repository revision may supply its missing grant; a floating
`licensesUrl` is insufficient. The retrieved grant must agree with the manifest's
declared license. Its exact evidence URL, SHA256, text and component scope are
retained. An archive that omits its notice requires the catalog license text as
a companion when materializing or redistributing.

`component-reviews.json` records individually inspected versions whose `External`
paths contain project-authored integration adapters. Each decision binds the
original archive SHA256, resolved tag commit, complete upstream code-file
comparison, reviewed paths/file hashes, and pinned license text. These records
only waive the ambiguous folder-name warning for those exact bytes. They do not
waive a restricted nested grant or grant rights to the separately supplied SDK.

Archives are fetched into memory for integrity verification, rights inspection,
fingerprinting and an optional publication callback. No command writes a package
cache or archive backup. The publisher must upload, anonymously read back and
hash-check an allowed object before its remote reference can enter the catalog.
