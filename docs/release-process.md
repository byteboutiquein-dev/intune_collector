# Release Process

## Source release

1. Update the project version and release notes.
2. Run native tests on Windows.
3. Run `scripts/Test-OpenSourceBoundary.ps1`.
4. Review dependency updates and privacy-impacting changes.
5. Create the source archive with
   `scripts/Export-OpenSourceRepository.ps1`.
6. Inspect the archive and its SHA-256 file before publishing it to the public
   repository.

## Binary release

1. Build from the reviewed tag using `scripts/Build-Collector.ps1`.
2. For a production release, use the approved SignPath workflow or the future
   SentVora HSM-backed certificate. Never export a private signing key.
3. Confirm `ReleaseReady=True` and independently verify signatures, trusted
   timestamps, product version, manifest hashes, and ZIP hash.
4. Publish the exact expected publisher subject and ZIP SHA-256 value.
5. Validate installation, update, revocation, rollback, and uninstall on the
   two controlled Windows endpoints before customer availability.

Unsigned output is a lab artifact regardless of where it was built or hosted.
Renaming an unsigned archive does not make it release-ready.

