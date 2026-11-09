# Release and DOI status

The user explicitly deferred independent human guidance sign-off and Zenodo author/publication details to the professor on 2026-11-09. These two items are excluded from the current execution task. Existing code tags/archives remain historical snapshots; a new final tag must identify the final measured delivery without modifying an older tag.

The code and measured artifacts can be cited by their Git commit after the final study changes are committed. A DOI has **not** been created. A Zenodo DOI needs an authenticated repository-owner/Zenodo connection, release metadata with the correct authors, and publication of the release/archive. Zenodo is not connected here, and author-approved archive metadata is missing.

Before publishing a version, run the checks and regenerate the study status and statistics, distinguish completed runs from planned cells, inspect the archive for credentials/runtime clones, tag the exact reviewed commit, and archive that version through Zenodo. Add the actual returned DOI to the repository citation metadata. Do not invent a DOI, independent reviewer, author affiliation, or claim that a draft release has already been archived.


`CITATION.cff` identifies the code version without inventing a DOI. Once the delivery is committed, `python review/release_archive.py` creates a Git-tracked source/evidence archive and SHA256 manifest in `.review-work/release`. A Git tag and local archive do not establish Zenodo publication.

Current public exports are allowlisted summaries under `public_results/review2`. New raw model messages, test logs and machine metadata remain local unless the user separately approves publication after review. They are ignored by default, with pinned baselines and already tracked historical evidence preserved. `review/release_archive.py --tracked-only` archives the exact public commit without adding unpublished local evidence; all tracked changes must still be committed.
