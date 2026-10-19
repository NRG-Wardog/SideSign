# Separate coherent-pair design assessment (not implemented)

The one-line mismatch throw prevents a declared bad archive from reaching any
asset replacement, including when a previous pair exists. It does not solve
partial extraction for an accepted archive. Individual `.atomic` file writes
cannot publish two files as one generation; an archive missing the second file
can still reuse its old on-disk counterpart under current existence checks.

The smallest defensible future transaction must cover both publication and
reader lifetime, across SideSign and AnisetteKit:

1. Resolve and check the archive digest before writing assets. Explicitly decide
   missing/empty digest policy and where trusted metadata originates; neither
   authenticity requirement is silently added by this patch.
2. Create a new private sibling generation directory on the same filesystem.
   Extract only into it, then verify both required entries belong to this archive,
   are safe regular files, and satisfy the chosen nonempty/type/digest policy.
   An old cache must never satisfy a new generation's completeness check.
3. Publish the fully validated immutable generation through one atomic pointer or
   metadata replacement. A pair of sequential renames is not sufficient. Account
   for rename/filesystem errors and the desired crash-durability contract.
4. Resolve that pointer once per provider construction and keep that generation
   pinned for all library opens. The native loader opens paths separately, so a
   mutable `current` symlink used by each open can still mix generations. Return
   the immutable resolved directory to the existing library resolver boundary.
5. On validation or publication failure, delete only uncommitted staging and keep
   the old pointer/provider untouched. Retain old generations until no live reader
   can use them; define cleanup and concurrent updater serialization explicitly.

A directory-only rename over an existing nonempty cache is not a portable drop-in
replacement. The current `isCaching` flag alone is not an established concurrent
reader/updater transaction or cross-instance/process lock. Existing caches need a
separate migration/revalidation policy, rather than being silently labeled valid.

Required follow-on tests include second-entry extraction failure, omitted second
entry with an old pair present, invalid entry kinds, publication failure, process
interruption before/after pointer replacement, two updater races, readers spanning
publication, and old-generation cleanup while a provider remains alive.

No transaction implementation, API change, asset download, fixture/native-library
execution, package-lock edit, or capture modification is included in this task.
