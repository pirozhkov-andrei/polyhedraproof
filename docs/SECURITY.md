# Reporting a soundness or security problem

The result this project prepares is only as good as the argument that a certificate means what
it says ([TRUST](TRUST.md)). A defect that could let a leaf, a formula or a claim count as proved
without the evidence it needs is treated as a security problem: the recognition of checker
success, the binding of a result to its record, the journal codec and recovery, the certifiers,
the CNF and cube writers, the encoder, the claim gate, the pinned tools and the release image.

Report it privately, through the
[private vulnerability reporting](https://github.com/pirozhkov-andrei/polyhedraproof/security/advisories/new)
of the repository's Security tab, or by e-mail to the author (the address is on the first
page of the article), not in a public issue. Say which release or commit, what you observed
and how to reproduce it; a journal, a campaign or a certificate that shows it is the most
useful attachment.

You will get an answer within two weeks. A confirmed defect is fixed in a new release, its
CHANGELOG entry says which recorded evidence it affects, and the releases whose sessions wrote
affected records are named (`cubeproof_sha256` of the journals, `tools.used_cubeproof_sha256`
of a claim). An error in the article is reported in the same way when it could change a
conclusion, and in a public issue otherwise.
