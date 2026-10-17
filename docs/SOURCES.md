# Sources

Every work the article cites: what it is cited for, what was checked, and what was not.
“Checked” identifies the specific source text or metadata inspected, as described
in each entry; it does not mean that an entire book or every earlier dependency
was audited. Open source checks remain listed in [CLAIMS](CLAIMS.md).
Bibliographic years and source versions identify the works being cited.

Updated 2026-10-15. Every bibliography entry was reviewed for its role, attribution
and available source. A checked passage is distinguished from metadata-only access;
an inaccessible book chapter is not counted as a verified theorem. This is a source
audit by the project, not independent refereeing or an exhaustive novelty search.

## Cited in the argument

**Hatcher, *Algebraic Topology*, Cambridge University Press, 2002.** Cited in the proof of
(paper: prop:euler) for: a closed non-orientable surface does not embed in R³ (§3.3,
Corollary 3.46 and the remarks after it). *Checked* in the author's online
edition, Corollaries 3.28 and 3.46, printed page 256. The online edition is not a fixed
revision, and the wording of the printed book was not compared. The fact is standard;
Hatcher's own errata for §1.2, p. 49 point to Corollary 3.46 for it.

**Björner, Las Vergnas, Sturmfels, White and Ziegler, *Oriented Matroids*, 2nd ed.,
Cambridge University Press, 1999.** Cited in the proof of (paper: thm:chirotope) for
Theorem 3.6.2, printed p. 138. *Checked directly* in the actual second-edition
page image in the publisher-authorized
[Google Books preview](https://books.google.com/books?id=k2an6eBxn3kC&pg=PA138),
with the edition authenticated against the publisher's Chapter 3 record
(doi:10.1017/CBO9780511586507.006). The theorem requires both an alternating sign map
whose nonzero subsets are the bases of a matroid (B1') and the three-term condition
(B2''). Here all four-element subsets have nonzero signs, so the support is the uniform
matroid U(4,13). Substitution (x1,x2,x3,x4,y1,y2) = (a,b,i,j,c,d), together with swapping
a and b, gives exactly the two forbidden equal-sign patterns in the article's (GP).
Tuples with repeated labels have value zero; their instances follow from alternation.
The book itself warns that the matroid-support hypothesis cannot be dropped.
The first claim of (paper: thm:chirotope) relies on this published theorem; the necessary
direction used in the reduction follows directly from determinant identities.
The theorem and its application were checked, not the earlier results used in the book's
proof. The general non-realizability discussion in (paper: rem:noconverse) now uses
the directly inspected Sections 2–3 of Scheucher rather than an unlocated passage
in this book. Publisher record: <https://doi.org/10.1017/CBO9780511586507>.

**Bokowski and Sturmfels, *Computational Synthetic Geometry*, Lecture Notes in
Mathematics 1355, Springer, 1989.** Cited in (paper: rem:noconverse) as background
on realizability methods. The publisher's title, authors, year, series, contents
and description were checked at <https://doi.org/10.1007/BFb0089253>.
**Metadata and scope only:** the full book was not available. No theorem in the
reduction depends on this general citation; Scheucher supports the distinction
between chirotopes and realizable configurations below.

**Meisters, *Polygons have ears*, Amer. Math. Monthly 82(6), 1975, 648–651,
doi:10.1080/00029890.1975.11993898.** Cited in the proof of (paper: thm:genpos) for the
fact that every simple polygon, convex or not, can be triangulated by diagonals. *Checked*
in the scan of the published article in the University of Nebraska–Lincoln
repository
(<https://digitalcommons.unl.edu/cgi/viewcontent.cgi?article=1053&context=mathfacpub>):
its Two Ears Theorem, "Except for triangles, every Jordan polygon has at least two
non-overlapping ears", from which the triangulation follows by cutting off one ear at a
time.

**Lazarus, *Linear Embeddings*, lecture notes, 2020, Section 2.** Cited in
(paper: thm:genpos), for comparison, next to (paper: lem:plstability), which the article
proves in full; nothing in the argument depends on it. *Checked* at the URL
given in the article: Section 2, "Linear embeddings and immersions", begins on p. 5; Lemma
2.1 is the criterion of the first paragraph of the proof of (paper: lem:plstability), that
a linear map is an embedding if and only if disjoint simplices go to disjoint sets, and
the argument for Lemma 2.2 notes that, by Lemma 2.1, any sufficiently small perturbation
of the vertex images keeps an embedding. The notes carry no version beyond the year.

**Tan, Heule and Myreen, *Verified propagation redundancy and compositional UNSAT
checking in CakeML*, Int. J. Softw. Tools Technol. Transf. 25(2), 2023, 167–184,
doi:10.1007/s10009-022-00690-y.** Cited in (paper: sec:protocol) for cake_lpr.
*Checked*: the SAT Competition 2024 checker note and, on 2026-10-15, the journal
text in the [Chalmers repository](https://research.chalmers.se/publication/534843/file/534843_Fulltext.pdf),
§5.2, Figure 10 (PDF pp. 11–12 including the repository cover). For the two-input-file
invocation, successful standard output implies that the DIMACS input denotes an
unsatisfiable formula. The theorem assumes well-formed command-line and filesystem
models and the compiled program in the specified x64 machine state; resource
exhaustion is allowed. The project checks the output and process status for each
leaf. Its Python orchestration and journal certifiers are not covered by the CakeML
theorem. Pinning an executable does not re-prove its correctness.

**Biere, Faller, Fazekas, Fleury, Froleyks and Pollitt, *CaDiCaL 2.0*, CAV 2024, LNCS 14681,
Springer, 2024, 133–152, doi:10.1007/978-3-031-65627-9_7.** Cited in the acknowledgement of
tooling for CaDiCaL, the proposing solver. *Checked (metadata)*: title, authors, series, volume,
pages and DOI against the Crossref record of the DOI on 16 October 2026; the chapter itself was
not read for this citation. Nothing in the argument depends on this source: the solver is not trusted
(paper: sec:protocol), and the release pins its own commit and binary
(`docker/test/tools.json`, `faces12_campaign.pins`).

**Battleman, Reeves and Heule, *Problem partitioning via proof prefixes*, SAT 2025, LIPIcs
341, 3:1–3:18, doi:10.4230/LIPIcs.SAT.2025.3.** Cited in (paper: sub:cases) for the
partition heuristic. *Checked*: §3.1. The implementation is an adaptation,
and the heuristic affects only cost: any prefix of distinct variables covers every case
(paper: prop:cases).

**Grünbaum and Szilassi, *Geometric realizations of special toroidal complexes*,
Contributions to Discrete Mathematics 4(1), 2009, 21–39,
doi:10.55016/ojs/cdm.v4i1.61986.** Cited in (paper: sec:protocol) for the rational
coordinates of the Szilassi polyhedron. *Checked*: Table 3, printed p. 37.
The fixture `data/fixtures/szilassi.json` is a perturbation of those coordinates into
general position made by this project, not taken from the paper. The paper does not
contain the residue condition n ≡ 0, 3, 4, 7 (mod 12) or a statement that the
twelve-face problem is open, although secondary sources cite it for both; the article
proves the first itself (paper: prop:euler).

## Classification and contextual sources

**Altshuler, Bokowski and Schuchert, *Neighborly 2-manifolds with 12 vertices*, J.
Combin. Theory Ser. A 75(1), 1996, 148–162, doi:10.1006/jcta.1996.0069.** Cited in
(paper: sec:intro) and in (paper: thm:59) for the classification into 59 types. *Checked*:
the publisher's record and abstract state a complete list of 59 types; the
enumeration data were not recovered, so with this source only the number agrees. The
classes were compared one by one with the list of the next entry instead. The article uses the published classification, also stated in Ellingham and Stephens,
for completeness; its own exhaustive search recomputes the representatives. Agreement
of counts alone does not identify the classes. The matrix numbering is this project's.

**Lutz, *The Manifold Page*, section *Surfaces*,
<https://www3.math.tu-berlin.de/IfM/Nachrufe/Frank_Lutz/stellar/surfaces.html>.** Cited in
(paper: thm:59) and (paper: app:numbers) for the list of the 59 triangulations of the
orientable surface of genus 6 with twelve vertices, the file
`manifolds_lex/manifolds_lex_d2_n12_o1_g6.txt` of that page. *Checked*: the file as
retrieved on 2026-10-13 (25,272 bytes, SHA-256
`55912614618733476d07094ca4ed638df84ab58b42e8dba9eb81730da1a589b7`) holds 59 facet lists of
44 triangles on twelve vertices. Each is the dual of exactly one map of `data/matrices/`
under the relabelling of the faces recorded in `data/fixtures/lutz_correspondence.json`,
and every map is used once: `test_corpus12_lutz.py` applies the relabellings, writes the
result in the notation of the file and compares its SHA-256 with that of the file without
white space (`tr -d ' \n' < FILE | sha256sum` gives
`eac588cb5d93c8e33ed9a424853ea01745b56a1ec3b75e074848adea7a69cc1e`). The file is not
redistributed here, so the test shows the equality for a file with that hash; that the
page serves such a file is checked by downloading it. The table of the page gives the
number 59 for twelve vertices and genus 6. Its part on triangulations with up to twelve
vertices names Sulanke and Lutz and Sulanke's program `lextri`, and directly below it the
page gives Ellingham and Stephens for the neighbourly triangulations with 12 and 13
vertices; it does not say separately how this file was produced. Every entry is written
with sorted triangles in lexicographic order, the form of `lextri`. The address is a copy of the page kept by TU
Berlin and may move. Rechecked on 2026-10-15: a fresh download has the same 25,272 bytes
and raw SHA-256; the explicit-relabelling test checks its normalized content.

**Sulanke and Lutz, *Isomorphism-free lexicographic enumeration of triangulated
surfaces and 3-manifolds*, European J. Combin. 30, 2009, 1965–1979.** Cited in
(paper: thm:59) as a reference named by the page hosting the external list.
*Checked*: [arXiv:math/0610022v3](https://arxiv.org/pdf/math/0610022v3), §3 and
Table 4 (p. 9), whose orientable genus-6 row gives 59 for twelve vertices.
The discussion on p. 10 identifies the earlier completeness result and the
non-orientable enumeration. This supports the count; identity of the individual
classes uses the explicit bijections described above. Journal DOI:
<https://doi.org/10.1016/j.ejc.2008.12.016>. The final journal text was not compared.

**Ellingham and Stephens, *Triangular embeddings of complete graphs (neighborly maps) with
12 and 13 vertices*, J. Combin. Des. 13, 2005, 336–344.** Cited in (paper: thm:59) and
(paper: app:numbers) for the automorphism orders. *Checked* in the authors' preprint of
7 October 2003 (<https://math.vanderbilt.edu/ellingmn/paper/tricomp/a10.pdf>): Theorem 4
states 59 nonisomorphic orientable triangular embeddings of K12 with automorphism groups
"39 of order 1, 9 of order 2, 1 of order 3, 7 of order 4, 2 of order 6, 1 of order 12",
the distribution of (paper: app:numbers), and Section 6 says that their programs generated
the orientable embeddings again and that they confirm Altshuler, Bokowski and Schuchert.
Theorem 4 and the orientable recomputation in Section 6 were rechecked on 2026-10-15;
the article invokes this classification in (paper: thm:59). Labels of triangulation
vertices become labels of polyhedron faces, and triangular facets become triples at
polyhedron vertices. The journal data are those given on the Manifold Page; the published version was not
compared with the preprint. The same theorem of the preprint gives "25,079,040 distinct
embeddings" for the orientable case, which is not what its own orders give (12! times
46, that is 22,034,073,600; the figure for the nonorientable case is consistent with its
orders); the article uses the number of classes and the orders only.

**Arseneva, Kleist, Klemz, Löffler, Schulz, Vogtenhuber and Wolff, *Adjacency graphs
of polyhedral surfaces*, Discrete Comput. Geom. 71(4), 2024, 1429–1455,
doi:10.1007/s00454-023-00537-6.** Cited in (paper: sec:intro) for the open question.
*Checked* in arXiv:2103.09803v2 and then in the
[published version](https://research-portal.uu.nl/ws/portalfiles/portal/240419958/s00454-023-00537-6.pdf):
§1, pp. 1430–1431, defines polygonal complexes with full side or corner contacts;
it does **not** require distinct supporting planes or maximal planar faces.
Proposition 3.2 realizes planar graphs by flat complexes. Section 2, p. 1435,
separately asks which complete graphs arise from closed polyhedral surfaces.
The article's remark following (H1)–(H3) proves that, for its closed embedded
polygonal-cell surfaces, maximal planar faces are equivalent to noncoplanarity of
edge-adjacent faces. Pairwise adjacency then makes this (H3). This is a restriction
of Arseneva's general model, not an equivalence of the unrestricted definitions.

**Schewe, *Nonrealizable minimal vertex triangulations of surfaces*, Discrete Comput. Geom. 43(2),
2010, 289–302, doi:10.1007/s00454-009-9222-y.** Cited in (paper: sec:intro), after (paper:
thm:chirotope) and in (paper: sec:status). *Checked* in arXiv:0801.2582v1 and the journal record:
Theorem 1.1 and Proposition 1.2. Section 2, printed p. 6, defines admissibility by excluding
circuits whose positive and negative supports lie in disjoint simplices; in uniform rank 4 it
suffices to exclude intersections between a triangle and a disjoint edge. Proposition 1.2 concerns
acyclic uniform rank-4 oriented matroids admissible for each triangulation, not arbitrary oriented
matroids on twelve labels. Its consequence, Theorem 1.1, settles the dual problem of twelve
vertices; combinatorial duality does not transfer that conclusion to the twelve-face problem.

**Scheucher, *A SAT attack on Erdős–Szekeres numbers in R^d and the empty hexagon
theorem*, Computing in Geometry and Topology 2(1), 2023, 2:1–2:13,
doi:10.57717/cgt.v2i1.12.** Cited after (paper: thm:chirotope) for chirotope SAT
encodings. *Checked* in the [published PDF](https://www.cgt-journal.org/index.php/cgt/article/download/12/21):
§3, Definition 4 and its uniform case, and §4's Boolean encoding. Its theorem
locator for Björner et al. was checked against that book itself. Section 2, p. 2:4,
reports non-realizable witnessing chirotopes with biquadratic-final-polynomial
certificates; §3, p. 2:6 distinguishes chirotopes from realizable configurations.
The article uses that distinction in (paper: rem:noconverse); it does not claim
that any of its own 59 formulas has a non-realizable model. Scheucher's supplemental
certificates were not independently rerun.

**Ringel and Youngs, *Solution of the Heawood map-coloring problem*, Proc. Nat. Acad.
Sci. U.S.A. 60(2), 1968, 438–445; Ringel, *Map Color Theorem*, Springer, 1974.** Cited in
(paper: sec:intro) for the genus of the complete graph. *Checked* against the
publishers' records: <https://doi.org/10.1073/pnas.60.2.438> and
<https://doi.org/10.1007/978-3-642-65759-7>. Full proofs were not audited.
The specific non-orientable twelve-vertex enumeration is now sourced directly to
the inspected Theorem 4 of Ellingham and Stephens, rather than inferred from the book.

**Jungerman and Ringel, *Minimal triangulations on orientable surfaces*, Acta Math.
145, 1980, 121–154, doi:10.1007/BF02414187.** *Checked* against the
[publisher's record](https://link.springer.com/article/10.1007/BF02414187).
Full-text retrieval did not succeed. The article now gives the elementary genus-6
minimum-vertex bound itself: Euler's formula and triangulation give E = 3(v + 10),
while E ≤ v(v − 1)/2 forces v ≥ 12. Existence with twelve vertices follows from the
classified maps. This source is retained for the general minimum-vertex theorem,
not needed for that calculation.

**Szilassi, *Regular toroids*, Structural Topology 13, 1986, 69–80.** Cited in
(paper: sec:intro) for the Szilassi polyhedron. *Checked* in the
[journal's complete issue](https://www.iri.upc.edu/people/ros/StructuralTopology/WholeIssues/st13-ocr.pdf):
§4, printed pp. 75–76, Figure 4 and Table 2 on p. 74 describe the seven hexagonal
faces, 21 edges and 14 vertices with every pair of faces adjacent. Printed p. 74
is PDF page 75. The rational control fixture here uses the separate coordinate
source Grünbaum–Szilassi 2009, not this scan's OCR numbers.

**Bokowski and Kevin H., *Polyhedral Embeddings of Triangular Regular Maps of Genus g,
2 ≤ g ≤ 14, and Neighborly Spatial Polyhedra*, Symmetry 17(4), 2025, article 622,
doi:10.3390/sym17040622.** *Checked* in the publisher's `symmetry-17-00622-v2.pdf`:
title page, §4 (the numerical method), §8.3, pp. 25–26, and Figure 38. The author
name is printed **Kevin H.**, with affiliation **CodeParade**; the previous attribution
to C. McDonald was unsupported and has been removed. Section 8.3 reports no embeddings
found among the 59 dual types and illustrates an intersecting model. This is an
adjacent numerical-search result, not a nonexistence proof. Its scope includes twelve
planes carrying 44 vertices, the face-based direction relevant here. The numerical
searches and example coordinates were not independently rerun.
Publication: <https://doi.org/10.3390/sym17040622>;
[university record](https://tuprints.ulb.tu-darmstadt.de/entities/publicationzv/4a6be59e-b2db-4692-9ddf-196ff16ee856).

**HackerPoet (CodeParade), *NeighborlyPolyhedra*,
<https://github.com/HackerPoet/NeighborlyPolyhedra>.** The README describes a search
through 59 topologies, including the intersecting Razorcross, and explicitly disclaims
a rigorous optimality proof. This remains a software citation alongside the published
account above. Its code and numerical records were not independently verified. The
unsupported start date `2020–` was removed; the citation now gives the access date.
No claim that this is the only search is made.

## Search scope and remaining limits

The 2026-10-15 search used the exact project name, `Razorcross`, `CodeParade`,
`McDonald polyhedra`, and `Polyhedral Embeddings of Triangular Regular Maps`.
Discovery used web search; verification used publisher and university sources,
including the 2025 paper's discussion of the twelve-face problem. The first two
queries alone did not identify the publication. This bounded search does not
establish global novelty or rule out later work.

All bibliography entries have a source record above. Metadata-only checks remain
for the general books, the Jungerman–Ringel article and the CaDiCaL 2.0 entry (compared
with its Crossref record); Hatcher was checked in
the author's electronic edition, not a physical copy. No inaccessible original
enumeration is represented as recovered, and no external computational result is
represented as independently rerun. The central classification also has the
inspected Ellingham–Stephens theorem and the Lutz correspondence; the necessary
chirotope implication follows directly from determinant identities in the article.


## Locally retained source identity

The following open PDFs were retained in the ignored literature cache on 2026-10-15.
Text was extracted with pypdf; the hashes identify the PDF bytes, not a verified
mathematical result. They are not included in the release.

| Source copy | PDF SHA-256 |
|---|---|
| bokowski-kevin-2025 | `2503851aef019de6988a93284d9a859633a600852cc36b538d5ad7939f9b4d02` |
| arseneva-2024 | `a2970bc54549bf5901d2a0627aa26c7d06689f5a28d22d63783298b226a5e4bb` |
| tan-2023 | `bf1c38999b9bffe5457f3ea1cf9edc3c195ad12951a089ae4c3249c90be1f85c` |
| scheucher-2023 | `6cb7ec8ae7ccef0a7356a5472f6eb50dd59093b86581c5cad0b926e1a3888c0c` |
| structural-topology-13 | `a9e0eb24d96fe3b64a1bd8f20259fca4d0a1957557864f151a717e1915c8092a` |
