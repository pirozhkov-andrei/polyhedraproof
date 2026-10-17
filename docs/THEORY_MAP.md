# Theory map

Every numbered statement of the article, [`paper/faces12-en.pdf`](../paper/faces12-en.pdf) (source
`paper/faces12-en.tex`), with the code that implements it and the tests that check it. Code
and documents cite a statement by its label, as in `(paper: lem:parity)`: labels stay
when numbers change.

## What the article proves, in one paragraph

Under the article's hypotheses (H1)–(H3), a polyhedron with twelve pairwise adjacent faces has
trivalent vertices and genus 6 and induces one of exactly 59 neighbourly maps. Its twelve face
planes can be moved, without changing its combinatorics, until they are in general position with
the plane at infinity, so the 715 brackets of the thirteen covectors are all non-zero and form a
uniform chirotope of rank 4. Every clause of the formula of its map is then a necessary
condition: layers S, H and A are the chirotope axioms in three-term form, layer B forbids
crossings of nonadjacent edges within a face, and layer I fixes the orientation of each face by
a crossing parity and forbids two reflex corners at a vertex. The thirteen gauge clauses hold
after the realization is moved by one of its symmetries. So if all 59 formulas are
unsatisfiable, no such polyhedron exists (paper: cor:conditional). A formula is unsatisfiable
when every leaf of a finite tree of case splits rooted at the empty cube is refuted (paper:
thm:coverage, cor:treecover); a refuted tree below a nonempty pilot root settles only that
region (paper: rem:pilotroot), and a journal record of a checked leaf is an attestation,
verified independently only by rechecking a retained proof or recomputing the leaf (paper:
rem:attestation). **The complete computation has not been carried out**, and the nonexistence
conclusion is conditional.

## Statements

A dash means that the statement has no implementation or test of its own recorded in this
table: the article's proof, or its definition, is all there is, or its implementation is named
only in the section after the table. What each test covers, and what it does not, is in
[CLAIMS](CLAIMS.md). The table is generated from `docs/claims.json` by
`python3 tools/checks/claims_docs.py` (`make lint` checks that it is current, and that the code
and tests it names exist).

<!-- BEGIN GENERATED: statements -->
| Statement | Label | Implemented in | Checked by |
|---|---|---|---|
| Definition 2.1 | `def:polyhedron` | — | — |
| Hypothesis 2.2 | `hyp:H` | — | — |
| Lemma 2.4 (Trivalence) | `lem:trivalent` | — | — |
| Proposition 2.5 (Euler count) | `prop:euler` | `neighbourly.maps.CombinatorialMap.euler_characteristic` | [`test_map_files_load_and_are_the_expected_surfaces`](../packages/neighbourly/tests/maps/test_maps_combinatorial.py) |
| Lemma 2.6 (At most one reflex corner) | `lem:onereflex` | `neighbourly.enumeration.vertex_profiles.at_most_one_reflex_corner`, `neighbourly.encoding.faces.FaceLayers.layer_I` | [`test_the_vertex_table_admits_only_two_profiles`](../packages/neighbourly/tests/enumeration/test_enumeration_tables.py)<br>[`test_every_identity_holds_with_the_fixture_planes`](../packages/neighbourly/tests/checks/test_checks_identities.py) |
| Remark 2.7 | `rem:octants` | `neighbourly.enumeration.vertex_profiles.admissible_profiles` | [`test_the_vertex_table_admits_only_two_profiles`](../packages/neighbourly/tests/enumeration/test_enumeration_tables.py) |
| Definition 3.1 | `def:map` | `neighbourly.maps.CombinatorialMap` | [`test_broken_input_is_not_silently_repaired`](../packages/neighbourly/tests/maps/test_maps_combinatorial.py)<br>[`test_tetrahedron_is_a_valid_map`](../packages/neighbourly/tests/maps/test_maps_combinatorial.py) |
| Lemma 3.2 | `lem:inducedmap` | — | — |
| Definition 3.3 | `def:realization` | — | — |
| Lemma 3.4 | `lem:bridge` | — | — |
| Lemma 3.5 (Oriented form) | `lem:oriented` | `neighbourly.enumeration.oriented.enumerate_oriented` | [`test_small_enumerations_reproduce_their_reference_counts`](../packages/neighbourly/tests/enumeration/test_enumeration_oriented.py) |
| Lemma 3.6 (Framing count) | `lem:framing` | `neighbourly.enumeration.oriented.canonical`, `neighbourly.enumeration.oriented.enumerate_classes` | [`test_the_orbit_identity_is_checked_per_class`](../packages/neighbourly/tests/enumeration/test_enumeration_oriented.py)<br>[`test_canonical_form_agrees_with_brute_force_relabelling`](../packages/neighbourly/tests/enumeration/test_enumeration_oriented.py) |
| Theorem 3.8 (Case list) | `thm:59` | `neighbourly.enumeration.oriented.enumerate_classes`, `neighbourly.corpus12.enumerate_corpus`, `neighbourly.corpus12.shipped_classes` | [`test_the_twelve_face_census_reproduces_the_corpus`](../packages/neighbourly/tests/corpus12/test_corpus12_census.py)<br>[`test_the_matrices_match_their_sums_and_the_corpus_is_well_formed`](../packages/neighbourly/tests/corpus12/test_corpus12_data.py)<br>[`test_the_published_list_is_the_59_maps_relabelled`](../packages/neighbourly/tests/corpus12/test_corpus12_lutz.py)<br>[`test_the_automorphism_orders_are_those_of_the_literature`](../packages/neighbourly/tests/corpus12/test_corpus12_lutz.py) |
| Hypothesis 4.1 (General position) | `hyp:G` | — | — |
| Theorem 4.2 (Reduction to general position) | `thm:genpos` | — | — |
| Lemma 4.3 (Stability of a finite triangulation) | `lem:plstability` | — | — |
| Lemma 4.5 (Nondegeneracy is open) | `lem:step1` | — | — |
| Lemma 4.6 (No straight angles) | `lem:step2` | — | — |
| Convention 4.7 | `conv:genpos` | — | — |
| Lemma 5.1 | `lem:cofactor` | `neighbourly.exact.bracket` | — |
| Theorem 5.2 (Order bits) | `thm:order` | `neighbourly.encoding.chirotope.ChirotopeLayers.layer_S`, `neighbourly.encoding.chirotope.ChirotopeLayers.order_literal` | [`test_every_identity_holds_with_the_fixture_planes`](../packages/neighbourly/tests/checks/test_checks_identities.py)<br>[`test_brackets_and_orders_are_signed_consistently`](../packages/neighbourly/tests/encoding/test_encoding_layers.py) |
| Remark 5.3 (Why a 0 appears) | `rem:cut` | `neighbourly.encoding.chirotope.ChirotopeLayers.layer_S`, `neighbourly.encoding.chirotope.ChirotopeLayers.layer_A` | — |
| Definition 5.4 | `def:onb` | `neighbourly.encoding.faces.FaceLayers.boundary_bit` | — |
| Lemma 5.5 | `lem:onb` | `neighbourly.encoding.faces.FaceLayers.boundary_bit` | [`test_the_boundary_predicate_is_the_exact_interior_point_test`](../packages/neighbourly/tests/exact/test_exact_controls_nb.py) |
| Lemma 5.6 (Cyclic adjacency) | `lem:adjacency` | `neighbourly.maps.CombinatorialMap.link_successor`, `neighbourly.maps.CombinatorialMap.is_real` | [`test_every_identity_holds_with_the_fixture_planes`](../packages/neighbourly/tests/checks/test_checks_identities.py) |
| Lemma 5.7 (Turn bits) | `lem:turn` | `neighbourly.encoding.faces.FaceLayers.corner_literal` | [`test_the_turn_bit_is_the_sign_of_the_measured_turn_at_every_corner`](../packages/neighbourly/tests/exact/test_exact_controls_nb.py) |
| Lemma 5.8 (One orientation bit per face) | `lem:sf` | `neighbourly.encoding.faces.FaceLayers.corner_literal`, `neighbourly.encoding.formula.Encoder.face_orientation_bits` | [`test_corner_literals_are_symmetric_in_their_two_neighbours`](../packages/neighbourly/tests/encoding/test_encoding_layers.py)<br>[`test_every_identity_holds_with_the_fixture_planes`](../packages/neighbourly/tests/checks/test_checks_identities.py)<br>[`test_every_clause_holds_on_a_realized_configuration`](../packages/neighbourly/tests/exact/test_exact_controls_nb.py) |
| Remark 5.9 (An easy way to get this wrong) | `rem:order-matters` | `neighbourly.encoding.faces.FaceLayers.corner_literal` | [`test_corner_literals_are_symmetric_in_their_two_neighbours`](../packages/neighbourly/tests/encoding/test_encoding_layers.py) |
| Lemma 5.10 (Crossing parity fixes the orientation) | `lem:parity` | `neighbourly.encoding.faces.FaceLayers.layer_I` | [`test_every_clause_holds_on_a_realized_configuration`](../packages/neighbourly/tests/exact/test_exact_controls_nb.py) |
| Lemma 6.1 (Cut order) | `lem:cutorder` | `neighbourly.encoding.chirotope.ChirotopeLayers.layer_A`, `neighbourly.enumeration.tournaments.census` | [`test_every_identity_holds_with_the_fixture_planes`](../packages/neighbourly/tests/checks/test_checks_identities.py)<br>[`test_a_second_computation_by_cyclic_triangles_agrees`](../packages/neighbourly/tests/enumeration/test_enumeration_tables.py)<br>[`test_the_lemma_and_the_counts_on_seven_elements`](../packages/neighbourly/tests/enumeration/test_enumeration_tables.py) |
| Remark 6.2 (Why transitivity of the raw tournament would be wrong) | `rem:counts` | `neighbourly.enumeration.tournaments.census` | [`test_the_census_reproduces_the_lemma_and_both_counts`](../packages/neighbourly/tests/enumeration/test_enumeration_tables.py)<br>[`test_the_lemma_and_the_counts_on_seven_elements`](../packages/neighbourly/tests/enumeration/test_enumeration_tables.py) |
| Theorem 6.3 (What S, H and A say) | `thm:chirotope` | `neighbourly.encoding.chirotope.ChirotopeLayers.layer_S`, `neighbourly.encoding.chirotope.ChirotopeLayers.layer_H`, `neighbourly.encoding.chirotope.ChirotopeLayers.layer_A` | [`test_unconditional_layers_hold_on_random_planes`](../packages/neighbourly/tests/exact/test_exact_controls_nb.py) |
| Lemma 7.1 | `lem:B` | `neighbourly.encoding.faces.FaceLayers.layer_B` | [`test_every_clause_holds_on_a_realized_configuration`](../packages/neighbourly/tests/exact/test_exact_controls_nb.py)<br>[`test_layer_b_constrains_exactly_the_non_adjacent_pairs`](../packages/neighbourly/tests/encoding/test_encoding_layers.py) |
| Lemma 7.2 | `lem:I` | `neighbourly.encoding.faces.FaceLayers.layer_I` | [`test_every_clause_holds_on_a_realized_configuration`](../packages/neighbourly/tests/exact/test_exact_controls_nb.py)<br>[`test_every_identity_holds_with_the_fixture_planes`](../packages/neighbourly/tests/checks/test_checks_identities.py) |
| Lemma 8.1 (The reorientation group) | `lem:gaugegroup` | `neighbourly.encoding.gauge.gauge_targets` | [`test_the_gauge_keeps_a_representative_of_a_realized_configuration`](../packages/neighbourly/tests/exact/test_exact_controls_nb.py) |
| Corollary 8.2 (Gauge) | `cor:gauge` | `neighbourly.encoding.gauge.gauge_targets`, `neighbourly.encoding.formula.Encoder.add_gauge` | [`test_every_identity_holds_with_the_fixture_planes`](../packages/neighbourly/tests/checks/test_checks_identities.py)<br>[`test_every_gauge_basis_spans_all_sign_patterns`](../packages/neighbourly/tests/encoding/test_encoding_reference.py)<br>[`test_the_gauge_keeps_a_representative_of_a_realized_configuration`](../packages/neighbourly/tests/exact/test_exact_controls_nb.py)<br>[`test_the_formula_of_a_map_is_the_formula_of_the_article`](../tests/reference/test_ref_formula.py) |
| Definition 9.1 (The formula) | `def:formula` | `neighbourly.encoding.formula.Encoder.build`, `neighbourly.cnf.dimacs.dimacs_bytes` | [`test_the_base_formula_goldens`](../packages/neighbourly/tests/encoding/test_encoding_emission_golden.py)<br>[`test_all_59_base_formulas_keep_their_bytes`](../packages/neighbourly/tests/corpus12/test_corpus12_census.py)<br>[`test_each_of_the_59_formulas_is_the_formula_of_the_article`](../tests/reference/test_ref_formula.py) |
| Theorem 9.2 (Necessity) | `thm:necessity` | `neighbourly.encoding.formula.Encoder.build` | [`test_every_clause_holds_on_a_realized_configuration`](../packages/neighbourly/tests/exact/test_exact_controls_nb.py)<br>[`test_the_gauge_keeps_a_representative_of_a_realized_configuration`](../packages/neighbourly/tests/exact/test_exact_controls_nb.py)<br>[`test_realizations_with_four_and_seven_faces_satisfy_their_formulas`](../tests/reference/test_ref_realizations.py)<br>[`test_realizations_in_many_labellings_satisfy_their_formulas`](../tests/reference/test_ref_realizations.py) |
| Corollary 9.3 (Conditional non-existence) | `cor:conditional` | `faces12_campaign.claim.claim` | [`test_a_proved_certificate_gives_conditional_support`](../packages/faces12-campaign/tests/test_f12_claim.py)<br>[`test_the_conclusion_is_unconditional_only_with_every_obligation_reviewed`](../packages/faces12-campaign/tests/test_f12_claim.py) |
| Remark 9.4 (No realizability conclusion) | `rem:noconverse` | — | — |
| Proposition 9.5 | `prop:cases` | `cubeproof.split.static.child_cube`, `cubeproof.split.static.child_index` | [`test_case_indexing_matches_the_contract_children`](../packages/cubeproof/tests/split/test_cp_split_static.py)<br>[`test_split_needs_every_child_closed`](../packages/cubeproof/tests/certify/test_cp_certify_scenarios.py) |
| Definition 9.6 (Cubes and splits) | `def:cube` | — | — |
| Lemma 9.7 (A split partitions its cube) | `lem:split` | — | — |
| Definition 9.8 (Cube tree) | `def:cubetree` | — | — |
| Theorem 9.9 (Coverage) | `thm:coverage` | — | — |
| Lemma 9.10 (Closed cubes) | `lem:closure` | — | — |
| Corollary 9.11 (Conditional non-existence from cube trees) | `cor:treecover` | — | — |
| Remark 9.12 (A closed nonempty root settles only its region) | `rem:pilotroot` | — | — |
| Remark 10.1 (Attestation and verification are different guarantees) | `rem:attestation` | — | — |
<!-- END GENERATED: statements -->

## Where the statements live in the packages

The table above names functions; this section, written by hand, names the modules and packages
that implement each group of statements, including those (cube trees, coverage,
attestation) whose implementation the table leaves to this section. The tests check the
implementation, not the proofs ([CLAIMS](CLAIMS.md) says what each covers and what it does not).

| Statements | Implementation | Tests |
|---|---|---|
| Maps and the census: `def:map`, `prop:euler`, `lem:oriented`, `lem:framing`, `thm:59` | `neighbourly.maps`, `neighbourly.enumeration`, `neighbourly.corpus12` (the 59 matrices and their pinned formula hashes) | `packages/neighbourly/tests` |
| Exact controls: `lem:cofactor`, general position, the octant enumeration `lem:onereflex`, `rem:octants` | `neighbourly.exact`, `neighbourly.geometry`, `neighbourly.enumeration.vertex_profiles`, `neighbourly.checks` | `packages/neighbourly/tests` |
| The formula: layers S, H and A (`thm:order`, `thm:chirotope`, `lem:cutorder`), B and I (`lem:B`, `lem:I`, `lem:parity`, `lem:sf`), the gauge (`cor:gauge`) | `neighbourly.encoding` (`chirotope`, `faces`, `gauge`, `layers`, `formula`) emitting clauses through `neighbourly.cnf` | `packages/neighbourly/tests`; the base hashes of all 59 formulas |
| Cube trees: `def:cube`, `lem:split`, `def:cubetree` | cube canonical form, node and split identities, the cube CNF: `cubeproof.cnf` (`cube`, `cubecnf`), `cubeproof.contracts.identity` | `packages/cubeproof/tests/cnf`; the shared contract vectors in `tests/contracts` |
| Coverage: `thm:coverage`, `lem:closure`, `cor:treecover` | closure, deterministic selected tree, frontier, Merkle roots, verdict: `cubeproof.evidence.certify`; written independently in `tools/certify_min.py` | `packages/cubeproof/tests/certify` (including brute-force checks on random tiny formulas); `tests/independent`; agreement of the two on the contract corpus (`tests/contracts`) and in the end-to-end suites (`tests/endtoend`) |
| A closed nonempty root settles its region only: `rem:pilotroot` | the same closure rules (literal closure at requested roots); `faces12_campaign` pilot roots and the claim gate, which requires the empty cube of all 59 formulas | `packages/cubeproof/tests/certify`; `packages/faces12-campaign/tests` |
| Attestation versus independent verification: `rem:attestation` | admission and certification of journals; `cubeproof audit` (strict and reprove) and `cubeproof verify-retained` | `packages/cubeproof/tests/audit`; `tests/endtoend` |
| The conditional conclusion: `cor:conditional` | `faces12-campaign claim`, which prints a conditional statement unless enumeration, encoding and reduction are reviewed with verified artifacts | `packages/faces12-campaign/tests` |

A statement without a row is entirely the article's: nothing in the software checks it.

## Supplementary octant check

The reduction uses the geometric proof of (paper: lem:onereflex); the finite check
of (paper: rem:octants) is additional implementation evidence.
Three independent planes through a point define eight octants, indexed by their
three sign bits. A quadrant in plane i fixes the other two signs; it separates
the two octants with those signs. A ray in the intersection of planes i and j
fixes the remaining sign and is incident to four quadrants.

For each of the 256 octant subsets, take the quadrants separating an included
octant from an excluded one. Keep the subset only if all three planes occur,
each ray has zero or two incident boundary quadrants, that incidence graph is
connected, and the quadrants in each plane form a sector bounded by one ray of
each of its two intersection lines. These are exactly the filters in
`neighbourly.enumeration.vertex_profiles`. A one-quadrant sector is convex and
a three-quadrant sector reflex; two-quadrant sectors have opposite boundary
rays on one line and are excluded. The sorted sector sizes are (1,1,1) for 16
subsets and (1,1,3) for 48 subsets. This check is finite and assumes independent
planes; the geometric lemma does not depend on this enumeration.
