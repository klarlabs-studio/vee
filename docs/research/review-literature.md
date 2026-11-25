# Literature review: grounding Vee's review features

Scope: six feature areas for Vee (local, bring-your-own-model AI code review: multi-reviewer LLM findings with evidence, verification, static change-impact analysis, deterministic pass/block/incomplete gate with a replayable decision record).

Method: each source below was found and checked against a primary page (DOI, arXiv, publisher, or author pre-print) during this review. Numbers are quoted from the paper text. Where a claim is my inference rather than a finding, it is marked **[inference]**. Items I could not verify are listed at the end of each section and in the final "Unverified / dropped" list.

Convention: "precision" = share of emitted items that are correct; "recall" = share of true items emitted.

---

## 1. Change-impact precision

### Key sources

| # | Source | Link |
|---|---|---|
| 1.1 | Lehnert, S. (2011). *A taxonomy for software change impact analysis.* IWPSE-EVOL '11, pp. 41-50. | https://doi.org/10.1145/2024445.2024454 |
| 1.2 | Li, B., Sun, X., Leung, H., Zhang, S. (2013). *A survey of code-based change impact analysis techniques.* Software Testing, Verification and Reliability 23(8). | https://doi.org/10.1002/stvr.1475 |
| 1.3 | Hassan, A. E., Holt, R. C. (2004). *Predicting change propagation in software systems.* ICSM 2004, pp. 284-293. | https://research.cs.queensu.ca/home/ahmed/home/pubs/icsm2004.pdf |
| 1.4 | Zimmermann, T., Weißgerber, P., Diehl, S., Zeller, A. (2005). *Mining version histories to guide software changes.* IEEE TSE 31(6), pp. 429-445. | https://thomas-zimmermann.com/publications/files/zimmermann-tse-2005.pdf (DOI 10.1109/TSE.2005.72) |
| 1.5 | Kagdi, H., Gethers, M., Poshyvanyk, D., Collard, M. (2010). *Blending conceptual and evolutionary couplings to support change impact analysis in source code.* WCRE 2010; and Gethers, Dit, Kagdi, Poshyvanyk (2012). *Integrated impact analysis for managing software changes.* ICSE 2012. | https://doi.org/10.1109/WCRE.2010.21 ; https://www.cs.wm.edu/~dposhyvanyk/pubs/ICSE12-ImpactAnalysis.pdf |
| 1.6 | Hattori, L., Guerrero, D., Figueiredo, J., Brunet, J., Damásio, J. (2008). *On the precision and accuracy of impact analysis techniques.* ICIS 2008. | https://doi.org/10.1109/ICIS.2008.104 |
| 1.7 | Salis, V., Sotiropoulos, T., Louridas, P., Spinellis, D., Mitropoulos, D. (2021). *PyCG: Practical call graph generation in Python.* ICSE 2021. | https://arxiv.org/abs/2103.00587 |
| 1.8 | Herzig, K., Just, S., Zeller, A. (2016). *The impact of tangled code changes on defect prediction models.* EMSE 21. | https://doi.org/10.1007/s10664-015-9376-6 |
| 1.9 | Gligoric, M., Eloussi, L., Marinov, D. (2015). *Practical regression test selection with dynamic file dependencies.* ISSTA 2015. | https://users.ece.utexas.edu/~gligoric/papers/GligoricETAL15Ekstazi.pdf |

### Quantified findings

- **Taxonomy (1.1, 1.2).** Impact analysis splits along analysis type (static structural, textual/IR, historical, dynamic), granularity of change and of impact set, and "safety" vs precision. Li et al. found 30 papers empirically evaluating 23 code-based techniques and noted the absence of common benchmarks and unified metrics. Both surveys treat precision and recall of the *impact set* as the right evaluation lens.
- **Structural dependencies are a weak predictor of where change must propagate (1.3).** Across five C systems (NetBSD, FreeBSD, OpenBSD, Postgres, GCC), unpruned heuristics scored on average:
  - historical co-change: recall 0.87, precision 0.06
  - same-file: recall 0.83, precision 0.12
  - call/use/define (static code structure): recall 0.42, precision 0.02
  - same developer: recall 0.74, precision 0.01

  A pruned hybrid (co-changed at least twice and in more than A% of cases, relaxed threshold for same-file entities) reached about **0.51 recall and 0.49 precision**. The authors note that call/use/define relations explain only about 42% of propagations.
- **Co-change mining (1.4).** With support 1 and confidence 0.1 ("navigation"), ROSE gave suggestions for 66% of queries, with average precision 29-30% and recall 33-34%. A correct item was in the top 3 in 70% of cases. In "error prevention" mode (confidence of at least 0.9, support of at least 3), precision was above 66%, but it warned in only **3%** of the cases where an item was actually missing. Stable systems such as GCC predicted well; feature-heavy systems such as KOffice predicted poorly.
- **Combining signals (1.5).** A disjunctive union of conceptual (textual) and evolutionary coupling beat either alone with statistical significance on every system, for example Apache httpd at cut-point 5: P 21 / R 43 vs P 15 / R 28 (conceptual) and P 18 / R 38 (evolutionary). The conjunctive (intersection) combination was worse than either alone, because the two signals find largely different true positives. Gethers et al. 2012 found that adding history to IR gave gains in recall that were statistically significant on all systems, while gains in precision were significant on only some. Absolute precision stays low: about 5-20% at realistic cut-points.
- **Depth vs precision (1.6).** On a Java static IA tool, limiting traversal to direct dependents (depth 1) raised precision from 73.5% to 84.2% (+15%) and cut recall from 100% to 81.2% (-19%). Depth 2 to 6 changed little. Most of the useful signal is in the first hop.
- **Name-based call resolution (1.7).** A careful static, assignment-based Python call graph reached **99.2% precision and 69.9% recall** on real packages. A conservative name-and-dependency tool reached 98.7% precision but 14.4% recall. A naive tool that attached edges to class names reached about 74% precision. Imprecision comes from resolving by bare name. Precision is recoverable when resolution is scoped (module, import, assignment flow).
- **Tangled changes pollute history (1.8).** 7-20% of bug fixes were tangled. At least 16.6% of files were wrongly associated with bug reports. Any co-change signal mined from raw commits inherits this noise.
- **Coarser granularity can be the better trade (1.9).** For regression test selection, file/class-level dependencies select more tests but reduce end-to-end time compared with method-level tracking, and are easier to make safe.

### Design implications for Vee

1. **Rank and cap impact; don't list it exhaustively.** The evidence puts unpruned impact precision at 2-12% (1.3) and combined approaches at 5-20% (1.5). Show the top-N references per changed symbol by a score, report "N more", and keep the full set in the decision record. Hattori (1.6) supports defaulting to **direct references only** (depth 1).
2. **Resolve names by scope before matching.** Restrict a reference to files that import or declare the defining module or package, and to qualified or receiver-typed calls where the language permits (1.7). Bare-name matches should be a lower-confidence tier, shown separately or down-weighted. **[inference]** For generic names (`review`, `run`, `new`, `get`), weight by inverse frequency of the identifier across the repo, and suppress matches whose name has more than K definitions in the repo unless an import links them. No paper tests this exact heuristic. It follows from the ambiguity results.
3. **Use git history as a second, independent signal, and combine by union with provenance.** Union beats intersection (1.5). Co-change has much higher recall than call structure (1.3). Mine co-change with minimum support of 2 and a confidence threshold (1.3, 1.4), skip very large commits (tangling, 1.8), and label each impacted item with its evidence (`ref` / `co-change` / `both`). Items supported by both signals are the strongest candidates.
4. **Test code and self-references.** No primary study I found directly measures test-vs-production noise in impact sets (see unverified list). **[inference]** Exclude references inside the changed file itself, and inside the same symbol's own definition. Group test-file references separately as "tests that exercise this", which is regression-test-selection information (1.9) rather than impact. Filter test-local helpers by path convention plus "defined in a test file".

---

## 2. Change risk / merge risk

### Key sources

| # | Source | Link |
|---|---|---|
| 2.1 | Mockus, A., Weiss, D. M. (2000). *Predicting risk of software changes.* Bell Labs Technical Journal 5(2), pp. 169-180. | https://doi.org/10.1002/bltj.2229 |
| 2.2 | Kamei, Y., Shihab, E., Adams, B., Hassan, A. E., Mockus, A., Sinha, A., Ubayashi, N. (2013). *A large-scale empirical study of just-in-time quality assurance.* IEEE TSE 39(6), pp. 757-773. | https://doi.org/10.1109/TSE.2012.70 |
| 2.3 | Hassan, A. E. (2009). *Predicting faults using the complexity of code changes.* ICSE 2009, pp. 78-88. | https://doi.org/10.1109/ICSE.2009.5070510 |
| 2.4 | McIntosh, S., Kamei, Y. (2018). *Are fix-inducing changes a moving target? A longitudinal case study of just-in-time defect prediction.* IEEE TSE 44(5), pp. 412-428. | https://posl.ait.kyushu-u.ac.jp/~kamei/publications/McIntosh_TSE2017.pdf |
| 2.5 | Yang, Y. et al. (2016). *Effort-aware just-in-time defect prediction: simple unsupervised models could be better than supervised models.* FSE 2016. Contested by Fu & Menzies (2017), *Revisiting unsupervised learning for defect prediction*, FSE 2017. | https://doi.org/10.1145/2950290.2950353 |
| 2.6 | Abreu, R., Murali, V., Rigby, P. C., et al. (2025). *Moving faster and reducing risk: Using LLMs in release deployment* (Meta Diff Risk Score). ICSE-SEIP 2025. | https://arxiv.org/abs/2410.06351 |
| 2.7 | Mockus, A., Abreu, R., Rigby, P. C., Amsallem, D., Bansal, P., et al. (2025). *Leveraging risk models to improve productivity for effective code un-freeze at scale.* ACM TOSEM. | https://doi.org/10.1145/3722216 |
| 2.8 | Yu, X., Cogo, F. R., McIntosh, S., Godfrey, M. W. (2024). *Studying the impact of risk assessment analytics on risk awareness and code review performance.* EMSE. | https://doi.org/10.1007/s10664-024-10443-x |
| 2.9 | Paraspatki, A. G., Reznicek, B., Abreu, R., Garberson, F., Mockus, A., Nagappan, N., Rigby, P. C. (2026). *Code reviewer recommendation for high risk diffs at scale: workflow, recommender, and live experiments.* FSE 2026. | https://doi.org/10.1145/3803437.3805220 |
| 2.10 | Jiarpakdee, J., Tantithamthavorn, C., Grundy, J. (2021). *Practitioners' perceptions of the goals and visual explanations of defect prediction models.* MSR 2021; and Pornprasit, C., Tantithamthavorn, C. (2021). *JITLine.* MSR 2021. | https://doi.org/10.1109/MSR52588.2021.00055 ; https://doi.org/10.1109/MSR52588.2021.00049 |

### Quantified findings

- **What predicts risk (2.1).** At about 15,000 changes in a 5ESS switch codebase, the reduced logistic model kept: **log number of subsystems touched (coef 0.41)**, number of deltas (0.10), lines added (0.18), is-a-field-fix (0.60), interval (0.05), and developer experience (−0.11). All were significant. Diffusion was singled out as "one of the most important factors". The deployed tool classified changes into **high / medium / normal** using two cut-offs and attached **per-predictor flags** ("many subsystems touched", "is a field fault fix") explaining *why* a change was high risk. This is the original explainable risk label.
- **JIT metric families and effort-aware evaluation (2.2).** 14 change metrics in five families: diffusion (NS, ND, NF, entropy), size (LA, LD, LT), purpose (FIX), history (NDEV, AGE, NUC) and experience (EXP, REXP, SEXP). Over 11 projects (6 OSS, 5 commercial), average accuracy was 68% and recall 64%. Effort-aware evaluation changes the picture: ranking by plain predicted probability caught only **5-8%** of defect-inducing changes at 20% of review effort, which is worse than random (20%). Ranking by risk per changed line (EALR) caught **35%** on average (28% OSS, 43% commercial). The best return on effort was usually at about the 10% effort cut-off.
- **Entropy (2.3).** Hassan's change-entropy measures (how scattered a period's changes are across files) cut prediction error by 13-42% (32% on average) compared with prior-modification counts, and matched or beat prior-fault counts. This is the origin of the "entropy" diffusion feature.
- **Drift and calibration (2.4).** Over 37,524 changes (Qt, OpenStack), JIT models lost **3-34 AUC points and calibration (Brier) one year after training**. The importance of Size ranged from 10% to 43% of explanatory power by period. Recommendation: retrain on data from the most recent 3 months, and base quality plans on at least 6 months of data.
- **Simple baselines (2.5).** Yang et al. reported that simple unsupervised rankings (for example, smallest change first) can beat supervised models under effort-aware metrics. Fu & Menzies disputed this for per-project use, and later work (Huang, Xia & Lo) showed such rankers produce many initial false alarms. The takeaway is that size normalisation drives effort-aware results.
- **Industrial diff risk (2.6).** Meta's Diff Risk Score, a logistic regression baseline in production for more than 9 months, captured **18.7% / 27.9% / 84.6% of severe incidents while gating the riskiest 5% / 10% / 50% of diffs**. Incident base rate was about 0.17-0.23% of diffs. A risk-aligned, diff-pretrained 13B LLM improved this to 26.2% / 42.3% / 88.5%. Unaligned foundation-model embeddings did worse than logistic regression (0.58-0.90×). Gating is tiered: green, weekend, yellow, red.
- **Risk-gated un-freeze (2.7).** During the winter 2023 freeze, only 16% of changes were gated. 42% more changes landed than the prior year, and outages fell by 52%. File-level risk plus change properties let 2-2.5× more changes through.
- **Do risk labels change reviewer behaviour? Yes, modestly (2.8, 2.9).**
  - Controlled experiment, n = 48: showing a risk-analytics view significantly improved risk awareness and **review effectiveness** (median 0.17 vs 0 known defects found, p = 0.03, Cliff's δ 0.27, small). Speed gains were not significant (p = 0.0503).
  - Meta randomized trial on the riskiest 5% of diffs (15,794 diffs): adding a risk-targeted extra reviewer plus a bypassable pre-land dialog increased the share of diffs whose final version dropped below the high-risk threshold by **9.56%**. It also raised abandonment by 13.1%, long comments by 9%, and commenters by 5.6%, at a cost of only **+0.45%** diff processing time.
- **Explainability (2.10).** 82-84% of practitioners found defect-prediction goals useful. Per-prediction explanations (LIME-style "which features drove this") were most preferred (66-78% agreement), but respondents complained about too much information. Line-level JIT (JITLine) localised risky lines 133-150% better than an NLP baseline (Top-10 accuracy), so risk can point at hunks, not just whole changes.

### Design implications for Vee

1. **Build risk from Kamei/Mockus change metrics, explained per factor.** Without labelled defect history, Vee can't train a calibrated per-repo model. **[inference]** Use a transparent, rule-based score over diffusion (subsystems/directories touched, files, entropy), size (LA/LD), purpose (fix vs feature), and history (number of prior authors, file age, recent churn). Output a **tier with named contributing flags**, as Mockus & Weiss did (2.1), not a bare probability. Record the factor values in the decision record so the score replays exactly.
2. **Don't present uncalibrated probabilities.** Calibration decays within a year even for trained models (2.4), and unaligned LLM judgments of risk underperform simple regression (2.6). Use ordinal tiers (low / elevated / high). If a probability is ever shown, it needs per-repo calibration and a stated data window.
3. **Make prioritisation effort-aware.** Ranking findings or changes by raw risk is worse than random per unit of effort (2.2). Normalise by size (risk per changed line), and surface the smallest high-risk hunks first.
4. **Use risk to route attention, not only to block.** The strongest behavioural evidence is for *routing*: an extra reviewer, a bypassable pre-land prompt, deeper LLM passes on risky hunks (2.8, 2.9). In Vee, high risk could trigger more reviewer samples or the verification pass and require explicit acknowledgement, rather than an automatic block.

---

## 3. Code review effectiveness and what reviewers need

### Key sources

| # | Source | Link |
|---|---|---|
| 3.1 | Bacchelli, A., Bird, C. (2013). *Expectations, outcomes, and challenges of modern code review.* ICSE 2013. | https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/ICSE202013-codereview.pdf (DOI 10.1109/ICSE.2013.6606617) |
| 3.2 | McIntosh, S., Kamei, Y., Adams, B., Hassan, A. E. (2016). *An empirical study of the impact of modern code review practices on software quality.* EMSE 21(5), pp. 2146-2189. | https://doi.org/10.1007/s10664-015-9381-9 |
| 3.3 | Sadowski, C., Söderberg, E., Church, L., Sipko, M., Bacchelli, A. (2018). *Modern code review: a case study at Google.* ICSE-SEIP 2018. | https://doi.org/10.1145/3183519.3183525 |
| 3.4 | Rigby, P. C., Bird, C. (2013). *Convergent contemporary software peer review practices.* ESEC/FSE 2013. | https://doi.org/10.1145/2491411.2491444 |
| 3.5 | Bosu, A., Greiler, M., Bird, C. (2015). *Characteristics of useful code reviews: an empirical study at Microsoft.* MSR 2015. | https://doi.org/10.1109/MSR.2015.21 |
| 3.6 | Czerwonka, J., Greiler, M., Tilford, J. (2015). *Code reviews do not find bugs.* ICSE-SEIP 2015; Mäntylä, M., Lassenius, C. (2009). *What types of defects are really discovered in code reviews?* IEEE TSE 35(3). | https://ieeexplore.ieee.org/document/7202946/ ; https://doi.org/10.1109/TSE.2008.71 |
| 3.7 | Kononenko, O., Baysal, O., Guerrouj, L., Cao, Y., Godfrey, M. W. (2015). *Investigating code review quality: do people and participation matter?* ICSME 2015. | https://doi.org/10.1109/ICSM.2015.7332457 |
| 3.8 | Cohen, J. (2006). Cisco Systems code review case study, in *Best Kept Secrets of Peer Code Review* (vendor-published book; **not peer-reviewed**). | https://static1.smartbear.co/support/media/resources/cc/book/code-review-cisco-case-study.pdf |

### Quantified findings

- **Understanding is the bottleneck (3.1).** Finding defects is the top stated motivation, but comments are dominated by code improvements, and *understanding* is the second most frequent comment category. 91% (798) of surveyed developers said unfamiliar files take longer to review. Reviewers named "what instigated the change" as their biggest information need. Tools gave "only basic support" (diffs, inline comments).
- **Participation matters more than coverage (3.2).** In Qt, VTK and ITK, review coverage was significant in only 2 of 4 releases. Participation metrics (changes **approved without discussion**, discussion length, review speed) were significant in all studied systems. More changes approved without discussion was associated with more post-release defects.
- **Scale and size at Google (3.3).** About 9M changes. Median change is **24 lines**. More than 35% touch a single file, about 90% touch fewer than 10 files. Median time to first feedback is under 1 hour for small changes and about 5 hours for very large ones. Median overall review latency is under 4 hours. Compare 14.7-19.8 h at Microsoft/AMD/Chrome OS (3.4).
- **Convergent parameters (3.4).** Across Google-led, Microsoft, AMD and OSS projects, review intervals, about 2 reviewers, and small changes converged independently. Review increases the number of distinct files a developer knows by 66-150%.
- **What makes a comment useful (3.5).** About 1.5M comments across five Microsoft projects. Reviewers who had reviewed the file before were about 2× as useful (65-71% vs 32-37% useful). Usefulness density falls as the number of files in the change grows. Build and config files received the least useful comments (make files 53%, solution files 57%, source 70%).
- **Bugs are a minority of review output (3.6).** At Microsoft, only about **15%** of review comments indicate a possible defect, while about 50% or more concern maintainability. The fall in usefulness with change size becomes noticeable at about **20 or more files**. Mäntylä & Lassenius: **75%** of defects found in reviews were evolvability, not functional.
- **Reviewed code still ships bugs (3.7).** At Mozilla, 54% of reviewed changes were later linked (via SZZ) to bug-inducing changes. Reviewer workload and experience, and participation, were associated with review quality.
- **Size and pace limits (3.8, non-peer-reviewed).** Cisco: 2,500 reviews and 3.2M LOC. Defect density dropped sharply above **about 200 LOC per review**; recommended maximum 400 LOC. Inspection rates **above about 450-500 LOC/hour** were below-average in 87% of cases. Effectiveness drops after about 60 minutes. McIntosh et al. (3.2) cite Kemerer & Paulk's 200 LOC/hour guideline to flag "hastily reviewed" changes.

### Design implications for Vee

1. **Every finding should explain the change, not just flag a line.** Understanding dominates (3.1). Each finding needs file, line range, the **diff hunk**, a short **rationale** ("why this is a problem here"), and evidence. A per-change summary of *what changed and why* (from commit messages and description) and the impact list (section 1) are part of the review product.
2. **Detect and warn on oversized reviews.** Thresholds of 200-400 LOC (3.8, weak evidence) and about 20 files (3.6, 3.5) are defensible defaults. **[inference]** Above them, Vee should mark the run as reduced-confidence (for example "incomplete: change too large for reliable review") or suggest decomposition (section 6), not silently produce a pass.
3. **Separate defect findings from maintainability findings.** Most human review output is evolvability (3.6). The gate should consider only correctness, security and data-loss classes. Maintainability findings stay advisory.
4. **Record participation in the decision record.** "Approved without discussion" predicts defects (3.2). **[inference]** Record whether findings were viewed, dispositioned, or overridden. A pass where blocking-class findings were dismissed without a written reason should be visible in the replay.

---

## 4. LLM-based code review and its evaluation

### Key sources

| # | Source | Link |
|---|---|---|
| 4.1 | Li, Z., Lu, S., Guo, D., et al. (2022). *Automating code review activities by large-scale pre-training* (CodeReviewer). ESEC/FSE 2022. | https://arxiv.org/abs/2203.09095 |
| 4.2 | Tufano, R., Dabić, O., Mastropaolo, A., Ciniselli, M., Bavota, G. (2024). *Code review automation: strengths and weaknesses of the state of the art.* IEEE TSE. | https://arxiv.org/abs/2401.05136 |
| 4.3 | Frömmgen, A., Austin, J., Choy, P., et al. (2024). *Resolving code review comments with ML.* ICSE-SEIP 2024 (Google). | https://doi.org/10.1145/3639477.3639746 |
| 4.4 | Vijayvergiya, M., Salawa, M., et al., Just, R. (2024). *AI-assisted assessment of coding practices in modern code review* (AutoCommenter, Google). AIware 2024. | https://arxiv.org/abs/2405.13565 |
| 4.5 | Sun, T., Xu, J., Li, Y., Yan, Z., Zhang, G., et al. (2025). *BitsAI-CR: Automated code review via LLM in practice* (ByteDance). FSE 2025 Industry. | https://arxiv.org/abs/2501.15134 |
| 4.6 | Lu, J., Jiang, L., Li, X., Fang, J., Zhang, F., Yang, L., Zuo, C. (2025). *Towards practical defect-focused automated code review* (Kuaishou). ICML 2025. | https://arxiv.org/abs/2505.17928 |
| 4.7 | Bhandari, J. et al. (2025). *A note on Code Quality Score: LLMs for maintainable large codebases* (Meta). arXiv. | https://arxiv.org/abs/2508.02732 |
| 4.8 | Olewicki, D., Da Silva, L., Ben Sghaier, O., Mujahid, S., et al. (2026). *Impact of an LLM-based review assistant in practice: a mixed open-/closed-source case study* (Mozilla and Ubisoft). IEEE TSE. | https://doi.org/10.1109/TSE.2026.3663093 |
| 4.9 | Sun, K., Kuang, H., Baltes, S., Zhou, X., Zhang, H., Ma, X., Rong, G., Shao, D., Treude, C. (2026). *Does AI code review lead to code changes? A case study of GitHub Actions.* IEEE TSE. | https://arxiv.org/abs/2508.18771 (DOI 10.1109/TSE.2026.3688237) |
| 4.10 | Cihan, U., Haratian, V., İçöz, A., et al., Tüzün, E. (2025). *Automated code review in practice.* ICSE-SEIP 2025 (Beko). | https://arxiv.org/abs/2412.18531 |
| 4.11 | Tantithamthavorn, C. et al. (2026). *[product name omitted] Code Reviewer: a large-scale online evaluation of LLM-based code review automation at Atlassian.* arXiv. | https://arxiv.org/abs/2601.01129 |
| 4.12 | Maddila, C., Ghorbani, N., et al., Rigby, P. C. (2025). *AI-assisted fixes to code review comments at scale* (Meta). arXiv. | https://arxiv.org/abs/2507.13499 |
| 4.13 | Benchmarks and judges: *Benchmarking and studying the LLM-based code review* (SWR-Bench), arXiv 2509.01494 (2025); Klieber, D., Svoboda, D., Flynn, L., Martins, R. (2026). *Using LLMs to adjudicate static-analysis alerts with error reduction techniques*, arXiv 2607.09979; CRScore (NAACL 2025). | https://arxiv.org/abs/2509.01494 ; https://arxiv.org/abs/2607.09979 ; https://aclanthology.org/2025.naacl-long.457.pdf |

### Quantified findings

**Precision is the binding constraint in production.**
- **Google, comment resolution (4.3).** The model was calibrated to a **target precision of 50%**, and serving-time heuristics traded quantity for quality. 40-50% of previewed suggestions were applied. In deployment, authors addressed **7.5%** of all reviewer comments with an ML edit.
- **Google, AutoCommenter (4.4).** The useful ratio was 54% from developer feedback and 60% from raters, below the **80% target** for wide rollout. Suppressing 17 non-actionable best-practice URLs lifted historical usefulness from 54% to 66%. Only about 10% of comments received explicit feedback. The estimated resolution rate measured by code change was **about 40%**. In the A/B test, there was no significant change in review duration or iterations.
- **ByteDance (4.5).** A two-stage pipeline: a detector, then a separate fine-tuned **ReviewFilter** verifier.
  - The verifier raised precision from 54.5% to 67.1% in ablation. In production, precision rose from about 25% to **75%** over 18 weeks.
  - The **conclusion-first** verifier format (decision token, then rationale) was chosen for latency and explainability.
  - "Outdated rate" (flagged lines later modified) was 26.7%, against a human baseline of 35-46%.
  - Pruning poorly performing rule categories raised the outdated rate.
- **Kuaishou (4.6).** Multi-reviewer, meta-reviewer, validator pipeline with three 1-7 scores per comment (nitpick? fake problem? severity?), discarding at 4 or below.
  - Going from 1 to 3 reviewer samples **raised key-bug inclusion but also raised false-alarm rate**. Only the **validator** made multi-sampling a net win.
  - "Left-flow" code slicing beat both diff-only and full-flow context. Longer context distracted the model.
- **Meta, Code Quality Score (4.7).** Detector alone: precision 13.5%, recall 9.3%. Detector plus fine-tuned validator plus rules: precision **78.2%**, recall **1.2%**. An off-the-shelf frontier model used as both detector and judge reached 51.6% precision and 11.5% recall. Verification buys precision at a steep recall cost, and an un-tuned LLM judge discriminates valid from invalid issues poorly. The production helpfulness rate was about 60%.

**Acceptance in the field is low to moderate, and depends on design.**
- **Mozilla and Ubisoft (4.8).** Even with RAG plus an LLM-as-judge filter, reviewers accepted only about **8%** of generated comments. Another 14.6-20.5% were marked useful as tips. **Refactoring comments were accepted far more than functional ones (18.2-18.6% vs 4.8-5.2%).** Accepted AI comments led to revisions as often as human comments (74% vs 73% at chunk level). Median added reviewer time was 43 s per patch.
- **GitHub review actions (4.9).** About 22,000 comments across 178 repositories. Valid AI comments were addressed in only **0.9-19.2%** of cases, against **60%** for human comments. Predictors of being addressed: **hunk-level** (not file-level) placement, **concise and code-rich** comments (more than half code), **manually triggered** runs (12.8% vs 6.8%), and less experienced authors (5× higher).
- **Industrial deployment (4.10).** 73.8% of bot comments were marked resolved (range 55-90% by project), but mean PR closure time **rose from 5 h 52 m to 8 h 20 m**. The bot posted 3.65 comments per PR, against 0.31 for humans. Complaints were faulty reviews, unnecessary corrections, and irrelevant comments.
- **Atlassian (4.11).** Pipeline: LLM generation, then an LLM-as-judge for factual correctness, then a fine-tuned classifier for actionability trained on about 50k comments labelled by whether code changed afterwards. Code-resolution rate was **38.7% vs 44.5% for human comments**. Most-resolved categories: readability, bugs, maintainability.
- **Meta, comment fixes (4.12).** Showing AI patches to *reviewers* in a safety trial made reviews **more than 5% slower**. Showing them only to authors removed the regression. This argues for randomized safety trials on UX placement.

**Offline accuracy is modest, and benchmarks mostly expose low precision.**
- **CodeReviewer and successors (4.1, 4.2).** Exact-match accuracy is low. Manual analysis of about 2,300 predictions found that 25% of test instances were noise (unclear comments, comments with no requested change, changes unrelated to the comment). Techniques fail when they lack context beyond the method or hunk.
- **SWR-Bench (4.13, preprint).** 1,000 PRs, half of them clean. State-of-the-art pipelines reached **precision of 3-17%** and F1 of 19% at best. Aggregating multiple reviews improved F1 by up to 43.7%. LLM-as-judge matching against structured ground truth agreed with humans about 90% of the time.
- **Static-alert adjudication (4.13, preprint).** Running the LLM N = 10 times and accepting a verdict only at 80% or higher agreement (else "uncertain") reached at least 98% recall and at least 94.8% specificity on three suites. Self-consistency with an abstain option works for *verification* of specific claims.
- **CRScore (4.13).** A reference-free metric grounded in code claims and smells correlated only moderately with human judgment (Spearman 0.54). Reference-based metrics such as BLEU barely correlate. Don't evaluate reviewers by text similarity.

### Design implications for Vee

1. **Separate generation and verification stages, and record recall loss honestly.** Every industrial system that reached acceptable precision added a separate verifier (4.5, 4.6, 4.7, 4.11). Multi-sampling without a verifier raises false alarms (4.6). Vee's verify step should:
   - re-check each finding against code (evidence lines exist, claim is consistent with the code);
   - use **N-sample agreement with an explicit "uncertain" outcome** (4.13);
   - log what verification removed, because recall drops steeply (4.7: 9.3% to 1.2%).

   Track precision targets per category, for example at least 50% overall (Google's bar, 4.3) and higher for gate-blocking classes (4.4 targeted 80%).
2. **Treat categories differently.** Field data shows that functional/bug comments are accepted least but matter most, and refactoring/style comments are accepted most (4.8; 3.6). **[inference]** Only verified correctness, security and data-loss findings should affect the gate. Style and maintainability findings are advisory, can be collapsed, and should never block. Classify each finding at generation time *and* re-classify at verification.
3. **Comment format follows the evidence.** Anchor to hunk and line, keep it concise, include code or a suggested patch, give the rationale in one or two sentences (4.9). Cap comments per change: 3.65 per PR increased closure time (4.10). Present low-confidence items as "review tips" separately from publishable findings (4.8).
4. **Measure outcomes, not text similarity.** Instrument an "addressed" or outdated-rate signal: did the flagged lines change before merge (4.4, 4.5, 4.11)? Explicit thumbs-feedback is rare (about 10%, 4.4). Use it with a human baseline to tune and prune rules, and retrain or re-threshold as repos change (4.11 saw resolution rate drop from 40% to 33% on rollout to new repos). Test UX placement before rollout (4.12).

---

## 5. Automated approval / gating

### Key sources

| # | Source | Link |
|---|---|---|
| 5.1 | Adams, C., Banga, A. S., Bansal, P., et al. (2026). *Automating low-risk code review at Meta: RADAR, risk calibration, and review efficiency.* ASE 2026. | https://arxiv.org/abs/2605.30208 (DOI 10.1145/3832783.3834493) |
| 5.2 | Wang, Y., Welc, A., Clapp, L., Chen, L. (2023). *Last Diff Analyzer: multi-language automated approver for behavior-preserving code revisions* (Uber). ESEC/FSE 2023 Industry. | https://doi.org/10.1145/3611643.3613870 |
| 5.3 | Abreu et al. (2025), Diff Risk Score (2.6); Mockus et al. (2025), code un-freeze (2.7). | see section 2 |
| 5.4 | Gön, M. F., Yetiştiren, B., Tüzün, E. (2024). *Towards unmasking LGTM smells in code reviews: a comparative study of comment-free and commented reviews.* ICSME 2024. | https://repository.bilkent.edu.tr/items/eb456249-b19d-4c99-9dfb-6ba115f1ecb3/full |
| 5.5 | McIntosh et al. (2016), "changes without discussion" (3.2); Shan, Q., Sukhdeo, D., et al., Rigby, P. C., Nagappan, N. (2022). *Using nudges to accelerate code reviews at scale.* ESEC/FSE 2022. | https://doi.org/10.1145/3540250.3549104 |
| 5.6 | *Habituation at the gate: rising approval and declining scrutiny in human review of AI agent code* (2026). arXiv preprint (authors not shown on the indexed page). | https://arxiv.org/abs/2606.22721 |

### Quantified findings

- **Layered auto-approval at Meta (5.1).** The funnel runs: authorship and source classification, eligibility gates (for example, no compliance-scoped code, no extra-review requirements, an onboarded automation source with a track record), static heuristics, a **Diff Risk Score percentile threshold**, an LLM review agent that rejects on *any* risk signal, then deterministic validation.
  - 535K diffs reviewed and 331K landed.
  - Relaxing the DRS threshold from p25 to p50 raised the approve rate to 60.3%.
  - Revert rate was **1/3** and production-incident rate **1/50** of non-automated diffs. These are observational and confounded by selection, and the authors state as much.
  - Median time to close was more than 4× faster.
  - Bot diffs land after a **configurable delay** during which a human can still reject. There are **volume caps** per automation source per day. Stricter thresholds (p20) apply to non-allowlisted bots.
- **Behaviour-preserving revisions (5.2).** Uber auto-approves a *new revision* only if a reviewer **approved a prior revision** and static analysis shows the delta is behaviour-preserving (formatting, renames, constant extraction). About **15%** of analysed diffs were auto-approved weekly, and 13.5% of end-to-end test node usage was saved. This is the empirical template for "approval carries forward only across provably safe deltas".
- **Risk thresholds as a dial (5.3).** At Meta's base rates, gating 5% of diffs captured about 19-26% of severe incidents, and gating 50% captured about 85-89%. Freeze-period gating of 16% of changes coincided with 52% fewer outages.
- **Rubber-stamping (5.4, 5.5, 5.6).**
  - 64.7% of PRs in five large projects had comment-free reviews. These showed the LGTM smell **3.5× more often** and had significantly more **late commits** (commits after approval) (5.4).
  - Changes approved without discussion are associated with more post-release defects (3.2).
  - Meta guarded its review-speed nudges with "eyeball time" and the fraction of diffs reviewed within 24 h, and saw no regression (5.5).
  - **Preprint, not peer reviewed (5.6):** across 400 repeat reviewers of agent-authored PRs, approval rate rose from 27.9% to 42.4% by experience decile. Inline comments per review fell 22%, and the change-request rate halved. This is consistent with habituation rather than calibrated trust.

### Design implications for Vee

1. **Auto-pass must be layered and conservative, with the cheapest deterministic gates first.** Follow the RADAR order (5.1):
   1. eligibility (paths, protected areas, change class, size);
   2. deterministic heuristics (docs-only, test-only, formatting-only, generated files);
   3. risk tier (section 2);
   4. LLM review that rejects on any blocking-class finding;
   5. deterministic checks (build, tests, verification complete).

   Any stage failing or missing produces **block** or **incomplete**, never pass. Record each stage's verdict in the decision record so a pass is replayable stage by stage.
2. **Invalidate approval on new commits by default, and carry it forward only across verified-safe deltas.** Late commits after approval are a known smell (5.4). Uber's carry-forward requires both a prior human approval *and* a proof that the delta preserves behaviour (5.2). **[inference]** Vee's decision record should bind a verdict to the exact base/head tree hashes. A new head invalidates the verdict unless the inter-revision diff is classified trivial by a deterministic analyser (whitespace, comment, rename). An LLM's judgment alone shouldn't carry an approval forward.
3. **Build in anti-rubber-stamp guardrails.** **[inference from 5.1, 5.5, 5.6]**
   - Rate-limit auto-passes.
   - Keep a hold window for automated sources.
   - Track override and dismissal rates per user over time (the habituation signal).
   - Require written reasons to dismiss blocking-class findings.
   - Report auto-pass outcomes against later reverts so thresholds can be tuned. RADAR's p25 to p50 relaxation was driven by observed outcomes.
4. **Make the threshold an explicit, versioned policy parameter.** Organisations set the risk percentile per source (allowlisted vs not) (5.1). Vee's policy file should name the threshold, and the decision record should store the policy version used.

---

## 6. Multi-change and agent-generated change review

### Key sources

| # | Source | Link |
|---|---|---|
| 6.1 | Li, H., Zhang, H., Hassan, A. E. (2025). *The rise of AI teammates in software engineering (SE) 3.0: how autonomous coding agents are reshaping software engineering* (AIDev dataset). arXiv. | https://arxiv.org/abs/2507.15003 |
| 6.2 | Watanabe, M., Li, H., Kashiwa, Y., Reid, B., Iida, H., Hassan, A. E. (2025). *On the use of agentic coding: an empirical study of pull requests on GitHub.* arXiv. | https://arxiv.org/abs/2509.14745 |
| 6.3 | Ehsani, R., Pathak, S., Rawal, S., Al Mujahid, A., Imran, M. M., Chatterjee, P. (2026). *Where do AI coding agents fail? An empirical study of failed agentic pull requests in GitHub.* arXiv. | https://arxiv.org/abs/2601.15195 |
| 6.4 | Nakashima, S., Ishimoto, Y., Kondo, M., McIntosh, S., Kamei, Y. (2026). *Why agentic-PRs get rejected: a comparative study of coding agents.* arXiv. | https://arxiv.org/abs/2602.04226 |
| 6.5 | Adams et al. (2026), RADAR (5.1): AI-driven code growth context. | see 5.1 |
| 6.6 | Barnett, M., Bird, C., Brunet, J., Lahiri, S. K. (2015). *Helping developers help themselves: automatic decomposition of code review changesets.* ICSE 2015. | https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/barnett2015hdh.pdf |
| 6.7 | di Biase, M., Bruntink, M., van Deursen, A., Bacchelli, A. (2019). *The effects of change decomposition on code review: a controlled experiment.* PeerJ Computer Science 5:e193. | https://peerj.com/articles/cs-193/ |
| 6.8 | Tao, Y., Kim, S. (2015). *Partitioning composite code changes to facilitate code review.* MSR 2015; Herzig et al. 2016 (1.8). | https://people.csail.mit.edu/hunkim/papers/tao-msr2015.pdf |

### Quantified findings

- **Agent PR acceptance (6.1).** 456,535 agent PRs from five agents across 61,453 repositories, up to June 2025. In popular repositories (more than 500 stars), agent PR acceptance ranged from **about 38% to 65%** by agent, against a human baseline of about 77%. The gap was largest for feature, fix and performance tasks. Documentation PRs from two agents beat the human baseline (85.7-88.6% vs 76.5%). Acceptance rates are observational and confounded by user and repo selection.
- **Single-agent matched comparison (6.2).** 567 vs 567 PRs, same authors and repositories. Agent PRs accepted **83.8% vs 91.0%** for humans (significant). Merge time did not differ. 55% of merged agent PRs went in unrevised, against 58.5% for humans. Where revised, **47.7% of agent PRs needed bug fixes**, 29% docs, 27% refactor, 23% style.
- **Failure modes (6.3, 6.4).** About 33k agent PRs. Unmerged PRs are **larger, touch more files, and more often fail CI**. Performance and bug-fix tasks fare worst; docs, CI and build fare best. Rejection taxonomy: no meaningful reviewer engagement, duplicate PRs, unwanted features, agent misalignment with the task. In a separate sample of 654 rejected agent PRs, **67.9% had no explicit reviewer feedback**. Seven rejection modes are unique to agents, including **distrust of AI-generated code**.
- **Volume pressure (6.5).** At Meta, lines per landed diff grew 105.9% year over year and per-developer diff volume rose 51%, more than 80% of it attributed to agentic AI, while the share of diffs reviewed on time fell. This is the motivation for risk-stratified automation.
- **Decomposition (6.6, 6.7, 6.8).**
  - In about 1,000 Microsoft changesets, **42%** contained more than one independent non-trivial partition when def-use relations among diff regions were used. 16 of 20 developers agreed the partitions were correct and complete (6.6).
  - Controlled experiment, n = 28: reviewing a tangled change split into coherent PRs produced **significantly fewer false-positive issues** (6 vs 1 total, p = 0.03). It did not change defects found or understanding of rationale, and it increased context-seeking (6.7).
  - Tao & Kim found composite changes are common and that heuristic partitioning helps review (6.8).
- **Gap.** I found no peer-reviewed empirical study of *stacked* change review (review effectiveness vs stack depth). Practitioner accounts exist but aren't evidence.

### Design implications for Vee

1. **Treat agent-authored changes as a risk factor with specific checks, not a different pipeline.** Failure concentrates in large, multi-file, CI-failing, bug-fix and feature changes (6.3), and in misalignment with the stated task (6.3, 6.4). **[inference]** For agent-authored changes (detected from trailers or branch prefixes, or declared), add a **task-alignment check** (does the diff do what the linked issue or description asks, and nothing more), require CI or test evidence before pass, and weight the size and diffusion risk factors more heavily.
2. **Decompose large or tangled changes before reviewing them.** Use the def-use clustering from the impact analyser (6.6) to split a change into partitions. Review partitions independently, then run one cross-partition pass for interactions. This reduces false positives (6.7), which matters most for LLM reviewers whose main weakness is precision (section 4).
3. **Review stacks and related changes with shared context, but gate per change.** **[inference; no direct study]** Give the reviewer the parent changes' diffs and decision records as context. Bind each verdict to its own base/head. When a lower change in a stack changes, invalidate the verdicts above it (consistent with section 5, implication 2).
4. **Design against habituation for high-volume agent traffic.** Reviewer scrutiny of agent PRs declines with exposure (5.6, preprint), and most rejected agent PRs get no explicit feedback (6.4). Vee's dispositions and replayable records give the explicit, attributable feedback trail these studies found missing. Surface per-reviewer override trends.

---

## Unverified, weakly sourced, or dropped

- **Cisco 200-400 LOC / 500 LOC-per-hour figures (3.8)** come from a vendor-published book chapter, not peer review. Kemerer & Paulk (2009, IEEE TSE) is cited by McIntosh et al. for the 200 LOC/hour rate. I did not open that paper directly.
- **Bacchelli & Bird exact comment-category percentages.** I verified the qualitative findings (understanding is the main challenge, 91% and 82% survey figures). I did not re-verify the exact share of defect-related comments, so none is quoted.
- **"Google ML-based risk scoring for diffs."** I could not find a peer-reviewed Google paper on a production diff-risk model comparable to Meta's DRS. Not cited.
- **Test-vs-production handling in impact analysis.** No primary study found that measures noise from test-local or self references in symbol-based impact sets. The recommendations in section 1 are marked as inference. The regression-test-selection literature (1.9) is adjacent evidence only.
- **Generic-identifier down-weighting (IDF-style).** Engineering inference; no paper found that evaluates it for impact analysis.
- **Stacked-diff effectiveness.** No peer-reviewed study found. The figure circulating online ("1.5M PRs, 200-400 lines have 40% fewer defects") has no traceable primary source and was dropped.
- **Preprints.** These are not yet peer reviewed (to my knowledge as of this review): Habituation at the gate (5.6), SWR-Bench (4.13), Klieber et al. adjudication (4.13), Code Quality Score (4.7), MetaMateCR (4.12), the Atlassian evaluation (4.11), AIDev (6.1), Watanabe et al. (6.2), Ehsani et al. (6.3), and Nakashima et al. (6.4). Treat their numbers as indicative.
- **Fu & Menzies (2017) and Huang, Xia & Lo (2017/2019)** rebuttals to Yang et al. are named from the citing literature. I did not open them individually.
- **Agent and vendor names** are omitted on purpose. Several cited studies compare named commercial agents and review tools; only aggregate figures are reported here.
