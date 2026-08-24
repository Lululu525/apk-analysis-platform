# APK Risk Analysis Model

Static-analysis pipeline that extracts Manifest/component/Intent-Filter/permission/sensitive-API
features from Android APKs and scores components for exported-and-unprotected risk, combining a
rule engine with a `filter_row` ML classifier.

## Language

**Component row (`filter_row`)**:
One row of training/inference data representing a single Android component (Activity, Service,
Receiver, Provider) and its exported/permission/Intent-Filter features. This is the unit both the
rule engine and the ML classifier operate on.
_Avoid_: sample, record (too generic — say "component row" or "APK" depending on which level).

**MalDroid category**:
The APK-level malware family label assigned by the CIC MalDroid-2020 dataset (e.g. Benign,
Banking, SMS, Adware, Riskware), carried by which source folder an APK came from. This is a
separate signal from a component row's label — an APK's MalDroid category says something about
the APK as a whole, not about any specific component inside it.
_Avoid_: malware type, label (ambiguous with component-row label).

**Weak label**:
A component row's `label` value computed by a fixed rule (`exported ∧ ¬protected`) rather than by
human review or a detector pinpointing that exact component. Currently the only label source used
for real-world component rows; known to conflate "APK is malicious" with "this component is
malicious" (see `docs/PLAN_phase2.md` Task 9).
_Avoid_: rule label, auto label.

**Strong label**:
A component row's label produced when a specific detector (e.g.
`EXPORTED_UNPROTECTED_RECEIVER`) points at that exact component, or from human-reviewed ground
truth (the 30 toy APKs). Higher confidence than a weak label because it isn't inherited from a
broader scope.
_Avoid_: verified label, gold label (reserve "golden set" for a future human-reviewed
component-level benchmark, not yet built).

**Bag label** (not yet adopted — reference only):
MIL (Multiple Instance Learning) term for treating an APK's MalDroid category as a label over the
*bag* of its components, where only "at least one component is positive" can be inferred, not
"all components are positive." Proposed as a future fix for weak-label leakage (Task 9) but
explicitly deferred — not used by the current pipeline. Recorded here so the term isn't reinvented
under another name later.
_Avoid_: APK label pushed down to components (this is exactly the anti-pattern bag labels avoid).
