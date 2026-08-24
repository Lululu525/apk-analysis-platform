---
status: accepted
---

# Record MalDroid category per component row, but don't use it as a label yet

New component rows from the dataset expansion get a weak label the same way the existing 68
samples do (`exported ∧ ¬protected`), even though each row could instead inherit its APK's
MalDroid category (Benign/Banking/SMS) as a training signal. We chose to **capture the MalDroid
category as a plain column, deliberately not wired into `label`**, rather than adopt it now.
Reason: pushing an APK-level category down to every component row is exactly the label-leakage
anti-pattern `docs/PLAN_phase2.md` Task 9 already flags — a malicious APK's benign components
would get mislabeled positive. The correct fix (MIL-style bag labeling, or detector-based strong
labels) is genuine Task 9 scope, deferred this round to keep the dataset-expansion work from
absorbing an unrelated architecture change. Recording the category now means Task 9 won't need to
re-run static analysis over these APKs just to get at it later.
