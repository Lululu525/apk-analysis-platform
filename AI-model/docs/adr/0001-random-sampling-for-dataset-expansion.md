---
status: accepted
---

# Random sampling (not stratified) for the MalDroid-2020 dataset expansion

We need ~1,795 Benign and ~1,795 Malware (Banking+SMS) component rows out of the 4,039/2,308/1,019
APKs available locally from CIC MalDroid-2020. We chose **random sampling, excluding sha256s
already used in `dataset/labels/ground_truth_with_split.csv`**, over stratifying by MalDroid's
official category/family metadata (available in the 595MB `feature_vectors_static.csv`). Reason:
stratified sampling requires parsing that CSV and designing a family-balance target first — real
work that would stall this round's goal of simply getting the corpus size up. Family
representativeness can be revisited once results from this larger-but-unstratified set are in.
