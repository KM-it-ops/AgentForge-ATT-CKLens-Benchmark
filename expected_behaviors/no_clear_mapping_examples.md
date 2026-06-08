# No Clear Mapping Examples

The following examples illustrate inputs for which ATT&CKLens should refuse to assign a tactic or technique because the evidence is too weak or too ambiguous.

## Example 1 – Generic complaint

```
User reported that the system seemed slow yesterday.
```

Expected behaviour:

* `tactic` = `null`
* `technique_id` = `null`
* `confidence` = `low`
* `why_not` explains that performance issues may result from many benign causes and there is no specific indication of malicious activity.

## Example 2 – Vague network comment

```
There were some odd noises and blinking lights on the router.
```

Expected behaviour:

* `tactic` and `technique_id` remain `null`.
* `why_not` notes that physical symptoms of hardware issues do not map to ATT&CK techniques.

ATT&CKLens must be honest about its limitations.  It should encourage users to collect more detailed logs or evidence rather than guess.