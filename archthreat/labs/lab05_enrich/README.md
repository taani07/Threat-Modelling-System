# Lab 05: Never trust the model's output

## Goal

Implement `jaccard`, `is_duplicate` and `clean_references`. Then read `enrich()` in
`src/archthreat/enrich.py` to see all the checks applied to LLM-proposed threats.

- `jaccard(a, b)`: |A ∩ B| / |A ∪ B| over the sets of `tokenize()`d words; 0.0 if either is empty.
- `is_duplicate(candidate, existing, threshold=0.5)`: true if any existing threat has the same
  element and STRIDE category and a title Jaccard similarity >= threshold.
- `clean_references(refs)`: strip and upper-case each ref; keep only matches of `REFERENCE_RE`
  (`CWE-n`, `CAPEC-n`, `LLM01`..`LLM10`); drop repeats; return `(kept, dropped_count)`.

## Why it matters

LLMs are good at brainstorming context-specific threats and bad at not repeating themselves,
staying inside the categories that make sense, and citing real identifiers. The pattern in
`enrich()` generalises to any LLM feature: **let the model propose, and let code decide what
to accept.** In interviews, describe it as "the model is an untrusted component".

Jaccard is crude (it misses synonyms), and that's fine for a first pass. The stretch is to
replace it with embedding similarity from `archthreat.rag` and measure the duplicate rate
before and after with `archthreat eval --llm`.

## Python you will learn

- Set operators `&` and `|`; `len()` of a set.
- `any(...)` with a multi-line generator condition.
- Returning a tuple and unpacking it: `kept, dropped = clean_references(refs)`.
