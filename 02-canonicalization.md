# PromptSign Spec 02 — Canonicalization

Digests over instruction Markdown are computed on a **canonical form** so that
line-ending churn (git `autocrlf`), BOMs, editor trailing-newline differences,
and Unicode encoding variants do not break signatures — while content-visible
changes always do.

Applies to files matching `*.md` / `*.markdown` with role `entrypoint` or
`reference`. Files with role `executable`, and all non-Markdown files, are
hashed as **raw bytes** (you never normalize code you will run).

## Canonical form (in order)

1. Decode as **strict UTF-8**; invalid byte sequences are a hard error.
2. Strip a leading BOM (U+FEFF).
3. Normalize line endings: `CRLF | CR → LF`.
4. Unicode-normalize to **NFC**.
5. Excise the single-line `x-promptsign:` scalar from YAML frontmatter, if
   present (embedded-signature carriage must not sign itself). Only the marker
   line is removed — the `---` fences are never added or removed here, so
   embedding requires pre-existing frontmatter (see Spec 03). Verifiers MUST
   strictly validate whatever occupies this excised region (single line,
   canonical base64, well-formed bundle) per Spec 03, since it is excluded from
   the signature yet still read by any agent that loads the file.
6. Strip trailing spaces/tabs from every line.
7. Strip trailing blank lines; the canonical form ends with exactly one `\n`.

The digest is SHA-256 over the UTF-8 encoding of the result.

## Rejected content

Canonicalization refuses (hard error, cannot be signed or verified) content
carrying the standard invisible-injection vectors:

| Characters | Where rejected | Why |
|---|---|---|
| Tags block U+E0000–U+E007F | everywhere | invisible ASCII-mirroring instruction smuggling |
| Bidi controls U+202A–U+202E, U+2066–U+2069, U+200E, U+200F, U+061C | everywhere | Trojan-Source reordering |
| Zero-width U+200B, U+2060, interior U+FEFF | outside code fences | invisible content |
| ZWNJ/ZWJ U+200C, U+200D | only between two ASCII characters | legitimate in Persian/Arabic text and emoji sequences; pure smuggling in ASCII context |

Code fences are lines beginning with ``` or `~~~` (toggle). This is the only
content opinion PromptSign holds: not "is it malicious" but "is it honest about
what it visibly says."
