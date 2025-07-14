# ghostyara/utils

Utility scripts, templates, and helper resources for building and maintaining high-quality YARA rules within the [GhostYARA](https://github.com/Sab0x1D/ghostyara) and [Sigtrack](https://github.com/Sab0x1D/sigtrack) repositories.

---

## Contents

### Templates
Reusable scaffolds to ensure consistent rule authoring:
- `*_basic.yar` — Static YARA rule template
- `*_behavior.yar` — Behavioral YARA rule template
- `*.md` — Sigtrack markdown template for YARA pattern notes
- One-liner index snippet templates:
  - GhostYARA index (inline table row)
  - Sigtrack coverage index (GitHub table row)

### Planned Helper Scripts
Coming soon — utilities to automate and accelerate your rule-writing workflow:
- **Template Generator**: Pre-fills rule + markdown templates for new families
- **Metadata Filler**: Adds missing meta fields like author, date, score, etc.
- **Rule Linter**: Validates formatting, required tags, and consistency
- **Index Generator**: Outputs ready-to-paste index lines for both GhostYARA and Sigtrack

---

## Usage

1. Copy any relevant template from this folder when starting a new family.  
2. Replace placeholders (e.g. `NAME`, `TXXXX`, strings) with actual indicators.  
3. Store static rules in `/families/`, behavioral rules in `/ttps/`, and notes in `/sigtrack/yara_map/`.  
4. Use the matching index snippet to update the two index files in each repo.  

---

## Naming Conventions

- Use `snake_case` file names: `examplefamily_basic.yar`, `examplefamily_behavior.yar`  
- Rule names follow: `examplefamily_basic`, `examplefamily_behavior`  
- Sigtrack markdown files: `examplefamily_yara_patterns.md`  

---

Stay consistent, stay fast — and keep the rules clean.
