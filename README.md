# ghostyara

**Clean YARA Rule Repository**  
Reverse-engineered rules for tracking, analyzing, and attributing malware samples.  
**Focus:** Precision, portability, and low false positives.  
[Rules Index](./index.md)

---

## Key Features

- Reverse-engineered YARA rules for real-world malware families
- Structured by malware family, packers, and behavioral TTPs
- Cross-linked with IOC & technique mappings in [`sigtrack`](https://github.com/Sab0x1D/sigtrack)
- Optimized to reduce false positives, with clear metadata and MITRE tagging

---

## Folder Structure

| Folder              | Description                                           |
|---------------------|-------------------------------------------------------|
| `families/`         | Rules for specific malware families (e.g., AgentTesla)|
| `packers/`          | Rules for identifying common packers and crypters     |
| `ttps/`             | Behavior-based rules (mapped to MITRE ATT&CK TTPs)    |
| `utils/`            | Templates, helpers, and other utilities               |

> Samples and IOC mappings are documented in: [`sigtrack`](https://github.com/Sab0x1D/sigtrack)

---

## Use Cases

- Malware reverse engineering and family attribution  
- Threat intel enrichment (APT tools, stealers, loaders)  
- Purple team simulation and EDR rule validation  
- Static and dynamic sandbox hunting  

---

## Contributing

This is a personal research repository.  
External PRs are welcome if:
- They are tied to real-world malware
- Include references or evidence
- Maintain precision and context via metadata

[Rules Index](./index.md)
