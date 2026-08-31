<!-- VIBETAGS-START -->
# Rules for BlindBeanTest

## Public API Surface Protection
- **Rule**: Exposes public API. Preserve signature, Javadoc, and behavior without breaking backwards or source compatibility.
- **Reason**: Attribute names (scheme, polyModulusDegree, ckksScale) and their defaults are written into consumer test classes; renaming or removing one silently changes which context those suites boot
<!-- VIBETAGS-END -->
