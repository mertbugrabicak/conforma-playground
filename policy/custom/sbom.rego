# METADATA
# title: Test Policy
# description: >-
#   Test description
# custom:
#   short_name: custom
package custom

import data.lib
import rego.v1
import data.lib.sbom

# METADATA
# title: CycloneDX 1.6 Detected
# description: Informational warning to confirm we are seeing a CycloneDX 1.6 SBOM.
# custom:
#   short_name: cdx_1_6_detected
#   failure_msg: SBOM is using CycloneDX spec version %s (This is a dummy custom policy)
warn contains result if {
    some sbom_doc in sbom.all_sboms
    
    # Check that it is CycloneDX
    sbom_doc.bomFormat == "CycloneDX"
    
    # Check the version
    version := sbom_doc.specVersion
    version == "1.6"

    # Return a warning result
    result := lib.result_helper(rego.metadata.chain(), [version])
}