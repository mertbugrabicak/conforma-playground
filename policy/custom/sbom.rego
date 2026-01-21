# METADATA
# title: Test Policy
# description: >-
#   Test description
package custom

import data.lib
import rego.v1

# METADATA
# title: No Log4j Allowed
# description: Check if the SBOM contains the restricted package 'log4j'
# custom:
#   short_name: no_log4j_allowed
#   failure_msg: Found restricted package '%s'
deny contains result if {
    # 1. Iterate over all attestations in the input
    some att in input.attestations
    
    # 2. Iterate over COMPONENTS (CycloneDX uses 'components', SPDX uses 'packages')
    # CHANGED THIS LINE:
    some comp in att.statement.predicate.components
    
    # 3. The Condition: Match the banned package name
    # Note: In your input example, the name is "log4j-core". 
    # Exact match "log4j" might fail, so checking if it contains the string is often safer.
    contains(comp.name, "log4j")

    # 4. Construct the Result
    result := object.union(
        lib.result_helper(rego.metadata.chain(), [comp.name]),
        {"foo": "bar"},
    )
}