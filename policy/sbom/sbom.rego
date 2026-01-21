# METADATA
# title: Test Policy
# description: >-
#   Test description
package sbom

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
    
    # 2. Iterate over packages (Assumes SPDX format based on 'predicate.packages')
    # If using CycloneDX, this path might be 'predicate.components'
    some pkg in att.statement.predicate.packages
    
    # 3. The Condition: Match the banned package name
    pkg.name == "log4j"

    # 4. Construct the Result using the EC library helper
    # We pass [pkg.name] as the argument to fill the '%s' in failure_msg
    result := object.union(
        lib.result_helper(rego.metadata.chain(), [pkg.name]),
        {"foo": "bar"},
    )
}