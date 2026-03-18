Conforma SBOM Policy Validator
==================================

This script is a specialized wrapper for **Conforma (Enterprise Contract)**. It automates the process of checking multiple Software Bill of Materials (SBOM) files against your organization's security and compliance policies.

**What this script does**
-------------------------

Checking SBOMs manually against Conforma policies can be tedious. This script simplifies the workflow into a single command:

1.  **Scans Folders:** Recursively finds every .json SBOM file in a directory.
    
2.  **Auto-Formats:** Automatically wraps raw SBOMs into the "In-Toto Statement" format that Conforma requires.
    
3.  **Validates:** Runs your **SBOM-specific policies** (CycloneDX or SPDX) against each file.
    
4.  **Generates Reports:** Creates a single, interactive **HTML Dashboard** that shows:
    
    *   Which files passed or failed.
        
    *   The specific **Rego policy code** that triggered a violation.
        
    *   A **code snippet** from the SBOM showing exactly where the error is.
        

**How to Use**
--------------

If your SBOMs are in a folder called incoming_sboms and your Conforma rules are in sbom-policy.yaml:

```bash
python3 scan_sboms.py ./sboms --policy policy.yaml --output my_audit_results.html
```

**Viewing Results**
-------------------

Once the script finishes, open the generated report.html in any web browser.

*   **Searchable:** Use the search bar to filter by filename or specific error messages.
    
*   **Evidence-Based:** Click on any "Violation" to see the exact JSON path and data that caused the policy to fail.
    
*   **Policy Overview:** The report embeds your policy.yaml content so you can verify which rules were applied during the scan.