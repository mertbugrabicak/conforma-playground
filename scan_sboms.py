#!/usr/bin/env python3
import json
import argparse
import sys
import os
import subprocess
import tempfile
import re
from datetime import datetime

# --- 1. Helper: Traverse JSON by dot notation ---
def get_json_value_by_path(data, path_str):
    keys = path_str.split('.')
    current = data
    try:
        for key in keys:
            if isinstance(current, list):
                index = int(key)
                current = current[index]
            else:
                current = current[key]
        return current
    except (KeyError, IndexError, ValueError, TypeError):
        return None

def extract_path_from_msg(msg):
    # Regex looks for pattern: "is not valid: <path>: <reason>"
    match = re.search(r"is not valid:\s+([a-zA-Z0-9_\.]+):\s", msg)
    if match:
        return match.group(1)
    return None

# --- 2. The Wrapper Logic ---
def create_ec_input(sbom_data):
    try:
        # Determine SBOM Type
        predicate_type = None
        if sbom_data.get("bomFormat") == "CycloneDX":
            predicate_type = "https://cyclonedx.org/bom"
        elif "spdxVersion" in sbom_data:
            predicate_type = "https://spdx.dev/Document"
        
        if not predicate_type:
            return None

        # Construct In-Toto Statement
        statement = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": predicate_type,
            "subject": [{
                "name": "manual-policy-check",
                "digest": {"sha256": "0000000000000000000000000000000000000000000000000000000000000000"}
            }],
            "predicate": sbom_data
        }
        return {"attestations": [{"statement": statement}]}
    except Exception:
        return None

# --- 3. The Runner Logic ---
def run_ec_validate(wrapper_data, policy_path):
    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json') as temp_input:
        json.dump(wrapper_data, temp_input)
        temp_input_path = temp_input.name

    try:
        cmd = [
            "ec", "validate", "input",
            "--file", temp_input_path,
            "--policy", policy_path,
            "--output", "json"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        output_str = result.stdout.strip()
        if not output_str:
            return {"error": "No output from EC", "stderr": result.stderr}

        try:
            return json.loads(output_str)
        except json.JSONDecodeError:
            return {"error": "Invalid JSON from EC", "raw_output": output_str}
    finally:
        if os.path.exists(temp_input_path):
            os.remove(temp_input_path)

# --- 4. HTML Generator with Smart Search ---
def generate_html_report(results, output_file, policy_path):
    
    try:
        with open(policy_path, 'r') as f:
            policy_content = f.read()
    except Exception:
        policy_content = "# Could not read policy file content."

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>EC Policy Validation Report</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }}
            .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
            h1 {{ color: #2c3e50; border-bottom: 2px solid #eee; padding-bottom: 10px; }}
            h2 {{ font-size: 1.2em; margin-top: 20px; margin-bottom: 10px; color: #34495e; }}
            
            .info-box {{ background-color: #e8f4fd; border-left: 4px solid #3498db; padding: 15px; margin-bottom: 20px; border-radius: 4px; }}
            .info-box p {{ margin: 0 0 10px 0; line-height: 1.5; }}
            
            pre {{ background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; font-size: 0.9em; margin: 0; }}
            
            /* Search Bar */
            .search-box {{ margin-bottom: 20px; }}
            #searchInput {{ width: 100%; padding: 12px; font-size: 16px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }}
            
            .summary {{ display: flex; gap: 20px; margin-bottom: 20px; }}
            .card {{ padding: 15px; border-radius: 5px; flex: 1; text-align: center; color: white; font-weight: bold; }}
            .bg-green {{ background-color: #28a745; }}
            .bg-red {{ background-color: #dc3545; }}
            .bg-gray {{ background-color: #6c757d; }}
            
            details {{ margin-bottom: 10px; border: 1px solid #ddd; border-radius: 4px; overflow: hidden; background: white; }}
            summary {{ padding: 12px; cursor: pointer; background-color: #eee; font-weight: bold; list-style: none; display: flex; align-items: center; justify-content: space-between; }}
            summary::-webkit-details-marker {{ display: none; }}
            summary:hover {{ background-color: #e2e2e2; }}
            
            .status-badge {{ padding: 4px 8px; border-radius: 4px; font-size: 0.85em; color: white; }}
            .content {{ padding: 15px; background: #fff; border-top: 1px solid #ddd; }}
            
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.9em; }}
            th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #eee; vertical-align: top; }}
            th {{ background-color: #f8f9fa; }}
            
            .violation-row {{ color: #d9534f; }}
            .warning-row {{ color: #f0ad4e; }}
            .meta {{ font-size: 0.85em; color: #666; font-family: monospace; min-width: 150px; }}
            
            .snippet-box {{ margin-top: 5px; background: #f8f8f8; border-left: 3px solid #d9534f; padding: 8px; font-family: monospace; font-size: 0.85em; color: #333; white-space: pre-wrap; overflow-x: auto; }}
            .path-label {{ font-weight: bold; color: #555; display: block; margin-bottom: 2px; }}
        </style>
        
        <script>
            function filterReports() {{
                var input = document.getElementById("searchInput");
                var filter = input.value.toUpperCase();
                var details = document.getElementsByTagName("details");
                
                // If filter is empty, just reset everything to closed (or previous state) and show all rows
                if (filter === "") {{
                    for (var i = 0; i < details.length; i++) {{
                        details[i].style.display = ""; // Show file
                        // Reset rows
                        var rows = details[i].getElementsByTagName("tr");
                        for (var j = 0; j < rows.length; j++) {{
                            rows[j].style.display = ""; 
                        }}
                    }}
                    return;
                }}

                // Iterate over all SBOM files
                for (var i = 0; i < details.length; i++) {{
                    var detail = details[i];
                    var summary = detail.getElementsByTagName("summary")[0];
                    var fileText = summary.textContent || summary.innerText;
                    var isFileMatch = fileText.toUpperCase().indexOf(filter) > -1;
                    
                    var rows = detail.getElementsByTagName("tr");
                    var hasVisibleRow = false;

                    // Iterate over all rows (Violations/Warnings) inside this file
                    for (var j = 0; j < rows.length; j++) {{
                        var row = rows[j];
                        
                        // Always keep header rows visible
                        if (row.getElementsByTagName("th").length > 0) {{
                            row.style.display = "";
                            continue;
                        }}

                        var rowText = row.textContent || row.innerText;
                        var isRowMatch = rowText.toUpperCase().indexOf(filter) > -1;

                        // Logic: 
                        // 1. If filename matches, show all rows (so you can browse the file)
                        // 2. If row matches, show row
                        // 3. Otherwise, hide row
                        if (isFileMatch || isRowMatch) {{
                            row.style.display = "";
                            hasVisibleRow = true;
                        }} else {{
                            row.style.display = "none";
                        }}
                    }}

                    // Parent Visibility:
                    // Show file block if filename matched OR if we found a matching error inside
                    if (isFileMatch || hasVisibleRow) {{
                        detail.style.display = "";
                        
                        // AUTO-EXPAND: If we found a specific error match (and not just a filename match), open the details
                        if (!isFileMatch && hasVisibleRow) {{
                            detail.open = true;
                        }}
                    }} else {{
                        detail.style.display = "none";
                    }}
                }}
            }}
        </script>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Enterprise Contract Policy Report</h1>
            <p>Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            
            <div class="info-box">
                <h2>Configuration & Scope</h2>
                <p>
                    This report details the validation results of Software Bill of Materials (SBOM) files provided by the SBOMer team. 
                    The assessment was performed using <strong>Conforma (EC)</strong>, scoped specifically to 
                    run <strong>SBOM-related policies</strong>.
                </p>
                <details>
                    <summary style="background:none; padding:0; color:#0056b3; text-decoration:underline;">View Policy Configuration YAML</summary>
                    <div style="margin-top:10px;">
                        <pre>{policy_content}</pre>
                    </div>
                </details>
            </div>

            <div class="summary">
                <div class="card bg-gray">Total Files: {len(results)}</div>
                <div class="card bg-green">Passed: {len([r for r in results if r['success']])}</div>
                <div class="card bg-red">Failed: {len([r for r in results if not r['success']])}</div>
            </div>

            <div class="search-box">
                <input type="text" id="searchInput" onkeyup="filterReports()" placeholder="🔍 Filter by filename, error message, or JSON path...">
            </div>
    """

    for res in results:
        file_path = res['file']
        success = res['success']
        ec_data = res['data']
        sbom_data = res.get('raw_sbom', {})
        
        status_color = "bg-green" if success else "bg-red"
        status_text = "PASS" if success else "FAIL"
        
        violations = []
        warnings = []
        
        if 'filepaths' in ec_data and isinstance(ec_data['filepaths'], list):
            for item in ec_data['filepaths']:
                violations.extend(item.get('violations', []))
                warnings.extend(item.get('warnings', []))
        
        violation_count = len(violations)
        warning_count = len(warnings)

        html_content += f"""
        <details>
            <summary>
                <span>{file_path}</span>
                <span>
                    <span class="status-badge {status_color}">{status_text}</span>
                    <span style="font-size:0.8em; color:#555; margin-left:10px;">
                        (Errors: {violation_count}, Warnings: {warning_count})
                    </span>
                </span>
            </summary>
            <div class="content">
        """

        if violations:
            html_content += "<h3>🚫 Violations</h3><table><tr><th>Message & Evidence</th><th>Code</th></tr>"
            for v in violations:
                msg = v.get('msg', 'N/A')
                code = v.get('metadata', {}).get('code', 'N/A')
                
                path = extract_path_from_msg(msg)
                snippet_html = ""
                if path and sbom_data:
                    found_value = get_json_value_by_path(sbom_data, path)
                    if found_value is not None:
                        if isinstance(found_value, (dict, list)):
                            val_str = json.dumps(found_value, indent=2)
                        else:
                            val_str = str(found_value)
                        snippet_html = f'<div class="snippet-box"><span class="path-label">Path: {path}</span>{val_str}</div>'

                html_content += f"<tr class='violation-row'><td>{msg}{snippet_html}</td><td class='meta'>{code}</td></tr>"
            html_content += "</table>"

        if warnings:
            html_content += "<h3>⚠️ Warnings</h3><table><tr><th>Message</th><th>Code</th></tr>"
            for w in warnings:
                msg = w.get('msg', 'N/A')
                code = w.get('metadata', {}).get('code', 'N/A')
                html_content += f"<tr class='warning-row'><td>{msg}</td><td class='meta'>{code}</td></tr>"
            html_content += "</table>"
            
        if not violations and not warnings and success:
             html_content += "<p style='color:green'>✅ All checks passed successfully.</p>"
        
        if 'error' in ec_data:
             html_content += f"<p style='color:red'><strong>System Error:</strong> {ec_data.get('error')}</p>"

        html_content += """
            </div>
        </details>
        """

    html_content += """
        </div>
    </body>
    </html>
    """

    with open(output_file, 'w') as f:
        f.write(html_content)
    print(f"\n✨ HTML Report generated at: {output_file}")

# --- 5. Main Execution ---
def main():
    parser = argparse.ArgumentParser(description="Wrap SBOMs, run EC policies, and generate HTML.")
    parser.add_argument("input_dir", help="Root directory containing SBOM JSON files")
    parser.add_argument("--policy", required=True, help="Path to policy.yaml")
    parser.add_argument("--output", default="ec_report.html", help="Path to output HTML report")
    
    args = parser.parse_args()

    results = []
    print(f"📂 Scanning directory: {args.input_dir}")
    print(f"📜 Using policy: {args.policy}\n")

    for root, dirs, files in os.walk(args.input_dir):
        for file in files:
            if file.endswith(".json"):
                full_path = os.path.join(root, file)
                try:
                    with open(full_path, 'r') as f:
                        raw_sbom = json.load(f)
                except Exception as e:
                    print(f"   ❌ Read Error: {full_path} - {e}")
                    continue

                wrapped_data = create_ec_input(raw_sbom)
                if not wrapped_data:
                    continue
                
                print(f"🔍 Processing: {full_path}")
                ec_result = run_ec_validate(wrapped_data, args.policy)
                
                results.append({
                    "file": full_path,
                    "success": ec_result.get('success', False),
                    "data": ec_result,
                    "raw_sbom": raw_sbom
                })

    if results:
        # Pass the policy path to the report generator
        generate_html_report(results, args.output, args.policy)
    else:
        print("⚠️ No valid SBOM files found to process.")

if __name__ == "__main__":
    main()