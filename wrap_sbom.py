import json
import argparse
import sys
import hashlib

# Constants for Predicate Types
TYPE_CYCLONEDX = "https://cyclonedx.org/bom"
TYPE_SPDX = "https://spdx.dev/Document" # Matches the strict expectation of ec-policies

# Dummy Digest (Zeroes)
DUMMY_SHA = "0" * 64
DUMMY_REF = f"localhost/my-app@{DUMMY_SHA}"

def detect_sbom_type(sbom_content):
    """
    Analyzes the JSON to determine if it is SPDX or CycloneDX.
    """
    if "bomFormat" in sbom_content and sbom_content["bomFormat"] == "CycloneDX":
        return TYPE_CYCLONEDX
    if "spdxVersion" in sbom_content:
        return TYPE_SPDX
    return None

def create_mock_input(sbom_data, predicate_type):
    """
    Wraps the SBOM data into the Enterprise Contract input structure.
    """
    return {
        "attestations": [
            {
                "statement": {
                    "_type": "https://in-toto.io/Statement/v0.1",
                    "predicateType": predicate_type,
                    "subject": [
                        {
                            "name": "my-local-image",
                            "digest": {
                                "sha256": DUMMY_SHA
                            }
                        }
                    ],
                    "predicate": sbom_data
                }
            }
        ],
        "image": {
            "ref": DUMMY_REF,
            "config": {
                "Labels": {
                    "maintainer": "local-test",
                    "description": "Mock image for EC policy testing"
                }
            }
        }
    }

def main():
    parser = argparse.ArgumentParser(description="Wrap a raw SBOM file into an EC input.json format.")
    parser.add_argument("sbom_file", help="Path to the raw SBOM JSON file (SPDX or CycloneDX)")
    parser.add_argument("-o", "--output", default="local-input.json", help="Output file path (default: local-input.json)")
    
    args = parser.parse_args()

    try:
        # 1. Read the raw SBOM
        with open(args.sbom_file, 'r') as f:
            sbom_data = json.load(f)

        # 2. Detect Type
        pred_type = detect_sbom_type(sbom_data)
        if not pred_type:
            print("Error: Could not detect SBOM format. File must contain 'bomFormat': 'CycloneDX' or 'spdxVersion'.")
            sys.exit(1)
        
        print(f"Detected SBOM Type: {pred_type}")

        # 3. Wrap it
        wrapped_data = create_mock_input(sbom_data, pred_type)

        # 4. Write to file
        with open(args.output, 'w') as f:
            json.dump(wrapped_data, f, indent=2)
        
        print(f"Successfully created '{args.output}'")

    except FileNotFoundError:
        print(f"Error: File '{args.sbom_file}' not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: File '{args.sbom_file}' is not valid JSON.")
        sys.exit(1)

if __name__ == "__main__":
    main()