# conforma-playground
A place to test features available for Rego policies based on Conforma

## Prerequisites
- [Conforma CLI (`ec`)](https://github.com/conforma/cli) installed.

## Directory Structure
```text
.
├── input/
│   └── local-input.json   # The mock SBOM/Input data
├── policy/
│   └── main/              # Directory containing own Rego rules
├── policy.yaml            # The EC configuration file
└── README.md
```

## How to run

Run the below command:

```bash
ec validate input --file input/local-input.json --policy policy.yaml
```

## How to wrap attestion for own SBOM

Since the input for the release policies relies on a certain payload of attestations and such, this script helps convert the raw SBOM to an attestation within the payload required of the input.

```python
python3 wrap_sbom.py input/my-sbom.json -o input/my-sbom-input-payload.json
```
