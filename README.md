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
