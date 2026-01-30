# conforma-playground
A place to test Conforma release policies on example OCI artifacts that contain Provenance, VSA, SBOMs and Signatures.

## Prerequisites
- [Conforma CLI (`ec`)](https://github.com/conforma/cli) patched with a workaround for bypassing some parts is necessary for this experiment.

Here is how to build the binary for it:
```bash
git clone https://github.com/mertbugrabicak/cli.git -b debug/bypass-schema
cd cli
make build
# use the executable that gets created in ./dist/ec
```

## Directory Structure
```text
.
├── policy/
│   └── custom/              # Directory containing own custom Rego rules
├── policy.yaml            # The EC configuration file
└── README.md
```

## How to run

Run the below command:

```bash
ec_patched validate image \
  --image <oci-artifact-from-quay> \
  --public-key key.pub \
  --policy policy-general.yaml \
  --ignore-rekor \
  --output yaml
```
