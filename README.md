# pySigma Google SecOps (Chronicle) Backend

This is the Google SecOps (formerly Chronicle) backend for pySigma. It provides the package `sigma.backends.secops` with the `SecOpsBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.secops`:

* secops_udm_pipeline: Converts Sigma rules into Google SecOps UDM (Unified Data Model) compatible format.

This backend is currently in development and not yet complete.

It supports the following output formats:

* default: Plain Google SecOps queries
* yara: YARA-L v2.0 output format ( In progress )

## Usage

The usage of this backend is similar to other pySigma backends:

```python
from sigma.rule import SigmaRule
from sigma.backends.secops import SecOpsBackend
from sigma.pipelines.secops import secops_udm_pipeline

backend = SecOpsBackend()

# Convert a Sigma rule to a Google SecOps query
query = backend.convert_sigma_rule(sigma_rule)

# Create a Google SecOps backend instance
secops_backend = SecOpsBackend(processing_pipeline=secops_udm_pipeline)

# Load Sigma rules
sigma_rules = SigmaRule.from_yaml("path/to/sigma_rule.yml")

# Convert Sigma rules to Google SecOps queries
secops_queries = secops_backend.convert_rule(sigma_rules)

# Print the resulting queries
for query in secops_queries:
    print(query)
```

## Installation

This package is currently in development and not yet available on PyPI.

## Development Status

This backend is currently under development. The following features are planned or in progress:

* [X] Customize backend to use regex for contains, startswith, endswith, etc.
* [X] Implement `nocase` for case insensitive matching in backend
* [ ] Imply rule `event_type` using more robust category, service, product matching, and from EventID/EventCodes to determine appropriate field mappings
* [ ] Pipeline testing
* [X] Backend testing
* [ ] Confirm current field mapping and add more mappings for rule coverage
* [ ] Add YARA-L v2.0 output format/converter in backend

## Contributing

Contributions to this backend are welcome. Please ensure your contributions align with the overall design of pySigma.

## License

This project is licensed under the MIT license.