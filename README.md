# pySigma Google SecOps (Chronicle) Backend (Alpha)

![Tests](https://github.com/AttackIQ/pySigma-backend-secops/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/slincoln-aiq/f9db5eaebc0a30cde8045bea889df922/raw/slincoln-aiq-pySigma-backend-secops.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)
![PyPI version](https://badge.fury.io/py/pysigma-backend-secops.svg)
![Python versions](https://img.shields.io/pypi/pyversions/pysigma-backend-secops.svg)
![pySigma version](https://img.shields.io/badge/pySigma-%3E%3D0.11.0-blue)
![License](https://img.shields.io/github/license/AttackIQ/pySigma-backend-secops.svg)

## Contents

- [pySigma Google SecOps (Chronicle) Backend (Alpha)](#pysigma-google-secops-chronicle-backend-alpha)
  - [📖 Overview](#-overview)
  - [🚀 Quick Start](#-quick-start)
  - [🛠️ Advanced Features](#️-advanced-features)
  - [Development Status](#development-status)
  - [🚀 Latest Features](#-latest-features)
  - [🔧 Processing Pipelines](#-processing-pipelines)
  - [📤 Output Formats](#-output-formats)
  - [🗺️ Field Mappings](#️-field-mappings)
  - [🤝 Contributing](#-contributing)
  - [📄 License](#-license)


## 📖 Overview

The **pySigma SecOps Backend** transforms Sigma Rules into UDM queries and YARA-L 2.0 for Google SecOps, formally Chronicle.

### 🔑 Key Features

- **Backend**: `sigma.backends.secops` with `SecOpsBackend` class
- **Pipelines**: Provides `secops_udm_pipeline` for query tables and field renames
- **Output**: Query strings in Google SecOps UDM (Unified Data Model) format and YARA-L 2.0 Detection Rules format
- 
**This backend is currently in development and not yet complete.**

### 🧑‍💻 Maintainer

- [Stephen Lincoln](https://github.com/slincoln-aiq) via [AttackIQ](https://github.com/AttackIQ)

## 🚀 Quick Start

1. Install the package:

   ```bash
   pip install pysigma-backend-secops
   ```

   > **Note:** This package requires `pySigma` version 0.11.17 or higher.

2. Convert a Sigma rule to Google SecOps UDM query using sigma-cli:

   ```bash
   sigma convert -t secops -p secops_udm path/to/your/rule.yml
   ```

3. Or use in a Python script:

   ```python
   from sigma.rule import SigmaRule

   from sigma.backends.secops import SecOpsBackend
   from sigma.pipelines.secops import secops_udm_pipeline

   # Load your Sigma rule
   rule = SigmaRule.from_yaml(
      """
      title: Mimikatz CommandLine
      status: test
      logsource:
            category: process_creation
            product: windows
      detection:
            sel:
               CommandLine|contains: mimikatz.exe
            condition: sel
      """
   )

   # Convert the rule
   udm_pipeline = secops_udm_pipeline()
   backend = SecOpsBackend(processing_pipeline=udm_pipeline)
   print(backend.convert_rule(rule)[0])

   ```

### 🖥️ sigma-cli

Use with `sigma-cli` per [typical sigma-cli usage](https://github.com/SigmaHQ/sigma-cli#usage):

```bash
sigma convert -t secops -p secops_udm -f default -s ~/sigma/rules
```

### 🐍 Python Script

Use the backend and pipeline in a standalone Python script. Note, the backend automatically applies the pipeline, but
you can manually add it if you would like.

```python
from sigma.rule import SigmaRule
from sigma.backends.secops import SecOpsBackend
from sigma.pipelines.secops import secops_udm_pipeline

# Define an example rule as a YAML str
sigma_rule = SigmaRule.from_yaml("""
  title: Mimikatz CommandLine
  status: test
  logsource:
      category: process_creation
      product: windows
  detection:
      sel:
          CommandLine|contains: mimikatz.exe
      condition: sel
""")
# Create backend, which automatically adds the pipeline
secops_backend = SecOpsBackend()

# Or apply the pipeline manually
pipeline = secops_udm_pipeline()
pipeline.apply(sigma_rule)

# Convert the rule
print(sigma_rule.title + " UDM Query: \n")
print(secops_backend.convert_rule(sigma_rule)[0])

# Or convert to YARA-L 2.0
print(sigma_rule.title + " YARA-L 2.0 Query: \n")
print(secops_backend.convert_rule(sigma_rule, output_format="yara_l")[0])
```

Output:

```text
Mimikatz CommandLine UDM Query:

(metadata.event_type = "PROCESS_LAUNCH") AND (target.process.command_line = /.*mimikatz.exe.*/ nocase)

Mimikatz CommandLine YARA-L 2.0 Query:

rule mimikatz_commandline {
  meta:
    id = "None"
    title = "Mimikatz CommandLine"
    description = "None"
    author = "None"
    reference = ""
    date = "None"
    tags = ""
    severity = "None"
    falsepositives = "Unknown" 

  events:
    $event1.metadata.event_type = "PROCESS_LAUNCH"
    $event1.target.process.command_line = /.*mimikatz.exe.*/ nocase
    
  conditions: 
    $event1
}
```

## 🛠️ Advanced Features

### 🔄 Pipeline Args

- `prepend_metadata`: Prepends `(metadata.event_type = <event_type>) AND` to the query
    - Defaults to `True`
    - When `True` will prepend `(metadata.event_type = <event_type>) AND` to the query
    - When False, the `metadata.event_type` field/values will be excluded from the query

### Event Type and Field Mapping Determination (New in 0.2.0)

- Improved event type determination logic in `determine_event_type` function
- Now considers logsource category, product, and service values to determine the event type
- If no event type can be determined via logsource, the EventID field (if present in a selection) will be used to determine the event type
- Field mappings are determined based on the event type discovered for the rule.
- Common field mappings are applied automatically after event type mappings

## Development Status

This backend is currently under development. The following features are planned or in progress:

* [X] Customize backend to use regex for contains, startswith, endswith, etc.
* [X] Implement `nocase` for case insensitive matching in backend
* [X] Imply rule `event_type` using more robust category, service, product matching, and from EventID/EventCodes to determine appropriate field mappings
* [X] Pipeline testing
* [X] Backend testing
* [X] Confirm current field mapping and add more mappings for rule coverage
* [X] Add YARA-L v2.0 output format/converter in backend
* [ ] Add more robust field mapping logic
* [ ] Add $selection and $filter variables to YARA-L condition, and break out events into multiple lines based on $selection and $filter detection items for better readability

## 🚀 Latest Features

### Event Type Determination (New in v0.0.3)
- Improved event type determination logic in `determine_event_type` function
- Now considers both category and specific fields in the rule to accurately set the event type
- Supports various event types including process, network, file, authentication, and registry events

### Field Mapping Enhancements
- Introduced new field mappings for different event types
- Added separate mapping functions for common, process, network, file, authentication, and registry fields
- Improved flexibility and accuracy in field translations

### UDM Schema Validation
- Implemented `is_valid_udm_field` function to validate fields against the UDM schema
- Ensures that all mapped fields conform to the Universal Data Model (UDM) standard

### Pipeline Simplification
- Removed unnecessary transformations and postprocessing items
- Streamlined the pipeline to focus on core functionality

### Improved Error Handling
- Added `InvalidUDMFieldError` for better error reporting when encountering invalid UDM fields

### Code Optimization
- Refactored and optimized various utility functions
- Improved overall code structure and readability

### Testing Improvements
- Updated and expanded test cases to cover new functionality
- Enhanced test coverage for field mappings and UDM validation

These new features and improvements enhance the backend's ability to accurately convert Sigma rules to UDM-compliant queries, with better event type determination and more precise field mappings.

## 🔧 Processing Pipelines

The backend provides the following processing pipeline in `sigma.pipelines.secops`:

* `secops_udm_pipeline`: Converts Sigma rules into Google SecOps UDM (Unified Data Model) compatible format.

This pipeline performs the following transformations:

1. Determines the appropriate event type based on rule categories and fields
2. Maps Sigma field names to their UDM equivalents
3. Validates mapped fields against the UDM schema
4. Applies necessary transformations for UDM compatibility
5. Prepends `(metadata.event_type = <event_type>) AND` to the query if `prepend_metadata` is `True`

## 📤 Output Formats

The SecOps backend supports the following output formats:

* `default`: Plain Google SecOps UDM queries
* `yara`: YARA-L v2.0 output format (In Beta)

## 🗺️ Field Mappings

The backend includes comprehensive field mappings for various event types:

* Common fields (applicable to all event types, includes grouped fields)
* Process event fields
* Network event fields
* File event fields
* Authentication event fields
* Registry event fields
* DNS event fields
* Authentication event fields

These mappings ensure that Sigma rule fields are correctly translated to their UDM counterparts.

## 🤝 Contributing

Contributions to this backend are welcome. Please ensure your contributions align with the overall design of pySigma. Here are some ways you can contribute:

* Adding support for new event types
* Expanding field mappings
* Improving UDM schema validation
* Enhancing the YARA-L output format
* Writing additional tests

## 📄 License

This project is licensed under the LGPLv3 license.
