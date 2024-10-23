import json
import re

import requests
from bs4 import BeautifulSoup


def add_grouped_fields() -> dict:
    """Returns dictionary of grouped fields and the fields that are in each group"""
    return {
        "domain": [
            "about.administrative_domain",
            "about.asset.network_domain",
            "network.dns.questions.name",
            "network.dns_domain",
            "principal.administrative_domain",
            "principal.asset.network_domain",
            "target.administrative_domain",
            "target.asset.hostname",
            "target.asset.network_domain",
            "target.hostname",
        ],
        "email": [
            "intermediary.user.email_addresses",
            "network.email.from",
            "network.email.to",
            "principal.user.email_addresses",
            "security_result.about.user.email_addresses",
            "target.user.email_addresses",
        ],
        "file_path": [
            "principal.file.full_path",
            "principal.process.file.full_path",
            "principal.process.parent_process.file.full_path",
            "target.file.full_path",
            "target.process.file.full_path",
            "target.process.parent_process.file.full_path",
        ],
        "hash": [
            "about.file.md5",
            "about.file.sha1",
            "about.file.sha256",
            "principal.process.file.md5",
            "principal.process.file.sha1",
            "principal.process.file.sha256",
            "security_result.about.file.sha256",
            "target.file.md5",
            "target.file.sha1",
            "target.file.sha256",
            "target.process.file.md5",
            "target.process.file.sha1",
        ],
        "hostname": [
            "intermediary.hostname",
            "observer.hostname",
            "principal.asset.hostname",
            "principal.hostname",
            "src.asset.hostname",
            "src.hostname",
            "target.asset.hostname",
            "target.hostname",
        ],
        "ip": [
            "intermediary.ip",
            "observer.ip",
            "principal.artifact.ip",
            "principal.asset.ip",
            "principal.ip",
            "src.artifact.ip",
            "src.asset.ip",
            "src.ip",
            "target.artifact.ip",
            "target.asset.ip",
            "target.ip",
        ],
        "namespace": [
            "principal.namespace",
            "src.namespace",
            "target.namespace",
        ],
        "process_id": [
            "principal.process.parent_process.pid",
            "principal.process.parent_process.product_specific_process_id",
            "principal.process.pid",
            "principal.process.product_specific_process_id",
            "target.process.parent_process.pid",
            "target.process.parent_process.product_specific_process_id",
            "target.process.pid",
            "target.process.product_specific_process_id",
        ],
        "user": [
            "about.user.userid",
            "observer.user.userid",
            "principal.user.user_display_name",
            "principal.user.userid",
            "principal.user.windows_sid",
            "src.user.userid",
            "target.user.user_display_name",
            "target.user.userid",
            "target.user.windows_sid",
        ],
    }


def camel_to_snake(name):
    """Convert CamelCase to snake_case, handling consecutive uppercase letters and dots properly."""
    parts = name.split(".")
    converted_parts = []
    for part in parts:
        s1 = re.sub("(.)([A-Z][a-z0-9]+)", r"\1_\2", part)
        s2 = re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1)
        converted_parts.append(s2.lower())
    return ".".join(converted_parts)


def extract_udm_schema():
    url = "https://cloud.google.com/chronicle/docs/reference/udm-field-list"
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")

    # Initialize the schema dictionaries
    udm_schema = {
        "Nouns": ["about", "intermediary", "observer", "principal", "src", "target"],
        "Enums": {},
        "Subtypes": {},
        "TopLevelFields": {},
        "GroupedFields": add_grouped_fields(),
    }

    # Find all h2 headers
    h2_headers = soup.find_all("h2")

    # Mapping of section titles to categories
    section_mapping = {
        "UDM Event data model": "udm_event_data_model",
        "Event top level types": "event_top_level_types",
        "Event subtypes": "event_subtypes",
        "Event enumerated types": "event_enumerated_types",
    }

    # Dictionary to hold the content of each section
    sections = {}

    for h2 in h2_headers:
        h2_text = h2.get_text(strip=True)
        if h2_text in section_mapping:
            section_key = section_mapping[h2_text]
            sections[section_key] = []
            # Collect all content until the next h2
            next_node = h2.find_next_sibling()
            while next_node and next_node.name != "h2":
                sections[section_key].append(next_node)
                next_node = next_node.find_next_sibling()

    # Process UDM Event data model section
    if "udm_event_data_model" in sections:
        for node in sections["udm_event_data_model"]:
            if node.name == "div" and node.find("table"):
                table = node.find("table")
                fields = parse_table(table)
                # Process top-level fields
                for field in fields:
                    field_name_raw = field.get("Field Name", "").strip()
                    field_name = camel_to_snake(field_name_raw)
                    udm_schema["TopLevelFields"][field_name] = {}
                break  # Only one table in this section

    # Process Event top level types
    if "event_top_level_types" in sections:
        process_type_sections(sections["event_top_level_types"], udm_schema, "TopLevelFields")

    # Process Event subtypes
    if "event_subtypes" in sections:
        process_type_sections(sections["event_subtypes"], udm_schema, "Subtypes")

    # Process Event enumerated types
    if "event_enumerated_types" in sections:
        process_enum_sections(sections["event_enumerated_types"], udm_schema)

    return udm_schema


def parse_table(table):
    headers = []
    header_row = table.find("thead").find("tr")
    for th in header_row.find_all("th"):
        headers.append(th.get_text(strip=True))

    rows = []
    tbody = table.find("tbody")
    if not tbody:
        return rows  # Return empty list if no tbody

    for tr in tbody.find_all("tr"):
        cells = tr.find_all("td")
        if len(cells) != len(headers):
            print("Skipping row due to mismatched number of cells.")
            continue  # Skip rows that don't match header length

        row_data = {}
        for idx, cell in enumerate(cells):
            header = headers[idx]
            row_data[header] = cell.get_text(strip=True)
        rows.append(row_data)
    return rows


def process_type_sections(nodes, udm_schema, category):
    current_type = None
    for node in nodes:
        if node.name == "h3":
            type_name = node.get_text(strip=True).strip()
            current_type = camel_to_snake(type_name)
            print(f"Processing type: {type_name} -> {current_type}")
        elif node.name == "div" and node.find("table") and current_type:
            table = node.find("table")
            fields = parse_table(table)
            for field in fields:
                field_name_raw = field.get("Field Name", "").strip()
                field_name = camel_to_snake(field_name_raw)
                field_type = field.get("Type", "").strip()
                print(f"Processing field: {field_name_raw} -> {field_name}, Type: {field_type}")

                if not field_type:
                    print(f"Skipping field '{field_name}' due to missing type.")
                    continue  # Skip fields with no type

                if current_type not in udm_schema[category]:
                    udm_schema[category][current_type] = {}

                # Convert field_type to snake_case if it's a type name
                if field_type[0].isupper() and "Type:" not in field_type:
                    field_type_snake = camel_to_snake(field_type)
                else:
                    field_type_snake = field_type.lower()

                if "EventType" in field_type or "Enum" in field_type:
                    # Handle enum reference
                    enum_name = f"{current_type}.{field_name}"
                    udm_schema[category][current_type][field_name] = f"@enum:{enum_name}"
                elif field_type.startswith("Type:"):
                    subtype_ref = field_type.replace("Type:", "").strip()
                    subtype_ref = camel_to_snake(subtype_ref)
                    udm_schema[category][current_type][field_name] = f"@{subtype_ref}"
                elif field_type_snake in udm_schema["Subtypes"]:
                    # Reference to another subtype
                    udm_schema[category][current_type][field_name] = f"@{field_type_snake}"
                else:
                    # Standard data type or new subtype
                    udm_schema[category][current_type][field_name] = field_type_snake
                    # If field_type is CamelCase and not in standard types, treat it as a subtype
                    if (
                        field_type
                        and field_type[0].isupper()
                        and field_type_snake not in ["string", "integer", "boolean", "list"]
                    ):
                        subtype_name = field_type_snake
                        if subtype_name not in udm_schema["Subtypes"]:
                            udm_schema["Subtypes"][subtype_name] = {}
                            print(f"Added new subtype: {subtype_name}")
            # You can also capture descriptions if needed


def process_enum_sections(nodes, udm_schema):
    current_enum = None
    for node in nodes:
        if node.name == "h3":
            enum_name_raw = node.get_text(strip=True).strip()
            current_enum = camel_to_snake(enum_name_raw)
            print(f"Processing enum: {enum_name_raw} -> {current_enum}")
            udm_schema["Enums"][current_enum] = []
        elif node.name == "div" and node.find("table") and current_enum:
            table = node.find("table")
            enum_values = parse_enum_table(table)
            udm_schema["Enums"][current_enum].extend(enum_values)


def parse_enum_table(table):
    headers = []
    header_row = table.find("thead").find("tr")
    for th in header_row.find_all("th"):
        headers.append(th.get_text(strip=True))

    enum_values = []
    tbody = table.find("tbody")
    if not tbody:
        return enum_values

    for tr in tbody.find_all("tr"):
        cells = tr.find_all("td")
        if len(cells) != len(headers):
            print("Skipping enum row due to mismatched number of cells.")
            continue  # Skip rows that don't match header length

        row_data = {}
        for idx, cell in enumerate(cells):
            header = headers[idx]
            row_data[header] = cell.get_text(strip=True)
        value = row_data.get("Enum Value") or row_data.get("Value")
        if value:
            enum_values.append(value)
    return enum_values


def save_to_json(data, filename):
    with open(filename, "w", encoding="utf-8") as json_file:
        json.dump(data, json_file, indent=2, ensure_ascii=False)
    print(f"Data saved to {filename}")


if __name__ == "__main__":
    # Path to the local HTML file

    # Extract schema data
    udm_schema = extract_udm_schema()
    output_file = "sigma/pipelines/secops/udm_field_schema.json"

    # Save schema to JSON
    if udm_schema:
        save_to_json(udm_schema, output_file)
    else:
        print("Could not extract UDM schema from the file.")
