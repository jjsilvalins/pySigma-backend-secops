import pytest

from sigma.backends.secops import SecOpsBackend
from sigma.pipelines.secops.mappings import get_field_mappings_by_event_type
from sigma.pipelines.secops.secops import secops_udm_pipeline
from sigma.pipelines.secops.utils import (
    determine_event_type_event_id,
    determine_event_type_logsource,
    get_rule_detection_fields,
)
from sigma.rule import SigmaRule
from sigma.types import SigmaString


@pytest.fixture
def secops_pipeline():
    return secops_udm_pipeline()


@pytest.fixture
def secops_backend_prepend_metadata():
    return SecOpsBackend(processing_pipeline=secops_udm_pipeline())


def test_field_mapping_transformation(secops_pipeline):
    rule = SigmaRule.from_yaml(
        """
        title: Test Field Mapping
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                Image: C:\\Windows\\System32\\cmd.exe
                CommandLine: '*whoami*'
            condition: selection
    """
    )

    secops_pipeline.apply(rule)

    assert rule.detection.detections["selection"].detection_items[0].field == "target.process.file.full_path"
    assert rule.detection.detections["selection"].detection_items[1].field == "target.process.command_line"


def test_event_type_field_mapping(secops_pipeline):
    rule = SigmaRule.from_yaml(
        """
        title: Test Event Type Field Mapping
        logsource:
            category: network_connection
            product: windows
        detection:
            selection:
                SourceIp: 192.168.1.100
                DestinationIp: 10.0.0.1
            condition: selection
    """
    )

    secops_pipeline.apply(rule)

    assert rule.detection.detections["selection"].detection_items[0].field == "principal.ip"
    assert rule.detection.detections["selection"].detection_items[1].field == "target.ip"


def test_utils_get_rule_detection_fields():
    rule = SigmaRule.from_yaml(
        """
        title: Test Field Mapping
        logsource:
            category: process_creation
            product: windows
        detection:
            selection1:
                Image: C:\\Windows\\System32\\cmd.exe
                CommandLine: '*whoami*'
            selection2:
                Image:
                  - C:\\Windows\\System32\\cmd.exe
                  - C:\\Windows\\System32\\net.exe
                ParentProcessImage:
                  - C:\\Windows\\System32\\cmd.exe
                  - C:\\Windows\\System32\\net.exe
            condition: selection1 or selection2
    """
    )

    fields = sorted(get_rule_detection_fields(rule))
    assert fields == ["CommandLine", "Image", "ParentProcessImage"]


def test_determine_event_type_logsource():
    logsource = {
        "category": "process_creation",
        "product": "windows",
    }
    rule = SigmaRule.from_dict(
        {"title": "Test", "logsource": logsource, "detection": {"sel": {"field": "value"}, "condition": "sel"}}
    )

    event_type = determine_event_type_logsource(rule)
    assert event_type == "PROCESS_LAUNCH"


def test_determine_event_type_event_id():
    event_id = "4688"
    event_type = determine_event_type_event_id(event_id)
    assert event_type == "PROCESS_LAUNCH"


def test_get_field_mappings_by_event_type():
    mappings = get_field_mappings_by_event_type("PROCESS_LAUNCH")
    assert "CommandLine" in mappings
    assert mappings["CommandLine"] == "target.process.command_line"


def test_add_metadata_postprocessing(secops_pipeline):
    rule = SigmaRule.from_yaml(
        """
        title: Test Add Metadata
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                Image: C:\\Windows\\System32\\cmd.exe
            condition: selection
    """
    )

    secops_pipeline.apply(rule)

    # Check if metadata is added to the rule
    assert "event_types" in rule.custom_attributes
    assert rule.custom_attributes["event_types"] == {"PROCESS_LAUNCH"}


def test_convert_enum_values(secops_pipeline):
    rule = SigmaRule.from_yaml(
        """
        title: Test Convert Enum Values
        logsource:
            category: network_connection
            product: windows
        detection:
            selection:
                Initiated: 'true'
            condition: selection
    """
    )

    secops_pipeline.apply(rule)

    assert rule.detection.detections["selection"].detection_items[0].field == "network.direction"
    assert rule.detection.detections["selection"].detection_items[0].value[0] == SigmaString("OUTBOUND")


def test_udm_validation(secops_pipeline):
    rule = SigmaRule.from_yaml(
        """
        title: Test UDM Validation
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                Image: C:\\Windows\\System32\\cmd.exe
                InvalidField: some_value
            condition: selection
    """
    )

    with pytest.raises(Exception, match="Invalid UDM field"):
        secops_pipeline.apply(rule)


def test_remove_hash_algo_from_hashes(secops_pipeline):
    rule = SigmaRule.from_yaml(
        """
        title: Test Remove Hash Algo
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                Hashes: 
                  - 'MD5|1234567890abcdef1234567890abcdef'
                  - 'SHA1|92429d82a41e930486c6de5ebda9602d55c39986'
                  - 'SHA256|2413fb3709b05939f04cf2e92f7d0897fc2596f9ad0b8a9ea855c7bfebaae892'
                
            condition: selection
    """
    )

    secops_pipeline.apply(rule)

    assert rule.detection.detections["selection"].detection_items[0].field == "hash"
    assert rule.detection.detections["selection"].detection_items[0].value[0] == SigmaString(
        "1234567890abcdef1234567890abcdef"
    )
    assert rule.detection.detections["selection"].detection_items[0].value[1] == SigmaString(
        "92429d82a41e930486c6de5ebda9602d55c39986"
    )
    assert rule.detection.detections["selection"].detection_items[0].value[2] == SigmaString(
        "2413fb3709b05939f04cf2e92f7d0897fc2596f9ad0b8a9ea855c7bfebaae892"
    )


def test_prepend_metadata_postprocessing(secops_backend_prepend_metadata: SecOpsBackend):
    rule = SigmaRule.from_yaml(
        """
        title: Test Prepend Metadata
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                Image: C:\\Windows\\System32\\cmd.exe
            condition: selection
    """
    )

    assert (
        secops_backend_prepend_metadata.convert_rule(rule)[0]
        == '(metadata.event_type = "PROCESS_LAUNCH") AND (target.process.file.full_path = "C:\\\\Windows\\\\System32\\\\cmd.exe" nocase)'
    )


def test_set_event_type_from_event_id_transformation(secops_pipeline):
    """Tests setting the event_type custom attribute on the rule if the EventID field is present and the event
    type cannot be determined from the logsource.
    """
    rule = SigmaRule.from_yaml(
        """
        title: Test Set Event Type From Event ID
        logsource:
            category: unknown
            product: unknown
        detection:
            selection:
                EventID: 4688
            condition: selection
    """
    )

    secops_pipeline.apply(rule)

    assert rule.custom_attributes["event_types"] == {"PROCESS_LAUNCH"}


def test_set_event_type_already_set(secops_pipeline):
    """Tests that the event_type custom attribute is not overwritten if it is already set."""
    rule = SigmaRule.from_yaml(
        """
        title: Test Set Event Type Already Set
        logsource:
            category: unknown
            product: unknown
        detection:
            selection:
                EventID: 4688
            condition: selection
    """
    )
    rule.custom_attributes["event_types"] = {"PROCESS_UNCATEGORIZED"}

    secops_pipeline.apply(rule)

    assert rule.custom_attributes["event_types"] == {"PROCESS_UNCATEGORIZED"}


def test_hash_field_common_field_mappings(secops_pipeline):
    rule = SigmaRule.from_yaml(
        """
        title: Test Hash Field Common Field Mappings
        logsource:
            category: process_creation
            product: windows
        detection:
            selection_hashes:
                Hashes:
                    - 'MD5|1234567890abcdef1234567890abcdef'
                    - 'SHA1|92429d82a41e930486c6de5ebda9602d55c39986'
                    - 'SHA256|2413fb3709b05939f04cf2e92f7d0897fc2596f9ad0b8a9ea855c7bfebaae892'
                
            selection_algos:
                md5: '0987654321abcdef0987654321abcdef'
                sha1: '6c66b4e46de761b856df0e14ad11098da2e6c351'
                sha256: 'ba8fb484289ee92eb908642324f2a783586c5c1be12957c4a4b89524ad5b3acd'
            condition: selection_hashes or selection_algos
    """
    )

    secops_pipeline.apply(rule)

    assert rule.detection.detections["selection_hashes"].detection_items[0].field == "hash"
    assert rule.detection.detections["selection_hashes"].detection_items[0].value[0] == SigmaString(
        "1234567890abcdef1234567890abcdef"
    )
    assert rule.detection.detections["selection_hashes"].detection_items[0].value[1] == SigmaString(
        "92429d82a41e930486c6de5ebda9602d55c39986"
    )
    assert rule.detection.detections["selection_hashes"].detection_items[0].value[2] == SigmaString(
        "2413fb3709b05939f04cf2e92f7d0897fc2596f9ad0b8a9ea855c7bfebaae892"
    )
    assert rule.detection.detections["selection_algos"].detection_items[0].field == "hash"
    assert rule.detection.detections["selection_algos"].detection_items[0].value[0] == SigmaString(
        "0987654321abcdef0987654321abcdef"
    )
    assert rule.detection.detections["selection_algos"].detection_items[1].value[0] == SigmaString(
        "6c66b4e46de761b856df0e14ad11098da2e6c351"
    )
    assert rule.detection.detections["selection_algos"].detection_items[2].value[0] == SigmaString(
        "ba8fb484289ee92eb908642324f2a783586c5c1be12957c4a4b89524ad5b3acd"
    )
    assert len(rule.detection.detections["selection_algos"].detection_items) == 3
    assert len(rule.detection.detections["selection_hashes"].detection_items) == 1
    