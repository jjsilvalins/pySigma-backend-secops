from sigma.pipelines.secops.utils import (
    determine_event_type_event_id,
    determine_event_type_logsource,
    get_rule_detection_fields,
)
from sigma.rule import SigmaRule


def test_get_rule_detection_fields_complex():
    rule = SigmaRule.from_yaml(
        """
        title: Test Complex Detection Fields
        logsource:
            category: process_creation
            product: windows
        detection:
            selection1:
                Image: cmd.exe
                CommandLine: '*whoami*'
            selection2:
                User: 'admin'
                ParentImage:
                    - 'cmd.exe'
                    - 'powershell.exe'
            filter:
                ProcessId: 4
            condition: (selection1 or selection2) and not filter
    """
    )

    fields = get_rule_detection_fields(rule)
    expected_fields = {"Image", "CommandLine", "User", "ParentImage", "ProcessId"}
    assert fields == expected_fields


def test_determine_event_type_logsource_variations():
    # Test with category
    rule1 = SigmaRule.from_yaml(
        """
        title: Test Category
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                Field: value
            condition: selection
    """
    )
    assert determine_event_type_logsource(rule1) == "PROCESS_LAUNCH"


def test_determine_event_type_event_id_variations():
    # Test various Windows event IDs
    assert determine_event_type_event_id("4688") == "PROCESS_LAUNCH"
    assert determine_event_type_event_id("4624") == "USER_LOGIN"
    assert determine_event_type_event_id("1") == "PROCESS_LAUNCH"  # Sysmon event ID
    assert determine_event_type_event_id("999999") is None  # Invalid event ID
