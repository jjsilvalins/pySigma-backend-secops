from typing import Dict, Optional, Set

from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule


def _process_detection(detection_value, rule) -> Optional[str]:
    if isinstance(detection_value, SigmaDetectionItem):
        field_name = detection_value.field
        if field_name:
            return field_name
    elif isinstance(detection_value, SigmaDetection):
        for item in detection_value.detection_items:
            _process_detection(item, rule)
    else:
        return None


def get_rule_detection_fields(rule: SigmaRule) -> Set[str]:
    fields = set()
    for detection, detection_value in rule.detection.detections.items():
        field = _process_detection(detection_value, rule)
        if field:
            fields.add(field)
    return fields


def determine_event_type(rule: SigmaRule) -> str:
    category = rule.logsource.category
    service = rule.logsource.service

    process_indicators = [
        "process_creation",
        "process_access",
        "process_termination",
        "Image",
        "CommandLine",
        "ProcessId",
    ]
    network_indicators = ["network_connection", "firewall", "dns_query", "proxy", "DestinationIp", "SourceIp"]
    file_indicators = ["file_event", "file_change", "file_rename", "file_delete", "file_access", "TargetFilename"]
    auth_indicators = ["authentication", "login", "auth", "LogonType", "AuthenticationPackageName"]
    registry_indicators = ["registry_add", "registry_delete", "registry_set", "registry_event", "TargetObject"]

    fields: Set[str] = get_rule_detection_fields(rule)

    if category in process_indicators or service == "sysmon" or any(field in process_indicators for field in fields):
        return "process"
    elif (
        category in network_indicators
        or service in ["firewall", "dns"]
        or any(field in network_indicators for field in fields)
    ):
        return "network"
    elif category in file_indicators or any(field in file_indicators for field in fields):
        return "file"
    elif category in auth_indicators or any(field in auth_indicators for field in fields):
        return "authentication"
    elif category in registry_indicators or any(field in registry_indicators for field in fields):
        return "registry"
    elif service == "wmi":
        return "wmi"
    elif service in ["powershell", "powershell-classic"]:
        return "powershell"
    else:
        return "generic"


def get_windows_event_id_mapping() -> Dict[str, str]:
    return {
        "1": "PROCESS_LAUNCH",
        "3": "NETWORK_CONNECTION",
        "4": "SYSMON_SERVICE_STATE_CHANGED",
        "5": "PROCESS_TERMINATED",
        "6": "DRIVER_LOADED",
        "7": "IMAGE_LOADED",
        "8": "CREATE_REMOTE_THREAD",
        "9": "RAW_ACCESS_READ",
        "10": "PROCESS_ACCESS",
        "11": "FILE_CREATE",
        "12": "REGISTRY_EVENT",
        "13": "REGISTRY_EVENT",
        "14": "REGISTRY_EVENT",
        "15": "FILE_CREATE_STREAM_HASH",
        "16": "SYSMON_CONFIGURATION_CHANGE",
        "17": "PIPE_CREATED",
        "18": "PIPE_CONNECTED",
        "19": "WMI_EVENT",
        "20": "WMI_EVENT",
        "21": "WMI_EVENT",
        "22": "DNS_EVENT",
        "23": "FILE_DELETE",
        "24": "CLIPBOARD_CAPTURE",
        "25": "PROCESS_TAMPERING",
        "26": "FILE_DELETE_DETECTED",
        "4624": "USER_LOGIN",
        "4625": "USER_LOGIN",
        "4688": "PROCESS_LAUNCH",
        "4663": "FILE_ACCESS",
        "5156": "NETWORK_CONNECTION",
        "4656": "FILE_ACCESS",
        "4660": "FILE_DELETE",
        "4657": "REGISTRY_CHANGE",
        "4697": "SERVICE_INSTALL",
        "4720": "USER_CREATION",
        "4728": "GROUP_MEMBER_ADD",
        "4732": "GROUP_MEMBER_ADD",
        "4756": "GROUP_MEMBER_ADD",
    }


# You can remove or comment out the map_windows_event_id function if it's no longer used
