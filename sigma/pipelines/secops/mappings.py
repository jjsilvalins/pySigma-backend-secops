from functools import lru_cache
from typing import Dict


# TODO: EventType field in sysmon logs, ensure value is valid for metadata.event_type
# TODO: Add mappings/transformations for LogonType to Authentication.Mechanism enum conversion for logon events

@lru_cache(maxsize=128)
def get_common_mappings() -> Dict[str, str]:
    return {
        "AccessMask": "target.process.access_mask",
        "User": "principal.user.userid",
        "SourceHostname": "principal.hostname",
        "DestinationHostname": "target.hostname",
        "EventID": "metadata.product_event_type",
        "EventType": "metadata.event_type",
        "EventLog": "metadata.log_type",
        "Channel": "metadata.log_type",
        "Provider_Name": "metadata.product_name",
        "ServiceName": "target.process.file.names",
        "ServiceFileName": "target.process.file.full_path",
        "AccountName": "principal.user.user_display_name",
        "SubjectUserName": "principal.user.user_display_name",
        "SubjectDomainName": "principal.domain.name",
        "TargetUserName": "target.user.userid",
        "TargetDomainName": "target.domain.name",
        "IpAddress": "principal.ip",
        "IpPort": "principal.port",
        "WorkstationName": "principal.hostname",
        "Hostname": "target.hostname",
        "ComputerName": "target.hostname",
    }


@lru_cache(maxsize=128)
def get_process_mappings() -> Dict[str, str]:
    return {
        "CommandLine": "target.process.command_line",
        "CurrentDirectory": "target.process.file.full_path",
        "Image": "target.process.file.full_path",
        "OriginalFileName": "target.process.file.names",  # Not sure if correct, but it's the file name without the path
        "ParentImage": "principal.process.file.full_path",
        "ParentCommandLine": "principal.process.command_line",
        "ProcessGuid": "target.process.product_specific_process_id",
        "ProcessId": "target.process.pid",
        "ParentProcessImage": "principal.process.file.full_path",
        "ParentProcessCommandLine": "principal.process.command_line",
        "ParentProcessId": "principal.process.pid",
        "ParentProcessGuid": "principal.process.product_specific_process_id",
        "ParentUser": "principal.user.userid",
        "IntegrityLevel": "target.process.integrity_level_rid",
        "User": "target.user.userid",
    }


@lru_cache(maxsize=128)
def get_network_mappings() -> Dict[str, str]:
    return {
        "SourceIp": "principal.ip",
        "DestinationIp": "target.ip",
        "SourcePort": "principal.port",
        "DestinationPort": "target.port",
        "Protocol": "network.ip_protocol",
        "Image": "principal.process.file.full_path",
        "Initiated": "network.direction",
        "User": "principal.user.userid",
        "DestinationHostname": "target.hostname",
        "SourceHostname": "principal.hostname",
        "QueryName": "network.dns.questions.name",
        "QueryResults": "network.dns.answers.data",
        "QueryStatus": "network.dns.response_code",
    }


@lru_cache(maxsize=128)
def get_file_mappings() -> Dict[str, str]:
    return {
        "TargetFilename": "target.file.names",
        "Image": "target.process.file.full_path",
        "ObjectName": "target.file.full_path",
        "OldName": "target.file.names",
        "NewName": "target.file.names",
        "OriginalFileName": "target.file.names",
    }


@lru_cache(maxsize=128)
def get_authentication_mappings() -> Dict[str, str]:
    return {
        "TargetUserName": "target.user.userid",
        "SubjectUserName": "principal.user.user_display_name",
        "TargetOutboundUserName": "target.user.userid",
        "TargetUserSid": "target.user.windows_sid",
        "TargetServerName": "target.hostname",
        "WorkstationName": "principal.hostname",
        "IpAddress": "principal.ip",
        "IpPort": "principal.port",
        "LogonGuid": "principal.user.product_object_id",
    }


@lru_cache(maxsize=128)
def get_registry_mappings() -> Dict[str, str]:
    return {
        "TargetObject": "target.registry.registry_key",
        "Details": "target.registry.registry_value_data",
        "EventType": "metadata.event_type",
        "Image": "principal.process.file.full_path",
        "ProcessId": "principal.process.pid",
        "User": "principal.user.userid",
        "ObjectName": "target.registry.registry_key",
        "ObjectValueName": "target.registry.registry_value_name",
        "NewName": "target.registry.registry_key",
    }


@lru_cache(maxsize=128)
def get_dns_mappings() -> Dict[str, str]:
    return {
        "QueryName": "network.dns.questions.name",
        "QueryResults": "network.dns.answers.data",
        "QueryStatus": "network.dns.response_code",
        "record_type": "network.dns.questions.type",
        "answers": "network.dns.answers.name",
    }


def get_field_mapping(event_type: str) -> Dict[str, str]:

    event_type_mappings = {
        "process": get_process_mappings(),
        "network": get_network_mappings(),
        "file": get_file_mappings(),
        "authentication": get_authentication_mappings(),
        "registry": get_registry_mappings(),
        "dns": get_dns_mappings(),
    }

    mappings = {**event_type_mappings.get(event_type, {})}

    return mappings


enum_mappings = {
    "network.direction": {  # From Initiated sysmon field
        "Inbound": "INBOUND",
        "Outbound": "OUTBOUND",
        "Broadcast": "BROADCAST",
        "true": "OUTBOUND",
        "false": "INBOUND",
    }
}