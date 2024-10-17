from functools import lru_cache
from typing import Dict


@lru_cache(maxsize=128)
def get_common_mappings() -> Dict[str, str]:
    return {
        "User": "principal.user.userid",
        "SourceHostname": "principal.hostname",
        "DestinationHostname": "target.hostname",
        "EventID": "metadata.product_event_type",
        "EventType": "metadata.event_type",
        "EventLog": "metadata.log_type",
        "Channel": "metadata.log_type",
        "Provider_Name": "metadata.product_name",
        "ServiceName": "target.process.name",
        "ServiceFileName": "target.process.file.full_path",
        "AccountName": "principal.user.user_display_name",
        "SubjectUserName": "principal.user.user_display_name",
        "SubjectDomainName": "principal.user.user_domain",
        "SubjectLogonId": "principal.user.session_id",
        "TargetUserName": "target.user.userid",
        "TargetDomainName": "target.user.user_domain",
        "TargetLogonId": "target.user.session_id",
        "IpAddress": "principal.ip",
        "IpPort": "principal.port",
        "WorkstationName": "principal.hostname",
        "Status": "metadata.status",
        "Severity": "metadata.severity",
        "Category": "metadata.event_category",
        "Hostname": "target.hostname",
        "ComputerName": "target.hostname",
    }


@lru_cache(maxsize=128)
def get_process_mappings() -> Dict[str, str]:
    return {
        "CommandLine": "target.process.command_line",
        "Image": "target.process.file.full_path",
        "ParentImage": "principal.process.file.full_path",
        "ParentCommandLine": "principal.process.command_line",
        "ProcessId": "target.process.pid",
        "ParentProcessId": "principal.process.pid",
        "IntegrityLevel": "target.process.integrity_level",
        "Hashes": "target.process.file.hash",
        "CurrentDirectory": "target.process.cwd",
        "Product": "target.process.file.pe.product",
        "Description": "target.process.file.pe.file_description",
        "Company": "target.process.file.pe.company",
        "FileVersion": "target.process.file.pe.file_version",
        "User": "target.user.userid",
        "LogonId": "target.user.session_id",
        "TerminalSessionId": "target.user.terminal_session_id",
        "CallTrace": "target.process.call_trace",
        "ParentUser": "principal.user.userid",
    }


@lru_cache(maxsize=128)
def get_network_mappings() -> Dict[str, str]:
    return {
        "SourceIp": "principal.ip",
        "DestinationIp": "target.ip",
        "SourcePort": "principal.port",
        "DestinationPort": "target.port",
        "Protocol": "network.ip_protocol",
        "Image": "network.application",
        "Initiated": "network.direction",
        "SourceIsIpv6": "principal.ip_is_ipv6",
        "DestinationIsIpv6": "target.ip_is_ipv6",
        "User": "principal.ip_user_info.userid",
        "DestinationHostname": "target.hostname",
        "SourceHostname": "principal.hostname",
        "QueryName": "network.dns.questions.name",
        "QueryResults": "network.dns.answers.data",
        "QueryStatus": "network.dns.response_code",
    }


@lru_cache(maxsize=128)
def get_file_mappings() -> Dict[str, str]:
    return {
        "TargetFilename": "target.file.full_path",
        "Image": "principal.process.file.full_path",
        "ObjectName": "target.file.full_path",
        "AccessMask": "target.file.access_mask",
        "CreationUtcTime": "target.file.creation_time",
        "PreviousCreationUtcTime": "target.file.previous_creation_time",
        "Contents": "target.file.content",
        "Hash": "target.file.hash",
        "OldName": "target.file.previous_full_path",
        "NewName": "target.file.full_path",
        "FileVersion": "target.file.pe.file_version",
        "Description": "target.file.pe.file_description",
        "Product": "target.file.pe.product",
        "Company": "target.file.pe.company",
        "OriginalFileName": "target.file.pe.original_file_name",
    }


@lru_cache(maxsize=128)
def get_authentication_mappings() -> Dict[str, str]:
    return {
        "LogonType": "principal.authentication.auth_type",
        "AuthenticationPackageName": "principal.authentication.auth_protocol",
        "TargetUserName": "target.user.userid",
        "SubjectUserName": "principal.user.user_display_name",
        "TargetOutboundUserName": "target.user.userid",
        "TargetUserSid": "target.user.user_uid",
        "TargetServerName": "target.hostname",
        "LogonProcessName": "principal.authentication.auth_service",
        "WorkstationName": "principal.hostname",
        "IpAddress": "principal.ip",
        "IpPort": "principal.port",
        "TargetInfo": "target.user.group_info",
        "LogonGuid": "principal.authentication.session_id",
    }


@lru_cache(maxsize=128)
def get_registry_mappings() -> Dict[str, str]:
    return {
        "TargetObject": "target.registry.registry_key",
        "Details": "target.registry.registry_value",
        "EventType": "metadata.event_type",
        "Image": "principal.process.file.full_path",
        "ProcessId": "principal.process.pid",
        "User": "principal.user.userid",
        "ObjectName": "target.registry.registry_key",
        "ObjectValueName": "target.registry.registry_value_name",
        "NewName": "target.registry.new_registry_key",
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
