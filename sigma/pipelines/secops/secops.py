import json
from importlib import resources

from sigma.processing.conditions import (
    DetectionItemProcessingItemAppliedCondition,
    IncludeFieldCondition,
    RuleProcessingItemAppliedCondition,
    RuleProcessingStateCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline, QueryPostprocessingItem
from sigma.processing.transformations import (
    FieldMappingTransformation,
)

from .mappings import enum_mappings, get_field_mappings
from .postprocessing import PrependMetadataPostprocessingTransformation
from .transformations import (
    ConvertEnumValueTransformation,
    EnsureValidUDMFieldsTransformation,
    EventTypeFieldMappingTransformation,
    RemoveHashAlgoFromValueTransformation,
    SetPrependMetadataTransformation,
    SetRuleEventTypeFromEventIDTransformation,
    SetRuleEventTypeFromLogsourceTransformation,
)

# LOAD UDM SCHEMA
udm_schema = json.loads(resources.read_text("sigma.pipelines.secops", "udm_field_schema.json"))

# PROCESSING ITEMS

## SET PIPELINE STATE FOR POSTPROCESSING


def set_prepend_metadata_proc_item(prepend_metadata: bool = True) -> ProcessingItem:
    return ProcessingItem(
        identifier="secops_set_prepend_metadata",
        transformation=SetPrependMetadataTransformation(prepend_metadata),
    )


## SET EVENT TYPE IN RULE CUSTOM ATTRIBUTE

set_event_type_proc_items = [
    ProcessingItem(
        identifier="secops_set_event_type_from_logsource",
        transformation=SetRuleEventTypeFromLogsourceTransformation(),
    ),
    ProcessingItem(
        identifier="secops_set_event_type_from_event_id",
        transformation=SetRuleEventTypeFromEventIDTransformation(),
        field_name_conditions=[
            IncludeFieldCondition(["EventID"]),
        ],
        rule_conditions=[RuleProcessingItemAppliedCondition("secops_set_event_type_from_logsource")],
        rule_condition_negation=True,  # If we can set the event type from the logsource, we don't need to set it from any EventIDs present in selection items
    ),
]


## FIELD MAPPINGS

event_type_field_mapping_proc_item = ProcessingItem(
    identifier="secops_event_type_field_mappings",
    transformation=EventTypeFieldMappingTransformation(),
)

# If field has not been mapped by event_type_field_mapping_proc_item, map using common_field_mappings
common_field_mappings_proc_item = ProcessingItem(
    identifier="secops_common_field_mappings",
    transformation=FieldMappingTransformation(get_field_mappings().get("common")),
    detection_item_conditions=[DetectionItemProcessingItemAppliedCondition("secops_event_type_field_mappings")],
    detection_item_condition_linking=any,
    detection_item_condition_negation=True,
)

## CONVERT ENUM VALUES IF POSSIBLE

convert_enum_values_proc_item = ProcessingItem(
    identifier="secops_convert_enum_values",
    transformation=ConvertEnumValueTransformation(),
    field_name_conditions=[
        IncludeFieldCondition(list(enum_mappings.keys())),
    ],
)

# UDM VALIDATION
## ENSURE ALL FIELDS ARE VALID UDM FIELDS

udm_validation_proc_item = ProcessingItem(
    identifier="secops_udm_validation",
    transformation=EnsureValidUDMFieldsTransformation(udm_schema),
)

## REMOVE HASH ALGORITHM FROM HASHES FIELD
### MUST OCCUR AFTER FIELD RENAMES

remove_hash_algo_from_hashes_proc_item = ProcessingItem(
    identifier="secops_remove_hash_algo_from_hashes",
    transformation=RemoveHashAlgoFromValueTransformation(),
    field_name_conditions=[
        IncludeFieldCondition(["hash"]),
    ],
)

# POSTPROCESSING
## ADD METADATA TO QUERY

prepend_metadata_postprocessing_item = QueryPostprocessingItem(
    identifier="secops_prepend_metadata_postprocessing",
    transformation=PrependMetadataPostprocessingTransformation(),
    rule_conditions=[RuleProcessingStateCondition(key="prepend_metadata", val=True)],
)


def secops_udm_pipeline(prepend_metadata: bool = True) -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Google SecOps UDM Pipeline",
        priority=20,
        items=[
            set_prepend_metadata_proc_item(prepend_metadata),
            *set_event_type_proc_items,
            event_type_field_mapping_proc_item,
            common_field_mappings_proc_item,
            udm_validation_proc_item,
            convert_enum_values_proc_item,
            remove_hash_algo_from_hashes_proc_item,
        ],
        postprocessing_items=[prepend_metadata_postprocessing_item],
        allowed_backends=["secops"],
    )
