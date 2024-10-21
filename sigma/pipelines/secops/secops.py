import json
from importlib import resources

from sigma.processing.conditions import DetectionItemProcessingItemAppliedCondition, IncludeFieldCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    FieldMappingTransformation,
)

from .mappings import get_common_mappings, enum_mappings
from .transformations import (
    ConvertEnumValueTransformation,
    EnsureValidUDMFieldsTransformation,
    EventTypeFieldMappingTransformation,
    SetRuleEventTypeTransformation,
    
)

# LOAD UDM SCHEMA
udm_schema = json.loads(resources.read_text("sigma.pipelines.secops", "udm_field_schema.json"))

# PROCESSING ITEMS

## SET EVENT TYPE IN RULE CUSTOM ATTRIBUTE

set_event_type_proc_item = ProcessingItem(
    identifier="secops_set_event_type",
    transformation=SetRuleEventTypeTransformation(),
)


## FIELD MAPPINGS

event_type_field_mapping_proc_item = ProcessingItem(
    identifier="secops_event_type_field_mappings",
    transformation=EventTypeFieldMappingTransformation(),
)

# If field has not been mapped by event_type_field_mapping_proc_item, map using common_field_mappings
common_field_mappings_proc_item = ProcessingItem(
    identifier="secops_common_field_mappings",
    transformation=FieldMappingTransformation(get_common_mappings()),
    detection_item_conditions=[DetectionItemProcessingItemAppliedCondition("secops_event_type_field_mappings")],
    detection_item_condition_linking=any,
    detection_item_condition_negation=True,
)

## CONVERT ENUM VALUES IF POSSIBLE

convert_enum_values_proc_item = ProcessingItem(
    identifier="secops_convert_enum_values",
    transformation=ConvertEnumValueTransformation(),
    field_name_conditions=[IncludeFieldCondition(list(enum_mappings.keys())),],
)

# UDM VALIDATION

udm_validation_proc_item = ProcessingItem(
    identifier="secops_udm_validation",
    transformation=EnsureValidUDMFieldsTransformation(udm_schema),
)



def secops_udm_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Google SecOps UDM Pipeline",
        priority=20,
        items=[
            set_event_type_proc_item,
            event_type_field_mapping_proc_item,
            common_field_mappings_proc_item,
            udm_validation_proc_item,
            convert_enum_values_proc_item,
            # ProcessingItem(
            #    identifier="map_windows_event_ids",
            #    transformation=MapStringTransformation(mapping=get_windows_event_id_mapping()),
            # ),
            # Commented out for now, uncomment if needed
            # ProcessingItem(
            #     identifier="handle_unmapped_fields",
            #     transformation=DetectionItemFailureTransformation(
            #         "The field {field} is not mapped to UDM schema",
            #     ),
            #     condition=IncludeFieldCondition(fields=["*"]),
            # ),
            # ProcessingItem(
            #     identifier="ensure_critical_fields",
            #     transformation=RuleFailureTransformation(
            #         "Critical field {field} is missing",
            #     ),
            #     condition=ExcludeFieldCondition(fields=["metadata.event_type", "metadata.product_name"]),
            # ),
        ],
    )
