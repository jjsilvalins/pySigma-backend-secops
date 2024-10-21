from dataclasses import dataclass
from typing import Iterable, Union

from sigma.correlations import SigmaCorrelationRule
from sigma.pipelines.secops.mappings import get_field_mapping
from sigma.pipelines.secops.utils import determine_event_type
from sigma.processing.pipeline import ProcessingPipeline
from sigma.processing.transformations import (
    DetectionItemTransformation,
    FieldMappingTransformation,
    Transformation,
    ValueTransformation,
)
from sigma.rule import SigmaDetectionItem, SigmaRule

from .errors import InvalidUDMFieldError
from .validators import is_valid_udm_field

from .mappings import enum_mappings

from sigma.types import SigmaString, SigmaType



@dataclass
class ConvertEnumValueTransformation(ValueTransformation):
    """
    Convert the value of a field to an enum value, with modified ValueTransformation.
    """
    def apply_detection_item(self, detection_item: SigmaDetectionItem):
        """Call apply_value for each value and integrate results into value list."""
        results = []
        modified = False
        if detection_item.field in enum_mappings:
            for value in detection_item.value:
                if self.value_types is None or isinstance(
                    value, self.value_types
                ):  # run replacement if no type annotation is defined or matching to type of value
                    res = self.apply_value(detection_item.field, value)
                    if res is None:  # no value returned: drop value
                        results.append(value)
                    elif isinstance(res, Iterable) and not isinstance(res, SigmaType):
                        results.extend(res)
                        modified = True
                    else:
                        results.append(res)
                        modified = True
                else:  # pass original value if type doesn't matches to apply_value argument type annotation
                    results.append(value)
            if modified:
                detection_item.value = results
                self.processing_item_applied(detection_item)

    def apply_value(self, field: str, val: SigmaType) -> SigmaType:
        return SigmaString(enum_mappings.get(field, {}).get(val.to_plain(), None)) or val

@dataclass
class EnsureValidUDMFieldsTransformation(DetectionItemTransformation):
    """
    Ensure that all fields in the detection item are valid UDM fields.
    """

    udm_schema: dict

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> None:
        if detection_item.field:
            if not is_valid_udm_field(detection_item.field, self.udm_schema):
                raise InvalidUDMFieldError(f"Field {detection_item.field} is not a valid UDM field")


@dataclass
class SetRuleEventTypeTransformation(Transformation):
    """
    Sets the event_type custom attribute on a rule, that can be used by the processing pipeline and backend during processing.
    """

    def apply(
        self,
        pipeline: ProcessingPipeline,
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> None:
        super().apply(pipeline, rule)
        rule.custom_attributes["event_type"] = determine_event_type(rule)


class EventTypeFieldMappingTransformation(FieldMappingTransformation):
    """
    Dynamically sets the mapping dictionary based on the Sigma rule's custom attribute 'event_type'.
    """

    def __init__(self):
        super().__init__({})  # Initialize parent class with an empty mapping for now

    def set_event_type_mapping(self, rule: SigmaRule):
        """
        Set the mapping dynamically based on the rule's custom attribute 'event_type'.
        """
        event_type = rule.custom_attributes.get("event_type", None)
        if event_type:
            self.mapping = get_field_mapping(event_type)

    def apply(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",  # noqa: F821 # type: ignore
        rule: Union[SigmaRule, SigmaCorrelationRule],  # noqa: F821 # type: ignore
    ) -> None:
        """Apply dynamic mapping before the field name transformations."""
        self.set_event_type_mapping(rule)  # Dynamically update the mapping
        super().apply(pipeline, rule)  # Call parent method to continue the transformation process
