from dataclasses import dataclass
from typing import List, Union

from sigma.processing.transformations import FieldMappingTransformation


@dataclass
class PrependEventVariableTransformation(FieldMappingTransformation):
    """Prepend event variable to every field name"""
    mapping = {}
    
    def get_mapping(self, field: str) -> Union[None, str, List[str]]:
        return f"$event1.{field}"