from sigma.processing.postprocessing import QueryPostprocessingTransformation
from sigma.rule import SigmaRule


class PrependMetadataPostprocessingTransformation(QueryPostprocessingTransformation):
    def apply(self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule, query: str) -> str:  # type: ignore # noqa: F821
        event_types = rule.custom_attributes.get('event_types', set())
        if pipeline.state.get("output_format", "default") == "yara_l":
            metadata_eventtype = " OR ".join([f'$event1.metadata.event_type = "{event_type}"' for event_type in event_types])
            return f"{metadata_eventtype}\n\n{query}"
        else:
            metadata_eventtype = " OR ".join([f'metadata.event_type = "{event_type}"' for event_type in event_types])
            return f"({metadata_eventtype}) AND ({query})"
        
