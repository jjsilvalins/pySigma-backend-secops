from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem, QueryPostprocessingItem
from .transformations import PrependEventVariableTransformation
from .postprocessing import YaraLPostprocessingTransformation


prepend_event_variable_transformation = ProcessingItem(
    identifier="yara_l_prepend_event_variable",
    transformation=PrependEventVariableTransformation(mapping={}),
)

output_format_postprocessing_item = QueryPostprocessingItem(
    identifier="yara_l_output_format_postprocessing",
    transformation=YaraLPostprocessingTransformation(),
)


def yara_l_pipeline() -> ProcessingPipeline:
    """Google SecOps backend format pipeline for YARA-L 2.0 output format
    Not for use as a general purpose pipeline, use the secops pipeline instead.
    """

    return ProcessingPipeline(
        name="Google SecOps YARA-L 2.0 Output Format Pipeline",
        priority=60,
        items=[prepend_event_variable_transformation],
        postprocessing_items=[output_format_postprocessing_item],
        allowed_backends=["secops"],
    )
