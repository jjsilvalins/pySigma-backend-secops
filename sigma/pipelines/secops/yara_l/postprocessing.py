from sigma.processing.postprocessing import QueryPostprocessingTransformation
from sigma.rule import SigmaRule


class YaraLPostprocessingTransformation(QueryPostprocessingTransformation):
    def apply(self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule, query: str) -> str:  # type: ignore # noqa: F821
        # Split the query into lines and remove any leading/trailing whitespace
        query_lines = [line.strip() for line in query.split('\n') if line.strip()]
        
        # Join the lines with proper indentation
        indented_query = '\n            '.join(query_lines)
        
        return f"""
    rule {rule.title.lower().replace(" ", "_")}
    {{
        meta:
            id = "{rule.id}"
            title = "{rule.title}"
            description = "{rule.description}"
            author = "{rule.author}"
            reference = "{", ".join(rule.references)}"
            date = "{rule.date}"
            tags = "{", ".join(str(t) for t in rule.tags)}"
            severity = "{rule.level}"
            falsepositives = "{", ".join(rule.falsepositives) if rule.falsepositives else "Unknown"}" 

        events:
            {indented_query}
        
        conditions: 
            $event1
    }}
    """
        
