from typing import ClassVar, Dict, Optional, Tuple, Type, Union

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
)
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.types import (
    SigmaCompareExpression,
    SigmaString,
    SpecialChars,
)


class SecOpsBackend(TextQueryBackend):
    """Google SecOps UDM backend."""

    name: ClassVar[str] = "Google SecOps UDM backend"
    formats: Dict[str, str] = {
        "default": "Plain UDM queries",
    }
    requires_pipeline: bool = True

    precedence: ClassVar[Tuple[Type[ConditionItem], Type[ConditionItem], Type[ConditionItem]]] = (
        ConditionOR,
        ConditionAND,
        ConditionNOT,
    )

    group_expression: ClassVar[str] = "({expr})"

    token_separator: str = " "
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = "="

    eq_expression: ClassVar[str] = "{field} {backend.eq_token} {value} nocase"  # Expression for field = value

    str_quote: ClassVar[str] = '"'
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "*"
    wildcard_single: ClassVar[str] = "?"
    add_escaped: ClassVar[str] = "\\"

    re_expression: ClassVar[str] = "{field} = /{regex}/ nocase"
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[Tuple[str]] = ('"',)

    compare_op_expression: ClassVar[str] = "{field} {operator} {value}"
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    field_null_expression: ClassVar[str] = '{field} = ""'
    field_exists_expression: ClassVar[str] = '{field} != ""'
    field_not_exists_expression: ClassVar[str] = '{field} = ""'

    convert_or_as_in: ClassVar[bool] = True
    convert_and_as_in: ClassVar[bool] = False
    in_expressions_allow_wildcards: ClassVar[bool] = True
    field_in_list_expression: ClassVar[str] = "{field} {op} /{list}/ nocase"
    or_in_operator: ClassVar[str] = "="
    list_separator: ClassVar[str] = "|"

    unbound_value_str_expression: ClassVar[str] = '"{value}"'
    unbound_value_num_expression: ClassVar[str] = "{value}"
    unbound_value_re_expression: ClassVar[str] = "{value}"

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression: ClassVar[Optional[str]] = "{field} = /^{value}.*/ nocase"
    endswith_expression: ClassVar[Optional[str]] = "{field} = /.*{value}$/ nocase"
    contains_expression: ClassVar[Optional[str]] = "{field} = /.*{value}.*/ nocase"
    wildcard_match_expression: ClassVar[Optional[str]] = (
        None  # Special expression if wildcards can't be matched with the eq_token operator
    )

    # cidr expressions
    cidr_expression: ClassVar[str] = (
        'net.ip_in_range_cidr({field}, "{value}")'  # CIDR expression query as format string with placeholders {field} = {value}
    )

    def __init__(self, processing_pipeline=None, **kwargs):
        super().__init__(processing_pipeline, **kwargs)

    def decide_string_quoting(self, s: SigmaString) -> bool:
        """
        Decide if string is quoted based on the pattern in the class attribute str_quote_pattern. If
        this matches (or not matches if str_quote_pattern_negation is set to True), the string is quoted.
        """
        if self.str_quote == "":  # No quoting if quoting string is empty.
            return False

        if s.contains_special() or self.wildcard_multi in s or self.wildcard_single in s:
            return False

        if self.str_quote_pattern is None:  # Always quote if pattern is not set.
            return True
        else:
            match = bool(self.str_quote_pattern.match(str(s)))
            if self.str_quote_pattern_negation:
                match = not match
            return match

    def convert_value_str(self, s: SigmaString, state: ConversionState, quote_string: bool = True) -> str:
        """Convert a SigmaString into a plain string which can be used in query.

        Override so when the wildcard is removed in startswith, endswith and contains expressions, we don't quote the string
        """
        converted = s.convert(
            self.escape_char,
            self.wildcard_multi,
            self.wildcard_single,
            self.str_quote + self.add_escaped,
            self.filter_chars,
        )
        if not quote_string:
            return converted
        if self.decide_string_quoting(s):
            return self.quote_string(converted)
        return converted

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions

        Override so when the wildcard is removed in startswith, endswith and contains expressions, we don't quote the string
        """
        try:
            quote_string = self.decide_string_quoting(cond.value)
            if (  # Check conditions for usage of 'startswith' operator
                self.startswith_expression is not None  # 'startswith' operator is defined in backend
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)  # String ends with wildcard
                and not cond.value[:-1].contains_special()  # Remainder of string doesn't contains special characters
            ):
                expr = (
                    self.startswith_expression
                )  # If all conditions are fulfilled, use 'startswith' operator instead of equal token
                value = cond.value[:-1]
            elif (  # Same as above but for 'endswith' operator: string starts with wildcard and doesn't contains further special characters
                self.endswith_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[1:].contains_special()
            ):
                expr = self.endswith_expression
                value = cond.value[1:]
            elif (  # contains: string starts and ends with wildcard
                self.contains_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[1:-1].contains_special()
            ):
                expr = self.contains_expression
                value = cond.value[1:-1]
            elif (  # wildcard match expression: string contains wildcard
                self.wildcard_match_expression is not None and cond.value.contains_special()
            ):
                expr = self.wildcard_match_expression
                value = cond.value
            else:
                expr = self.eq_expression
                value = cond.value
            return expr.format(
                field=self.escape_and_quote_field(cond.field),
                value=self.convert_value_str(value, state, quote_string),
                backend=self,
            )
        except TypeError:  # pragma: no cover
            raise NotImplementedError(
                "Field equals string value expressions with strings are not supported by the backend."
            )

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = number value expressions
        Override to add
        """
        try:
            return (
                self.escape_and_quote_field(cond.field)
                + self.token_separator
                + self.eq_token
                + self.token_separator
                + str(cond.value)
            )
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Field equals numeric value expressions are not supported by the backend.")

    def convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field in value list conditions.
        Overridden, as UDM search does not support the IN operator and we have to use the eq_token operator with a regex.
        Replace wildcards with .* and add nocase."""

        return self.field_in_list_expression.format(
            field=self.escape_and_quote_field(cond.args[0].field),
            op=self.or_in_operator if isinstance(cond, ConditionOR) else self.and_in_operator,
            list=self.list_separator.join(self.convert_value_for_in_expression(arg.value, state) for arg in cond.args),
        )

    def convert_value_for_in_expression(self, value, state):
        if isinstance(value, SigmaString):
            converted = self.convert_value_str(value, state).strip('"')
            return converted.replace("*", ".*").replace("?", ".") if value.contains_special() else converted
        return str(value).strip('"')
