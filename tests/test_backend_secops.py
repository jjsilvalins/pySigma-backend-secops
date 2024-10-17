import pytest

from sigma.backends.secops import SecOpsBackend
from sigma.collection import SigmaRule
from sigma.pipelines.secops import secops_udm_pipeline


@pytest.fixture
def secops_backend():
    return SecOpsBackend(processing_pipeline=secops_udm_pipeline())


def test_secops_and_expression(secops_backend: SecOpsBackend):
    assert (
        secops_backend.convert_rule(
            SigmaRule.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine: valueA
                    User: valueB
                condition: sel
        """
            )
        )
        == ['target.process.command_line = "valueA" nocase AND target.user.userid = "valueB" nocase']
    )


def test_secops_or_expression(secops_backend: SecOpsBackend):
    assert (
        secops_backend.convert_rule(
            SigmaRule.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel1:
                    CommandLine: valueA
                sel2:
                    User: valueB
                condition: 1 of sel*
        """
            )
        )
        == ['target.process.command_line = "valueA" nocase OR target.user.userid = "valueB" nocase']
    )


def test_secops_and_or_expression(secops_backend: SecOpsBackend):
    assert (
        secops_backend.convert_rule(
            SigmaRule.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine:
                        - valueA1
                        - valueA2
                    ProcessId:
                        - valueB1
                        - valueB2
                condition: sel
        """
            )
        )
        == ["target.process.command_line = /valueA1|valueA2/ nocase AND target.process.pid = /valueB1|valueB2/ nocase"]
    )


def test_secops_or_and_expression(secops_backend: SecOpsBackend):
    assert (
        secops_backend.convert_rule(
            SigmaRule.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel1:
                    CommandLine: valueA1
                    ProcessId: valueB1
                sel2:
                    CommandLine: valueA2
                    ProcessId: valueB2
                condition: 1 of sel*
        """
            )
        )
        == [
            '(target.process.command_line = "valueA1" nocase AND target.process.pid = "valueB1" nocase) OR (target.process.command_line = "valueA2" nocase AND target.process.pid = "valueB2" nocase)'
        ]
    )


def test_secops_in_expression(secops_backend: SecOpsBackend):
    assert (
        secops_backend.convert_rule(
            SigmaRule.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """
            )
        )
        == ["target.process.command_line = /valueA|valueB|valueC.*/ nocase"]
    )


def test_secops_regex_query(secops_backend: SecOpsBackend):
    assert (
        secops_backend.convert_rule(
            SigmaRule.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine|re: foo.*bar
                    ProcessId: pid:1234
                condition: sel
        """
            )
        )
        == ['target.process.command_line = /foo.*bar/ nocase AND target.process.pid = "pid:1234" nocase']
    )


def test_secops_cidr_query(secops_backend: SecOpsBackend):
    assert (
        secops_backend.convert_rule(
            SigmaRule.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: network_connection
                product: windows
            detection:
                sel:
                    SourceIp|cidr: 192.168.0.0/16
                condition: sel
        """
            )
        )
        == ['net.ip_in_range_cidr(principal.ip, "192.168.0.0/16")']
    )


def test_secops_negation_basic(secops_backend: SecOpsBackend):
    assert (
        secops_backend.convert_rule(
            SigmaRule.from_yaml(
                r"""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    Image: '*\process.exe'
                    CommandLine: 'this'
                filter:
                    CommandLine: 'notthis'  
                condition: selection and not filter
        """
            )
        )
        == [
            'target.process.file.full_path = /.*\\\\process.exe$/ nocase AND target.process.command_line = "this" nocase AND (NOT target.process.command_line = "notthis" nocase)'
        ]
    )


def test_secops_negation_contains(secops_backend: SecOpsBackend):
    assert (
        secops_backend.convert_rule(
            SigmaRule.from_yaml(
                r"""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    Image:
                        - '*\process.exe'
                    CommandLine:
                        - '*this*'
                filter:
                    CommandLine:
                        - '*notthis*'
                condition: selection and not filter
        """
            )
        )
        == [
            "target.process.file.full_path = /.*\\\\process.exe$/ nocase AND target.process.command_line = /.*this.*/ nocase AND (NOT target.process.command_line = /.*notthis.*/ nocase)"
        ]
    )


def test_secops_grouping(secops_backend: SecOpsBackend):
    assert (
        secops_backend.convert_rule(
            SigmaRule.from_yaml(
                r"""
            title: Net connection logic test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    Image:
                        - '*\powershell.exe'
                        - '*\pwsh.exe'
                    CommandLine: 
                        - '*pastebin.com*'
                        - '*anothersite.com*'
                condition: selection
    """
            )
        )
        == [
            "target.process.file.full_path = /.*\\\\powershell.exe|.*\\\\pwsh.exe/ nocase AND target.process.command_line = /.*pastebin.com.*|.*anothersite.com.*/ nocase"
        ]
    )


def test_secops_escape_cmdline_slash(secops_backend: SecOpsBackend):
    assert (
        secops_backend.convert_rule(
            SigmaRule.from_yaml(
                r"""
            title: Delete All Scheduled Tasks
            id: 220457c1-1c9f-4c2e-afe6-9598926222c1
            status: test
            description: Detects the usage of schtasks with the delete flag and the asterisk symbol to delete all tasks from the schedule of the local computer, including tasks scheduled by other users.
            references:
                - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-delete
            author: Nasreddine Bencherchali (Nextron Systems)
            date: 2022-09-09
            tags:
                - attack.impact
                - attack.t1489
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    Image|endswith: '\schtasks.exe'
                    CommandLine|contains|all:
                        - ' /delete '
                        - '/tn \*'
                        - ' /f'
                condition: selection
            falsepositives:
                - Unlikely
            level: high
        """
            )
        )
        == [
            "target.process.file.full_path = /.*\\\\schtasks.exe$/ nocase AND target.process.command_line = /.* /delete .*/ nocase AND target.process.command_line = /.*/tn \\*.*/ nocase AND target.process.command_line = /.* /f.*/ nocase"
        ]
    )


def test_secops_cmdline_filters(secops_backend: SecOpsBackend):
    assert (
        secops_backend.convert_rule(
            SigmaRule.from_yaml(
                r"""
            title: New Firewall Rule Added Via Netsh.EXE
            id: cd5cfd80-aa5f-44c0-9c20-108c4ae12e3c
            status: test
            description: Detects the addition of a new rule to the Windows firewall via netsh
            references:
                - https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf
            author: Markus Neis, Sander Wiebing
            date: 2019-01-29
            modified: 2023-02-10
            tags:
                - attack.defense_evasion
                - attack.t1562.004
                - attack.s0246
            logsource:
                category: process_creation
                product: windows
            detection:
                selection_img:
                    - Image|endswith: '\netsh.exe'
                selection_cli:
                    CommandLine|contains|all:
                        - ' firewall '
                        - ' add '
                filter_optional_dropbox:
                    CommandLine|contains:
                        - 'advfirewall firewall add rule name=Dropbox dir=in action=allow "program=?:\Program Files (x86)\Dropbox\Client\Dropbox.exe" enable=yes profile=Any'
                        - 'advfirewall firewall add rule name=Dropbox dir=in action=allow "program=?:\Program Files\Dropbox\Client\Dropbox.exe" enable=yes profile=Any'
                condition: all of selection_* and not 1 of filter_optional_*
            falsepositives:
                - Legitimate administration activity
                - Software installations
            level: medium
            """
            )
        )
        == [
            'target.process.file.full_path = /.*\\\\netsh.exe$/ nocase AND target.process.command_line = /.* firewall .*/ nocase AND target.process.command_line = /.* add .*/ nocase AND (NOT (target.process.command_line = /.*advfirewall firewall add rule name=Dropbox dir=in action=allow \\"program=.:\\\\Program Files (x86)\\\\Dropbox\\\\Client\\\\Dropbox.exe\\" enable=yes profile=Any.*|.*advfirewall firewall add rule name=Dropbox dir=in action=allow \\"program=.:\\\\Program Files\\\\Dropbox\\\\Client\\\\Dropbox.exe\\" enable=yes profile=Any.*/ nocase))'
        ]
    )
