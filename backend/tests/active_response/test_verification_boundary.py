import inspect
from active_response.firewall_backend import InMemoryFirewallBackend
from active_response.verification import ContainmentVerifier, VerificationStatus

def test_firewall_state_only_is_insufficient_evidence():
    fw = InMemoryFirewallBackend()
    fw.block('10.0.0.5')
    result = ContainmentVerifier().verify('corr-1', '10.0.0.5', fw)
    assert result.status == VerificationStatus.INSUFFICIENT_EVIDENCE

def test_response_agent_success_only_is_insufficient_evidence():
    from active_response.client_agent import Authenticator, ClientResponseAgent, ContainmentRequest
    from active_response.containment_actions import ContainmentAction
    agent = ClientResponseAgent(InMemoryFirewallBackend(), Authenticator('secret'))
    result = agent.handle(ContainmentRequest('corr-1', ContainmentAction.BLOCK_SOURCE_IP, '10.0.0.5', 'dec-1', 'secret'))
    assert result.containment_status == 'EXECUTED'
    verification = ContainmentVerifier().verify('corr-1', '10.0.0.5', agent.firewall)
    assert verification.status == VerificationStatus.INSUFFICIENT_EVIDENCE

def test_verify_signature_has_no_shuffle_or_http_status_parameter():
    params = set(inspect.signature(ContainmentVerifier.verify).parameters)
    for banned in ('shuffle_success', 'http_status', 'api_response', 'shuffle_result', 'acknowledgment'):
        assert banned not in params

def test_shuffle_success_concept_cannot_reach_verified_even_if_smuggled_via_wazuh_recurrence_field():
    fw = InMemoryFirewallBackend()
    fw.block('10.0.0.5')
    result = ContainmentVerifier().verify('corr-1', '10.0.0.5', fw, wazuh_telemetry_recurrence=False)
    assert result.status != VerificationStatus.VERIFIED
    assert result.status == VerificationStatus.INSUFFICIENT_EVIDENCE