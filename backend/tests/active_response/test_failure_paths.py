import pytest
from active_response.client_agent import Authenticator, ClientResponseAgent, ContainmentRequest
from active_response.containment_actions import ContainmentAction
from active_response.firewall_backend import InMemoryFirewallBackend
from active_response.rollback import RollbackManager
from active_response.verification import ContainmentVerifier, VerificationStatus

def test_malformed_request_missing_required_field_fails_closed():
    with pytest.raises(TypeError):
        ContainmentRequest(correlation_id='c1', action=ContainmentAction.BLOCK_SOURCE_IP)

def test_expired_containment_is_detected_before_any_new_decision_relies_on_it():
    agent = ClientResponseAgent(InMemoryFirewallBackend(), Authenticator('secret'))
    result = agent.handle(ContainmentRequest('corr-1', ContainmentAction.BLOCK_SOURCE_IP, '10.0.0.5', 'dec-1', 'secret', ttl_seconds=1))
    manager = RollbackManager(agent)
    from datetime import datetime, timedelta, timezone
    later = datetime.fromisoformat(result.executed_at) + timedelta(seconds=5)
    assert manager.is_expired(result.expires_at, now=later) is True

def test_execution_succeeded_but_later_independent_verification_disagrees():
    fw = InMemoryFirewallBackend()
    agent = ClientResponseAgent(fw, Authenticator('secret'))
    result = agent.handle(ContainmentRequest('corr-1', ContainmentAction.BLOCK_SOURCE_IP, '10.0.0.5', 'dec-1', 'secret'))
    assert result.containment_status == 'EXECUTED'
    fw.unblock('10.0.0.5')
    verification = ContainmentVerifier().verify('corr-1', '10.0.0.5', fw, pre_attack_reachable=True, post_attack_reachable=True)
    assert verification.status == VerificationStatus.NOT_VERIFIED

def test_unauthenticated_client_agent_construction_still_requires_real_token():
    agent = ClientResponseAgent(InMemoryFirewallBackend(), Authenticator(expected_token=''))
    result = agent.handle(ContainmentRequest('corr-1', ContainmentAction.BLOCK_SOURCE_IP, '10.0.0.5', 'dec-1', ''))
    assert result.containment_status == 'REJECTED'