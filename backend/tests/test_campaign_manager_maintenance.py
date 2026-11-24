from __future__ import annotations
from datetime import datetime, timedelta, timezone
import pytest
from campaign_manager import CampaignManager

@pytest.fixture()
def manager(monkeypatch):
    monkeypatch.setattr('campaign_manager.create_campaign_db', lambda attacker_ip, victim_ip, event_time=None: 'CAMP_TEST_UNKNOWN')
    monkeypatch.setattr('campaign_manager.expire_stale_campaigns_db', lambda timeout, reference_time=None: [])
    monkeypatch.setattr('campaign_manager.close_campaign_db', lambda campaign_id, closed_at=None: None)
    return CampaignManager()

def test_create_campaign_context_populates_first_and_last_seen(manager):
    context = manager.create_campaign_context('10.0.0.5', '10.0.0.9', current_technique=None)
    assert context.first_seen is not None
    assert context.last_seen is not None
    assert isinstance(context.last_seen, datetime)
    assert context.last_seen.tzinfo is not None

def test_expire_active_campaigns_does_not_crash_on_an_unknown_first_event_context(manager):
    manager.create_campaign_context('10.0.0.5', '10.0.0.9', current_technique=None)
    manager.expire_active_campaigns()

def test_expire_active_campaigns_actually_expires_a_genuinely_stale_unknown_context(manager, monkeypatch):
    from config import CAMPAIGN_TIMEOUT
    context = manager.create_campaign_context('10.0.0.5', '10.0.0.9', current_technique=None)
    context.last_seen = datetime.now(timezone.utc) - timedelta(seconds=CAMPAIGN_TIMEOUT + 30)
    closed = []
    monkeypatch.setattr('campaign_manager.close_campaign_db', lambda campaign_id, closed_at=None: closed.append(campaign_id))
    manager.expire_active_campaigns()
    assert context.status == 'INACTIVE'
    assert closed == ['CAMP_TEST_UNKNOWN']