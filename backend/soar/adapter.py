from __future__ import annotations
import copy
from campaign_context import CampaignContext
from soar.schema import Playbook, _new_id
_IDENTITY_INPUT_KEYS = {'ip', 'campaign_id', 'operation_id'}

class PlaybookAdaptation:

    def adapt(self, historical_playbook: Playbook, current_campaign: CampaignContext, operation_id: str | None=None) -> Playbook:
        adapted = copy.deepcopy(historical_playbook)
        adapted.playbook_id = _new_id('pb')
        adapted.version = 1
        adapted.adapted_from_playbook_id = historical_playbook.playbook_id
        adapted.source_campaign_id = current_campaign.campaign_id
        adapted.name = f'{historical_playbook.name}_ADAPTED'
        adapted.trigger_conditions = {**historical_playbook.trigger_conditions, 'adapted_from_campaign': historical_playbook.source_campaign_id}
        for action in adapted.actions:
            new_inputs = dict(action.inputs)
            for key in list(new_inputs.keys()):
                if key not in _IDENTITY_INPUT_KEYS:
                    continue
                if key == 'ip':
                    if new_inputs[key] and new_inputs[key] not in (current_campaign.attacker_ip, current_campaign.victim_ip):
                        continue
                elif key == 'campaign_id':
                    new_inputs[key] = current_campaign.campaign_id
                    continue
                elif key == 'operation_id':
                    new_inputs[key] = operation_id
                    continue
            if 'ip' in new_inputs:
                if action.action_type in ('enrich_ip', 'block_ip', 'threat_intel_lookup'):
                    new_inputs['ip'] = current_campaign.attacker_ip
                elif action.action_type in ('collect_evidence', 'isolate_host'):
                    new_inputs['ip'] = current_campaign.victim_ip
            action.inputs = new_inputs
            action.reason = f'[Adapted from {historical_playbook.playbook_id}] {action.reason}'
        return adapted