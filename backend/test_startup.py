import sys
print('=' * 60)
print('Testing CYUKTI Backend Startup Components')
print('=' * 60)
print('\n[1/5] Testing config...')
try:
    import config
    print('  ✓ Config loaded')
    print(f'  - MISP_URL: {config.MISP_URL}')
    print(f"  - Has VIRUSTOTAL_API_KEY: {hasattr(config, 'VIRUSTOTAL_API_KEY')}")
    print(f"  - Has SHUFFLE_WEBHOOK: {hasattr(config, 'SHUFFLE_WEBHOOK')}")
    print(f"  - Has AUTO_ENRICH_ATTACKERS: {hasattr(config, 'AUTO_ENRICH_ATTACKERS')}")
except Exception as e:
    print(f'  ✗ Config failed: {e}')
    sys.exit(1)
print('\n[2/5] Testing enhanced detection modules...')
try:
    from hybrid_threat_enrichment import get_enricher
    print('  ✓ hybrid_threat_enrichment imported')
    from intelligent_detection_system import get_detection_system
    print('  ✓ intelligent_detection_system imported')
    from enhanced_detection_api import enhanced_detection_bp
    print('  ✓ enhanced_detection_api imported')
except Exception as e:
    print(f'  ✗ Enhanced detection modules failed: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
print('\n[3/5] Testing SOAR module (deprecated)...')
try:
    from soar.api import soar_bp
    print('  ✓ soar.api imported (deprecated but working)')
except Exception as e:
    print(f'  ✗ SOAR module failed: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
print('\n[4/5] Testing dashboard API imports...')
try:
    import dashboard_api
    print('  ✓ dashboard_api imported')
except Exception as e:
    print(f'  ✗ Dashboard API failed: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
print('\n[5/5] Testing detection system initialization...')
try:
    detection_system = get_detection_system(auto_enrich=True, auto_execute_safe_actions=True, dry_run=True)
    print('  ✓ Detection system initialized')
    print(f'  - Auto enrich: {detection_system.auto_enrich}')
    print(f'  - Auto execute: {detection_system.auto_execute_safe_actions}')
    print(f'  - Dry run: {detection_system.dry_run}')
except Exception as e:
    print(f'  ✗ Detection system init failed: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
print('\n' + '=' * 60)
print('✅ ALL STARTUP TESTS PASSED')
print('=' * 60)
print('\nBackend should start successfully.')
print('Run: ./start_realtime_system.sh backend')