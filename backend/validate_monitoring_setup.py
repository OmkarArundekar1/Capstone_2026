import os
import sys
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

sys.path.insert(0, str(Path(__file__).parent))

try:
    from neo4j import GraphDatabase
except ImportError:
    print("ERROR: neo4j package not installed. Run: pip install neo4j", file=sys.stderr)
    sys.exit(1)

try:
    from dotenv import load_dotenv
except ImportError:
    print("WARNING: python-dotenv not installed. Using environment variables directly.", file=sys.stderr)
    load_dotenv = None


class MonitoringSetupValidator:
    def __init__(self):
        if load_dotenv:
            env_path = Path(__file__).parent / '.env'
            if env_path.exists():
                load_dotenv(env_path)

        self.neo4j_uri = os.getenv('NEO4J_URI', 'bolt://localhost:7687')
        self.neo4j_user = os.getenv('NEO4J_USERNAME', 'neo4j')
        self.neo4j_password = os.getenv('NEO4J_PASSWORD', 'password')

        self.checks_passed = 0
        self.checks_failed = 0
        self.checks_warnings = 0

    def print_header(self, title: str):
        print(f"\n{'='*70}")
        print(f"  {title}")
        print(f"{'='*70}")

    def print_success(self, message: str):
        print(f"✅ {message}")
        self.checks_passed += 1

    def print_failure(self, message: str):
        print(f"❌ {message}")
        self.checks_failed += 1

    def print_warning(self, message: str):
        print(f"⚠️  {message}")
        self.checks_warnings += 1

    def check_neo4j_connectivity(self) -> bool:
        self.print_header("Check 1: Neo4j Connectivity")

        try:
            driver = GraphDatabase.driver(
                self.neo4j_uri,
                auth=(self.neo4j_user, self.neo4j_password)
            )

            with driver.session() as session:
                result = session.run("RETURN 1 AS test")
                record = result.single()

                if record and record["test"] == 1:
                    self.print_success(f"Neo4j connection successful: {self.neo4j_uri}")

                    result = session.run("MATCH (c:Campaign) RETURN count(c) AS campaign_count")
                    record = result.single()
                    campaign_count = record["campaign_count"] if record else 0

                    result = session.run("MATCH (e:AttackEvent) RETURN count(e) AS event_count")
                    record = result.single()
                    event_count = record["event_count"] if record else 0

                    print(f"   Database stats: {campaign_count} campaigns, {event_count} events")

                    driver.close()
                    return True
                else:
                    self.print_failure("Neo4j connection test query failed")
                    driver.close()
                    return False

        except Exception as e:
            self.print_failure(f"Neo4j connection failed: {e}")
            return False

    def check_baseline_campaigns(self) -> Optional[datetime]:
        self.print_header("Check 2: Baseline Campaign Data")

        try:
            driver = GraphDatabase.driver(
                self.neo4j_uri,
                auth=(self.neo4j_user, self.neo4j_password)
            )

            with driver.session() as session:
                result = session.run("""
                    MATCH (c:Campaign)
                    RETURN c.campaign_id AS campaign_id,
                           c.first_seen AS first_seen,
                           c.last_seen AS last_seen,
                           c.attacker_ip AS attacker_ip,
                           c.victim_ip AS victim_ip
                    ORDER BY c.first_seen DESC
                    LIMIT 1
        self.print_header("Check 3: Code Version (Fix Present)")

        try:
            result = subprocess.run(
                ['git', 'log', '-1', '--oneline'],
                cwd=Path(__file__).parent.parent.parent,
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                commit_line = result.stdout.strip()
                print(f"   Current commit: {commit_line}")

            engine_path = Path(__file__).parent / 'campaign_decision_engine.py'

            if not engine_path.exists():
                self.print_failure(f"campaign_decision_engine.py not found at {engine_path}")
                return False

            with open(engine_path, 'r') as f:
                content = f.read()

            if 'lateral_movement_similarity' in content:
                self.print_success("lateral_movement_similarity fix is present in campaign_decision_engine.py")

                lines = content.split('\n')
                for i, line in enumerate(lines, 1):
                    if 'lateral_movement_similarity' in line and 'breakdown' in line:
                        print(f"   Found at line {i}: {line.strip()}")
                        break

                return True
            else:
                self.print_failure("lateral_movement_similarity NOT FOUND in campaign_decision_engine.py")
                self.print_warning("Fix may not be deployed. Service restart with corrected code required.")
                return False

        except subprocess.TimeoutExpired:
            self.print_warning("Git command timeout")
            return False
        except Exception as e:
            self.print_failure(f"Failed to check code version: {e}")
            return False

    def check_service_status(self) -> bool:
        self.print_header("Check 4: Service Status")

        try:
            result = subprocess.run(
                ['ps', 'aux'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                if 'realtime_socgraph' in result.stdout:
                    self.print_success("realtime_socgraph service is RUNNING")

                    for line in result.stdout.split('\n'):
                        if 'realtime_socgraph' in line and 'grep' not in line:
                            print(f"   Process: {line.strip()}")
                            break

                    return True
                else:
                    self.print_warning("realtime_socgraph service NOT RUNNING")
                    print("   Service must be restarted with corrected code before observation starts.")
                    return False
            else:
                self.print_warning("Could not check service status (ps command failed)")
                return False

        except subprocess.TimeoutExpired:
            self.print_warning("Process check timeout")
            return False
        except FileNotFoundError:
            self.print_warning("'ps' command not available (Windows/non-Unix system)")
            print("   Manual service verification required.")
            return False
        except Exception as e:
            self.print_warning(f"Failed to check service status: {e}")
            return False

    def check_fix_deployment_window(self, latest_campaign_time: Optional[datetime]) -> Dict[str, Any]:
        self.print_header("Check 5: Fix Deployment Status")

        fix_commit_time = datetime(2026, 11, 23, 14, 21, 29, tzinfo=timezone.utc)

        print(f"   Fix commit timestamp: {fix_commit_time.isoformat()}")

        if not latest_campaign_time:
            self.print_warning("Cannot determine deployment status (no campaign data)")
            return {
                "deployed": False,
                "reason": "no_campaign_data"
            }

        if latest_campaign_time.tzinfo is None:
            latest_campaign_time = latest_campaign_time.replace(tzinfo=timezone.utc)

        print(f"   Latest campaign timestamp: {latest_campaign_time.isoformat()}")

        time_diff = (latest_campaign_time - fix_commit_time).total_seconds()

        if time_diff > 0:
            self.print_success("Post-fix campaigns detected!")
            print(f"   Time since fix: {time_diff / 3600:.1f} hours")
            print(f"   Observation window can begin: {latest_campaign_time.isoformat()}")

            return {
                "deployed": True,
                "observation_start": latest_campaign_time,
                "reason": "post_fix_campaigns_exist"
            }
        else:
            gap_hours = abs(time_diff) / 3600
            self.print_warning(f"No post-fix campaigns detected (gap: {gap_hours:.1f} hours)")
            print("   Service must be restarted with corrected code.")
            print(f"   After restart, first campaign will establish observation start point.")

            return {
                "deployed": False,
                "observation_start": None,
                "gap_hours": gap_hours,
                "reason": "no_post_fix_campaigns"
            }

    def run_all_checks(self) -> Dict[str, Any]:
        print("\n" + "="*70)
        print("  PHASE B.2 MONITORING SETUP VALIDATION")
        print("  Lateral Movement Similarity Fix - Operational Validation")
        print("="*70)

        neo4j_ok = self.check_neo4j_connectivity()

        if not neo4j_ok:
            print("\n" + "="*70)
            print("❌ VALIDATION FAILED: Neo4j connectivity issue")
            print("="*70)
            return {"status": "FAILED", "reason": "neo4j_connectivity"}

        latest_campaign_time = self.check_baseline_campaigns()

        code_ok = self.check_code_version()

        service_running = self.check_service_status()

        deployment_status = self.check_fix_deployment_window(latest_campaign_time)

        self.print_header("VALIDATION SUMMARY")

        print(f"   ✅ Checks passed: {self.checks_passed}")
        print(f"   ❌ Checks failed: {self.checks_failed}")
        print(f"   ⚠️  Warnings: {self.checks_warnings}")

        if self.checks_failed > 0:
            status = "FAILED"
            message = "Critical checks failed. Cannot proceed."
        elif deployment_status["deployed"]:
            status = "READY"
            message = "✅ System is READY for metric collection!"
        elif service_running and code_ok:
            status = "PENDING"
            message = "Service running but no post-fix campaigns yet. Wait for first campaign."
        elif code_ok:
            status = "BLOCKED"
            message = "Service NOT RUNNING. Restart required with corrected code."
        else:
            status = "BLOCKED"
            message = "Fix not deployed. Code update and service restart required."

        print(f"\n{'='*70}")
        print(f"  STATUS: {status}")
        print(f"  {message}")
        print(f"{'='*70}")

        if status == "READY":
            print("\n📋 NEXT STEPS:")
            print("1. Run collect_campaign_metrics.py with observation start timestamp:")
            print(f"   python collect_campaign_metrics.py \\")
            print(f"     --observation-start \"{deployment_status['observation_start'].isoformat()}\" \\")
            print(f"     --output metrics_observation.json")
            print("\n2. After observation period (28 days recommended), compare metrics:")
            print("   python compare_metrics.py \\")
            print("     --baseline metrics_baseline.json \\")
            print("     --observation metrics_observation.json \\")
            print("     --output comparison_report.json")

        elif status == "BLOCKED" and not service_running:
            print("\n📋 NEXT STEPS:")
            print("1. Verify correct code version deployed:")
            print("   git log -1 --oneline")
            print("
            print("\n2. Restart realtime_socgraph service:")
            print("   cd isfcr/CYUKTI/backend")
            print("
            print("   pkill -f realtime_socgraph")
            print("
            print("   nohup python realtime_socgraph.py > realtime_socgraph.log 2>&1 &")
            print("\n3. Re-run validation after service starts:")
            print("   python validate_monitoring_setup.py")

        elif status == "PENDING":
            print("\n📋 NEXT STEPS:")
            print("1. Wait for first post-fix campaign to be created")
            print("   (Monitor realtime_socgraph.log for campaign creation)")
            print("\n2. Re-run validation to detect observation start:")
            print("   python validate_monitoring_setup.py")

        print()

        return {
            "status": status,
            "deployment_status": deployment_status,
            "checks_passed": self.checks_passed,
            "checks_failed": self.checks_failed,
            "checks_warnings": self.checks_warnings
        }


def main():
    validator = MonitoringSetupValidator()
    result = validator.run_all_checks()

    if result["status"] == "FAILED":
        sys.exit(1)
    elif result["status"] in ["BLOCKED", "PENDING"]:
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
