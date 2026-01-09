#!/usr/bin/env python3
"""
Verification script to ensure all STIX 2.1 SDO types are created in demo data
and that data is coherent with proper references.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.services.elasticsearch_service import ElasticsearchService


def verify_sdo_coverage():
    """Verify that all 13 STIX 2.1 SDO types have at least one object in the database."""
    
    # All STIX 2.1 Domain Object types we support
    REQUIRED_SDO_TYPES = [
        'attack-pattern',
        'campaign',
        'course-of-action',
        'identity',
        'infrastructure',
        'intrusion-set',
        'location',
        'malware',
        'note',
        'observed-data',
        'opinion',
        'report',
        'threat-actor',
    ]
    
    app = create_app()
    
    with app.app_context():
        es = ElasticsearchService()
        
        print("\n" + "=" * 70)
        print("STIX 2.1 SDO Type Coverage Verification")
        print("=" * 70)
        
        coverage_results = {}
        total_objects = 0
        
        for sdo_type in REQUIRED_SDO_TYPES:
            try:
                # Search for objects of this type
                result = es.search(
                    'stix_objects',
                    query={
                        'query': {
                            'match': {'type': sdo_type}
                        }
                    },
                    size=1000
                )
                
                count = result.get('hits', {}).get('total', {}).get('value', 0)
                coverage_results[sdo_type] = count
                total_objects += count
                
                status = "✓ OK" if count > 0 else "✗ MISSING"
                print(f"{status:8} | {sdo_type:20} | Count: {count:4}")
                
            except Exception as e:
                coverage_results[sdo_type] = 0
                print(f"✗ ERROR  | {sdo_type:20} | Error: {str(e)[:50]}")
        
        # Summary
        print("\n" + "-" * 70)
        covered = sum(1 for count in coverage_results.values() if count > 0)
        print(f"Coverage: {covered}/{len(REQUIRED_SDO_TYPES)} SDO types")
        print(f"Total objects created: {total_objects}")
        
        # Check for missing types
        missing = [t for t, count in coverage_results.items() if count == 0]
        if missing:
            print(f"\n⚠ MISSING TYPES: {', '.join(missing)}")
        else:
            print(f"\n✓ ALL SDO TYPES COVERED!")
        
        return coverage_results


def verify_data_coherence():
    """Verify that created data has coherent relationships and references."""
    
    app = create_app()
    
    with app.app_context():
        es = ElasticsearchService()
        
        print("\n" + "=" * 70)
        print("Data Coherence Verification")
        print("=" * 70)
        
        # Check for relationships
        try:
            rel_result = es.search(
                'stix_relationships',
                query={'query': {'match_all': {}}},
                size=1
            )
            rel_count = rel_result.get('hits', {}).get('total', {}).get('value', 0)
            print(f"✓ Relationships created: {rel_count}")
            
            if rel_count == 0:
                print("  ⚠ Warning: No relationships found")
        except Exception as e:
            print(f"✗ Error checking relationships: {e}")
        
        # Check specific relationship types
        relationship_types = [
            'attributed-to',
            'uses',
            'targets',
            'indicates',
            'related-to',
            'variant-of',
            'communicates-with',
            'delivers',
        ]
        
        print("\nRelationship Types Found:")
        for rel_type in relationship_types:
            try:
                result = es.search(
                    'stix_relationships',
                    query={
                        'query': {
                            'match': {'relationship_type': rel_type}
                        }
                    },
                    size=1
                )
                count = result.get('hits', {}).get('total', {}).get('value', 0)
                if count > 0:
                    print(f"  ✓ {rel_type:20} | Count: {count}")
            except:
                pass
        
        # Verify object_refs in Report, Opinion, Note, Observed-data
        print("\nVerifying object_refs in multi-object types:")
        
        for obj_type in ['report', 'opinion', 'note', 'observed-data']:
            try:
                result = es.search(
                    'stix_objects',
                    query={
                        'query': {
                            'bool': {
                                'must': [
                                    {'match': {'type': obj_type}},
                                    {'exists': {'field': 'object_refs'}}
                                ]
                            }
                        }
                    },
                    size=100
                )
                
                objs_with_refs = result.get('hits', {}).get('total', {}).get('value', 0)
                total_objs = es.search(
                    'stix_objects',
                    query={'query': {'match': {'type': obj_type}}},
                    size=1
                ).get('hits', {}).get('total', {}).get('value', 0)
                
                if total_objs > 0:
                    pct = (objs_with_refs / total_objs) * 100
                    status = "✓" if pct >= 50 else "⚠"
                    print(f"  {status} {obj_type:20} | {objs_with_refs}/{total_objs} have object_refs ({pct:.0f}%)")
            except Exception as e:
                print(f"  ✗ {obj_type:20} | Error: {str(e)[:40]}")
        
        return True


def verify_scenario_coherence():
    """Verify that objects from same scenario are properly linked."""
    
    app = create_app()
    
    with app.app_context():
        es = ElasticsearchService()
        
        print("\n" + "=" * 70)
        print("Scenario Coherence Verification")
        print("=" * 70)
        
        # Get unique labels to identify scenarios
        try:
            result = es.search(
                'stix_objects',
                query={
                    'aggs': {
                        'labels': {
                            'terms': {
                                'field': 'labels.keyword',
                                'size': 50
                            }
                        }
                    }
                },
                size=0
            )
            
            labels = result.get('aggregations', {}).get('labels', {}).get('buckets', [])
            
            # Look for scenario labels
            scenario_labels = [b for b in labels if any(x in b['key'] for x in ['apt29', 'lockbit', 'fin7'])]
            
            print(f"Found {len(scenario_labels)} scenario-related labels:")
            for label in scenario_labels:
                print(f"  • {label['key']:30} | Count: {label['doc_count']}")
            
            if scenario_labels:
                print("\n✓ Multiple scenarios detected in data")
            else:
                print("\n⚠ No scenario-specific labels found")
                
        except Exception as e:
            print(f"✗ Error analyzing scenarios: {e}")


def main():
    """Run all verifications."""
    print("\n" + "=" * 70)
    print("ELASLIP Demo Data Verification Suite")
    print("=" * 70)
    
    try:
        coverage = verify_sdo_coverage()
        coherence = verify_data_coherence()
        scenarios = verify_scenario_coherence()
        
        print("\n" + "=" * 70)
        print("Verification Complete")
        print("=" * 70)
        
        # Final summary
        covered = sum(1 for count in coverage.values() if count > 0)
        if covered == len(coverage):
            print(f"\n✓ PASSED: All {len(coverage)} SDO types are covered")
            return 0
        else:
            print(f"\n✗ FAILED: Only {covered}/{len(coverage)} SDO types covered")
            return 1
            
    except Exception as e:
        print(f"\n✗ Fatal error during verification: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
