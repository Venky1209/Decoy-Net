"""
Test the new scam dataset against the detection engine.
Verifies all scam types from the 2025 dataset are properly detected.
"""
import sys
sys.path.insert(0, 'd:\\honeypot')

from data.scam_dataset_2025 import (
    ALL_SCAM_MESSAGES, SCAM_MESSAGES, LEGIT_MESSAGES,
    get_dataset_stats, ScamType
)
from utils.scam_patterns_2025 import scam_engine_2025


def test_dataset_detection():
    """Test all messages from the dataset against the detection engine."""
    print("=" * 60)
    print("SCAM DATASET 2025 - DETECTION TEST")
    print("=" * 60)
    
    # Print dataset stats
    stats = get_dataset_stats()
    print(f"\n📊 Dataset Statistics:")
    print(f"   Total Messages: {stats['total_messages']}")
    print(f"   Scam Messages: {stats['scam_messages']}")
    print(f"   Legitimate Messages: {stats['legitimate_messages']}")
    print(f"   Scam Types: {stats['scam_types']}")
    print(f"   High Severity (8+): {stats['high_severity_count']}")
    
    # Test scam messages
    print(f"\n🔍 Testing Scam Detection...")
    scam_correct = 0
    scam_failed = []
    
    for msg in SCAM_MESSAGES:
        result = scam_engine_2025.analyze(msg.message)
        if result["is_scam"]:
            scam_correct += 1
        else:
            scam_failed.append({
                "id": msg.id,
                "type": msg.scam_type.value,
                "confidence": result["confidence"],
                "message": msg.message[:60] + "..."
            })
    
    # Test legitimate messages (should NOT be flagged)
    print(f"\n🔍 Testing False Positive Prevention...")
    legit_correct = 0
    legit_failed = []
    
    for msg in LEGIT_MESSAGES:
        result = scam_engine_2025.analyze(msg.message)
        if not result["is_scam"]:
            legit_correct += 1
        else:
            legit_failed.append({
                "id": msg.id,
                "confidence": result["confidence"],
                "category": result.get("category"),
                "message": msg.message[:60] + "..."
            })
    
    # Results
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    
    scam_accuracy = (scam_correct / len(SCAM_MESSAGES)) * 100 if SCAM_MESSAGES else 0
    legit_accuracy = (legit_correct / len(LEGIT_MESSAGES)) * 100 if LEGIT_MESSAGES else 0
    
    print(f"\n✅ Scam Detection Rate: {scam_correct}/{len(SCAM_MESSAGES)} ({scam_accuracy:.1f}%)")
    print(f"✅ False Positive Prevention: {legit_correct}/{len(LEGIT_MESSAGES)} ({legit_accuracy:.1f}%)")
    
    if scam_failed:
        print(f"\n❌ Failed Scam Detections ({len(scam_failed)}):")
        for fail in scam_failed[:5]:  # Show first 5
            print(f"   [{fail['id']}] {fail['type']}: conf={fail['confidence']:.2f}")
            print(f"       {fail['message']}")
    
    if legit_failed:
        print(f"\n⚠️ False Positives ({len(legit_failed)}):")
        for fail in legit_failed:
            print(f"   [{fail['id']}]: Detected as {fail['category']} (conf={fail['confidence']:.2f})")
    
    # Test by category
    print("\n" + "-" * 60)
    print("DETECTION BY CATEGORY")
    print("-" * 60)
    
    category_stats = {}
    for msg in SCAM_MESSAGES:
        cat = msg.scam_type.value
        if cat not in category_stats:
            category_stats[cat] = {"total": 0, "detected": 0}
        category_stats[cat]["total"] += 1
        
        result = scam_engine_2025.analyze(msg.message)
        if result["is_scam"]:
            category_stats[cat]["detected"] += 1
    
    for cat, data in sorted(category_stats.items()):
        rate = (data["detected"] / data["total"]) * 100
        status = "✅" if rate >= 80 else "⚠️" if rate >= 50 else "❌"
        print(f"{status} {cat}: {data['detected']}/{data['total']} ({rate:.0f}%)")
    
    # Overall score
    overall = ((scam_correct / len(SCAM_MESSAGES)) * 0.7 + 
               (legit_correct / len(LEGIT_MESSAGES)) * 0.3) * 100 if SCAM_MESSAGES and LEGIT_MESSAGES else 0
    
    print("\n" + "=" * 60)
    print(f"📈 OVERALL SCORE: {overall:.1f}%")
    if overall >= 90:
        print("🎉 EXCELLENT - Ready for production!")
    elif overall >= 80:
        print("✅ GOOD - Minor improvements needed")
    elif overall >= 70:
        print("⚠️ FAIR - Some patterns need tuning")
    else:
        print("❌ NEEDS WORK - Significant improvements required")
    print("=" * 60)
    
    return overall >= 80


if __name__ == "__main__":
    success = test_dataset_detection()
    sys.exit(0 if success else 1)
