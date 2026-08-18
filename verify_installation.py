"""
Quick test script to verify the APK Feature Extractor is working.
Run this after installation to confirm everything is set up correctly.
"""

def test_imports():
    """Test that all modules can be imported."""
    print("Testing imports...")
    
    try:
        from apk_extractor import APKFeatureExtractor
        print("  ✓ APKFeatureExtractor imported")
        
        from apk_extractor.extractors import (
            ManifestExtractor,
            PermissionExtractor,
            APIExtractor,
            StructuralExtractor,
        )
        print("  ✓ All extractors imported")
        
        from apk_extractor.models import APKFeatures
        print("  ✓ Data models imported")
        
        return True
    except Exception as e:
        print(f"  ✗ Import failed: {e}")
        return False


def test_extractor_initialization():
    """Test that the extractor can be initialized."""
    print("\nTesting extractor initialization...")
    
    try:
        from apk_extractor import APKFeatureExtractor
        extractor = APKFeatureExtractor(log_level="INFO")
        print("  ✓ APKFeatureExtractor initialized")
        return True
    except Exception as e:
        print(f"  ✗ Initialization failed: {e}")
        return False


def test_dependencies():
    """Test that key dependencies are installed."""
    print("\nTesting dependencies...")
    
    dependencies = [
        ('androguard', 'androguard.core.apk'),
        ('pandas', 'pandas'),
        ('pydantic', 'pydantic'),
        ('click', 'click'),
        ('rich', 'rich'),
        ('loguru', 'loguru'),
    ]
    
    all_ok = True
    for name, module in dependencies:
        try:
            __import__(module)
            print(f"  ✓ {name} installed")
        except ImportError:
            print(f"  ✗ {name} NOT installed")
            all_ok = False
    
    return all_ok


def main():
    """Run all tests."""
    print("="*60)
    print("  APK Feature Extractor - Installation Verification")
    print("="*60)
    print()
    
    results = []
    
    # Test imports
    results.append(("Imports", test_imports()))
    
    # Test initialization
    results.append(("Initialization", test_extractor_initialization()))
    
    # Test dependencies
    results.append(("Dependencies", test_dependencies()))
    
    # Summary
    print("\n" + "="*60)
    print("  Summary")
    print("="*60)
    
    all_passed = True
    for test_name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {test_name}: {status}")
        if not passed:
            all_passed = False
    
    print("="*60)
    
    if all_passed:
        print("\n🎉 All tests passed! The system is ready to use.")
        print("\nNext steps:")
        print("  1. Place APK files in: data/input/")
        print("  2. Run: apk-extract batch data/input/ -o features.csv")
        print("  3. Or try: python scripts/example_single_apk.py")
    else:
        print("\n⚠ Some tests failed. Please check the installation.")
        print("\nTry:")
        print("  pip install -r requirements.txt")
        print("  pip install -e .")
    
    print()
    return 0 if all_passed else 1


if __name__ == "__main__":
    exit(main())
