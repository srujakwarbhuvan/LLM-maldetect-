"""Test suite for manifest extractor."""

import pytest
from pathlib import Path
from unittest.mock import Mock, MagicMock
from apk_extractor.extractors.manifest_extractor import ManifestExtractor


class TestManifestExtractor:
    """Tests for ManifestExtractor."""
    
    @pytest.fixture
    def extractor(self):
        """Create ManifestExtractor instance."""
        return ManifestExtractor()
    
    @pytest.fixture
    def mock_apk(self):
        """Create mock APK object."""
        apk = Mock()
        apk.get_package.return_value = "com.example.testapp"
        apk.get_androidversion_code.return_value = "42"
        apk.get_androidversion_name.return_value = "1.2.3"
        apk.get_min_sdk_version.return_value = "21"
        apk.get_target_sdk_version.return_value = "33"
        apk.get_max_sdk_version.return_value = None
        apk.get_activities.return_value = ["Activity1", "Activity2"]
        apk.get_services.return_value = ["Service1"]
        apk.get_receivers.return_value = []
        apk.get_providers.return_value = []
        apk.get_permissions.return_value = [
            "android.permission.INTERNET",
            "android.permission.READ_SMS",
        ]
        apk.get_features.return_value = ["android.hardware.camera"]
        apk.get_main_activity.return_value = "MainActivity"
        apk.get_files.return_value = ["classes.dex", "AndroidManifest.xml"]
        return apk
    
    def test_extractor_initialization(self, extractor):
        """Test extractor initializes correctly."""
        assert extractor.name == "ManifestExtractor"
    
    def test_extract_basic_info(self, extractor, mock_apk):
        """Test extraction of basic package information."""
        features = extractor.extract(mock_apk, Path("test.apk"))
        
        assert features.package_name == "com.example.testapp"
        assert features.version_code == 42
        assert features.version_name == "1.2.3"
        assert features.min_sdk_version == 21
        assert features.target_sdk_version == 33
    
    def test_extract_component_counts(self, extractor, mock_apk):
        """Test component counting."""
        features = extractor.extract(mock_apk, Path("test.apk"))
        
        assert features.num_activities == 2
        assert features.num_services == 1
        assert features.num_receivers == 0
        assert features.num_providers == 0
    
    def test_extract_permissions(self, extractor, mock_apk):
        """Test permission extraction."""
        features = extractor.extract(mock_apk, Path("test.apk"))
        
        assert features.num_permissions == 2
        # INTERNET is normal, READ_SMS is dangerous
        assert features.num_dangerous_permissions >= 1
    
    def test_extract_flags(self, extractor, mock_apk):
        """Test boolean flags."""
        features = extractor.extract(mock_apk, Path("test.apk"))
        
        assert features.has_main_activity is True
        # No .so files in mock, so should be False
        assert features.uses_native_code is False
    
    def test_count_dangerous_permissions(self, extractor):
        """Test dangerous permission counting."""
        permissions = [
            "android.permission.INTERNET",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.CAMERA",
        ]
        
        count = extractor._count_dangerous_permissions(permissions)
        # READ_SMS, SEND_SMS, CAMERA are dangerous
        assert count == 3
    
    def test_count_normal_permissions(self, extractor):
        """Test normal permission counting."""
        permissions = [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.VIBRATE",
        ]
        
        count = extractor._count_normal_permissions(permissions)
        assert count == 3
    
    def test_uses_native_code(self, extractor, mock_apk):
        """Test native code detection."""
        # Test with no native libs
        mock_apk.get_files.return_value = ["classes.dex"]
        assert extractor._uses_native_code(mock_apk) is False
        
        # Test with native libs
        mock_apk.get_files.return_value = ["classes.dex", "lib/armeabi/test.so"]
        assert extractor._uses_native_code(mock_apk) is True


def test_manifest_extractor_import():
    """Test that ManifestExtractor can be imported."""
    from apk_extractor.extractors import ManifestExtractor
    assert ManifestExtractor is not None
