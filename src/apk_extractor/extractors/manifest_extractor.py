"""Manifest feature extractor."""

from typing import Any, Dict, List
from pathlib import Path
from apk_extractor.extractors.base import BaseExtractor
from apk_extractor.models.features import ManifestFeatures


class ManifestExtractor(BaseExtractor):
    """Extract features from AndroidManifest.xml."""
    
    def __init__(self):
        """Initialize manifest extractor."""
        super().__init__(name="ManifestExtractor")
    
    def extract(self, apk_obj: Any, apk_path: Path) -> ManifestFeatures:
        """
        Extract manifest features from APK.
        
        Args:
            apk_obj: Androguard APK object
            apk_path: Path to APK file
        
        Returns:
            ManifestFeatures object
        """
        self.logger.info(f"Extracting manifest features from {apk_path.name}")
        
        # Basic package information
        package_name = apk_obj.get_package()
        version_code = apk_obj.get_androidversion_code()
        version_name = apk_obj.get_androidversion_name()
        
        # SDK versions
        min_sdk = apk_obj.get_min_sdk_version()
        target_sdk = apk_obj.get_target_sdk_version()
        max_sdk = apk_obj.get_max_sdk_version()
        
        # Component counts
        activities = apk_obj.get_activities()
        services = apk_obj.get_services()
        receivers = apk_obj.get_receivers()
        providers = apk_obj.get_providers()
        
        num_activities = len(activities)
        num_services = len(services)
        num_receivers = len(receivers)
        num_providers = len(providers)
        
        # Exported components
        num_exported_activities = self._count_exported_components(apk_obj, "activity")
        num_exported_services = self._count_exported_components(apk_obj, "service")
        num_exported_receivers = self._count_exported_components(apk_obj, "receiver")
        num_exported_providers = self._count_exported_components(apk_obj, "provider")
        
        # Permissions
        permissions = apk_obj.get_permissions()
        num_permissions = len(permissions)
        
        # Count dangerous vs normal permissions
        dangerous_perms = self._count_dangerous_permissions(permissions)
        normal_perms = self._count_normal_permissions(permissions)
        custom_perms = num_permissions - dangerous_perms - normal_perms
        
        # Features (hardware/software features required)
        features = apk_obj.get_features()
        num_features = len(features)
        num_required_features = self._count_required_features(apk_obj)
        
        # Intent filters
        num_intent_filters = self._count_intent_filters(apk_obj)
        
        # Application flags
        has_main_activity = apk_obj.get_main_activity() is not None
        uses_native_code = self._uses_native_code(apk_obj)
        
        # Get application attributes from manifest
        debuggable = self._is_debuggable(apk_obj)
        allow_backup = self._allows_backup(apk_obj)
        test_only = self._is_test_only(apk_obj)
        
        return ManifestFeatures(
            package_name=package_name,
            version_code=int(version_code) if version_code else 0,
            version_name=version_name or "unknown",
            min_sdk_version=int(min_sdk) if min_sdk else 1,
            target_sdk_version=int(target_sdk) if target_sdk else 1,
            max_sdk_version=int(max_sdk) if max_sdk else None,
            num_activities=num_activities,
            num_services=num_services,
            num_receivers=num_receivers,
            num_providers=num_providers,
            num_exported_activities=num_exported_activities,
            num_exported_services=num_exported_services,
            num_exported_receivers=num_exported_receivers,
            num_exported_providers=num_exported_providers,
            num_permissions=num_permissions,
            num_dangerous_permissions=dangerous_perms,
            num_normal_permissions=normal_perms,
            num_custom_permissions=custom_perms,
            num_features=num_features,
            num_required_features=num_required_features,
            num_intent_filters=num_intent_filters,
            has_main_activity=has_main_activity,
            uses_native_code=uses_native_code,
            debuggable=debuggable,
            allow_backup=allow_backup,
            test_only=test_only,
        )
    
    def _count_exported_components(self, apk_obj: Any, component_type: str) -> int:
        """Count exported components of a specific type."""
        try:
            # Get the manifest XML
            from androguard.core.axml import AXMLPrinter
            import xml.etree.ElementTree as ET
            
            axml = apk_obj.get_android_manifest_axml()
            xml_string = AXMLPrinter(axml.get_buff()).get_xml()
            root = ET.fromstring(xml_string)
            
            # Namespace for Android manifest
            ns = {'android': 'http://schemas.android.com/apk/res/android'}
            
            # Find all components of the specified type
            components = root.findall(f".//application/{component_type}", ns)
            
            exported_count = 0
            for component in components:
                # Check if explicitly exported
                exported_attr = component.get('{http://schemas.android.com/apk/res/android}exported')
                
                # Check for intent filters (implicitly exported if has intent-filter)
                has_intent_filter = len(component.findall('intent-filter')) > 0
                
                if exported_attr == 'true' or (exported_attr is None and has_intent_filter):
                    exported_count += 1
            
            return exported_count
        except Exception as e:
            self.logger.warning(f"Failed to count exported {component_type}s: {e}")
            return 0
    
    def _count_dangerous_permissions(self, permissions: List[str]) -> int:
        """Count dangerous permissions."""
        # List of dangerous permissions (Android 13/API 33)
        dangerous_permissions = {
            'android.permission.READ_CALENDAR',
            'android.permission.WRITE_CALENDAR',
            'android.permission.CAMERA',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.GET_ACCOUNTS',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.ACCESS_BACKGROUND_LOCATION',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_PHONE_STATE',
            'android.permission.READ_PHONE_NUMBERS',
            'android.permission.CALL_PHONE',
            'android.permission.ANSWER_PHONE_CALLS',
            'android.permission.READ_CALL_LOG',
            'android.permission.WRITE_CALL_LOG',
            'android.permission.ADD_VOICEMAIL',
            'android.permission.USE_SIP',
            'android.permission.PROCESS_OUTGOING_CALLS',
            'android.permission.BODY_SENSORS',
            'android.permission.SEND_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.READ_SMS',
            'android.permission.RECEIVE_WAP_PUSH',
            'android.permission.RECEIVE_MMS',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.ACCESS_MEDIA_LOCATION',
        }
        
        return sum(1 for perm in permissions if perm in dangerous_permissions)
    
    def _count_normal_permissions(self, permissions: List[str]) -> int:
        """Count normal (non-dangerous) Android permissions."""
        # Common normal permissions
        normal_permissions = {
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.ACCESS_WIFI_STATE',
            'android.permission.CHANGE_WIFI_STATE',
            'android.permission.BLUETOOTH',
            'android.permission.BLUETOOTH_ADMIN',
            'android.permission.VIBRATE',
            'android.permission.WAKE_LOCK',
            'android.permission.FOREGROUND_SERVICE',
            'android.permission.REQUEST_INSTALL_PACKAGES',
        }
        
        return sum(1 for perm in permissions if perm in normal_permissions)
    
    def _count_required_features(self, apk_obj: Any) -> int:
        """Count required features."""
        try:
            import xml.etree.ElementTree as ET
            from androguard.core.axml import AXMLPrinter
            
            axml = apk_obj.get_android_manifest_axml()
            xml_string = AXMLPrinter(axml.get_buff()).get_xml()
            root = ET.fromstring(xml_string)
            
            ns = {'android': 'http://schemas.android.com/apk/res/android'}
            features = root.findall('.//uses-feature', ns)
            
            required_count = 0
            for feature in features:
                required = feature.get('{http://schemas.android.com/apk/res/android}required')
                if required != 'false':
                    required_count += 1
            
            return required_count
        except Exception as e:
            self.logger.warning(f"Failed to count required features: {e}")
            return 0
    
    def _count_intent_filters(self, apk_obj: Any) -> int:
        """Count total intent filters."""
        try:
            import xml.etree.ElementTree as ET
            from androguard.core.axml import AXMLPrinter
            
            axml = apk_obj.get_android_manifest_axml()
            xml_string = AXMLPrinter(axml.get_buff()).get_xml()
            root = ET.fromstring(xml_string)
            
            intent_filters = root.findall('.//intent-filter')
            return len(intent_filters)
        except Exception as e:
            self.logger.warning(f"Failed to count intent filters: {e}")
            return 0
    
    def _uses_native_code(self, apk_obj: Any) -> bool:
        """Check if APK uses native code (.so files)."""
        try:
            # Check for native libraries in lib/ directory
            files = apk_obj.get_files()
            return any(f.startswith('lib/') and f.endswith('.so') for f in files)
        except Exception:
            return False
    
    def _is_debuggable(self, apk_obj: Any) -> bool:
        """Check if application is debuggable."""
        try:
            import xml.etree.ElementTree as ET
            from androguard.core.axml import AXMLPrinter
            
            axml = apk_obj.get_android_manifest_axml()
            xml_string = AXMLPrinter(axml.get_buff()).get_xml()
            root = ET.fromstring(xml_string)
            
            ns = {'android': 'http://schemas.android.com/apk/res/android'}
            app = root.find('.//application', ns)
            
            if app is not None:
                debuggable = app.get('{http://schemas.android.com/apk/res/android}debuggable')
                return debuggable == 'true'
            
            return False
        except Exception:
            return False
    
    def _allows_backup(self, apk_obj: Any) -> bool:
        """Check if application allows backup."""
        try:
            import xml.etree.ElementTree as ET
            from androguard.core.axml import AXMLPrinter
            
            axml = apk_obj.get_android_manifest_axml()
            xml_string = AXMLPrinter(axml.get_buff()).get_xml()
            root = ET.fromstring(xml_string)
            
            ns = {'android': 'http://schemas.android.com/apk/res/android'}
            app = root.find('.//application', ns)
            
            if app is not None:
                allow_backup = app.get('{http://schemas.android.com/apk/res/android}allowBackup')
                return allow_backup != 'false'
            
            return True  # Default is true
        except Exception:
            return True
    
    def _is_test_only(self, apk_obj: Any) -> bool:
        """Check if application is test-only."""
        try:
            import xml.etree.ElementTree as ET
            from androguard.core.axml import AXMLPrinter
            
            axml = apk_obj.get_android_manifest_axml()
            xml_string = AXMLPrinter(axml.get_buff()).get_xml()
            root = ET.fromstring(xml_string)
            
            ns = {'android': 'http://schemas.android.com/apk/res/android'}
            app = root.find('.//application', ns)
            
            if app is not None:
                test_only = app.get('{http://schemas.android.com/apk/res/android}testOnly')
                return test_only == 'true'
            
            return False
        except Exception:
            return False
