"""Permission feature extractor."""

from typing import Any, Dict, List, Set
from pathlib import Path
from apk_extractor.extractors.base import BaseExtractor
from apk_extractor.models.features import PermissionFeatures


class PermissionExtractor(BaseExtractor):
    """Extract permission features as binary flags."""
    
    # Comprehensive list of Android permissions (Android 13/API 33)
    KNOWN_PERMISSIONS = {
        # Dangerous permissions
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
        # Normal permissions
        'android.permission.INTERNET',
        'android.permission.ACCESS_NETWORK_STATE',
        'android.permission.ACCESS_WIFI_STATE',
        'android.permission.CHANGE_WIFI_STATE',
        'android.permission.CHANGE_NETWORK_STATE',
        'android.permission.BLUETOOTH',
        'android.permission.BLUETOOTH_ADMIN',
        'android.permission.BLUETOOTH_CONNECT',
        'android.permission.BLUETOOTH_SCAN',
        'android.permission.NFC',
        'android.permission.VIBRATE',
        'android.permission.WAKE_LOCK',
        'android.permission.FOREGROUND_SERVICE',
        'android.permission.REQUEST_INSTALL_PACKAGES',
        'android.permission.REQUEST_DELETE_PACKAGES',
        'android.permission.SET_ALARM',
        'android.permission.INSTALL_SHORTCUT',
        'android.permission.UNINSTALL_SHORTCUT',
        'android.permission.RECEIVE_BOOT_COMPLETED',
        'android.permission.BROADCAST_STICKY',
        'android.permission.EXPAND_STATUS_BAR',
        'android.permission.FLASHLIGHT',
        'android.permission.GET_PACKAGE_SIZE',
        'android.permission.KILL_BACKGROUND_PROCESSES',
        'android.permission.READ_SYNC_SETTINGS',
        'android.permission.WRITE_SYNC_SETTINGS',
        'android.permission.READ_SYNC_STATS',
        'android.permission.REORDER_TASKS',
        'android.permission.RESTART_PACKAGES',
        'android.permission.SET_TIME_ZONE',
        'android.permission.SET_WALLPAPER',
        'android.permission.SET_WALLPAPER_HINTS',
        'android.permission.TRANSMIT_IR',
        'android.permission.USE_FINGERPRINT',
        'android.permission.USE_BIOMETRIC',
        'android.permission.MANAGE_OWN_CALLS',
        'android.permission.ACCEPT_HANDOVER',
        # Signature permissions (commonly seen)
        'android.permission.BIND_ACCESSIBILITY_SERVICE',
        'android.permission.BIND_DEVICE_ADMIN',
        'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE',
        'android.permission.BIND_VPN_SERVICE',
        'android.permission.SYSTEM_ALERT_WINDOW',
        'android.permission.WRITE_SETTINGS',
        'android.permission.PACKAGE_USAGE_STATS',
        'android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS',
    }
    
    DANGEROUS_PERMISSIONS = {
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
    
    SIGNATURE_PERMISSIONS = {
        'android.permission.BIND_ACCESSIBILITY_SERVICE',
        'android.permission.BIND_DEVICE_ADMIN',
        'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE',
        'android.permission.BIND_VPN_SERVICE',
        'android.permission.SYSTEM_ALERT_WINDOW',
        'android.permission.WRITE_SETTINGS',
        'android.permission.PACKAGE_USAGE_STATS',
        'android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS',
    }
    
    def __init__(self):
        """Initialize permission extractor."""
        super().__init__(name="PermissionExtractor")
    
    def extract(self, apk_obj: Any, apk_path: Path) -> PermissionFeatures:
        """
        Extract permission features from APK.
        
        Args:
            apk_obj: Androguard APK object
            apk_path: Path to APK file
        
        Returns:
            PermissionFeatures object
        """
        self.logger.info(f"Extracting permission features from {apk_path.name}")
        
        # Get all permissions from manifest
        declared_permissions = set(apk_obj.get_permissions())
        
        # Create binary feature vector for all known permissions
        # Use deterministic ordering (sorted) for consistency
        permission_flags = {}
        for perm in sorted(self.KNOWN_PERMISSIONS):
            # Create clean feature name: perm_PERMISSION_NAME
            feature_name = self._permission_to_feature_name(perm)
            permission_flags[feature_name] = 1 if perm in declared_permissions else 0
        
        # Count permissions by type
        dangerous_count = sum(1 for p in declared_permissions if p in self.DANGEROUS_PERMISSIONS)
        signature_count = sum(1 for p in declared_permissions if p in self.SIGNATURE_PERMISSIONS)
        normal_count = len(declared_permissions & self.KNOWN_PERMISSIONS) - dangerous_count - signature_count
        
        # Custom permissions (not in known Android permissions)
        custom_count = len(declared_permissions - self.KNOWN_PERMISSIONS)
        
        return PermissionFeatures(
            permissions=permission_flags,
            total_permissions=len(declared_permissions),
            dangerous_count=dangerous_count,
            normal_count=normal_count,
            signature_count=signature_count,
            custom_count=custom_count,
        )
    
    def _permission_to_feature_name(self, permission: str) -> str:
        """
        Convert permission string to feature name.
        
        Args:
            permission: Full permission string (e.g., android.permission.INTERNET)
        
        Returns:
            Feature name (e.g., perm_INTERNET)
        """
        # Remove 'android.permission.' prefix and add 'perm_' prefix
        if permission.startswith('android.permission.'):
            short_name = permission.replace('android.permission.', '')
            return f"perm_{short_name}"
        else:
            # For custom permissions, use full name with perm_ prefix
            return f"perm_{permission.replace('.', '_')}"
