"""API call feature extractor."""

from typing import Any, Dict, List, Set
from pathlib import Path
from apk_extractor.extractors.base import BaseExtractor
from apk_extractor.models.features import APICallFeatures


class APIExtractor(BaseExtractor):
    """Extract sensitive API call features from DEX files."""
    
    # Sensitive API calls grouped by category
    SMS_APIS = {
        'sendTextMessage', 'sendMultipartTextMessage', 'sendDataMessage',
        'divideMessage', 'getAllMessagesFromIcc', 'getDefault',
    }
    
    LOCATION_APIS = {
        'getLastKnownLocation', 'requestLocationUpdates', 'requestSingleUpdate',
        'getLastLocation', 'getCurrentLocation', 'addGeofence', 'removeGeofences',
    }
    
    CAMERA_APIS = {
        'takePicture', 'startPreview', 'setPreviewCallback',
        'open', 'Camera.open', 'Camera2',
    }
    
    NETWORK_APIS = {
        'HttpURLConnection', 'HttpsURLConnection', 'openConnection',
        'URLConnection', 'HttpClient', 'DefaultHttpClient',
        'Socket', 'ServerSocket', 'DatagramSocket',
    }
    
    CRYPTO_APIS = {
        'Cipher.getInstance', 'MessageDigest.getInstance', 'SecretKeyFactory',
        'KeyGenerator', 'Signature.getInstance', 'Mac.getInstance',
    }
    
    REFLECTION_APIS = {
        'Class.forName', 'Method.invoke', 'Field.get', 'Field.set',
        'Constructor.newInstance', 'getDeclaredMethod', 'getDeclaredField',
    }
    
    DYNAMIC_LOADING_APIS = {
        'DexClassLoader', 'PathClassLoader', 'DexFile',
        'loadClass', 'defineClass',
    }
    
    RUNTIME_EXEC_APIS = {
        'Runtime.exec', 'ProcessBuilder.start', 'Process',
    }
    
    DEVICE_INFO_APIS = {
        'getDeviceId', 'getSubscriberId', 'getSimSerialNumber',
        'getLine1Number', 'getNetworkOperator', 'getImei', 'getMeid',
    }
    
    ACCOUNT_APIS = {
        'getAccounts', 'getAccountsByType', 'addAccount', 'removeAccount',
    }
    
    NOTIFICATION_APIS = {
        'notify', 'NotificationManager', 'createNotificationChannel',
    }
    
    PACKAGE_APIS = {
        'getInstalledPackages', 'getPackageInfo', 'installPackage',
        'deletePackage', 'setInstaller',
    }
    
    FILE_IO_APIS = {
        'FileOutputStream', 'FileInputStream', 'openFileOutput',
        'openFileInput', 'deleteFile',
    }
    
    DATABASE_APIS = {
        'SQLiteDatabase', 'execSQL', 'rawQuery', 'query',
    }
    
    CLIPBOARD_APIS = {
        'ClipboardManager', 'setPrimaryClip', 'getPrimaryClip',
    }
    
    AUDIO_APIS = {
        'MediaRecorder', 'startRecording', 'AudioRecord',
    }
    
    CONTACTS_APIS = {
        'ContentResolver.query', 'ContactsContract', 'RawContacts',
    }
    
    TELEPHONY_APIS = {
        'TelephonyManager', 'getCallState', 'listen', 'PhoneStateListener',
    }
    
    NATIVE_APIS = {
        'System.loadLibrary', 'System.load', 'native',
    }
    
    def __init__(self):
        """Initialize API extractor."""
        super().__init__(name="APIExtractor")
        
        # Combine all APIs for easy lookup
        self.all_apis = (
            self.SMS_APIS | self.LOCATION_APIS | self.CAMERA_APIS |
            self.NETWORK_APIS | self.CRYPTO_APIS | self.REFLECTION_APIS |
            self.DYNAMIC_LOADING_APIS | self.RUNTIME_EXEC_APIS |
            self.DEVICE_INFO_APIS | self.ACCOUNT_APIS | self.NOTIFICATION_APIS |
            self.PACKAGE_APIS | self.FILE_IO_APIS | self.DATABASE_APIS |
            self.CLIPBOARD_APIS | self.AUDIO_APIS | self.CONTACTS_APIS |
            self.TELEPHONY_APIS | self.NATIVE_APIS
        )
    
    def extract(self, apk_obj: Any, apk_path: Path) -> APICallFeatures:
        """
        Extract API call features from APK.
        
        Args:
            apk_obj: Androguard APK object
            apk_path: Path to APK file
        
        Returns:
            APICallFeatures object
        """
        self.logger.info(f"Extracting API call features from {apk_path.name}")
        
        # Get all method calls from DEX analysis
        found_apis = self._find_api_calls(apk_obj)
        
        # Create binary feature vector for all known APIs
        api_flags = {}
        for api in sorted(self.all_apis):
            feature_name = self._api_to_feature_name(api)
            api_flags[feature_name] = 1 if api in found_apis else 0
        
        # Count APIs by category
        sms_count = sum(1 for api in found_apis if api in self.SMS_APIS)
        location_count = sum(1 for api in found_apis if api in self.LOCATION_APIS)
        camera_count = sum(1 for api in found_apis if api in self.CAMERA_APIS)
        network_count = sum(1 for api in found_apis if api in self.NETWORK_APIS)
        crypto_count = sum(1 for api in found_apis if api in self.CRYPTO_APIS)
        reflection_count = sum(1 for api in found_apis if api in self.REFLECTION_APIS)
        dynamic_loading_count = sum(1 for api in found_apis if api in self.DYNAMIC_LOADING_APIS)
        
        return APICallFeatures(
            api_calls=api_flags,
            total_sensitive_api_calls=len(found_apis),
            sms_api_count=sms_count,
            location_api_count=location_count,
            camera_api_count=camera_count,
            network_api_count=network_count,
            crypto_api_count=crypto_count,
            reflection_api_count=reflection_count,
            dynamic_loading_api_count=dynamic_loading_count,
        )
    
    def _find_api_calls(self, apk_obj: Any) -> Set[str]:
        """
        Find API calls in DEX files.
        
        Args:
            apk_obj: Androguard APK object
        
        Returns:
            Set of found API names
        """
        found_apis = set()
        
        # Helper to process strings
        def process_strings(strings_iter) -> None:
            # Convert to list if it's a generator, so we can iterate efficiently
            try:
                # Some androguard versions return iterators
                strings = list(strings_iter)
            except:
                return

            for api in self.all_apis:
                # Case-insensitive substring match
                api_lower = api.lower()
                for s in strings:
                    if isinstance(s, bytes):
                        try:
                            s = s.decode('utf-8', errors='ignore')
                        except:
                            continue
                    
                    if api_lower in s.lower():
                        found_apis.add(api)
                        # Break inner loop once found in this string set? 
                        # No, we want to find all APIs. But once an API is found
                        # we don't need to find it again in the same string set.
                        # However, found_apis is a set so it handles duplicates.
                        # Optimization: if api is already in found_apis, skip checking it?
                        # Yes, but we are iterating APIs then strings.
                        # Better: Iterate strings then check APIs? 
                        # Strings are many (10k+), APIs are few (100).
                        # Current order: O(NumAPIs * NumStrings).
                        pass
        
        try:
            # Try to import DEX parser (handles both legacy and new androguard)
            try:
                from androguard.core.bytecodes.dvm import DalvikVMFormat
            except ImportError:
                from androguard.core.dex import DEX as DalvikVMFormat
            
            # Method 1: Using get_all_dex() (returns bytes)
            dex_contents = []
            try:
                for dex in apk_obj.get_all_dex():
                    dex_contents.append(dex)
            except Exception as e:
                self.logger.debug(f"get_all_dex() failed: {e}")
            
            # Method 2: If Method 1 failed, try get_dex()
            if not dex_contents:
                try:
                    dex = apk_obj.get_dex()
                    if dex:
                        dex_contents.append(dex)
                except Exception as e:
                    self.logger.debug(f"get_dex() failed: {e}")
            
            # Method 3: Fallback - manual file iteration
            if not dex_contents:
                try:
                    for filename in apk_obj.get_files():
                        if filename.endswith('.dex'):
                            dex_contents.append(apk_obj.get_file(filename))
                except Exception as e:
                    self.logger.debug(f"Manual file iteration failed: {e}")
            
            if not dex_contents:
                self.logger.warning("No DEX files found in APK")
                return found_apis
            
            # Analyze each DEX file
            for i, dex_bytes in enumerate(dex_contents):
                try:
                    if not dex_bytes:
                        continue
                        
                    d = DalvikVMFormat(dex_bytes)
                    
                    # Get strings - this is much faster than full analysis
                    # and sufficient for static API finding
                    strings = d.get_strings()
                    process_strings(strings)
                    
                except Exception as e:
                    self.logger.warning(f"Error analyzing DEX file #{i}: {e}")
                    continue
                
        except Exception as e:
            # Use import traceback to get full stack trace in debug logs
            import traceback
            self.logger.warning(f"Error in DEX analysis: {e}")
            self.logger.debug(traceback.format_exc())
        
        return found_apis
    
    def _api_to_feature_name(self, api: str) -> str:
        """
        Convert API name to feature name.
        
        Args:
            api: API name (e.g., sendTextMessage)
        
        Returns:
            Feature name (e.g., api_sendTextMessage)
        """
        # Clean API name and add prefix
        clean_name = api.replace('.', '_').replace('()', '')
        return f"api_{clean_name}"
