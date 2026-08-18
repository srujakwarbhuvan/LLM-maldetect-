"""Example script: Batch extract features from multiple APKs."""

from pathlib import Path
from apk_extractor import APKFeatureExtractor

def main():
    # Initialize extractor with logging to file
    log_file = Path("data/logs/batch_extraction.log")
    log_file.parent.mkdir(parents=True, exist_ok=True)
    
    extractor = APKFeatureExtractor(
        log_level="INFO",
        log_file=log_file
    )
    
    # Directory containing APK files
    apk_dir = Path("data/input")
    
    if not apk_dir.exists():
        print(f"Creating input directory: {apk_dir}")
        apk_dir.mkdir(parents=True, exist_ok=True)
        print("Please place APK files in data/input/")
        return
    
    # Check if there are any APKs
    apk_files = list(apk_dir.glob("*.apk"))
    if not apk_files:
        print(f"No APK files found in {apk_dir}")
        print("Please place APK files in data/input/")
        return
    
    print(f"Found {len(apk_files)} APK files")
    print(f"Starting batch extraction...\n")
    
    # Batch extract with different output formats
    output_csv = Path("data/output/features.csv")
    output_json = Path("data/output/features.json")
    output_parquet = Path("data/output/features.parquet")
    
    # Extract to CSV
    print("Extracting to CSV...")
    results = extractor.batch_extract(
        apk_dir=apk_dir,
        output_file=output_csv,
        output_format="csv"
    )
    
    if results:
        # Also save as JSON and Parquet
        print(f"\nSaving to additional formats...")
        extractor.save_results(results, output_json, "json")
        extractor.save_results(results, output_parquet, "parquet")
        
        print(f"\n✓ Batch extraction completed!")
        print(f"\nResults:")
        print(f"  - CSV:     {output_csv}")
        print(f"  - JSON:    {output_json}")
        print(f"  - Parquet: {output_parquet}")
        print(f"  - Logs:    {log_file}")
        
        # Summary statistics
        successful = sum(1 for r in results if r.extraction_success)
        failed = len(results) - successful
        
        print(f"\nStatistics:")
        print(f"  - Total APKs:     {len(apk_files)}")
        print(f"  - Successful:     {successful}")
        print(f"  - Failed:         {failed}")
        
        # Feature statistics
        total_perms = sum(r.permissions.total_permissions for r in results)
        avg_perms = total_perms / len(results) if results else 0
        
        total_apis = sum(r.api_calls.total_sensitive_api_calls for r in results)
        avg_apis = total_apis / len(results) if results else 0
        
        print(f"\nFeature Statistics:")
        print(f"  - Avg permissions: {avg_perms:.1f}")
        print(f"  - Avg API calls:   {avg_apis:.1f}")
    else:
        print("\n✗ No APKs were successfully processed")

if __name__ == "__main__":
    main()
