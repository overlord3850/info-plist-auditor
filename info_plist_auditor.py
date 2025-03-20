import plistlib
import argparse
import json

def check_info_plist(plist_path):
    """Audit an Info.plist file for security misconfigurations"""
    
    # Load the Info.plist file
    with open(plist_path, 'rb') as f:
        plist_data = plistlib.load(f)
    
    issues = []

    print("\n🔍 Auditing Info.plist file: ", plist_path)
    print("=" * 80)

    # 1️⃣ Insecure Network Configurations (ATS Bypass)
    if plist_data.get("NSAppTransportSecurity", {}).get("NSAllowsArbitraryLoads", False):
        issues.append({
            "issue": "App Transport Security (ATS) is disabled.",
            "key": "NSAllowsArbitraryLoads",
            "severity": "High",
            "mitigation": "Remove NSAllowsArbitraryLoads or set it to false to enforce HTTPS connections."
        })

    # 2️⃣ Hardcoded API Keys & Sensitive Data
    sensitive_keys = ["API_KEY", "ACCESS_TOKEN", "CLIENT_SECRET"]
    for key in plist_data.keys():
        if any(s in key.upper() for s in sensitive_keys):
            issues.append({
                "issue": f"Sensitive key '{key}' found in Info.plist.",
                "key": key,
                "severity": "Critical",
                "mitigation": "Store API keys securely using Keychain or environment variables."
            })

    # 3️⃣ Privacy Violations (User Data Access)
    privacy_sensitive_keys = {
        "NSLocationAlwaysUsageDescription": "Unjustified always-on location tracking.",
        "NSMicrophoneUsageDescription": "Unnecessary microphone access.",
        "NSCameraUsageDescription": "Unnecessary camera access.",
        "NSContactsUsageDescription": "Unnecessary access to user contacts.",
        "NSBluetoothAlwaysUsageDescription": "Bluetooth access without explanation."
    }
    for key, issue in privacy_sensitive_keys.items():
        if key in plist_data:
            issues.append({
                "issue": issue,
                "key": key,
                "severity": "High",
                "mitigation": "Ensure permissions are needed and properly justified in privacy policies."
            })

    # 4️⃣ UIWebView Usage (Deprecated & Insecure)
    if "UIWebView" in plist_data:
        issues.append({
            "issue": "Deprecated UIWebView detected.",
            "key": "UIWebView",
            "severity": "Critical",
            "mitigation": "Replace UIWebView with WKWebView for security and performance improvements."
        })

    # 5️⃣ Clipboard Access Misuse
    if plist_data.get("UIPasteboardAutomaticDetection", False):
        issues.append({
            "issue": "App may be automatically reading clipboard data.",
            "key": "UIPasteboardAutomaticDetection",
            "severity": "High",
            "mitigation": "Disable UIPasteboardAutomaticDetection unless clipboard access is needed."
        })

    # 6️⃣ Persistent Wi-Fi Misuse
    if plist_data.get("UIRequiresPersistentWiFi", False):
        issues.append({
            "issue": "App requires persistent WiFi, which can drain battery and raise privacy concerns.",
            "key": "UIRequiresPersistentWiFi",
            "severity": "Medium",
            "mitigation": "Set UIRequiresPersistentWiFi to false unless necessary."
        })

    # 7️⃣ App Tracking Transparency Misuse
    if "NSUserTrackingUsageDescription" in plist_data:
        issues.append({
            "issue": "App is using tracking (IDFA).",
            "key": "NSUserTrackingUsageDescription",
            "severity": "High",
            "mitigation": "Ensure tracking is justified and follows Apple’s App Tracking Transparency (ATT) policies."
        })

    # 8️⃣ Bluetooth Device Monitoring
    if "NSBluetoothAlwaysUsageDescription" in plist_data:
        issues.append({
            "issue": "App requests Bluetooth access without clear justification.",
            "key": "NSBluetoothAlwaysUsageDescription",
            "severity": "Medium",
            "mitigation": "Limit Bluetooth access unless necessary for app functionality."
        })

    # 9️⃣ Debug Mode Detection
    if plist_data.get("CFBundleDevelopmentRegion", "") == "debug":
        issues.append({
            "issue": "App is running in Debug mode.",
            "key": "CFBundleDevelopmentRegion",
            "severity": "Critical",
            "mitigation": "Ensure the app is built in Release mode before publishing."
        })

    # 🔹 JSON Output for Further Analysis
    result = {
        "file": plist_path,
        "total_issues": len(issues),
        "issues": issues
    }

    print("\n🎯 Audit Summary")
    print("=" * 80)
    if issues:
        for idx, issue in enumerate(issues, 1):
            print(f"🚨 {idx}. {issue['issue']}")
            print(f"   🔹 Key: {issue['key']}")
            print(f"   ⚠️ Severity: {issue['severity']}")
            print(f"   🛠 Mitigation: {issue['mitigation']}\n")
    else:
        print("✅ No security issues detected!")

    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audit an Info.plist file for security misconfigurations.")
    parser.add_argument("plist_file", help="Path to the Info.plist file to audit")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()
    audit_results = check_info_plist(args.plist_file)

    if args.json:
        print(json.dumps(audit_results, indent=4))
