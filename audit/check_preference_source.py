#!/usr/bin/env python3
"""Android17 custom-preference source/Settings compatibility boundary.

Static checks only: do not build, execute, ship or activate Android14-era
Preference classes in the Android17 ROM. Pinned modern Lineage preference
sources are read-only architectural references, NOT PE-Reborn dependencies.
"""
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

OLD_SHA = "e9eabafcea9869a0af05489bf8ca5437616e29a6"
OLD_TREE = "6424e0b2ee8bcb72a50f006059a33087484c0867"
MODERN_LINEAGE_SDK_SHA = "854d7bfc24669e18e9a318e480d573703511237b"
AOSP17_SETTINGS_SHA = "213829fb67f5e070029e0513a088f31bc8f5c1ed"
AOSP17_SETTINGS_TREE = "f41bf360ab496bb4c018a33f93b74858b8ed223c"
PACKAGE = "src/com/android/settings/custom/preference/"
LIB_PREF = "packages/LineagePreferenceLib/"


def require(ok, msg):
    if not ok:
        raise RuntimeError(msg)


def git(repo, *args):
    return subprocess.check_output(
        ["git", "-C", str(repo), *args], text=True
    ).strip()


def show(repo, ref, path):
    return git(repo, "show", f"{ref}:{path}")


def old_source(pe):
    head = git(pe, "rev-parse", "refs/remotes/origin/seventeen")
    require(head == OLD_SHA, f"historical PE seventeen ref drifted: {head}")
    tree = git(pe, "rev-parse", f"{head}^{{tree}}")
    require(tree == OLD_TREE, f"historical PE tree changed: {tree}")
    files = git(pe, "ls-tree", "-r", "--name-only", head).splitlines()
    java = [f for f in files if f.startswith(PACKAGE) and f.endswith(".java")]
    require(len(files) == 18 and len(java) == 15,
            f"historic payload not as reviewed (files={len(files)}, Java={len(java)})")
    require(set(files) >= {
        "Android.bp", "AndroidManifest.xml", "res/values/attrs.xml",
        PACKAGE + "ConstraintsHelper.java",
        PACKAGE + "RemotePreference.java",
        PACKAGE + "RemotePreferenceManager.java",
        PACKAGE + "SettingsHelper.java",
    }, "expected PE preference source shape changed")

    bp = show(pe, head, "Android.bp")
    require(re.search(r'\bname:\s*"custom-preference"', bp) is not None
            and '"androidx.preference_preference"' in bp
            and '"androidx.appcompat_appcompat"' in bp,
            "old custom-preference Soong module or static libs changed")
    manifest = ET.fromstring(show(pe, head, "AndroidManifest.xml"))
    require(manifest.attrib.get("package") == "com.android.settings.custom",
            "legacy manifest package no longer matches")
    permission = [p for p in manifest.findall("permission")
                  if p.get("{http://schemas.android.com/apk/res/android}name")
                  == "lineageos.permission.MANAGE_REMOTE_PREFERENCES"]
    require(len(permission) == 1 and
            permission[0].get("{http://schemas.android.com/apk/res/android}protectionLevel")
            == "signature|privileged",
            "historical privileged cross-app permission changed")

    constraints = show(pe, head, PACKAGE + "ConstraintsHelper.java")
    require("com.android.internal.custom.hardware.LineageHardwareManager" in constraints
            and 'rFeature.startsWith("lineagehardware:")' in constraints,
            "legacy Lineage hardware binder/framework dependency changed")
    require("R.styleable.lineage_SelfRemovingPreference" in constraints,
            "old resource attribute contract changed")

    remote = show(pe, head, PACKAGE + "RemotePreference.java")
    manager = show(pe, head, PACKAGE + "RemotePreferenceManager.java")
    updater = show(pe, head, PACKAGE + "RemotePreferenceUpdater.java")
    require('"lineageos.intent.action.REFRESH_PREFERENCE"' in remote
            and '"lineageos.intent.action.UPDATE_PREFERENCE"' in remote
            and '"com.android.settings.summary.receiver"' in remote,
            "old remote preference intent/metadata protocol changed")
    require("sendOrderedBroadcastAsUser" in manager
            and "registerReceiver(" in manager
            and 'lineageos.permission.MANAGE_REMOTE_PREFERENCES' in manager
            and "Context.RECEIVER_" not in manager,
            "historical exported/nonexported receiver policy changed; re-audit")
    require("sendBroadcastAsUser" in updater
            and 'lineageos.permission.MANAGE_REMOTE_PREFERENCES' in updater,
            "legacy preference updater security contract changed")

    settings_helper = show(pe, head, PACKAGE + "SettingsHelper.java")
    require("Settings.Secure.getInt(" in settings_helper
            and "Settings.System.getInt(" in settings_helper
            and "getIntForUser" not in settings_helper,
            "legacy per-user setting semantics changed")
    attrs = ET.fromstring(show(pe, head, "res/values/attrs.xml"))
    style = attrs.find("declare-styleable")
    require(style is not None
            and style.get("name") == "lineage_SelfRemovingPreference",
            "legacy styleable API drift")
    print("PASS: exact PE 2022 source SHA/tree and 15 Java classes / 18 tracked files")
    print("PASS: legacy Lineage hardware binding and custom XML attrs identified")
    print("PASS: legacy signature|privileged permission and remote broadcast protocol identified")
    print("PASS: legacy receiver flags and multi-user settings usage recorded as unverified risks")


def modern_reference(lineage):
    sha = git(lineage, "rev-parse", "FETCH_HEAD^{commit}")
    require(sha == MODERN_LINEAGE_SDK_SHA,
            f"modern preference SDK ref changed; re-review: {sha}")
    bp = show(lineage, "FETCH_HEAD", LIB_PREF + "Android.bp")
    require(re.search(r'\bname:\s*"LineagePreferenceLib"', bp) is not None
            and '"org.lineageos.platform"' in bp
            and '"SettingsLibMainSwitchPreference"' in bp
            and 'min_sdk_version: "30"' in bp,
            "modern Lineage preference library module dependencies changed")
    constraints = show(lineage, "FETCH_HEAD",
                       LIB_PREF + "java/lineageos/preference/ConstraintsHelper.java")
    remote = show(lineage, "FETCH_HEAD",
                  LIB_PREF + "java/lineageos/preference/RemotePreference.java")
    manager = show(lineage, "FETCH_HEAD",
                   LIB_PREF + "java/lineageos/preference/RemotePreferenceManager.java")
    require("import lineageos.hardware.LineageHardwareManager;" in constraints,
            "modern library hardware SDK linkage changed")
    require('"org.lineageos.settings.summary.receiver"' in remote
            and '"lineageos.intent.action.REFRESH_PREFERENCE"' in remote,
            "modern remote preference metadata/action contract changed")
    require("import lineageos.platform.Manifest;" in manager
            and "Manifest.permission.MANAGE_REMOTE_PREFERENCES" in manager,
            "modern remote preference permission SDK linkage changed")
    print("PASS: pinned Lineage24 reference moved to lineage-sdk/LineagePreferenceLib")
    print("PASS: modern Lineage preference requires org.lineageos.platform")
    print("PASS: old and modern metadata/permission protocols are not identical")


def check_aosp17_settings(settings, manifest):
    commit = git(settings, "rev-parse", "FETCH_HEAD^{commit}")
    tree = git(settings, "rev-parse", "FETCH_HEAD^{tree}")
    require(commit == AOSP17_SETTINGS_SHA and tree == AOSP17_SETTINGS_TREE,
            f"official Android17 Settings tag changed: {commit}/{tree}")
    bp = show(settings, "FETCH_HEAD", "Android.bp")
    require('name: "Settings-core"' in bp and
            '"SettingsLibMetadata-processor"' in bp and
            '"Spa-search"' in bp,
            "AOSP17 Settings Soong generation/search modules changed")
    require('"custom-preference"' not in bp
            and '"LineagePreferenceLib"' not in bp
            and '"org.lineageos.platform"' not in bp,
            "AOSP17 Settings unexpectedly depends on legacy custom preference")
    root = ET.parse(manifest / "aosp17_reference.xml").getroot()
    default = root.find("default")
    require(default is not None and
            default.get("remote") == "aosp" and
            default.get("revision") == "refs/tags/android-17.0.0_r1",
            "official AOSP17 base tag not selected")
    projects = {p.get("path") or p.get("name"): p.get("name")
                for p in root.findall("project")}
    require(projects.get("packages/apps/Settings")
            == "platform/packages/apps/Settings",
            "official Android17 Settings source owner was replaced")
    require("vendor/custom-preference" not in projects,
            "old legacy preference module unexpectedly added to official source")
    entry = ET.parse(manifest / "default.xml").getroot()
    require(len(entry) == 1 and
            entry[0].tag == "include" and
            entry[0].get("name") == "aosp17_pe_p2_kernel_configs.xml",
            "staged default manifest entrypoint changed; re-audit")
    subprocess.run(
        [sys.executable, str(manifest / "tools/validate_aosp17_base_profiles.py")],
        cwd=manifest, check=True)
    print("PASS: official Android17 Settings has no PE or Lineage PreferenceLib dependency")
    print("PASS: all 25 reviewed AOSP17 profiles preserve official Settings owner")


def main():
    require(len(sys.argv) == 5,
            "usage: check_preference_source.py LEGACY_PE LEGACY_MODERN_LINEAGE_SDK AOSP17_SETTINGS AOSP17_MANIFEST")
    pe, lineage, settings, manifest = [Path(s).resolve() for s in sys.argv[1:]]
    require(all(x.is_dir() for x in [pe, lineage, settings, manifest]),
            "missing one or more required source checkouts")
    old_source(pe)
    modern_reference(lineage)
    check_aosp17_settings(settings, manifest)
    print("PASS: Android17 PE custom-preference source/Settings boundary audit")
    print("OPEN: independent PE preference design, protected broadcast identity, per-user state,")
    print("      Android17 resource/Soong app builds, Settings search/UI and physical mondrian tests")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, ET.ParseError,
            subprocess.CalledProcessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
