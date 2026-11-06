# Android 17 — `vendor/custom-preference` migration and security audit

**PixelExperience-Reborn matrix: P2 row 164. Audited 2026-11-07.**

## Decision

**Do not import `vendor_custom-preference` from 2022 into the active Android17 manifest and do not bulk-import `LineagePreferenceLib` from modern LineageOS.** Preserve the PE history in `seventeen`, protect the current official Android17 Settings build, and defer designing a **small independent PE preference library** until actual requirements and Settings UI integrations are known. This is *not* a statement that custom preference components are useless or that every legacy feature should be deleted.

The PE-Reborn goal is a clean independent AOSP17 base, with future device-specific product work on **POCO F5 Pro / Redmi K60 (mondrian)** only. Existing LF52406 trees are reference-only. There is no independent PE-Reborn mondrian device/product/vendor tree yet, and the reviewed AOSP17 `default.xml` must remain source-only.

## 1. Historical PE source and its precise purpose

- Old PE `seventeen` and `fourteen` are **the same commit** `e9eabafcea9869a0af05489bf8ca5437616e29a6`; last commit is dated **2022-10-14** (note earlier parent timestamps are not chronological). Exact root tree: `6424e0b2ee8bcb72a50f006059a33087484c0867`.
- **18 tracked files**, including `Android.bp`, `AndroidManifest.xml`, `res/values/attrs.xml`, and **15 Java classes** in package `com.android.settings.custom.preference`.
- Soong declares `android_library { name: "custom-preference" }` with `androidx.preference_preference`, `androidx.appcompat_appcompat` and other AndroidX libraries. Its manifest package is `com.android.settings.custom`.
- Reusable designs: `SystemSetting*`, `SecureSetting*`, `GlobalSetting*` variants; `SelfRemoving*` conditional preference classes; `SettingsHelper` and `ConstraintsHelper`; `RemotePreference` and its background ordered-broadcast updater/manager.
- This **was actually referenced** by historical PE `packages_apps_Settings` `seventeen` `Android.bp` in the `Settings-core` static libs. That historical Settings app is Android14-era and is **not** the active Android17 Settings tree.

### Dependencies and compatibility blockers

1. **Lineage hardware manager dependency:** `ConstraintsHelper.java` directly imports `com.android.internal.custom.hardware.LineageHardwareManager` and handles the XML prefix `lineagehardware:`. This is not supplied by the independent AOSP17 baseline. It must not be silently substituted with a different or stub hardware behavior (especially not by duplicating features already supported by the future mondrian device framework).
2. **Lineage remote broadcast protocol and security:** `RemotePreferenceManager` dynamically registers a receiver and uses `sendOrderedBroadcastAsUser` with `lineageos.permission.MANAGE_REMOTE_PREFERENCES`. Its `AndroidManifest.xml` declares this permission with `signature|privileged` and protected broadcast actions `lineageos.intent.action.REFRESH_PREFERENCE` and `lineageos.intent.action.UPDATE_PREFERENCE`. The 2022 code does **not** explicitly declare an exported/nonexported receiver flag. Modern Android17 receiver-export rules, platform permission ownership/manifest merge, multi-user isolation, cross-user dispatch and receiver authentication **must be audited on-device/with platform APIs** before a replacement. This is an identified compatibility/security risk, not evidence of a confirmed exploit.
3. **Metadata namespace:** old remote preferences use `com.android.settings.summary.receiver` and the old `:lineage:pref_*` extras. A modern implementation must choose PE-owned action/permission/metadata strings consistently across Settings and the provider, without accidentally granting privileges to legacy third-party receivers.
4. **Per-user state:** `SettingsHelper` uses `Settings.Secure/System/Global.getInt` and no explicit `getIntForUser`; `RemotePreferenceManager` sends as `UserHandle.CURRENT`. Android17 settings for personal/work profiles and secondary users need explicit design and tests rather than assumptions.
5. **XML/style lifecycle:** `lineage_SelfRemovingPreference` attributes, `ConstraintsHelper.Graveyard` hiding, preference attachment and dynamic summary handling were designed for older PreferenceFragment behavior. Validate against modern AndroidX, SettingsLib, SPA/search metadata, accessibility and UI refresh; do not copy only `Android.bp` into AOSP17 and assume it works.

## 2. Modern reference — important upstream relocation

Modern LineageOS 24.0 no longer uses a standalone project named `LineageOS/android_vendor_custom-preference` (that repository was not found). The functionality moved into the **Lineage SDK**, pinned read-only reference:

- Git repository: `LineageOS/android_lineage-sdk`, branch `lineage-24.0`, revision `854d7bfc24669e18e9a318e480d573703511237b`.
- Source path: `packages/LineagePreferenceLib/`.
- `Android.bp` module `LineagePreferenceLib` with `min_sdk_version: "30"`, static libs `androidx.preference_preference`, `SettingsLibMainSwitchPreference` and **`org.lineageos.platform`**.
- Java package `lineageos.preference`. The modern `ConstraintsHelper` imports `lineageos.hardware.LineageHardwareManager`; `RemotePreferenceManager` imports `lineageos.platform.Manifest` and its permission constant. Modern metadata uses `org.lineageos.settings.summary.receiver` rather than the old `com.android.settings.summary.receiver`.
- These are **LineageOS-specific internal APIs**. Importing the whole SDK/runtime into independent PE-Reborn merely to keep old preference widgets would be an unjustified architecture dependency. The modern source is a valuable *behavior and design reference*; specific functionality can be reimplemented or carefully ported into PE-owned packages with explicit tests after selecting actual product features.

Reference source: https://github.com/LineageOS/android_lineage-sdk/tree/854d7bfc24669e18e9a318e480d573703511237b/packages/LineagePreferenceLib .

## 3. Android17 Settings source owner

The **official AOSP17 `packages/apps/Settings` tag** `android-17.0.0_r1` has peeled commit `213829fb67f5e070029e0513a088f31bc8f5c1ed`, root tree `f41bf360ab496bb4c018a33f93b74858b8ed223c`. Its `Android.bp` includes `Settings-core`, `SettingsLibMetadata-processor`, `Spa-search` and modern settings/module metadata. Its `Settings-core` does **not** depend on `custom-preference`, `LineagePreferenceLib` or `org.lineageos.platform`.

The staged PE-Reborn manifest currently selects **only the official** `platform/packages/apps/Settings`, as already recorded in the P1 Settings audit: https://github.com/PixelExperience-Reborn/packages_apps_Settings/blob/audit/a17-mondrian-settings-20261104/docs/ANDROID_17_MONDRIAN_SETTINGS_AUDIT.md .

Historic `snippets/pixel-extras.xml` still contains an inactive `vendor_custom-preference` project. This is an archival reference, **not** a source active in `default.xml`.

## 4. Guardrails implemented in this audit

- Separate branch `audit/a17-custom-preference-boundary-20261107` based on the unmodified historical PE `seventeen`.
- `audit/check_preference_source.py` checks the **exact old tree and 15 Java-class inventory**, legacy hardware/broadcast/permission/resource dependencies and the pinned modern LineagePreferenceLib as a read-only reference.
- It independently checks the **immutable official AOSP17 Settings commit/tree**, Soong architecture and absence of legacy/Lineage preference imports.
- The manifest validator blocks a `vendor/custom-preference` project path/name from being silently activated; one negative test deliberately imports the old module and must fail. All 25 staged profiles should remain valid.
- GitHub Actions verifies these guards, runs the manifest regression suite and parses actual `repo manifest` for unique projects/source owners.
- **No** new library APK, privileged broadcast permission, preference classes, `Settings-core` static lib, user switch, device tree, kernel, proprietary vendor change or active manifest source override was added.

## 5. Acceptance criteria for later actual port

1. Define the PE-Reborn Settings features that genuinely need a custom preference class (prefer native Android17 SettingsLib/SPA components first).
2. Implement narrowly scoped **PE-owned** source modules and resource namespace, without unreviewed Lineage SDK imports; preserve PE history and upstream license attribution for any reused code.
3. Require explicit Android17 permission/receiver identity, exported flag contract where applicable, trusted component targeting, protected broadcasts, user/profile isolation and manifest owner tests.
4. Treat `lineagehardware:` as unsupported until an actual independently designed and verified PE hardware feature API exists. Never silently expose nonfunctional toggles.
5. Compile `Settings` and the new library together using Android17 Soong/SettingsLibMetadata; test rotation, UI search, navigation, SPA, privacy, multi-user, localization/accessibility, and protected Settings.Secure writes.
6. Validate full ROM build/boot, SELinux/VINTF, CTS/VTS and physical mondrian device only after independent PE device trees exist and server resources are available.

**Status: source/architectural/security dependency audit ONLY. A17 library runtime/Soong build and hardware validation are OPEN.**

## Links

- Original PE repository: https://github.com/PixelExperience-Reborn/vendor_custom-preference/tree/seventeen
- Historic PE `Settings-core`: https://github.com/PixelExperience-Reborn/packages_apps_Settings/blob/seventeen/Android.bp
- Modern Lineage SDK reference: https://github.com/LineageOS/android_lineage-sdk/tree/854d7bfc24669e18e9a318e480d573703511237b/packages/LineagePreferenceLib
- Official AOSP17 Settings: https://android.googlesource.com/platform/packages/apps/Settings/+/refs/tags/android-17.0.0_r1
- AOSP17 staged manifest: https://github.com/PixelExperience-Reborn/manifest/tree/port/a17-aosp17-manifest-20261102
