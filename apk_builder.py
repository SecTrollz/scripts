#!/usr/bin/env python3
"""
apk_builder.py
──────────────────────────────────────────────────────────────────
Convert  wrangler.toml + worker.js + index.html  →  Android APK
Target : Android 16 (API 36) / Google Pixel 9a (tegu, arm64-v8a)

Usage:
    python3 apk_builder.py
    python3 apk_builder.py --wrangler wrangler.toml --worker worker.js --html index.html
    python3 apk_builder.py --out myapp.apk --install
    python3 apk_builder.py --skip-build        # generate project only

Requirements (auto-detected):
    • JDK 17+          (apt install openjdk-17-jdk  /  brew install openjdk@17)
    • Android SDK      (export ANDROID_HOME=~/Android/Sdk)
    • gradle or ./gradlew (wrapper downloaded automatically)
──────────────────────────────────────────────────────────────────
"""

import argparse
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import urllib.request
import zlib
from pathlib import Path

# ─── Android / AGP versions ──────────────────────────────────────
COMPILE_SDK    = 35          # AGP 8.6.x is tested to 35; 36 needs AGP 8.7+
TARGET_SDK     = 35
MIN_SDK        = 26
BUILD_TOOLS    = "34.0.0"   # what Termux SDK installer provides
GRADLE_VERSION = "8.9"
AGP_VERSION    = "8.6.1"
JAVA_VER       = "17"

GRADLE_DIST_URL = (
    f"https://services.gradle.org/distributions/"
    f"gradle-{GRADLE_VERSION}-bin.zip"
)
WRAPPER_JAR_URL = (
    "https://raw.githubusercontent.com/gradle/gradle/"
    "v8.9.0/gradle/wrapper/gradle-wrapper.jar"
)

# ─── TOML parsing (stdlib 3.11+, else fallback) ──────────────────
try:
    import tomllib                          # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib             # pip install tomli
    except ImportError:
        tomllib = None


# ══════════════════════════════════════════════════════════════════
# TOML / WRANGLER PARSING
# ══════════════════════════════════════════════════════════════════

def parse_wrangler(path: Path) -> dict:
    """Extract useful fields from wrangler.toml."""
    cfg = {
        "name":    "MDMCheck",
        "package": "com.mdmcheck.app",
        "main":    "worker.js",
        "route":   None,
        "vars":    {},
        "version": "1.0",
    }

    if not path.exists():
        print(f"[WARN] {path} not found — using default app metadata")
        return cfg

    text = path.read_text(encoding="utf-8")

    if tomllib:
        data = tomllib.loads(text)
    else:
        # Minimal key=value parser (no sections needed for our fields)
        data = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            data[k] = v

    name = str(data.get("name", cfg["name"]))
    # Sanitise to a valid Java package component
    safe = re.sub(r"[^a-zA-Z0-9]", "", name).lower() or "app"

    cfg["name"]    = name
    cfg["package"] = f"com.{safe}.app"
    cfg["main"]    = str(data.get("main", "worker.js"))

    route = data.get("route")
    if isinstance(route, dict):
        route = route.get("pattern")
    cfg["route"] = route

    vars_section = data.get("vars", {})
    if isinstance(vars_section, dict):
        cfg["vars"] = vars_section

    return cfg


# ══════════════════════════════════════════════════════════════════
# PREREQUISITE DETECTION
# ══════════════════════════════════════════════════════════════════

def find_java() -> Path | None:
    j = shutil.which("java")
    if j:
        return Path(j)
    for p in (
        "/usr/lib/jvm/java-17-openjdk-amd64/bin/java",
        "/usr/lib/jvm/java-21-openjdk-amd64/bin/java",
        "/opt/homebrew/opt/openjdk@17/bin/java",
        "/opt/homebrew/opt/openjdk@21/bin/java",
    ):
        if Path(p).exists():
            return Path(p)
    return None


def find_sdk() -> Path | None:
    for p in (
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        os.path.expanduser("~/Android/Sdk"),
        os.path.expanduser("~/Library/Android/sdk"),
        "/opt/android-sdk",
    ):
        if p and Path(p).is_dir():
            return Path(p)
    return None


def find_highest_platform(sdk: Path | None) -> int | None:
    """
    Return the highest API level that has a valid android.jar installed.
    Falls back to the module-level COMPILE_SDK constant if nothing found.
    """
    if not sdk:
        return None
    platforms = sdk / "platforms"
    if not platforms.is_dir():
        return None
    best = None
    for d in platforms.iterdir():
        # Directory names are like android-34, android-35
        m = re.match(r"android-(\d+)$", d.name)
        if not m:
            continue
        api = int(m.group(1))
        jar = d / "android.jar"
        if jar.exists():
            if best is None or api > best:
                best = api
    return best


def find_aapt2(sdk: Path | None) -> str | None:
    """
    Find the ARM-native aapt2 binary in the local SDK build-tools.
    This is essential on Termux/ARM because AGP's bundled aapt2 is x86_64.
    Returns the absolute path string, or None if not found.
    """
    if not sdk:
        return None
    bt = sdk / "build-tools"
    if not bt.is_dir():
        return None
    # Prefer highest version
    for ver_dir in sorted(bt.iterdir(), reverse=True):
        candidate = ver_dir / "aapt2"
        if candidate.exists() and os.access(candidate, os.X_OK):
            print(f"[INFO] AAPT2 (ARM)  : {candidate}")
            return str(candidate)
    return None


def best_build_tools(sdk: Path) -> Path | None:
    bt = sdk / "build-tools"
    if not bt.is_dir():
        return None
    versions = sorted(bt.iterdir(), reverse=True)
    return versions[0] if versions else None


def check_prereqs(skip_build: bool) -> tuple[Path | None, Path | None]:
    java = find_java()
    sdk  = find_sdk()

    if skip_build:
        return java, sdk

    errors = []
    if not java:
        errors.append(
            "JDK 17+ not found.\n"
            "  Ubuntu:  sudo apt install openjdk-17-jdk\n"
            "  macOS:   brew install openjdk@17\n"
            "  Then:    export JAVA_HOME=$(java_home -v 17)"
        )
    if not sdk:
        errors.append(
            "Android SDK not found.\n"
            "  Set:     export ANDROID_HOME=~/Android/Sdk\n"
            "  Install: https://developer.android.com/studio (SDK Manager)"
        )

    if errors:
        print("\n[FATAL] Missing prerequisites:\n")
        for e in errors:
            print(f"  ▸ {e}\n")
        print("Re-run with --skip-build to generate the project only.")
        sys.exit(1)

    return java, sdk


# ══════════════════════════════════════════════════════════════════
# PNG ICON GENERATOR  (48 × 48 solid colour, no Pillow required)
# ══════════════════════════════════════════════════════════════════

def _png_chunk(kind: str, data: bytes) -> bytes:
    body = kind.encode("ascii") + data
    crc  = zlib.crc32(body) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + body + struct.pack(">I", crc)


def make_icon_png(w: int = 48, h: int = 48, rgba=(26, 26, 46, 255)) -> bytes:
    """Minimal valid RGBA PNG icon."""
    raw = b""
    for _ in range(h):
        raw += b"\x00" + bytes(rgba) * w          # filter=None per row
    compressed = zlib.compress(raw, 9)

    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk("IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
        + _png_chunk("IDAT", compressed)
        + _png_chunk("IEND", b"")
    )


# ══════════════════════════════════════════════════════════════════
# ANDROID PROJECT FILE GENERATORS
# ══════════════════════════════════════════════════════════════════

def _java_str(s: str) -> str:
    """Escape a Python string to a safe Java string literal (no quotes)."""
    return (
        s.replace("\\", "\\\\")
         .replace('"', '\\"')
         .replace("\n", "\\n")
         .replace("\r", "\\r")
         .replace("\t", "\\t")
    )


# ── AndroidManifest.xml ───────────────────────────────────────────

def gen_manifest(pkg: str, app_name: str) -> str:
    return """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools">

    <!-- Network -->
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />

    <!-- Storage (media) -->
    <uses-permission android:name="android.permission.READ_MEDIA_IMAGES" />
    <uses-permission android:name="android.permission.READ_MEDIA_VIDEO" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"
        android:maxSdkVersion="32" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"
        android:maxSdkVersion="28" />

    <!-- Camera / Mic for WebRTC / file chooser -->
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.MODIFY_AUDIO_SETTINGS" />

    <!-- Location (geolocation API) -->
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />

    <application
        android:allowBackup="false"
        android:icon="@mipmap/ic_launcher"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:label="APPNAME"
        android:supportsRtl="true"
        android:hardwareAccelerated="true"
        android:theme="@style/Theme.App"
        android:networkSecurityConfig="@xml/network_security_config"
        android:usesCleartextTraffic="false"
        tools:targetApi="36">

        <activity
            android:name=".MainActivity"
            android:exported="true"
            android:configChanges="orientation|keyboardHidden|screenSize|smallestScreenSize|screenLayout|uiMode"
            android:windowSoftInputMode="adjustResize">

            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

    </application>
</manifest>
""".replace("APPNAME", app_name)


# ── MainActivity.java ─────────────────────────────────────────────

_MAIN_ACTIVITY_TMPL = """\
package PKG;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Message;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.webkit.CookieManager;
import android.webkit.GeolocationPermissions;
import android.webkit.JavascriptInterface;
import android.webkit.PermissionRequest;
import android.webkit.ServiceWorkerClient;
import android.webkit.ServiceWorkerController;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;

import androidx.webkit.WebViewAssetLoader;
import androidx.webkit.WebViewAssetLoader.AssetsPathHandler;
import androidx.webkit.WebViewAssetLoader.ResourcesPathHandler;

/**
 * MainActivity — full-screen WebView wrapper for the Cloudflare Worker web app.
 *
 * Asset URL base : https://appassets.androidplatform.net/assets/
 * Service Worker : /assets/worker.js  (registered programmatically)
 * CF vars        : injected as window.__CF_VARS  after every page load
 */
public class MainActivity extends Activity {

    // ── Cloudflare Worker env-vars baked in at build time ─────────
    private static final String CF_VARS_JSON = "VARS_JSON";
    private static final String APP_NAME     = "APPNAME";

    // ── Asset base (WebViewAssetLoader serves assets here) ────────
    public static final String ASSET_BASE =
        "https://appassets.androidplatform.net/assets/";

    private WebView          webView;
    private WebViewAssetLoader assetLoader;
    private ValueCallback<Uri[]> fileChooserCb;

    @SuppressLint({"SetJavaScriptEnabled", "JavascriptInterface"})
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Edge-to-edge, no action-bar
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEPS_SCREEN_ON);
        getWindow().getDecorView()
            .setSystemUiVisibility(
                android.view.View.SYSTEM_UI_FLAG_FULLSCREEN |
                android.view.View.SYSTEM_UI_FLAG_HIDE_NAVIGATION |
                android.view.View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
            );

        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(0xFF1a1a2e);
        setContentView(root);

        webView = new WebView(this);
        root.addView(webView, new ViewGroup.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT));

        // ── Asset loader ─────────────────────────────────────────
        assetLoader = new WebViewAssetLoader.Builder()
            .setDomain("appassets.androidplatform.net")
            .addPathHandler("/assets/",   new AssetsPathHandler(this))
            .addPathHandler("/res/",      new ResourcesPathHandler(this))
            .build();

        // ── Service-worker controller (must be set before first load) ──
        ServiceWorkerController.getInstance()
            .setServiceWorkerClient(new ServiceWorkerClient() {
                @Override
                public WebResourceResponse shouldInterceptRequest(
                    WebResourceRequest req) {
                    return assetLoader.shouldInterceptRequest(req.getUrl());
                }
            });

        // ── WebView settings ─────────────────────────────────────
        WebSettings ws = webView.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        ws.setDatabaseEnabled(true);
        ws.setGeolocationEnabled(true);
        ws.setMediaPlaybackRequiresUserGesture(false);
        ws.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        ws.setCacheMode(WebSettings.LOAD_DEFAULT);
        ws.setSupportZoom(true);
        ws.setBuiltInZoomControls(false);
        ws.setDisplayZoomControls(false);
        ws.setAllowFileAccess(false);
        ws.setAllowContentAccess(false);
        ws.setAllowFileAccessFromFileURLs(false);
        ws.setAllowUniversalAccessFromFileURLs(false);
        ws.setUserAgentString(ws.getUserAgentString() + " " + APP_NAME + "/1.0");

        CookieManager.getInstance().setAcceptCookie(true);
        CookieManager.getInstance().setAcceptThirdPartyCookies(webView, true);

        // ── JavaScript bridge ─────────────────────────────────────
        webView.addJavascriptInterface(new Bridge(), "AndroidBridge");

        // ── WebViewClient ─────────────────────────────────────────
        webView.setWebViewClient(new WebViewClient() {

            @Override
            public WebResourceResponse shouldInterceptRequest(
                WebView view, WebResourceRequest req) {
                WebResourceResponse r =
                    assetLoader.shouldInterceptRequest(req.getUrl());
                return r != null ? r :
                    super.shouldInterceptRequest(view, req);
            }

            @Override
            public boolean shouldOverrideUrlLoading(
                WebView view, WebResourceRequest req) {
                String host = req.getUrl().getHost();
                // Keep appassets in-app; open everything else externally
                if (host != null &&
                    !host.equals("appassets.androidplatform.net")) {
                    Intent i = new Intent(Intent.ACTION_VIEW, req.getUrl());
                    i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    startActivity(i);
                    return true;
                }
                return false;
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
                injectEnv(view);
                registerServiceWorker(view);
            }
        });

        // ── WebChromeClient ───────────────────────────────────────
        webView.setWebChromeClient(new WebChromeClient() {

            @Override
            public void onPermissionRequest(PermissionRequest req) {
                req.grant(req.getResources());
            }

            @Override
            public void onGeolocationPermissionsShowPrompt(
                String origin,
                GeolocationPermissions.Callback cb) {
                cb.invoke(origin, true, false);
            }

            @Override
            public boolean onShowFileChooser(
                WebView view,
                ValueCallback<Uri[]> cb,
                FileChooserParams params) {
                if (fileChooserCb != null) {
                    fileChooserCb.onReceiveValue(null);
                }
                fileChooserCb = cb;
                Intent intent = params.createIntent();
                try {
                    startActivityForResult(intent, 1001);
                } catch (Exception e) {
                    fileChooserCb = null;
                    return false;
                }
                return true;
            }

            // Allow pop-up windows / target="_blank"
            @Override
            public boolean onCreateWindow(
                WebView view, boolean isDialog,
                boolean isUserGesture, Message resultMsg) {
                WebView popup = new WebView(MainActivity.this);
                WebView.WebViewTransport transport =
                    (WebView.WebViewTransport) resultMsg.obj;
                transport.setWebView(popup);
                resultMsg.sendToTarget();
                return true;
            }
        });

        // ── Load the app ──────────────────────────────────────────
        webView.loadUrl(ASSET_BASE + "index.html");
    }

    // ── Inject Cloudflare vars + Android flag ─────────────────────
    private void injectEnv(WebView view) {
        String js =
            "window.__CF_VARS = " + CF_VARS_JSON + ";" +
            "window.__ANDROID = true;" +
            "window.__ASSET_BASE = '" + ASSET_BASE + "';";
        view.evaluateJavascript(js, null);
    }

    // ── Register worker.js as a Service Worker ────────────────────
    private void registerServiceWorker(WebView view) {
        String js =
            "(function() {" +
            "  if (!('serviceWorker' in navigator)) return;" +
            "  navigator.serviceWorker" +
            "    .register('" + ASSET_BASE + "worker.js', " +
            "      {scope: '" + ASSET_BASE + "'})" +
            "    .then(r => console.log('[SW] registered:', r.scope))" +
            "    .catch(e => console.warn('[SW] registration failed:', e));" +
            "})();";
        view.evaluateJavascript(js, null);
    }

    // ── File chooser result ───────────────────────────────────────
    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        if (req == 1001 && fileChooserCb != null) {
            fileChooserCb.onReceiveValue(
                WebChromeClient.FileChooserParams.parseResult(res, data));
            fileChooserCb = null;
        }
    }

    // ── Back-press navigates WebView history ──────────────────────
    @Override
    public void onBackPressed() {
        if (webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    // ── Lifecycle ─────────────────────────────────────────────────
    @Override
    protected void onResume() {
        super.onResume();
        webView.onResume();
        webView.resumeTimers();
    }

    @Override
    protected void onPause() {
        webView.onPause();
        webView.pauseTimers();
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        webView.destroy();
        super.onDestroy();
    }

    // ══════════════════════════════════════════════════════════════
    // JavaScript ↔ Java bridge  (window.AndroidBridge)
    // ══════════════════════════════════════════════════════════════
    private final class Bridge {

        /** Returns the Cloudflare Worker vars as a JSON string. */
        @JavascriptInterface
        public String getVars() {
            return CF_VARS_JSON;
        }

        /** Returns "android" so JS can detect the host platform. */
        @JavascriptInterface
        public String getPlatform() {
            return "android";
        }

        /** Returns the appassets base URL for dynamic asset loading. */
        @JavascriptInterface
        public String getAssetBase() {
            return ASSET_BASE;
        }

        /** Logs a message from JavaScript to Android logcat. */
        @JavascriptInterface
        public void log(String tag, String msg) {
            android.util.Log.d(APP_NAME + "/" + tag, msg);
        }

        /** Trigger a native share sheet. */
        @JavascriptInterface
        public void share(String text) {
            Intent intent = new Intent(Intent.ACTION_SEND);
            intent.setType("text/plain");
            intent.putExtra(Intent.EXTRA_TEXT, text);
            Intent chooser = Intent.createChooser(intent, "Share via");
            chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            getApplicationContext().startActivity(chooser);
        }
    }
}
"""


def gen_main_activity(pkg: str, app_name: str, vars_json: str) -> str:
    return (
        _MAIN_ACTIVITY_TMPL
        .replace("PKG",       pkg)
        .replace("APPNAME",   app_name)
        .replace("VARS_JSON", _java_str(vars_json))
    )


# ── res/layout/activity_main.xml ─────────────────────────────────

def gen_layout() -> str:
    return """\
<?xml version="1.0" encoding="utf-8"?>
<!-- layout is built programmatically in MainActivity;
     this file satisfies the IDE / build tools. -->
<FrameLayout
    xmlns:android="http://schemas.android.com/apk/res/android"
    android:id="@+id/root"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:background="@android:color/black" />
"""


# ── res/values/strings.xml ───────────────────────────────────────

def gen_strings(app_name: str) -> str:
    return f"""\
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">{app_name}</string>
</resources>
"""


# ── res/values/themes.xml ────────────────────────────────────────

def gen_themes() -> str:
    return """\
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <style name="Theme.App" parent="android:Theme.Material.Light.NoActionBar">
        <item name="android:windowBackground">#1a1a2e</item>
        <item name="android:statusBarColor">#0f0f23</item>
        <item name="android:navigationBarColor">#0f0f23</item>
        <item name="android:windowFullscreen">true</item>
        <item name="android:windowContentOverlay">@null</item>
        <item name="android:colorPrimary">#1a1a2e</item>
        <item name="android:colorPrimaryDark">#0f0f23</item>
        <item name="android:colorAccent">#00ff88</item>
    </style>
</resources>
"""


# ── res/xml/network_security_config.xml ──────────────────────────

def gen_network_security() -> str:
    return """\
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <!-- All production traffic must be TLS -->
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <!-- Allow plaintext to localhost only (dev/debug) -->
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">localhost</domain>
        <domain includeSubdomains="true">127.0.0.1</domain>
        <domain includeSubdomains="true">[::1]</domain>
    </domain-config>
</network-security-config>
"""


# ── app/build.gradle ─────────────────────────────────────────────

def gen_app_build_gradle(pkg: str, compile_sdk: int, target_sdk: int) -> str:
    return f"""\
plugins {{
    id 'com.android.application'
}}

android {{
    namespace '{pkg}'
    compileSdk {compile_sdk}

    defaultConfig {{
        applicationId "{pkg}"
        minSdk        {MIN_SDK}
        targetSdk     {target_sdk}
        versionCode   1
        versionName   "1.0"

        // Pixel 9a is arm64; include x86_64 for emulator testing
        ndk {{
            abiFilters "arm64-v8a", "x86_64"
        }}
    }}

    signingConfigs {{
        debug {{
            storeFile     file(System.getProperty("user.home") + "/.android/debug.keystore")
            storePassword "android"
            keyAlias      "androiddebugkey"
            keyPassword   "android"
        }}
    }}

    buildTypes {{
        release {{
            minifyEnabled   false
            signingConfig   signingConfigs.debug   // debug-sign for ADB install
            proguardFiles   getDefaultProguardFile('proguard-android-optimize.txt'),
                            'proguard-rules.pro'
        }}
        debug {{
            debuggable true
            signingConfig signingConfigs.debug
        }}
    }}

    compileOptions {{
        sourceCompatibility JavaVersion.VERSION_{JAVA_VER}
        targetCompatibility JavaVersion.VERSION_{JAVA_VER}
    }}

    // Enable WebView developer tools in debug builds
    buildFeatures {{
        buildConfig true
    }}

    packagingOptions {{
        resources {{
            excludes += ['/META-INF/{{AL2.0,LGPL2.1}}',
                         '/META-INF/LICENSE*']
        }}
    }}
}}

dependencies {{
    // AndroidX
    implementation 'androidx.appcompat:appcompat:1.7.0'

    // WebView with Service Worker + asset loader support
    implementation 'androidx.webkit:webkit:1.12.1'

    // Material components (optional — used by themed dialogs)
    implementation 'com.google.android.material:material:1.12.0'
}}
"""


# ── build.gradle (root) ───────────────────────────────────────────

def gen_root_build_gradle() -> str:
    return f"""\
// Top-level build file — generated by apk_builder.py
plugins {{
    id 'com.android.application' version '{AGP_VERSION}' apply false
    id 'com.android.library'     version '{AGP_VERSION}' apply false
}}
"""


# ── settings.gradle ───────────────────────────────────────────────

def gen_settings_gradle(app_name: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_\-]", "", app_name) or "App"
    return f"""\
pluginManagement {{
    repositories {{
        google()
        mavenCentral()
        gradlePluginPortal()
    }}
}}
dependencyResolutionManagement {{
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {{
        google()
        mavenCentral()
    }}
}}
rootProject.name = "{safe}"
include ':app'
"""


# ── gradle.properties ─────────────────────────────────────────────

def gen_gradle_properties(aapt2_path: str | None = None) -> str:
    lines = [
        "org.gradle.jvmargs=-Xmx2048m -XX:MaxMetaspaceSize=512m -Dfile.encoding=UTF-8",
        "org.gradle.parallel=true",
        "org.gradle.caching=true",
        "org.gradle.configureondemand=true",
        "android.useAndroidX=true",
        "android.enableJetifier=true",
        "kotlin.code.style=official",
        # Suppress the compileSdk version mismatch warning if we ever bump to 36
        "android.suppressUnsupportedCompileSdk=36",
    ]
    if aapt2_path:
        # Critical for Termux/ARM: AGP downloads an x86_64 aapt2 binary by default.
        # On ARM devices (Pixel 9a, Termux) that binary cannot execute.
        # Point AGP at the ARM aapt2 already in the local SDK build-tools.
        lines.append(f"android.aapt2FromMavenOverride={aapt2_path}")
    return "\n".join(lines) + "\n"


# ── gradle/wrapper/gradle-wrapper.properties ──────────────────────

def gen_wrapper_properties() -> str:
    return f"""\
distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionUrl={GRADLE_DIST_URL.replace(":", "\\:")}
networkTimeout=10000
validateDistributionUrl=true
zipStoreBase=GRADLE_USER_HOME
zipStorePath=wrapper/dists
"""


# ── gradlew (Unix shell) ──────────────────────────────────────────

GRADLEW_SH = """#!/bin/sh
##
## Gradle start-up script — POSIX /bin/sh (dash/busybox/bash compatible)
## Generated by apk_builder.py
##
set -e
APP_HOME=$(cd "$(dirname "$0")" && pwd)

# Locate Java — check JAVA_HOME first, then PATH
if [ -n "$JAVA_HOME" ] && [ -f "$JAVA_HOME/bin/java" ]; then
    JAVA_EXE="$JAVA_HOME/bin/java"
else
    JAVA_EXE=$(command -v java 2>/dev/null || true)
fi
if [ -z "$JAVA_EXE" ]; then
    echo "ERROR: JAVA_HOME not set and 'java' not found in PATH." >&2
    exit 1
fi

CLASSPATH="$APP_HOME/gradle/wrapper/gradle-wrapper.jar"
exec "$JAVA_EXE" \\
    -classpath "$CLASSPATH" \\
    org.gradle.wrapper.GradleWrapperMain \\
    "$@"
"""


# ── app/proguard-rules.pro ────────────────────────────────────────

def gen_proguard() -> str:
    return """\
# Keep JavaScript interface methods reachable from WebView
-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}
-keepattributes JavascriptInterface
-keepattributes *Annotation*

# Keep WebView client classes
-keep class androidx.webkit.** { *; }
"""


# ── Service-worker compatibility shim ────────────────────────────

_SW_SHIM = """\
/* ================================================================
   Android WebView Service Worker shim — injected by apk_builder.py
   Provides the ASSET_BASE constant and a minimal Cloudflare-Worker-
   compatible fetch-event polyfill so that worker.js can intercept
   requests when running as a browser Service Worker.
   ================================================================ */

const ASSET_BASE = 'https://appassets.androidplatform.net/assets/';

/* If this file is NOT loaded as a Service Worker, skip setup. */
if (typeof self !== 'undefined' && typeof self.addEventListener === 'function') {

  self.addEventListener('install',  () => self.skipWaiting());
  self.addEventListener('activate', e  => e.waitUntil(self.clients.claim()));

  /* Wrap the Cloudflare-Worker "fetch" handler signature so that the
     original worker.js addEventListener('fetch', handler) works unmodified. */
  const _originalAddEventListener = self.addEventListener.bind(self);
  self.addEventListener = function(type, handler, opts) {
    if (type === 'fetch') {
      _originalAddEventListener('fetch', async (event) => {
        /* Build a Cloudflare-compatible event shim */
        const cfEvent = {
          request:      event.request,
          respondWith:  r => event.respondWith(r),
          waitUntil:    p => event.waitUntil(p),
          passThroughOnException: () => {}
        };
        try {
          await handler(cfEvent);
        } catch (err) {
          /* Fallback: fetch from network */
          event.respondWith(fetch(event.request));
        }
      }, opts);
    } else {
      _originalAddEventListener(type, handler, opts);
    }
  };
}

/* ── Original worker.js follows ── */
"""


# ══════════════════════════════════════════════════════════════════
# PROJECT BUILDER
# ══════════════════════════════════════════════════════════════════

def build_project(
    project_dir: Path,
    cfg: dict,
    worker_js: str,
    index_html: str,
    wrangler_raw: str | None,
    aapt2_path: str | None = None,
    sdk: Path | None = None,
) -> None:

    pkg      = cfg["package"]
    app_name = cfg["name"]
    vars_json = json.dumps(cfg["vars"])

    # Detect highest installed platform SDK — avoids "android.jar not found"
    platform_api = find_highest_platform(sdk) or COMPILE_SDK
    if platform_api != COMPILE_SDK:
        print(f"[INFO] Platform SDK : android-{platform_api} (auto-detected)")

    # ── Directory tree ────────────────────────────────────────────
    java_pkg = pkg.replace(".", "/")
    dirs = [
        project_dir / f"app/src/main/java/{java_pkg}",
        project_dir / "app/src/main/assets",
        project_dir / "app/src/main/res/xml",
        project_dir / "app/src/main/res/layout",
        project_dir / "app/src/main/res/values",
        *(project_dir / f"app/src/main/res/mipmap-{d}"
          for d in ("mdpi", "hdpi", "xhdpi", "xxhdpi", "xxxhdpi")),
        project_dir / "gradle/wrapper",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)

    # ── Manifest ──────────────────────────────────────────────────
    write(project_dir / "app/src/main/AndroidManifest.xml",
          gen_manifest(pkg, app_name))

    # ── Java source ───────────────────────────────────────────────
    write(project_dir / f"app/src/main/java/{java_pkg}/MainActivity.java",
          gen_main_activity(pkg, app_name, vars_json))

    # ── Layouts ───────────────────────────────────────────────────
    write(project_dir / "app/src/main/res/layout/activity_main.xml",
          gen_layout())

    # ── Resources ─────────────────────────────────────────────────
    write(project_dir / "app/src/main/res/values/strings.xml",
          gen_strings(app_name))
    write(project_dir / "app/src/main/res/values/themes.xml",
          gen_themes())
    write(project_dir / "app/src/main/res/xml/network_security_config.xml",
          gen_network_security())

    # ── Assets ────────────────────────────────────────────────────
    # index.html — verbatim (no patching needed)
    write(project_dir / "app/src/main/assets/index.html",
          index_html)

    # worker.js — prepend the SW shim so it works inside WebView
    write(project_dir / "app/src/main/assets/worker.js",
          _SW_SHIM + worker_js)

    if wrangler_raw:
        write(project_dir / "app/src/main/assets/wrangler.toml",
              wrangler_raw)

    # ── Icons (placeholder — replace with branded icon later) ─────
    icon = make_icon_png(48, 48, (26, 26, 46, 255))
    for res in ("mdpi", "hdpi", "xhdpi", "xxhdpi", "xxxhdpi"):
        for name in ("ic_launcher.png", "ic_launcher_round.png"):
            (project_dir / f"app/src/main/res/mipmap-{res}" / name
             ).write_bytes(icon)

    # ── Gradle build scripts ──────────────────────────────────────
    write(project_dir / "app/build.gradle",       gen_app_build_gradle(pkg, platform_api, platform_api))
    write(project_dir / "build.gradle",           gen_root_build_gradle())
    write(project_dir / "settings.gradle",        gen_settings_gradle(app_name))
    write(project_dir / "gradle.properties",      gen_gradle_properties(aapt2_path))
    write(project_dir / "app/proguard-rules.pro", gen_proguard())

    # ── Gradle wrapper ────────────────────────────────────────────
    write(project_dir / "gradle/wrapper/gradle-wrapper.properties",
          gen_wrapper_properties())

    gradlew = project_dir / "gradlew"
    gradlew.write_text(GRADLEW_SH)
    gradlew.chmod(gradlew.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # Download wrapper JAR (needed by gradlew script)
    jar = project_dir / "gradle/wrapper/gradle-wrapper.jar"
    _fetch_wrapper_jar(jar)

    print(f"[OK] Android project written → {project_dir}")
    print(f"     Package  : {pkg}")
    print(f"     App name : {app_name}")
    print(f"     CF vars  : {list(cfg['vars'].keys()) or '(none)'}")


def write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _fetch_wrapper_jar(dest: Path) -> None:
    if dest.exists():
        return
    try:
        print("[INFO] Downloading gradle-wrapper.jar …")
        urllib.request.urlretrieve(WRAPPER_JAR_URL, dest)
        print("[OK]  gradle-wrapper.jar downloaded")
    except Exception as exc:
        print(f"[WARN] Could not download wrapper jar: {exc}")
        print(f"       Run this manually in the project directory:")
        print(f"       gradle wrapper --gradle-version {GRADLE_VERSION}")


# ══════════════════════════════════════════════════════════════════
# LOCAL PROPERTIES
# ══════════════════════════════════════════════════════════════════

def write_local_properties(project_dir: Path, sdk: Path) -> None:
    text = f"sdk.dir={sdk}\n"
    java = find_java()
    if java:
        text += f"# java.home={java.parent.parent}\n"
    (project_dir / "local.properties").write_text(text)


# ══════════════════════════════════════════════════════════════════
# DEBUG KEYSTORE GENERATION
# ══════════════════════════════════════════════════════════════════

def ensure_debug_keystore() -> Path:
    ks = Path.home() / ".android/debug.keystore"
    if ks.exists():
        return ks
    ks.parent.mkdir(parents=True, exist_ok=True)

    keytool = shutil.which("keytool")
    java = find_java()
    if not keytool and java:
        keytool = str(java.parent / "keytool")

    if not keytool:
        print("[WARN] keytool not found — Gradle will generate a debug key itself")
        return ks

    subprocess.run([
        keytool, "-genkey", "-v",
        "-keystore", str(ks),
        "-storepass", "android",
        "-alias", "androiddebugkey",
        "-keypass", "android",
        "-keyalg", "RSA", "-keysize", "2048",
        "-validity", "10000",
        "-dname", "CN=Android Debug,O=Android,C=US",
    ], check=True, capture_output=True)
    print(f"[OK]  Debug keystore created at {ks}")
    return ks


# ══════════════════════════════════════════════════════════════════
# GRADLE BUILD RUNNER
# ══════════════════════════════════════════════════════════════════

def run_gradle(project_dir: Path, build_type: str) -> Path:
    # Prefer system 'gradle' command (reliable in Termux).
    # Fall back to ./gradlew if system gradle not found.
    system_gradle = shutil.which("gradle")
    gradlew = project_dir / "gradlew"

    if system_gradle:
        cmd = [system_gradle]
    elif gradlew.exists() and os.access(gradlew, os.X_OK):
        cmd = [str(gradlew)]
    else:
        raise RuntimeError(
            "Neither 'gradle' in PATH nor executable gradlew found.\n"
            "Install gradle:  pkg install gradle"
        )

    task = f"assemble{build_type.title()}"
    print(f"[BUILD] {cmd[0]} {task}")

    proc = subprocess.run(
        cmd + ["--no-daemon", "--stacktrace", task],
        cwd=project_dir,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    # Print last 6 000 chars of log (enough to see the failure)
    tail = proc.stdout[-6_000:] if len(proc.stdout) > 6_000 else proc.stdout
    print(tail)

    if proc.returncode != 0:
        log = project_dir / "build-log.txt"
        log.write_text(proc.stdout)
        print(f"[FULL LOG] {log}")
        raise RuntimeError(f"Gradle exited {proc.returncode}")

    # Locate output APK
    out_dir = project_dir / f"app/build/outputs/apk/{build_type}"
    apks = list(out_dir.glob("*.apk")) if out_dir.exists() else []
    if not apks:
        apks = list(project_dir.rglob("app-*.apk"))
    if not apks:
        raise RuntimeError("Build succeeded but no APK found under app/build/")

    return max(apks, key=lambda p: p.stat().st_size)


# ══════════════════════════════════════════════════════════════════
# APK SIGNING  (explicit apksigner pass — Gradle also signs,
#               but a second pass confirms the file is valid)
# ══════════════════════════════════════════════════════════════════

def sign_apk(apk: Path, sdk: Path) -> Path:
    bt = best_build_tools(sdk)
    if not bt:
        print("[SKIP] No build-tools found — skipping explicit signing")
        return apk

    apksigner = bt / "apksigner"
    if not apksigner.exists():
        print(f"[SKIP] apksigner not found in {bt}")
        return apk

    ks = ensure_debug_keystore()
    out = apk.parent / f"{apk.stem}-SIGNED.apk"

    result = subprocess.run([
        str(apksigner), "sign",
        "--ks", str(ks),
        "--ks-pass", "pass:android",
        "--key-pass", "pass:android",
        "--ks-key-alias", "androiddebugkey",
        "--out", str(out),
        str(apk),
    ], capture_output=True, text=True)

    if result.returncode == 0:
        print(f"[OK]  Signed: {out.name}")
        return out
    else:
        print(f"[WARN] apksigner failed: {result.stderr.strip()}")
        return apk


# ══════════════════════════════════════════════════════════════════
# ADB INSTALL  (optional)
# ══════════════════════════════════════════════════════════════════

def adb_install(apk: Path) -> None:
    adb = shutil.which("adb")
    if not adb:
        print("[SKIP] adb not in PATH — install manually:")
        print(f"       adb install -r -d -g {apk}")
        return

    result = subprocess.run([adb, "devices"], capture_output=True, text=True)
    devices = [l.split("\t")[0]
               for l in result.stdout.splitlines()
               if "\tdevice" in l]
    if not devices:
        print("[SKIP] No ADB device/emulator connected")
        print(f"       adb install -r -d -g {apk}")
        return

    target = devices[0]
    print(f"[ADB]  Installing on {target} …")
    subprocess.run(
        [adb, "-s", target, "install", "-r", "-d", "-g", str(apk)],
        check=True,
    )
    print(f"[OK]  App installed on {target}")


# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Convert wrangler.toml + worker.js + index.html → Android APK",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Run from the directory containing worker.js and index.html:
  cd ~/mdmcheck
  python3 apk_builder.py

Examples:
  python3 apk_builder.py --out mdmcheck.apk --install
  python3 apk_builder.py --skip-build          # generate project only
  python3 apk_builder.py --build-type debug
        """,
    )
    ap.add_argument("--wrangler",    default="wrangler.toml", metavar="FILE")
    ap.add_argument("--worker",      default="worker.js",     metavar="FILE")
    ap.add_argument("--html",        default="index.html",    metavar="FILE")
    ap.add_argument("--out",         default=None,            metavar="APK",
                    help="Output APK filename (default: <app-name>.apk)")
    ap.add_argument("--build-dir",   default=None,            metavar="DIR",
                    help="Build directory (default: apk-project/ next to worker.js)")
    ap.add_argument("--build-type",  default="release",
                    choices=["release", "debug"])
    ap.add_argument("--install",     action="store_true",
                    help="ADB-install the APK after build")
    ap.add_argument("--skip-build",  action="store_true",
                    help="Generate project files only, do not invoke Gradle")
    args = ap.parse_args()

    # ── Resolve input files ───────────────────────────────────────
    # Search current dir, then script dir, then parent dir
    def find_file(name: str, arg: str) -> Path:
        candidates = [
            Path(arg),
            Path(__file__).parent / arg,
            Path(arg).parent.parent / arg,
        ]
        for p in candidates:
            if p.exists():
                return p.resolve()
        return Path(arg)   # let it fail with a clear message below

    worker_path   = find_file("worker.js",    args.worker)
    html_path     = find_file("index.html",   args.html)
    wrangler_path = find_file("wrangler.toml", args.wrangler)

    # Also check parent directory for wrangler.toml (common when running
    # from inside a sub-directory)
    if not wrangler_path.exists():
        parent_w = Path.cwd().parent / "wrangler.toml"
        if parent_w.exists():
            wrangler_path = parent_w

    missing = [str(p) for p in (worker_path, html_path) if not p.exists()]
    if missing:
        print(f"[FATAL] Required file(s) not found: {', '.join(missing)}")
        print(f"  Run from the directory that contains worker.js and index.html.")
        sys.exit(1)

    worker_js    = worker_path.read_text(encoding="utf-8")
    index_html   = html_path.read_text(encoding="utf-8")
    wrangler_raw = (wrangler_path.read_text(encoding="utf-8")
                    if wrangler_path.exists() else None)

    # ── Parse wrangler config ─────────────────────────────────────
    cfg = parse_wrangler(wrangler_path)

    # ── Build directory — default next to worker.js, never nested ─
    if args.build_dir:
        project_dir = Path(args.build_dir).resolve()
    else:
        project_dir = (worker_path.parent / "apk-project").resolve()

    print(f"""
╔══════════════════════════════════════════════╗
║  apk_builder.py — Cloudflare Worker → APK   ║
╠══════════════════════════════════════════════╣
║  App name  : {cfg['name']:<30} ║
║  Package   : {cfg['package']:<30} ║
║  Target    : Android {TARGET_SDK} / Pixel 9a (arm64)  ║
║  Build     : {args.build_type:<30} ║
╚══════════════════════════════════════════════╝
""")

    # ── Prerequisites ─────────────────────────────────────────────
    _java, sdk = check_prereqs(args.skip_build)
    aapt2_path = find_aapt2(sdk)

    if sdk:
        print(f"[INFO] Android SDK : {sdk}")
    if _java:
        print(f"[INFO] Java        : {_java}")
    if aapt2_path:
        print(f"[INFO] AAPT2 override active (ARM binary)")
    elif sdk and not args.skip_build:
        print("[WARN] No ARM aapt2 found in SDK build-tools.")
        print("[WARN] If build fails with 'Daemon startup failed', install build-tools:")
        print("[WARN]   sdkmanager 'build-tools;34.0.0'")

    # ── Generate project ──────────────────────────────────────────
    if project_dir.exists():
        shutil.rmtree(project_dir)
    project_dir.mkdir(parents=True)

    build_project(project_dir, cfg, worker_js, index_html, wrangler_raw,
                  aapt2_path=aapt2_path, sdk=sdk)

    if sdk:
        write_local_properties(project_dir, sdk)
        ensure_debug_keystore()
    else:
        print("[WARN] Set ANDROID_HOME and re-run, or add local.properties manually")

    if args.skip_build:
        print(f"\n[DONE] Project generated at: {project_dir}")
        print(f"       Build: cd {project_dir} && gradle assembleRelease")
        return

    # ── Gradle build ──────────────────────────────────────────────
    try:
        apk = run_gradle(project_dir, args.build_type)
    except RuntimeError as e:
        print(f"\n[FATAL] {e}")
        print(f"\nProject is at: {project_dir}")
        print("Build manually:")
        print(f"  cd {project_dir}")
        print(f"  gradle assemble{args.build_type.title()}")
        sys.exit(1)

    # ── Sign ──────────────────────────────────────────────────────
    if sdk:
        apk = sign_apk(apk, sdk)

    # ── Copy to final location ────────────────────────────────────
    out_name = (args.out or
                f"{re.sub(r'[^a-zA-Z0-9_]', '_', cfg['name']).lower()}.apk")
    out_path = Path(out_name).resolve()
    shutil.copy2(apk, out_path)

    # ── Summary ───────────────────────────────────────────────────
    size_mb = out_path.stat().st_size / 1_048_576
    print(f"""
╔══════════════════════════════════════════════╗
║  BUILD COMPLETE                              ║
╠══════════════════════════════════════════════╣
║  APK  : {str(out_path):<36} ║
║  Size : {size_mb:>5.1f} MB                               ║
╚══════════════════════════════════════════════╝

Install on Pixel 9a:
  adb install -r -d -g "{out_path}"

Or wirelessly (Wireless Debugging active):
  adb connect <device-ip>:5555
  adb install -r -d -g "{out_path}"
""")

    # ── Optional ADB install ──────────────────────────────────────
    if args.install:
        adb_install(out_path)


if __name__ == "__main__":
    main()
