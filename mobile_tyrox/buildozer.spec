[app]
title = TYROX Mobile
package.name = tyroxmobile
package.domain = com.tyrox
source.dir = .
source.include_exts = py,kv,png,jpg,atlas
version = 0.4.0
requirements = python3,kivy
orientation = portrait
fullscreen = 0
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,CHANGE_WIFI_MULTICAST_STATE
android.api = 35
android.minapi = 23
android.archs = arm64-v8a, armeabi-v7a
android.allow_backup = False

[buildozer]
log_level = 2
warn_on_root = 1
