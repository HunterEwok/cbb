// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.res.Configuration
import java.util.Locale

/**
 * The language the user picks on the Start screen or in Settings; System
 * follows the system's.
 */
enum class LanguageChoice(val key: String) {
    SYSTEM("system"),
    EN("en"),
    ZH("zh"),
    ES("es"),
    RU("ru"),
    AR("ar"),
    SW("sw"),
    HE("he"),
    HI("hi"),
    ;

    /** The locale the app shows, null for the system's. */
    val locale: Locale? get() = if (this == SYSTEM) null else Locale.forLanguageTag(key)

    /**
     * The language by its own name ("English", "Russian" in Russian), so
     * that it can be found whichever language the app shows now; null for
     * System, whose title is a string resource.
     */
    val ownName: String?
        get() {
            val l = locale ?: return null
            return l.getDisplayLanguage(l).replaceFirstChar { it.titlecase(l) }
        }

    companion object {
        fun of(key: String?): LanguageChoice = entries.firstOrNull { it.key == key } ?: SYSTEM

        /** The languages the app is translated into, without System. */
        val translations = entries.filter { it != SYSTEM }
    }
}

/** What the app remembers between runs, besides the group. */
class Settings(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences("settings", Context.MODE_PRIVATE)
    private val debuggable = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0

    /** A name of Tokens.colors, or ColorChoice.MATERIAL. */
    var color: String
        get() = prefs.getString("color", null) ?: "terminal"
        set(v) = prefs.edit().putString("color", v).apply()

    var appearance: Appearance
        get() = Appearance.of(prefs.getString("appearance", null))
        set(v) = prefs.edit().putString("appearance", v.key).apply()

    /** Tiles or a list on a phone; on a big screen the orbit too, which it starts with. */
    var layout: DeviceLayout
        get() = DeviceLayout.of(prefs.getString("deviceLayout", null), DeviceLayout.TILES)
        set(v) = prefs.edit().putString("deviceLayout", v.key).apply()

    var wideLayout: DeviceLayout
        get() = DeviceLayout.of(prefs.getString("deviceLayoutWide", null), DeviceLayout.ORBIT)
        set(v) = prefs.edit().putString("deviceLayoutWide", v.key).apply()

    /**
     * The user's order of the device tiles and their collections, as the
     * kit's Arrangement writes it; null until the user changes something.
     * Kept on this phone only, never sent to the group.
     */
    var deviceArrangement: String?
        get() = prefs.getString("device_arrangement", null)
        set(v) = prefs.edit().putString("device_arrangement", v).apply()

    var language: LanguageChoice
        get() = LanguageChoice.of(prefs.getString("language", null))
        set(v) = prefs.edit().putString("language", v.key).apply()

    /**
     * The apps whose Share, selection menu and launcher entry go without
     * asking first: the user answered "Always allow" for each. Settings
     * forgets them. The old switch for every app is gone.
     */
    var allowedApps: Set<String>
        get() = prefs.getStringSet("allowedApps", null).orEmpty().toSet()
        set(v) = prefs.edit().putStringSet("allowedApps", v).remove("alwaysAllowShare").apply()

    /** Whether Settings shows the advanced ones. */
    var advanced: Boolean
        get() = prefs.getBoolean("advanced", false)
        set(v) = prefs.edit().putBoolean("advanced", v).apply()

    /** Whether this phone made its own key at the first launch. */
    var prepared: Boolean
        get() = prefs.getBoolean("prepared", false)
        set(v) = prefs.edit().putBoolean("prepared", v).apply()

    /**
     * Whether a message names the error underneath, to find out what
     * failed: on in debug builds, off in release ones, and either way what
     * the switch in Settings (seven taps on the version show it) or the
     * launch extra ShowErrorDetails set last
     * (adb shell am start -n tools.cbb/tools.cbb.MainActivity --ez ShowErrorDetails true).
     */
    var showsErrorDetails: Boolean
        get() = if (prefs.contains(ERROR_DETAILS)) prefs.getBoolean(ERROR_DETAILS, false) else debuggable
        set(v) = prefs.edit().putBoolean(ERROR_DETAILS, v).apply()

    /**
     * Whether the user chose to keep this phone as the hub when the app
     * suggested a computer that is always on (docs/design.md, "Moving the
     * hub to a computer"): the app then does not suggest it again.
     */
    var keepsPhoneHub: Boolean
        get() = prefs.getBoolean("keepsPhoneHub", false)
        set(v) = prefs.edit().putBoolean("keepsPhoneHub", v).apply()

    /** The bug reports' state as the core keeps it (docs/core-api.md, "Bug reports"). */
    var bugState: String?
        get() = prefs.getString("bugState", null)
        set(v) = prefs.edit().putString("bugState", v).apply()

    /** Whether seven taps on the version showed the error details switch in Settings. */
    var errorDetailsSwitch: Boolean
        get() = prefs.getBoolean("errorDetailsSwitch", false)
        set(v) = prefs.edit().putBoolean("errorDetailsSwitch", v).apply()

    companion object {
        const val ERROR_DETAILS = "ShowErrorDetails"

        /** context showing the chosen language, for the activity's base context. */
        fun localized(context: Context): Context {
            val locale = Settings(context).language.locale ?: return context
            val config = Configuration(context.resources.configuration)
            config.setLocale(locale)
            return context.createConfigurationContext(config)
        }
    }
}
