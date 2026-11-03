// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import tools.cbb.kit.Keyboard

/**
 * This phone as a Bluetooth keyboard (BluetoothKeyboard): the switch, the
 * host among the paired devices, the host's layout and the typing speed,
 * whether remote pastes go there, and a button that types the clipboard.
 * A phone whose maker left the profile out says so, with the underlying
 * error when error details are on.
 */
@Composable
internal fun KeyboardSection(keyboard: BluetoothKeyboard, details: Boolean) {
    val palette = LocalPalette.current
    val context = LocalContext.current
    val state by keyboard.state.collectAsState()
    var set by remember { mutableStateOf(keyboard.settings) }
    var hosts by remember { mutableStateOf(keyboard.pairedHosts()) }
    var typed by remember { mutableStateOf<BluetoothKeyboard.Failure?>(null) }
    var typedOK by remember { mutableStateOf(false) }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        set = keyboard.settings
        hosts = keyboard.pairedHosts()
        keyboard.apply()
    }
    fun change(new: Keyboard.Settings) {
        runCatching { keyboard.settings = new }.onFailure { Log.e("cbb", "saving the keyboard settings", it) }
        set = keyboard.settings
        hosts = keyboard.pairedHosts()
        keyboard.apply()
    }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        hosts = keyboard.pairedHosts()
        keyboard.apply()
    }
    val system = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        hosts = keyboard.pairedHosts()
        keyboard.apply()
    }
    val clipboardEmpty = stringResource(R.string.keyboard_clipboard_empty)
    Section(stringResource(R.string.keyboard)) {
        Column(Modifier.padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            Row(
                Modifier.fillMaxWidth().focusRing().clickable(role = Role.Switch) {
                    val on = !set.on
                    change(set.copy(on = on))
                    if (on && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && !keyboard.permitted()) {
                        permission.launch(arrayOf(Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_ADVERTISE))
                    }
                },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(stringResource(R.string.keyboard_switch), modifier = Modifier.weight(1f), fontWeight = FontWeight.SemiBold)
                Switch(checked = set.on, onCheckedChange = null)
            }
            Text(stringResource(R.string.keyboard_body), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
            if (!set.on) return@Column
            val (line, detail, bad) = when (val s = state) {
                BluetoothKeyboard.State.Off, BluetoothKeyboard.State.Starting -> Triple(R.string.keyboard_starting, null, false)
                is BluetoothKeyboard.State.Unsupported -> Triple(R.string.keyboard_unsupported, s.detail, true)
                BluetoothKeyboard.State.NoPermission -> Triple(R.string.keyboard_no_permission, null, true)
                BluetoothKeyboard.State.BluetoothOff -> Triple(R.string.keyboard_bluetooth_off, null, true)
                is BluetoothKeyboard.State.Refused -> Triple(R.string.keyboard_refused, s.detail, true)
                is BluetoothKeyboard.State.Ready -> Triple(if (s.host == null) R.string.keyboard_pick_host else R.string.keyboard_connecting, null, false)
                is BluetoothKeyboard.State.Connected -> Triple(R.string.keyboard_connected, null, false)
            }
            val connectedName = (state as? BluetoothKeyboard.State.Connected)?.name
            Text(
                if (connectedName != null) stringResource(line, connectedName) else stringResource(line),
                style = MaterialTheme.typography.bodyMedium,
                color = if (bad) palette.danger else palette.text,
            )
            if (details && detail != null) Text(detail, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, color = palette.textDim)
            when (state) {
                BluetoothKeyboard.State.NoPermission -> TextButton(onClick = {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        permission.launch(arrayOf(Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_ADVERTISE))
                    }
                }) { Text(stringResource(R.string.keyboard_allow), color = palette.accent) }
                BluetoothKeyboard.State.BluetoothOff -> TextButton(onClick = {
                    runCatching { system.launch(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE)) }
                }) { Text(stringResource(R.string.keyboard_turn_on_bluetooth), color = palette.accent) }
                else -> {}
            }
            if (state is BluetoothKeyboard.State.Unsupported || state == BluetoothKeyboard.State.NoPermission) return@Column
        }
        if (!set.on || state is BluetoothKeyboard.State.Unsupported || state == BluetoothKeyboard.State.NoPermission) return@Section
        HorizontalDivider(color = palette.grid)
        Text(stringResource(R.string.keyboard_host), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(Tokens.spacingMedium))
        if (hosts.isEmpty()) {
            Text(stringResource(R.string.keyboard_no_hosts), style = MaterialTheme.typography.bodyMedium, color = palette.textDim, modifier = Modifier.padding(horizontal = Tokens.spacingMedium))
        }
        for ((address, name) in hosts) Choice(name, set.host == address) { change(set.copy(host = address)) }
        TextButton(
            onClick = {
                // The host finds the phone and pairs with it from its own Bluetooth settings.
                runCatching { system.launch(Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE).putExtra(BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION, 120)) }
            },
            modifier = Modifier.padding(horizontal = Tokens.spacingSmall),
        ) { Text(stringResource(R.string.keyboard_discoverable), color = palette.accent) }
        HorizontalDivider(color = palette.grid)
        Text(stringResource(R.string.keyboard_layout), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(Tokens.spacingMedium))
        for (l in Keyboard.Layout.entries) {
            Choice(stringResource(if (l == Keyboard.Layout.US) R.string.keyboard_layout_us else R.string.keyboard_layout_ru), set.layout == l) { change(set.copy(layout = l)) }
        }
        HorizontalDivider(color = palette.grid)
        Text(stringResource(R.string.keyboard_rate), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(Tokens.spacingMedium))
        for (r in listOf(10, Keyboard.DEFAULT_RATE, 40)) {
            Choice(stringResource(R.string.keyboard_rate_value, r), set.rate == r) { change(set.copy(rate = r)) }
        }
        HorizontalDivider(color = palette.grid)
        Column(Modifier.padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            Row(Modifier.fillMaxWidth().focusRing().clickable(role = Role.Switch) { change(set.copy(pastes = !set.pastes)) }, verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.keyboard_pastes), modifier = Modifier.weight(1f))
                Switch(checked = set.pastes, onCheckedChange = null)
            }
            Text(stringResource(R.string.keyboard_pastes_body), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
            TextButton(
                enabled = state is BluetoothKeyboard.State.Connected,
                onClick = {
                    val text = Clipboard.read(context)
                    typed = if (text.isNullOrEmpty()) BluetoothKeyboard.Failure(clipboardEmpty) else keyboard.type(text.replace("\r\n", "\n"))
                    typedOK = typed == null
                },
            ) { Text(stringResource(R.string.keyboard_type_clipboard), color = palette.accent) }
            if (typedOK) Text(stringResource(R.string.keyboard_typing), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
            typed?.let { f ->
                val why = if (f.chars.isNotEmpty()) stringResource(R.string.keyboard_untypeable, f.chars.joinToString(" ")) else stringResource(R.string.keyboard_type_failed)
                Text(why, style = MaterialTheme.typography.bodyMedium, color = palette.danger)
                // The reason is in English, as it goes to a sender too; the details switch shows it.
                if (details) Text(f.reason + (f.detail?.let { "\n" + it } ?: ""), style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, color = palette.textDim)
            }
        }
    }
}
