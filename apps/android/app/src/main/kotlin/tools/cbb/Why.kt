// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import tools.cbb.kit.WhyReason
import java.text.DateFormat
import java.util.Date

/**
 * "Why it does not sync" in the advanced settings (docs/apps.md): the core's
 * reasons for this phone, the one that stops the most first and large, asked
 * again every two seconds while the settings show. The core decides the
 * reasons; the app only says each code in its words.
 */
@Composable
internal fun WhySection(model: AppModel, details: Boolean) {
    var reasons by remember { mutableStateOf<List<WhyReason>?>(null) }
    LaunchedEffect(Unit) {
        while (true) {
            reasons = withContext(Dispatchers.IO) { model.group.why() }
            delay(2_000)
        }
    }
    Section(stringResource(R.string.why_screen)) {
        Column(Modifier.padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            val rs = reasons
            when {
                rs == null -> {}
                rs.isEmpty() -> Text(stringResource(R.string.why_ok))
                else -> {
                    WhyRow(rs.first(), main = true, details = details)
                    if (rs.size > 1) {
                        Text(
                            stringResource(R.string.why_also),
                            style = MaterialTheme.typography.titleSmall,
                            color = LocalPalette.current.textDim,
                            modifier = Modifier.semantics { heading() },
                        )
                        rs.drop(1).forEach { WhyRow(it, main = false, details = details) }
                    }
                }
            }
        }
    }
}

@Composable
private fun WhyRow(r: WhyReason, main: Boolean, details: Boolean) {
    val palette = LocalPalette.current
    Column(Modifier.fillMaxWidth().testTag("why-" + r.code)) {
        Text(
            whyTitle(r),
            fontWeight = if (main) FontWeight.SemiBold else FontWeight.Normal,
            color = if (r.level == "stop") palette.danger else palette.text,
        )
        whyAction(r)?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = palette.textDim) }
        if (details) {
            Text(
                listOf(r.code, r.detail).filter { it.isNotEmpty() }.joinToString(": "),
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = palette.textDim,
            )
        }
    }
}

/** What is wrong, in the app's words. */
@Composable
internal fun whyTitle(r: WhyReason): String {
    val names = r.devices.joinToString(", ")
    val date = if (r.untilMS > 0) DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(r.untilMS)) else ""
    return when (r.code) {
        "not_in_group" -> stringResource(R.string.why_not_in_group_t)
        "removed" -> stringResource(R.string.why_removed_t)
        "taken_over" -> stringResource(R.string.why_taken_over_t, r.device)
        "frozen" -> stringResource(R.string.why_frozen_t)
        "cert_expired" -> stringResource(R.string.why_cert_expired_t, date)
        "cert_ending" -> stringResource(R.string.why_cert_ending_t, date)
        "stopped" -> stringResource(R.string.why_stopped_t)
        "secrets_stopped" -> stringResource(R.string.why_secrets_stopped_t)
        "sync_off" -> if (r.untilMS > 0) stringResource(R.string.why_sync_off_until_t, date) else stringResource(R.string.why_sync_off_t)
        "only_device" -> stringResource(R.string.why_only_device_t)
        "away_off" -> stringResource(R.string.why_away_off_t)
        "new_network" -> stringResource(R.string.why_new_network_t)
        "no_hub" -> stringResource(R.string.why_no_hub_t)
        "tunnel_blocked" -> stringResource(R.string.why_tunnel_blocked_t, r.device)
        "hub_unreachable" -> stringResource(R.string.why_hub_unreachable_t, r.device)
        "alone" -> stringResource(R.string.why_alone_t)
        "relay_down" -> stringResource(R.string.why_relay_down_t)
        "hub_waiting" -> stringResource(R.string.why_hub_waiting_t)
        "muted" -> if (r.untilMS > 0) stringResource(R.string.why_muted_until_t, date) else stringResource(R.string.why_muted_t)
        "forwarder_down" -> stringResource(R.string.why_forwarder_down_t)
        "entries_stale" -> stringResource(R.string.why_entries_stale_t)
        "newer" -> stringResource(R.string.why_newer_t)
        "unreached" -> stringResource(R.string.why_unreached_t, names)
        "devices_offline" -> stringResource(R.string.why_devices_offline_t, names)
        "devices_sync_off" -> stringResource(R.string.why_devices_sync_off_t, names)
        "devices_muted" -> stringResource(R.string.why_devices_muted_t, names)
        "update" -> stringResource(R.string.why_update_t, r.value)
        else -> r.code
    }
}

/** What to do, null when there is nothing to do. */
@Composable
internal fun whyAction(r: WhyReason): String? = when (r.code) {
    "not_in_group" -> stringResource(R.string.why_not_in_group_d)
    "removed" -> stringResource(R.string.why_removed_d)
    "taken_over" -> stringResource(R.string.why_taken_over_d, r.device)
    "frozen" -> stringResource(R.string.why_frozen_d)
    "cert_expired" -> stringResource(R.string.why_cert_expired_d)
    "cert_ending" -> stringResource(R.string.why_cert_ending_d)
    "stopped" -> stringResource(R.string.why_stopped_d)
    "sync_off" -> stringResource(R.string.why_sync_off_d)
    "only_device" -> stringResource(R.string.why_only_device_d)
    "away_off" -> stringResource(R.string.why_away_off_d)
    "new_network" -> stringResource(R.string.why_new_network_d)
    "no_hub" -> stringResource(R.string.why_no_hub_d)
    "tunnel_blocked" -> stringResource(R.string.why_tunnel_blocked_d)
    "hub_unreachable" -> stringResource(R.string.why_hub_unreachable_d)
    "alone" -> stringResource(R.string.why_alone_d)
    "relay_down" -> stringResource(R.string.why_relay_down_d)
    "hub_waiting" -> stringResource(R.string.why_hub_waiting_d)
    "muted" -> stringResource(R.string.why_muted_d)
    "forwarder_down" -> stringResource(R.string.why_forwarder_down_d)
    "entries_stale" -> stringResource(R.string.why_entries_stale_d)
    "newer" -> stringResource(R.string.why_newer_d)
    "unreached" -> stringResource(R.string.why_unreached_d)
    else -> null
}
