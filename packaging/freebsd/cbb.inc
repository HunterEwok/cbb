<?php

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The OPNsense plugin hook of CBB; install.sh puts it in
// /usr/local/etc/inc/plugins.inc.d on OPNsense. OPNsense writes pf's
// ruleset anew at each filter reload, so the rules firewall.sh loads into
// the anchor "cbb" count only while the ruleset names the
// anchor: cbb_firewall names it, at the end, after the user's
// rules, which therefore still win. cbb_services shows the
// service under System > Diagnostics > Services and on the dashboard.

function cbb_services()
{
    $services = [];
    if (!is_file('/usr/local/etc/rc.d/cbb')) {
        return $services;
    }
    $rc = '/usr/local/etc/rc.d/cbb';
    $services[] = [
        'description' => gettext('CBB'),
        'name' => 'cbb',
        'pidfile' => '/var/run/cbb/daemon.pid',
        'mwexec' => [
            'start' => ["{$rc} onestart"],
            'stop' => ["{$rc} onestop"],
            'restart' => ["{$rc} onerestart"],
        ],
    ];
    return $services;
}

function cbb_firewall($fw)
{
    $fw->registerAnchor('cbb', 'fw');
}
