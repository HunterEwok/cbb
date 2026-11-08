// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command cbb-desktop is the tray app for Windows and Linux: a tray item and
// a window over the cbb service, in the Glass design of the phone apps
// (docs/apps.md, "The tray app"). The service and its clipboard agent keep
// syncing without it.
package main

import (
	"embed"
	_ "embed"
	"log"
	"runtime"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

//go:embed all:frontend
var assets embed.FS

//go:embed icon.png
var icon []byte

func main() {
	desk := NewDesk()
	app := application.New(application.Options{
		Name:        "CBB",
		Description: "One clipboard for the devices of your home",
		Icon:        icon,
		Services:    []application.Service{application.NewService(desk)},
		Assets:      application.AssetOptions{Handler: application.BundledAssetFileServer(assets)},
		SingleInstance: &application.SingleInstanceOptions{
			UniqueID: "tools.cbb.desktop",
			OnSecondInstanceLaunch: func(application.SecondInstanceData) {
				desk.Open()
			},
		},
	})
	desk.app = app

	window := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:      "main",
		Title:     "CBB",
		Width:     920,
		Height:    640,
		MinWidth:  520,
		MinHeight: 420,
		URL:       "/",
		Hidden:    true,
	})
	// Closing the window keeps the tray item.
	window.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		window.Hide()
		e.Cancel()
	})
	desk.window = window

	tray := app.SystemTray.New()
	setTrayIcon(tray, "tray")
	tray.SetTooltip("CBB")
	if runtime.GOOS == "linux" {
		// Wails names the StatusNotifierItem (its title and tooltip) after
		// the label it has when the tray starts, else "Wails", and does not
		// pass a later tooltip on there yet.
		tray.SetLabel("CBB")
	}
	tray.OnClick(desk.Open)
	desk.tray = tray
	desk.updateTray()
	go desk.watch()
	// The start window, after the install and while this computer is in
	// no group.
	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) { go desk.openIfNoGroup() })

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
