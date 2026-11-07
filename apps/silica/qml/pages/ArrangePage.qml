// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0
import "arrange.js" as Arrange
import "devices.js" as Devices

// Every change of the arrangement for one tile, which a long press opens
// (docs/apps.md, "Collections and the order of the tiles"): the moves in
// its level, into and out of a collection, and on a collection its name
// and ungrouping. Nothing leaves the phone.
Page {
    id: page
    property var item          // an item of App::arranged
    property var level         // the items of its level
    property int index
    property var view          // the whole view, for its collections
    property string inCollection: "" // the collection it is in

    function apply(op) {
        if (op !== null)
            app.arrange(op)
        pageStack.pop()
    }

    SilicaListView {
        anchors.fill: parent
        header: PageHeader {
            title: page.item.kind === "device" ? Devices.name(page.item.device) : page.item.name
            description: qsTr("Arrange")
        }
        model: ListModel { id: actions }
        delegate: ListItem {
            visible: model.shown
            contentHeight: model.shown ? Theme.itemSizeSmall : 0
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                anchors.verticalCenter: parent.verticalCenter
                text: model.label
                color: highlighted ? Theme.highlightColor : Theme.primaryColor
                truncationMode: TruncationMode.Fade
            }
            onClicked: page.act(model.action, model.collection)
        }
        VerticalScrollDecorator {}
    }

    function act(action, collection) {
        var id = page.item.kind === "device" ? page.item.device.device : ""
        switch (action) {
        case "start": case "earlier": case "later": case "end":
            apply(Arrange.move(page.level, page.index, action))
            break
        case "into":
            apply({ op: "into", device: id, collection: collection })
            break
        case "new":
            pageStack.replace(Qt.resolvedUrl("CollectionNameDialog.qml"), { devices: [id] })
            break
        case "out":
            apply({ op: "out", device: id })
            break
        case "rename":
            pageStack.replace(Qt.resolvedUrl("CollectionNameDialog.qml"),
                              { collection: page.item.id, name: page.item.name })
            break
        case "ungroup":
            apply({ op: "ungroup", collection: page.item.id })
            break
        }
    }

    Component.onCompleted: {
        var last = page.level.length - 1
        function add(action, label, shown, collection) {
            actions.append({ action: action, label: label, shown: shown, collection: collection || "" })
        }
        add("start", qsTr("Move to start"), page.index > 0)
        add("earlier", qsTr("Move earlier"), page.index > 0)
        add("later", qsTr("Move later"), page.index < last)
        add("end", qsTr("Move to end"), page.index < last)
        if (page.item.kind === "device") {
            Arrange.collections(page.view).forEach(function(c) {
                add("into", qsTr("Move to %1").arg(c.name), c.id !== page.inCollection, c.id)
            })
            add("new", qsTr("New collection…"), true)
            add("out", qsTr("Take out of collection"), page.inCollection !== "")
        } else {
            add("rename", qsTr("Rename collection…"), true)
            add("ungroup", qsTr("Ungroup"), true)
        }
    }
}
