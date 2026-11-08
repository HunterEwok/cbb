// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The changes of the tiles' arrangement (docs/apps.md, "Collections and the
// order of the tiles") as operations of the core's arrange call, for the
// items App::arranged gives.

// How an operation names the item.
function ref(item) {
    return item.kind === "device" ? { device: item.device.device } : { collection: item.id }
}

// A collection's devices as items of its level.
function items(devices) {
    return devices.map(function(d) { return { kind: "device", device: d } })
}

// The move of level[index] to "start", "earlier", "later" or "end" of its
// level, or null when it is there already.
function move(level, index, to) {
    var op = { op: "move", item: ref(level[index]) }
    switch (to) {
    case "start":
        if (index === 0)
            return null
        op.before = ref(level[0])
        break
    case "earlier":
        if (index === 0)
            return null
        op.before = ref(level[index - 1])
        break
    case "later":
        if (index === level.length - 1)
            return null
        if (index + 2 < level.length)
            op.before = ref(level[index + 2])
        break
    case "end":
        if (index === level.length - 1)
            return null
        break
    }
    return op
}

// The collections of the view, as {id, name}.
function collections(view) {
    return view.filter(function(i) { return i.kind === "collection" })
               .map(function(i) { return { id: i.id, name: i.name } })
}

// The collection with the ID id in the view, or null.
function find(view, id) {
    for (var i = 0; i < view.length; i++)
        if (view[i].kind === "collection" && view[i].id === id)
            return view[i]
    return null
}

// How many of a collection's devices are online, this phone counting.
function online(devices) {
    return devices.filter(function(d) { return d.online || d.self }).length
}

// The change a drag of level[from] dropped on level[to] makes, as on
// Android: a device dropped on a collection goes into it, any other item
// takes the place of the one it is dropped on. null when nothing changes.
function drop(level, from, to) {
    var item = level[from], target = level[to]
    if (from === to)
        return null
    if (target.kind === "collection" && item.kind === "device")
        return { op: "into", device: item.device.device, collection: target.id }
    if (to < from)
        return { op: "move", item: ref(item), before: ref(target) }
    return to + 1 < level.length ? { op: "move", item: ref(item), before: ref(level[to + 1]) }
                                 : { op: "move", item: ref(item) }
}
