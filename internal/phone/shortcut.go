// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package phone

import (
	"bytes"
	"embed"
	"fmt"
	"sort"
	"unicode/utf16"
)

// The shortcut: UnsignedShortcut builds it as a property list, which
// tools/shortcut writes to shortcut/cbb.plist. iOS imports only a
// signed shortcut, so the maintainer converts that file to the binary form
// and signs it on a Mac with `shortcuts sign` into
// shortcut/cbb.shortcut, which the build embeds and the profile port
// serves (see docs/maintaining.md).
//
// The shortcut keeps its token in iCloud Drive at Shortcuts/cbb/token.txt.
// Without it, it asks for the pairing code, gets a token from /pair and
// saves it. With it, it posts the clipboard to /sync and copies what comes
// back; told that the token is unknown, it deletes the file, so the next
// run pairs again.
//
//go:embed shortcut
var shortcutFiles embed.FS

// The shortcuts, by the base name of their files.
const (
	SyncShortcut = "cbb" // the button: sync, and pair on the first run
)

// Shortcut returns a signed shortcut, or nil in a build without it.
func Shortcut(name string) []byte {
	b, err := shortcutFiles.ReadFile("shortcut/" + name + ".shortcut")
	if err != nil {
		return nil
	}
	return b
}

// UnsignedShortcuts returns the shortcuts as XML property lists, by name.
func UnsignedShortcuts() map[string][]byte {
	return map[string][]byte{SyncShortcut: UnsignedShortcut()}
}

const tokenPath = "cbb/token.txt"

// UnsignedShortcut returns the shortcut as an XML property list.
func UnsignedShortcut() []byte {
	var acts []any
	add := func(id string, params map[string]any) { acts = append(acts, action(id, params)) }

	file := output("file", "File")
	add("is.workflow.actions.documentpicker.open", map[string]any{
		"UUID": file.uuid, "WFGetFilePath": tokenPath, "WFFileErrorIfNotFound": false, "WFShowFilePicker": false,
	})

	// No token yet: pair.
	add(ifStart("paired", file, 101, "")) // does not have any value
	code := output("code", "Provided Input")
	add("is.workflow.actions.ask", map[string]any{
		"UUID": code.uuid, "WFAskActionPrompt": "The six-digit code that cbb pair -phone shows", "WFInputType": "Number",
	})
	paired := output("pair", "Contents of URL")
	add("is.workflow.actions.downloadurl", map[string]any{
		"UUID": paired.uuid, "WFURL": "https://cbb.local:8764/pair", "WFHTTPMethod": "POST",
		"WFHTTPBodyType": "JSON", "WFJSONValues": fields(numberField("v", "1"), textField("code", "", code)),
	})
	tok := output("token", "Dictionary Value")
	add("is.workflow.actions.getvalueforkey", valueFor(tok, "token", paired))
	add(ifStart("got-token", tok, 100, "")) // has any value
	add("is.workflow.actions.documentpicker.save", map[string]any{
		"UUID": uuid("save"), "WFInput": attachment(tok), "WFAskWhereToSave": false,
		"WFFileDestinationPath": tokenPath, "WFSaveFileOverwrite": true,
	})
	add(ifEnd("got-token"))
	pairMsg := output("pair-message", "Dictionary Value")
	add("is.workflow.actions.getvalueforkey", valueFor(pairMsg, "message", paired))
	add(notify(pairMsg))

	// A token: sync.
	add(ifElse("paired"))
	clipboard := output("clipboard", "Clipboard")
	add("is.workflow.actions.getclipboard", map[string]any{"UUID": clipboard.uuid})
	synced := output("sync", "Contents of URL")
	add("is.workflow.actions.downloadurl", map[string]any{
		"UUID": synced.uuid, "WFURL": "https://cbb.local:8764/sync", "WFHTTPMethod": "POST",
		"ShowHeaders": true, "WFHTTPHeaders": fields(textField("Authorization", "Bearer ", file)),
		"WFHTTPBodyType": "JSON", "WFJSONValues": fields(numberField("v", "1"), textField("text", "", clipboard)),
	})
	dir := output("direction", "Dictionary Value")
	add("is.workflow.actions.getvalueforkey", valueFor(dir, "direction", synced))
	add(ifStart("to-iphone", dir, 4, "to_iphone"))
	copied := output("copy", "Dictionary Value")
	add("is.workflow.actions.getvalueforkey", valueFor(copied, "copy", synced))
	// Only on this iPhone: Universal Clipboard would carry it back to a Mac.
	add("is.workflow.actions.setclipboard", map[string]any{"UUID": uuid("set"), "WFInput": attachment(copied), "WFLocalOnly": true})
	add(ifEnd("to-iphone"))
	add(ifStart("unpaired", dir, 4, "unpaired"))
	add("is.workflow.actions.file.delete", map[string]any{
		"UUID": uuid("forget"), "WFInput": attachment(file), "WFDeleteFileConfirmDeletion": false,
	})
	add(ifEnd("unpaired"))
	syncMsg := output("sync-message", "Dictionary Value")
	add("is.workflow.actions.getvalueforkey", valueFor(syncMsg, "message", synced))
	add(notify(syncMsg))
	add(ifEnd("paired"))
	return workflow(acts)
}

// workflow returns the property list of a shortcut with these actions.
func workflow(acts []any) []byte {
	wf := map[string]any{
		"WFWorkflowActions":                    acts,
		"WFWorkflowClientVersion":              "2605.0.5",
		"WFWorkflowMinimumClientVersion":       900,
		"WFWorkflowMinimumClientVersionString": "900",
		"WFWorkflowIcon":                       map[string]any{"WFWorkflowIconStartColor": 463140863, "WFWorkflowIconGlyphNumber": 59511},
		"WFWorkflowImportQuestions":            []any{},
		"WFWorkflowTypes":                      []any{},
		"WFWorkflowInputContentItemClasses":    []any{},
		"WFWorkflowOutputContentItemClasses":   []any{},
		"WFWorkflowHasShortcutInputVariables":  false,
		"WFQuickActionSurfaces":                []any{},
	}
	var b bytes.Buffer
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
		"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
		"<plist version=\"1.0\">\n")
	writePlist(&b, wf, 0)
	b.WriteString("</plist>\n")
	return b.Bytes()
}

// out is an action's output that later actions refer to.
type out struct{ uuid, name string }

// uuid returns a fixed UUID for a name, so the file is the same on every
// build.
func uuid(name string) string {
	var h uint64 = 14695981039346656037
	for _, c := range []byte(name) {
		h = (h ^ uint64(c)) * 1099511628211
	}
	return fmt.Sprintf("C11B0000-0000-4000-8000-%012X", h&0xFFFFFFFFFFFF)
}

func output(name, outputName string) out { return out{uuid(name), outputName} }

func ref(o out) map[string]any {
	return map[string]any{"Type": "ActionOutput", "OutputUUID": o.uuid, "OutputName": o.name}
}

// attachment is a parameter that is a variable.
func attachment(o out) map[string]any {
	return map[string]any{"Value": ref(o), "WFSerializationType": "WFTextTokenAttachment"}
}

// text is a text parameter: prefix, then the variable o, if any.
func text(prefix string, o *out) map[string]any {
	v := map[string]any{"string": prefix}
	if o != nil {
		v["string"] = prefix + "￼"
		pos := len(utf16.Encode([]rune(prefix)))
		v["attachmentsByRange"] = map[string]any{fmt.Sprintf("{%d, 1}", pos): ref(*o)}
	}
	return map[string]any{"Value": v, "WFSerializationType": "WFTextTokenString"}
}

func textField(key, prefix string, o out) map[string]any {
	return map[string]any{"WFItemType": 0, "WFKey": text(key, nil), "WFValue": text(prefix, &o)}
}

func numberField(key, n string) map[string]any {
	return map[string]any{"WFItemType": 3, "WFKey": text(key, nil), "WFValue": text(n, nil)}
}

func fields(items ...any) map[string]any {
	return map[string]any{
		"Value":               map[string]any{"WFDictionaryFieldValueItems": items},
		"WFSerializationType": "WFDictionaryFieldValue",
	}
}

func valueFor(o out, key string, dict out) map[string]any {
	return map[string]any{"UUID": o.uuid, "WFDictionaryKey": key, "WFGetDictionaryValueType": "Value", "WFInput": attachment(dict)}
}

func notify(msg out) (string, map[string]any) {
	return "is.workflow.actions.notification", map[string]any{
		"UUID": uuid("notify-" + msg.uuid), "WFNotificationActionTitle": "cbb", "WFNotificationActionBody": text("", &msg),
	}
}

func action(id string, params map[string]any) map[string]any {
	return map[string]any{"WFWorkflowActionIdentifier": id, "WFWorkflowActionParameters": params}
}

// ifStart begins an If on a variable: condition 4 compares it, as text,
// with is; 100 and 101 test whether it has a value.
func ifStart(group string, o out, condition int, is string) (string, map[string]any) {
	v := ref(o)
	if condition == 4 {
		v["Aggrandizements"] = []any{map[string]any{"Type": "WFCoercionVariableAggrandizement", "CoercionItemClass": "WFStringContentItem"}}
	}
	p := map[string]any{
		"GroupingIdentifier": uuid("if-" + group), "WFControlFlowMode": 0, "UUID": uuid("if-start-" + group),
		"WFCondition": condition,
		"WFInput":     map[string]any{"Type": "Variable", "Variable": map[string]any{"Value": v, "WFSerializationType": "WFTextTokenAttachment"}},
	}
	if condition == 4 {
		p["WFConditionalActionString"] = is
	}
	return "is.workflow.actions.conditional", p
}

func ifElse(group string) (string, map[string]any) {
	return "is.workflow.actions.conditional", map[string]any{
		"GroupingIdentifier": uuid("if-" + group), "WFControlFlowMode": 1, "UUID": uuid("if-else-" + group),
	}
}

func ifEnd(group string) (string, map[string]any) {
	return "is.workflow.actions.conditional", map[string]any{
		"GroupingIdentifier": uuid("if-" + group), "WFControlFlowMode": 2, "UUID": uuid("if-end-" + group),
	}
}

// writePlist writes v as XML property list elements; dictionary keys are
// sorted, so the output is stable.
func writePlist(b *bytes.Buffer, v any, depth int) {
	indent := func(d int) {
		for range d {
			b.WriteByte('\t')
		}
	}
	indent(depth)
	switch v := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("<dict>\n")
		for _, k := range keys {
			indent(depth + 1)
			b.WriteString("<key>" + escapeXML(k) + "</key>\n")
			writePlist(b, v[k], depth+1)
		}
		indent(depth)
		b.WriteString("</dict>\n")
	case []any:
		if len(v) == 0 {
			b.WriteString("<array/>\n")
			return
		}
		b.WriteString("<array>\n")
		for _, e := range v {
			writePlist(b, e, depth+1)
		}
		indent(depth)
		b.WriteString("</array>\n")
	case string:
		b.WriteString("<string>" + escapeXML(v) + "</string>\n")
	case int:
		fmt.Fprintf(b, "<integer>%d</integer>\n", v)
	case bool:
		if v {
			b.WriteString("<true/>\n")
		} else {
			b.WriteString("<false/>\n")
		}
	default:
		panic(fmt.Sprintf("phone: no plist form for %T", v))
	}
}

func escapeXML(s string) string {
	var b bytes.Buffer
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
