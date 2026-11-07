// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command sbom writes the software bills of materials a release carries,
// in CycloneDX 1.6 JSON, from what each part of the project is built
// with (docs/maintaining.md, "What a release is built from"):
//
//	sbom go -o sbom-go.cdx.json -version 0.6.0 ARCHIVE|BINARY...
//	sbom cargo -o sbom-lite.cdx.json -version 0.6.0 -manifest Cargo.toml -package cbb-lite -target T,...
//	sbom swift -o sbom-ios-kit.cdx.json -version 0.6.0 Package.resolved
//	sbom gradle -o sbom-android.cdx.json -version 0.6.0 DEPENDENCIES...
//
// go reads the modules each Go program was built with from the program
// itself (its build information), in the release's archives or as a
// file; cargo asks cargo for the crates a package is built with on the
// given targets, without the ones only its tests and builds use, with
// their checksums from Cargo.lock; swift reads a SwiftPM Package.resolved;
// gradle reads the lists that packaging/sbom.init.gradle.kts writes, one
// module (group:name:version) a line. The same input gives the same file:
// no time, and a serial number derived from the content.
package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// Component is a CycloneDX component.
type Component struct {
	Type       string     `json:"type"`
	BOMRef     string     `json:"bom-ref"`
	Group      string     `json:"group,omitempty"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	Purl       string     `json:"purl,omitempty"`
	Hashes     []Hash     `json:"hashes,omitempty"`
	Licenses   []License  `json:"licenses,omitempty"`
	ExtRefs    []ExtRef   `json:"externalReferences,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

// Hash is a CycloneDX hash.
type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// License is a CycloneDX license choice, as an SPDX expression.
type License struct {
	Expression string `json:"expression"`
}

// ExtRef is a CycloneDX external reference.
type ExtRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Property is a CycloneDX property.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Dependency is a CycloneDX dependency entry.
type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// BOM is a CycloneDX document.
type BOM struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     Metadata     `json:"metadata"`
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies"`
}

// Metadata is the CycloneDX metadata: what the document describes.
type Metadata struct {
	Tools     Tools     `json:"tools"`
	Component Component `json:"component"`
}

// Tools names what made the document.
type Tools struct {
	Components []Component `json:"components"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmds := map[string]func([]string) ([]Component, error){
		"go": goCmd, "cargo": cargoCmd, "swift": swiftCmd, "gradle": gradleCmd,
	}
	cmd, ok := cmds[os.Args[1]]
	if !ok {
		usage()
	}
	if err := run(os.Args[1], os.Args[2:], cmd); err != nil {
		fmt.Fprintln(os.Stderr, "sbom:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: sbom go|cargo|swift|gradle -o FILE -version V ... (see the comment in tools/sbom/main.go)")
	os.Exit(2)
}

// common holds the flags every kind shares.
type common struct {
	out, version, name string
}

func (c *common) register(fs *flag.FlagSet, name string) {
	fs.StringVar(&c.out, "o", "", "the file to write")
	fs.StringVar(&c.version, "version", "", "the release's version")
	fs.StringVar(&c.name, "name", name, "what the document describes")
}

// flags is shared by run and the kinds, so each kind adds its own flags
// to the set run parses.
var flags *flag.FlagSet

var opts common

func run(kind string, args []string, cmd func([]string) ([]Component, error)) error {
	flags = flag.NewFlagSet(kind, flag.ContinueOnError)
	names := map[string]string{
		"go": "cbb (the Go programs)", "cargo": "cbb (Rust)",
		"swift": "CBBKit (Swift packages)", "gradle": "cbb (Android)",
	}
	opts = common{}
	opts.register(flags, names[kind])
	comps, err := cmd(args)
	if err != nil {
		return err
	}
	if opts.out == "" {
		return errors.New("-o is needed")
	}
	data, err := Document(opts.name, strings.TrimPrefix(opts.version, "v"), comps)
	if err != nil {
		return err
	}
	return os.WriteFile(opts.out, data, 0o644)
}

// Document makes the CycloneDX document for the components: sorted, each
// once, with the described thing depending on all of them.
func Document(name, version string, comps []Component) ([]byte, error) {
	byRef := map[string]Component{}
	for _, c := range comps {
		if c.Type == "" {
			c.Type = "library"
		}
		if c.BOMRef == "" {
			c.BOMRef = c.Purl
		}
		if c.BOMRef == "" {
			return nil, fmt.Errorf("component %s has no purl", c.Name)
		}
		byRef[c.BOMRef] = c
	}
	refs := make([]string, 0, len(byRef))
	for r := range byRef {
		refs = append(refs, r)
	}
	sort.Strings(refs)
	b := BOM{
		BOMFormat: "CycloneDX", SpecVersion: "1.6", Version: 1,
		Metadata: Metadata{
			Tools: Tools{Components: []Component{{Type: "application", BOMRef: "tool", Name: "cbb tools/sbom"}}},
			Component: Component{Type: "application", BOMRef: "root", Name: name, Version: version,
				Licenses: []License{{Expression: "AGPL-3.0-only"}},
				ExtRefs:  []ExtRef{{Type: "vcs", URL: "https://github.com/HunterEwok/cbb"}}},
		},
		Components:   []Component{},
		Dependencies: []Dependency{{Ref: "root", DependsOn: refs}},
	}
	for _, r := range refs {
		b.Components = append(b.Components, byRef[r])
	}
	// The serial number is derived from the content, so the same input
	// makes the same file.
	body, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	sum[6] = sum[6]&0x0f | 0x50 // a name-based UUID's version and variant
	sum[8] = sum[8]&0x3f | 0x80
	b.SerialNumber = fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// purl makes a package URL of the type, with the name's path segments
// and the version escaped.
func purl(typ, name, version string) string {
	segs := strings.Split(name, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	// PathEscape keeps "+", which a purl's version escapes.
	v := strings.ReplaceAll(url.PathEscape(version), "+", "%2B")
	return "pkg:" + typ + "/" + strings.Join(segs, "/") + "@" + v
}

// goCmd lists the modules of the Go programs in the files.
func goCmd(args []string) ([]Component, error) {
	if err := flags.Parse(args); err != nil {
		return nil, err
	}
	if flags.NArg() == 0 {
		return nil, errors.New("go needs the archives or programs")
	}
	var comps []Component
	found := 0
	for _, path := range flags.Args() {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		progs, err := programs(path, data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		for _, p := range progs {
			info, err := buildinfo.Read(bytes.NewReader(p))
			if err != nil {
				continue // not a Go program
			}
			found++
			comps = append(comps, GoModules(info)...)
		}
	}
	if found == 0 {
		return nil, errors.New("no Go program in the files")
	}
	return comps, nil
}

// GoModules lists the modules a Go program was built with, and the
// standard library of its Go version, without the program's own module.
func GoModules(info *buildinfo.BuildInfo) []Component {
	goVersion := strings.TrimPrefix(info.GoVersion, "go")
	comps := []Component{{Name: "stdlib", Version: goVersion, Purl: purl("golang", "stdlib", goVersion)}}
	for _, d := range info.Deps {
		m := d
		if d.Replace != nil {
			m = d.Replace
		}
		if m.Version == "" || m.Version == "(devel)" {
			continue // a replacement by a directory, part of the source
		}
		c := Component{Name: m.Path, Version: m.Version, Purl: purl("golang", m.Path, m.Version)}
		if m.Sum != "" {
			c.Properties = []Property{{Name: "cbb:go:h1", Value: m.Sum}}
		}
		comps = append(comps, c)
	}
	return comps
}

// programs returns the files of an archive, or the file itself when it
// is no archive.
func programs(name string, data []byte) ([][]byte, error) {
	switch {
	case strings.HasSuffix(name, ".tar.gz"):
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		tr := tar.NewReader(gz)
		var out [][]byte
		for {
			h, err := tr.Next()
			if err == io.EOF {
				return out, nil
			}
			if err != nil {
				return nil, err
			}
			if h.Typeflag != tar.TypeReg || h.Mode&0o111 == 0 {
				continue
			}
			b, err := io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			out = append(out, b)
		}
	case strings.HasSuffix(name, ".zip"):
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, err
		}
		var out [][]byte
		for _, f := range zr.File {
			if !strings.HasSuffix(strings.ToLower(f.Name), ".exe") {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			b, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, err
			}
			out = append(out, b)
		}
		return out, nil
	}
	return [][]byte{data}, nil
}

// cargoMetadata is what sbom reads of `cargo metadata`.
type cargoMetadata struct {
	Packages []struct {
		ID      string  `json:"id"`
		Name    string  `json:"name"`
		Version string  `json:"version"`
		Source  *string `json:"source"`
		License string  `json:"license"`
	} `json:"packages"`
	Resolve struct {
		Nodes []struct {
			ID   string `json:"id"`
			Deps []struct {
				Pkg      string `json:"pkg"`
				DepKinds []struct {
					Kind *string `json:"kind"`
				} `json:"dep_kinds"`
			} `json:"deps"`
		} `json:"nodes"`
	} `json:"resolve"`
}

// cargoCmd lists the crates a package is built with on each target.
func cargoCmd(args []string) ([]Component, error) {
	manifest := flags.String("manifest", "Cargo.toml", "the workspace's Cargo.toml")
	pkg := flags.String("package", "", "the package the programs or libraries are built from")
	targets := flags.String("target", "", "the targets, comma-separated")
	if err := flags.Parse(args); err != nil {
		return nil, err
	}
	if *pkg == "" || *targets == "" {
		return nil, errors.New("cargo needs -package and -target")
	}
	lock, err := os.ReadFile(strings.TrimSuffix(*manifest, "Cargo.toml") + "Cargo.lock")
	if err != nil {
		return nil, err
	}
	sums := LockChecksums(string(lock))
	var comps []Component
	for _, t := range strings.Split(*targets, ",") {
		cmd := exec.Command("cargo", "metadata", "--locked", "--format-version", "1",
			"--manifest-path", *manifest, "--filter-platform", t)
		cmd.Stderr = os.Stderr
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("cargo metadata for %s: %w", t, err)
		}
		c, err := CargoCrates(out, *pkg, sums)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", t, err)
		}
		comps = append(comps, c...)
	}
	return comps, nil
}

// CargoCrates lists the crates that the package reaches through normal
// (not dev or build) dependencies in the metadata, without the
// workspace's own.
func CargoCrates(metadata []byte, pkg string, sums map[string]string) ([]Component, error) {
	var m cargoMetadata
	if err := json.Unmarshal(metadata, &m); err != nil {
		return nil, err
	}
	byID := map[string]int{}
	root := ""
	for i, p := range m.Packages {
		byID[p.ID] = i
		if p.Name == pkg && p.Source == nil {
			root = p.ID
		}
	}
	if root == "" {
		return nil, fmt.Errorf("no package %s in the workspace", pkg)
	}
	deps := map[string][]string{}
	for _, n := range m.Resolve.Nodes {
		for _, d := range n.Deps {
			for _, k := range d.DepKinds {
				if k.Kind == nil {
					deps[n.ID] = append(deps[n.ID], d.Pkg)
					break
				}
			}
		}
	}
	seen := map[string]bool{root: true}
	queue := []string{root}
	var comps []Component
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, d := range deps[id] {
			if seen[d] {
				continue
			}
			seen[d] = true
			queue = append(queue, d)
			i, ok := byID[d]
			if !ok {
				return nil, fmt.Errorf("the resolve names %s, which is not among the packages", d)
			}
			p := m.Packages[i]
			if p.Source == nil {
				continue // the workspace's own
			}
			c := Component{Name: p.Name, Version: p.Version, Purl: purl("cargo", p.Name, p.Version)}
			if p.License != "" {
				c.Licenses = []License{{Expression: p.License}}
			}
			if s := sums[p.Name+" "+p.Version]; s != "" {
				c.Hashes = []Hash{{Alg: "SHA-256", Content: s}}
			}
			comps = append(comps, c)
		}
	}
	return comps, nil
}

// LockChecksums reads the checksums of a Cargo.lock, by "name version".
func LockChecksums(lock string) map[string]string {
	sums := map[string]string{}
	var name, version string
	for _, line := range strings.Split(lock, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "[[package]]":
			name, version = "", ""
		case strings.HasPrefix(line, "name = "):
			name = strings.Trim(strings.TrimPrefix(line, "name = "), `"`)
		case strings.HasPrefix(line, "version = "):
			version = strings.Trim(strings.TrimPrefix(line, "version = "), `"`)
		case strings.HasPrefix(line, "checksum = "):
			sums[name+" "+version] = strings.Trim(strings.TrimPrefix(line, "checksum = "), `"`)
		}
	}
	return sums
}

// swiftCmd lists the packages of a Package.resolved.
func swiftCmd(args []string) ([]Component, error) {
	if err := flags.Parse(args); err != nil {
		return nil, err
	}
	if flags.NArg() != 1 {
		return nil, errors.New("swift needs one Package.resolved")
	}
	data, err := os.ReadFile(flags.Arg(0))
	if err != nil {
		return nil, err
	}
	return SwiftPackages(data)
}

// SwiftPackages lists the pinned packages of a Package.resolved, version
// 2 or 3.
func SwiftPackages(data []byte) ([]Component, error) {
	var r struct {
		Pins []struct {
			Identity string `json:"identity"`
			Location string `json:"location"`
			State    struct {
				Revision string `json:"revision"`
				Version  string `json:"version"`
			} `json:"state"`
		} `json:"pins"`
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	if r.Version != 2 && r.Version != 3 {
		return nil, fmt.Errorf("the Package.resolved is of version %d, not 2 or 3", r.Version)
	}
	var comps []Component
	for _, p := range r.Pins {
		u, err := url.Parse(p.Location)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("pin %s: the location %q is not a URL", p.Identity, p.Location)
		}
		name := u.Host + strings.TrimSuffix(u.Path, ".git")
		version := p.State.Version
		if version == "" {
			version = p.State.Revision
		}
		c := Component{Name: p.Identity, Version: version, Purl: purl("swift", name, version),
			ExtRefs: []ExtRef{{Type: "vcs", URL: p.Location}}}
		if p.State.Revision != "" {
			c.Properties = []Property{{Name: "cbb:swift:revision", Value: p.State.Revision}}
		}
		comps = append(comps, c)
	}
	return comps, nil
}

// gradleCmd lists the modules in the files packaging/sbom.init.gradle.kts
// writes.
func gradleCmd(args []string) ([]Component, error) {
	if err := flags.Parse(args); err != nil {
		return nil, err
	}
	if flags.NArg() == 0 {
		return nil, errors.New("gradle needs the dependency lists")
	}
	var comps []Component
	for _, path := range flags.Args() {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		c, err := GradleModules(string(data))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		comps = append(comps, c...)
	}
	return comps, nil
}

// GradleModules reads a list of group:name:version lines.
func GradleModules(list string) ([]Component, error) {
	var comps []Component
	for i, line := range strings.Split(list, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			return nil, fmt.Errorf("line %d is not group:name:version: %q", i+1, line)
		}
		comps = append(comps, Component{Group: parts[0], Name: parts[1], Version: parts[2],
			Purl: purl("maven", parts[0]+"/"+parts[1], parts[2])})
	}
	if len(comps) == 0 {
		return nil, errors.New("no modules")
	}
	return comps, nil
}
