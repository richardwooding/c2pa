package c2pa

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestStatusCodesHaveEmissionSites keeps the invariant the package doc states:
// every declared StatusCode is emitted somewhere. StatusCode.Severity treats an
// unknown code as informational, so a declared code that nothing records is a
// promise a caller can wait on forever — manifest.multipleParents was one such
// until it was noticed by hand. The check is by identifier, in any non-test
// file other than statuscodes.go, because a few emissions route through a
// variable (a `code :=` chosen from several) rather than a literal v.add.
func TestStatusCodesHaveEmissionSites(t *testing.T) {
	fset := token.NewFileSet()
	decl, err := parser.ParseFile(fset, "statuscodes.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var codes []string
	for _, d := range decl.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "StatusCode" {
				continue
			}
			for _, n := range vs.Names {
				codes = append(codes, n.Name)
			}
		}
	}
	if len(codes) < 30 {
		t.Fatalf("found only %d StatusCode constants; the parser missed the tables", len(codes))
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var src strings.Builder
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "statuscodes.go" {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src.Write(b)
		src.WriteByte('\n')
	}
	all := src.String()
	for _, c := range codes {
		if !regexp.MustCompile(`\b` + regexp.QuoteMeta(c) + `\b`).MatchString(all) {
			t.Errorf("%s is declared but never emitted by any non-test file", c)
		}
	}
}
