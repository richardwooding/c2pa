package c2pa

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
)

// twoStorePDF builds a document whose catalog associates one manifest store
// (§A.4.1) and which additionally carries an embedded file bearing its own,
// unassociated store — the §A.4.3 shape ReadAll exists for.
func twoStorePDF(docStore, attachmentStore []byte) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	b.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AF [3 0 R] >>\nendobj\n")
	b.WriteString("2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n")
	b.WriteString("3 0 obj\n<< /Type /Filespec /F (doc.c2pa) /UF (doc.c2pa)" +
		" /AFRelationship /C2PA_Manifest /EF << /F 4 0 R >> >>\nendobj\n")
	fmt.Fprintf(&b, "4 0 obj\n<< /Type /EmbeddedFile /Subtype /application#2Fc2pa /Length %d >>\nstream\n", len(docStore))
	b.Write(docStore)
	b.WriteString("\nendstream\nendobj\n")
	// The attachment's own store: marker-bearing file specification that no
	// catalog /AF references.
	b.WriteString("5 0 obj\n<< /Type /Filespec /F (attachment.c2pa) /UF (attachment.c2pa)" +
		" /AFRelationship /C2PA_Manifest /EF << /F 6 0 R >> >>\nendobj\n")
	fmt.Fprintf(&b, "6 0 obj\n<< /Type /EmbeddedFile /Subtype /application#2Fc2pa /Length %d >>\nstream\n", len(attachmentStore))
	b.Write(attachmentStore)
	b.WriteString("\nendstream\nendobj\n")
	b.WriteString("trailer\n<< /Root 1 0 R >>\nstartxref\n0\n%%EOF\n")
	return b.Bytes()
}

// fixtureStore returns a real manifest store to embed, taken from a fixture.
func fixtureStore(t *testing.T, path string, container Container) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	store := extractJUMBF(context.Background(), container, data)
	if len(store) == 0 {
		t.Fatalf("no store in %s", path)
	}
	return store
}

func TestReadAll_PDFWithTwoStores(t *testing.T) {
	docStore := fixtureStore(t, "testdata/c2pa_chatgpt.pdf", PDF)
	attachmentStore := fixtureStore(t, "testdata/c2pa_signed.jpg", JPEG)

	pdf := twoStorePDF(docStore, attachmentStore)
	infos := ReadAll(context.Background(), PDF, bytes.NewReader(pdf))

	if len(infos) != 2 {
		t.Fatalf("got %d stores, want 2", len(infos))
	}
	if infos[0].Attribution != AttributionAsset {
		t.Errorf("first store attribution = %q, want %q", infos[0].Attribution, AttributionAsset)
	}
	if infos[0].ClaimGenerator != "ChatGPT" {
		t.Errorf("first store generator = %q, want the document's %q", infos[0].ClaimGenerator, "ChatGPT")
	}
	if infos[1].Attribution != AttributionUnknown {
		t.Errorf("second store attribution = %q, want %q — nothing associates it with the document",
			infos[1].Attribution, AttributionUnknown)
	}
	if got, want := infos[1].ClaimGenerator, "make_test_images/0.33.1 c2pa-rs/0.33.1"; got != want {
		t.Errorf("second store generator = %q, want the attachment's %q", got, want)
	}

	// Read stays the first entry's view.
	single := Read(context.Background(), PDF, bytes.NewReader(pdf))
	if single.ClaimGenerator != infos[0].ClaimGenerator || single.Attribution != AttributionAsset {
		t.Errorf("Read = %+v, want ReadAll's first entry", single)
	}
}

// TestReadAll_DoesNotDuplicateTheCatalogStore: the catalog's own store also
// carries the markers, so the marker walk rediscovers it; byte identity folds it.
func TestReadAll_DoesNotDuplicateTheCatalogStore(t *testing.T) {
	data, err := os.ReadFile("testdata/c2pa_chatgpt.pdf")
	if err != nil {
		t.Fatal(err)
	}
	infos := ReadAll(context.Background(), PDF, bytes.NewReader(data))
	if len(infos) != 1 {
		t.Fatalf("got %d stores for a single-store document, want 1", len(infos))
	}
	if infos[0].Attribution != AttributionAsset {
		t.Errorf("attribution = %q, want %q", infos[0].Attribution, AttributionAsset)
	}
}

func TestReadAll_SingleStoreContainers(t *testing.T) {
	for _, tc := range []struct {
		file      string
		container Container
	}{
		{"testdata/c2pa_signed.jpg", JPEG},
		{"testdata/c2pa_2x_openai.png", PNG},
		{"testdata/c2pa_signed_video.mp4", BMFF},
	} {
		f, err := os.Open(tc.file)
		if err != nil {
			t.Fatal(err)
		}
		infos := ReadAll(context.Background(), tc.container, f)
		_ = f.Close()
		if len(infos) != 1 {
			t.Errorf("%s: got %d stores, want 1", tc.file, len(infos))
			continue
		}
		if infos[0].Attribution != AttributionAsset {
			t.Errorf("%s: attribution = %q, want %q", tc.file, infos[0].Attribution, AttributionAsset)
		}
	}
}

func TestReadAll_NoStore(t *testing.T) {
	if got := ReadAll(context.Background(), JPEG, bytes.NewReader([]byte("\xff\xd8\xff\xe0 nothing"))); got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if got := ReadAll(context.Background(), PDF, bytes.NewReader([]byte("%PDF-1.7\nno store here\n%%EOF"))); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}
