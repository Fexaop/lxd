package lxd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/canonical/lxd/shared/api"
)

func newUnifiedImageResponse(t *testing.T, filename string, content []byte) *http.Response {
	t.Helper()

	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":        []string{"application/octet-stream"},
			"Content-Disposition": []string{`attachment; filename="` + filename + `"`},
		},
		Body: io.NopCloser(bytes.NewReader(content)),
	}
}

func newSplitImageResponse(t *testing.T, metaName string, metaContent []byte, rootfsName string, rootfsContent []byte) *http.Response {
	t.Helper()

	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)

	part, err := mw.CreateFormFile("metadata", metaName)
	require.NoError(t, err)
	_, err = part.Write(metaContent)
	require.NoError(t, err)

	part, err = mw.CreateFormFile("rootfs", rootfsName)
	require.NoError(t, err)
	_, err = part.Write(rootfsContent)
	require.NoError(t, err)

	require.NoError(t, mw.Close())

	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{mw.FormDataContentType()}},
		Body:       io.NopCloser(body),
	}
}

func fingerprint(t *testing.T, contents ...[]byte) string {
	t.Helper()
	hash := sha256.New()
	for _, content := range contents {
		_, err := hash.Write(content)
		require.NoError(t, err)
	}

	return hex.EncodeToString(hash.Sum(nil))
}

func TestLXDDownloadImageSanitizesNames(t *testing.T) {
	metaContent := []byte("metadata")
	rootfsContent := []byte("rootfs")
	uFp := fingerprint(t, metaContent)
	sFp := fingerprint(t, metaContent, rootfsContent)
	fpToAddr := func(fp string) string { return "http://localhost/1.0/images/" + fp + "/export" }
	tmpDir := t.TempDir()

	targetMeta := filepath.Join(tmpDir, "target.meta")
	targetRootfs := filepath.Join(tmpDir, "target.rootfs")

	dest, err := os.Create(targetMeta)
	require.NoError(t, err)

	defer func() { _ = dest.Close() }()

	destRootfs, err := os.Create(targetRootfs)
	require.NoError(t, err)

	defer func() { _ = destRootfs.Close() }()
	req := ImageFileRequest{MetaFile: io.WriteSeeker(dest), RootfsFile: io.WriteSeeker(destRootfs)}

	tests := []struct {
		name           string
		response       func(t *testing.T) *http.Response
		fp             string
		wantMetaName   string
		wantRootfsName string
	}{
		{
			name: "unified image with an absolute path",
			response: func(t *testing.T) *http.Response {
				return newUnifiedImageResponse(t, "/etc/cron.d/evil.tar.gz", metaContent)
			},
			fp:           uFp,
			wantMetaName: "evil.tar.gz",
		},
		{
			name: "unified image with a trailing slash",
			response: func(t *testing.T) *http.Response {
				return newUnifiedImageResponse(t, "/etc/cron.d/evil.tar.gz/", metaContent)
			},
			fp:           uFp,
			wantMetaName: "evil.tar.gz",
		},

		{
			name: "unified image with a relative path",
			response: func(t *testing.T) *http.Response {
				return newUnifiedImageResponse(t, "../../evil.tar.gz", metaContent)
			},
			fp:           uFp,
			wantMetaName: "evil.tar.gz",
		},
		{
			name: "split image with absolute and relative paths",
			response: func(t *testing.T) *http.Response {
				return newSplitImageResponse(t, "/etc/cron.d/evil.tar.gz", metaContent, "../../evil.squashfs", rootfsContent)
			},
			fp:             sFp,
			wantMetaName:   "evil.tar.gz",
			wantRootfsName: "evil.squashfs",
		},
		{
			name: "split image with trailing slashes",
			response: func(t *testing.T) *http.Response {
				return newSplitImageResponse(t, "/etc/cron.d/evil.tar.gz/", metaContent, "/evil.squashfs/", rootfsContent)
			},
			fp:             sFp,
			wantMetaName:   "evil.tar.gz",
			wantRootfsName: "evil.squashfs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			do := func(*http.Request) (*http.Response, error) {
				return tt.response(t), nil
			}

			resp, err := lxdDownloadImage(tt.fp, fpToAddr(tt.fp), "", do, req)
			require.NoError(t, err)

			assert.Equal(t, tt.wantMetaName, resp.MetaName)
			assert.Equal(t, tt.wantRootfsName, resp.RootfsName)
		})
	}
}

func TestUpdateImageAliasType(t *testing.T) {
	tests := []struct {
		name       string
		extensions []string
		imageType  string
		untyped    bool
		path       string
		wantError  bool
	}{
		{
			name:       "container with duplicate name",
			extensions: []string{"image_alias_types"},
			imageType:  "container",
			path:       "/1.0/images/container/aliases/shared/name",
		},
		{
			name:       "virtual machine with duplicate name",
			extensions: []string{"image_alias_types"},
			imageType:  "virtual-machine",
			path:       "/1.0/images/virtual-machine/aliases/shared/name",
		},
		{
			name:      "legacy server rejects typed update",
			imageType: "virtual-machine",
			wantError: true,
		},
		{
			name:    "legacy untyped update",
			untyped: true,
			path:    "/1.0/images/aliases/shared/name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aliases := map[string]api.ImageAliasesEntryPut{
				"container":       {Target: "container-image", Description: "container"},
				"virtual-machine": {Target: "vm-image", Description: "virtual machine"},
			}

			update := api.ImageAliasesEntryPut{Target: "replacement-image", Description: "updated description"}
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				assert.Equal(t, http.MethodPut, r.Method)
				assert.Equal(t, tt.path, r.URL.Path)
				assert.Equal(t, `"alias-etag"`, r.Header.Get("If-Match"))
				if r.Method != http.MethodPut || r.URL.Path != tt.path {
					http.Error(w, "Ambiguous alias lookup", http.StatusConflict)
					return
				}

				var body api.ImageAliasesEntryPut
				err := json.NewDecoder(r.Body).Decode(&body)
				assert.NoError(t, err)
				assert.Equal(t, update, body)
				aliases[tt.imageType] = body
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"type":"sync","status":"Success","status_code":200,"metadata":{}}`)
			}))
			defer server.Close()

			baseURL, err := url.Parse(server.URL)
			require.NoError(t, err)
			client := ProtocolLXD{
				ctx:         context.Background(),
				http:        server.Client(),
				httpBaseURL: *baseURL,
				server:      &api.Server{ServerUntrusted: api.ServerUntrusted{APIExtensions: tt.extensions}},
			}

			if tt.untyped {
				err = client.UpdateImageAlias("shared/name", update, `"alias-etag"`)
			} else {
				err = client.UpdateImageAliasType(tt.imageType, "shared/name", update, `"alias-etag"`)
			}

			if tt.wantError {
				require.ErrorContains(t, err, `missing the required "image_alias_types" API extension`)
				require.Zero(t, requests)
				assert.Equal(t, "container-image", aliases["container"].Target)
				assert.Equal(t, "vm-image", aliases["virtual-machine"].Target)
				return
			}

			require.NoError(t, err)
			require.Equal(t, 1, requests)
			assert.Equal(t, update, aliases[tt.imageType])
			if tt.imageType == "container" {
				assert.Equal(t, "vm-image", aliases["virtual-machine"].Target)
			} else {
				assert.Equal(t, "container-image", aliases["container"].Target)
			}
		})
	}
}

func TestImageAliasMutationsLegacy(t *testing.T) {
	operations := []struct {
		name   string
		method string
		mutate func(*ProtocolLXD, string) error
	}{
		{
			name:   "delete",
			method: http.MethodDelete,
			mutate: func(client *ProtocolLXD, imageType string) error {
				return client.DeleteImageAliasType(imageType, "shared/name")
			},
		},
		{
			name:   "rename",
			method: http.MethodPost,
			mutate: func(client *ProtocolLXD, imageType string) error {
				return client.RenameImageAliasType(imageType, "shared/name", api.ImageAliasesEntryPost{Name: "renamed"})
			},
		},
		{
			name:   "update",
			method: http.MethodPut,
			mutate: func(client *ProtocolLXD, imageType string) error {
				return client.UpdateImageAliasType(imageType, "shared/name", api.ImageAliasesEntryPut{Target: "replacement"}, "")
			},
		},
	}

	for _, operation := range operations {
		for _, imageType := range []string{"container", "virtual-machine", "microvm", ""} {
			name := imageType
			if name == "" {
				name = "untyped"
			}

			t.Run(operation.name+"/"+name, func(t *testing.T) {
				requests := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests++
					assert.Equal(t, operation.method, r.Method)
					assert.Equal(t, "/1.0/images/aliases/shared/name", r.URL.Path)
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"type":"sync","status":"Success","status_code":200,"metadata":{}}`)
				}))
				defer server.Close()

				baseURL, err := url.Parse(server.URL)
				require.NoError(t, err)
				client := ProtocolLXD{
					ctx:         context.Background(),
					http:        server.Client(),
					httpBaseURL: *baseURL,
					server:      &api.Server{},
				}

				err = operation.mutate(&client, imageType)
				if imageType != "" {
					require.ErrorContains(t, err, `missing the required "image_alias_types" API extension`)
					assert.Zero(t, requests)
					return
				}

				require.NoError(t, err)
				assert.Equal(t, 1, requests)
			})
		}
	}
}

func TestGetImageAliasTypeLegacy(t *testing.T) {
	tests := []struct {
		name      string
		aliasType string
		imageType string
		wantType  string
		wantError bool
	}{
		{name: "microvm as container", aliasType: "microvm", imageType: "container", wantType: "container"},
		{name: "microvm not virtual machine", aliasType: "microvm", imageType: "virtual-machine", wantError: true},
		{name: "untyped microvm", aliasType: "microvm", wantType: "container"},
		{name: "empty as container", imageType: "container", wantType: "container"},
		{name: "empty not virtual machine", imageType: "virtual-machine", wantError: true},
		{name: "untyped empty", wantType: "container"},
		{name: "container", aliasType: "container", imageType: "container", wantType: "container"},
		{name: "container not virtual machine", aliasType: "container", imageType: "virtual-machine", wantError: true},
		{name: "virtual machine", aliasType: "virtual-machine", imageType: "virtual-machine", wantType: "virtual-machine"},
		{name: "virtual machine not container", aliasType: "virtual-machine", imageType: "container", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				assert.Equal(t, http.MethodGet, r.Method)
				assert.Equal(t, "/1.0/images/aliases/legacy", r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("ETag", `"alias-etag"`)
				err := json.NewEncoder(w).Encode(map[string]any{
					"type":        "sync",
					"status":      "Success",
					"status_code": http.StatusOK,
					"metadata": api.ImageAliasesEntry{
						Name:   "legacy",
						Target: "legacy-image",
						Type:   tt.aliasType,
					},
				})
				assert.NoError(t, err)
			}))
			defer server.Close()

			baseURL, err := url.Parse(server.URL)
			require.NoError(t, err)
			client := ProtocolLXD{
				ctx:         context.Background(),
				http:        server.Client(),
				httpBaseURL: *baseURL,
				server:      &api.Server{},
			}

			alias, etag, err := client.GetImageAliasType(tt.imageType, "legacy")
			assert.Equal(t, 1, requests)
			if tt.wantError {
				require.EqualError(t, err, "Alias does not exist for the specified type")
				assert.Nil(t, alias)
				assert.Empty(t, etag)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, alias)
			assert.Equal(t, tt.wantType, alias.Type)
			assert.Equal(t, "legacy-image", alias.Target)
			assert.Equal(t, `"alias-etag"`, etag)
		})
	}
}

func TestCreateImageAliasLegacyMicroVM(t *testing.T) {
	for _, explicitType := range []bool{false, true} {
		name := "inferred type"
		if explicitType {
			name = "explicit type"
		}

		t.Run(name, func(t *testing.T) {
			alias := api.ImageAliasesPost{
				ImageAliasesEntry: api.ImageAliasesEntry{
					Name:   "legacy",
					Target: "legacy-image",
				},
			}

			if explicitType {
				alias.Type = string(api.InstanceTypeMicroVM)
			}

			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodGet && r.URL.Path == "/1.0/images/legacy-image" {
					assert.False(t, explicitType)
					_, _ = io.WriteString(w, `{"type":"sync","status":"Success","status_code":200,"metadata":{"type":"microvm"}}`)
					return
				}

				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "/1.0/images/container/aliases", r.URL.Path)
				var body api.ImageAliasesPost
				err := json.NewDecoder(r.Body).Decode(&body)
				assert.NoError(t, err)
				assert.Equal(t, alias, body)
				_, _ = io.WriteString(w, `{"type":"sync","status":"Success","status_code":200,"metadata":{}}`)
			}))
			defer server.Close()

			baseURL, err := url.Parse(server.URL)
			require.NoError(t, err)
			client := ProtocolLXD{
				ctx:         context.Background(),
				http:        server.Client(),
				httpBaseURL: *baseURL,
				server:      &api.Server{ServerUntrusted: api.ServerUntrusted{APIExtensions: []string{"image_alias_types"}}},
			}

			require.NoError(t, client.CreateImageAlias(alias))
			expectedRequests := 2
			if explicitType {
				expectedRequests = 1
			}

			assert.Equal(t, expectedRequests, requests)
		})
	}
}
