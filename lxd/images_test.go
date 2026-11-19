package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/canonical/lxd/client"
	"github.com/canonical/lxd/lxd/db"
	"github.com/canonical/lxd/lxd/metrics"
	"github.com/canonical/lxd/lxd/request"
	"github.com/canonical/lxd/shared/api"
	"github.com/canonical/lxd/shared/entity"
)

func TestImageEndpointResolver(t *testing.T) {
	tests := []struct {
		name              string
		path              string
		rawPath           string // If set, simulates URL-encoded path
		wantEndpoint      *APIEndpoint
		wantPathValueKey  string
		wantPathValueVal  string
		wantPathValueKey2 string
		wantPathValueVal2 string
	}{
		// Alias routes
		{
			name:             "alias simple name",
			path:             "/1.0/images/aliases/myalias",
			wantEndpoint:     &imageAliasCmd,
			wantPathValueKey: "name",
			wantPathValueVal: "myalias",
		},
		{
			name:         "alias with unescaped slash in name (path is too long)",
			path:         "/1.0/images/aliases/my/alias",
			wantEndpoint: nil,
		},
		{
			name:             "alias with encoded slash",
			path:             "/1.0/images/aliases/my/alias",
			rawPath:          "/1.0/images/aliases/my%2Falias",
			wantEndpoint:     &imageAliasCmd,
			wantPathValueKey: "name",
			wantPathValueVal: "my/alias",
		},
		{
			name:             "alias with spaces",
			path:             "/1.0/images/aliases/my alias",
			rawPath:          "/1.0/images/aliases/my%20alias",
			wantEndpoint:     &imageAliasCmd,
			wantPathValueKey: "name",
			wantPathValueVal: "my alias",
		},
		{
			name:             "alias ubuntu/noble",
			path:             "/1.0/images/aliases/ubuntu/noble",
			rawPath:          "/1.0/images/aliases/ubuntu%2Fnoble",
			wantEndpoint:     &imageAliasCmd,
			wantPathValueKey: "name",
			wantPathValueVal: "ubuntu/noble",
		},

		// Fingerprint routes
		{
			name:             "fingerprint only",
			path:             "/1.0/images/abc123def456",
			wantEndpoint:     &imageCmd,
			wantPathValueKey: "fingerprint",
			wantPathValueVal: "abc123def456",
		},
		{
			name:             "fingerprint export",
			path:             "/1.0/images/abc123def456/export",
			wantEndpoint:     &imageExportCmd,
			wantPathValueKey: "fingerprint",
			wantPathValueVal: "abc123def456",
		},
		{
			name:             "fingerprint secret",
			path:             "/1.0/images/abc123def456/secret",
			wantEndpoint:     &imageSecretCmd,
			wantPathValueKey: "fingerprint",
			wantPathValueVal: "abc123def456",
		},
		{
			name:             "fingerprint refresh",
			path:             "/1.0/images/abc123def456/refresh",
			wantEndpoint:     &imageRefreshCmd,
			wantPathValueKey: "fingerprint",
			wantPathValueVal: "abc123def456",
		},

		// Unknown action returns nil
		{
			name:             "fingerprint unknown action",
			path:             "/1.0/images/abc123def456/unknown",
			wantEndpoint:     nil,
			wantPathValueKey: "fingerprint",
			wantPathValueVal: "abc123def456",
		},

		// Base path returns nil (404)
		{
			name:         "base images path",
			path:         "/1.0/images/",
			wantEndpoint: nil,
		},
		{
			name:         "base aliases path",
			path:         "/1.0/images/aliases/",
			wantEndpoint: nil,
		},

		// Invalid URL escape sequences are treated as literals
		{
			name:             "typed alias collection",
			path:             "/1.0/images/container/aliases",
			wantEndpoint:     &imageTypeAliasesCmd,
			wantPathValueKey: "imageType",
			wantPathValueVal: "container",
		},
		{
			name:              "typed alias name",
			path:              "/1.0/images/container/aliases/jammy",
			wantEndpoint:      &imageTypeAliasCmd,
			wantPathValueKey:  "imageType",
			wantPathValueVal:  "container",
			wantPathValueKey2: "name",
			wantPathValueVal2: "jammy",
		},
		{
			name:              "typed alias with encoded slash",
			path:              "/1.0/images/virtual-machine/aliases/ubuntu/noble",
			rawPath:           "/1.0/images/virtual-machine/aliases/ubuntu%2Fnoble",
			wantEndpoint:      &imageTypeAliasCmd,
			wantPathValueKey:  "imageType",
			wantPathValueVal:  "virtual-machine",
			wantPathValueKey2: "name",
			wantPathValueVal2: "ubuntu/noble",
		},
		{
			name:             "untyped alias whose name starts with container",
			path:             "/1.0/images/aliases/container/jammy",
			rawPath:          "/1.0/images/aliases/container%2Fjammy",
			wantEndpoint:     &imageAliasCmd,
			wantPathValueKey: "name",
			wantPathValueVal: "container/jammy",
		},
		{
			name:         "image type without aliases",
			path:         "/1.0/images/container",
			wantEndpoint: nil,
		},

		{
			name:             "invalid escape in alias",
			path:             "/1.0/images/aliases/bad%2",
			rawPath:          "/1.0/images/aliases/bad%2",
			wantEndpoint:     &imageAliasCmd,
			wantPathValueKey: "name",
			wantPathValueVal: "bad%2",
		},
		{
			name:             "invalid escape in fingerprint",
			path:             "/1.0/images/bad%2/export",
			rawPath:          "/1.0/images/bad%2/export",
			wantEndpoint:     &imageExportCmd,
			wantPathValueKey: "fingerprint",
			wantPathValueVal: "bad%2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &url.URL{Path: tt.path, RawPath: tt.rawPath}
			r := &http.Request{URL: u}

			got := imageEndpointResolver(r)

			if got != tt.wantEndpoint {
				var gotPath, wantPath string
				if got != nil {
					gotPath = got.Path
				}

				if tt.wantEndpoint != nil {
					wantPath = tt.wantEndpoint.Path
				}

				t.Errorf("imageEndpointResolver() = %s: %v (Path: %q), want %v (Path: %q)", tt.name, got, gotPath, tt.wantEndpoint, wantPath)
			}

			if tt.wantPathValueKey != "" && tt.wantEndpoint != nil {
				gotVal := r.PathValue(tt.wantPathValueKey)
				if gotVal != tt.wantPathValueVal {
					t.Errorf("PathValue(%q) = %q, want %q", tt.wantPathValueKey, gotVal, tt.wantPathValueVal)
				}
			}

			if tt.wantPathValueKey2 != "" && tt.wantEndpoint != nil {
				gotVal := r.PathValue(tt.wantPathValueKey2)
				if gotVal != tt.wantPathValueVal2 {
					t.Errorf("PathValue(%q) = %q, want %q", tt.wantPathValueKey2, gotVal, tt.wantPathValueVal2)
				}
			}
		})
	}
}

func TestUpdateImageAliasCrossType(t *testing.T) {
	daemon, cleanup := newTestDaemon(t)
	defer cleanup()
	err := daemon.State().DB.Cluster.Transaction(context.Background(), func(ctx context.Context, tx *db.ClusterTx) error {
		_, err := tx.Tx().ExecContext(ctx, `INSERT INTO images (fingerprint, filename, size, architecture, upload_date, project_id, type)
VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '', 1, 1, datetime('now'), 1, 0),
       ('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', '', 1, 1, datetime('now'), 1, 1)`)
		return err
	})
	require.NoError(t, err)
	client, err := lxd.ConnectLXDUnix(daemon.os.GetUnixSocket(), nil)
	require.NoError(t, err)
	listener, err := client.GetEvents()
	require.NoError(t, err)
	defer listener.Disconnect()
	events := make(chan api.Event, 16)
	_, err = listener.AddHandler([]string{api.EventTypeLifecycle}, func(event api.Event) {
		events <- event
	})
	require.NoError(t, err)

	containerTarget := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	vmTarget := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	err = client.CreateImageAlias(api.ImageAliasesPost{
		ImageAliasesEntry: api.ImageAliasesEntry{Name: "retarget", Target: containerTarget},
	})
	require.NoError(t, err)
	waitImageAliasLifecycleEvent(t, events, api.EventLifecycleImageAliasCreated)

	for _, tt := range []struct {
		imageType string
		target    string
		method    string
	}{
		{imageType: "virtual-machine", target: vmTarget, method: http.MethodPut},
		{imageType: "container", target: containerTarget, method: http.MethodPut},
		{imageType: "virtual-machine", target: vmTarget, method: http.MethodPatch},
		{imageType: "container", target: containerTarget, method: http.MethodPatch},
	} {
		t.Run(tt.method+"/"+tt.imageType, func(t *testing.T) {
			alias, etag, err := client.GetImageAlias("retarget")
			require.NoError(t, err)
			update := api.ImageAliasesEntryPut{Target: tt.target, Description: "Moved to " + tt.imageType}

			// Explicitly typed updates must not move an alias to a different image type.
			if tt.method == http.MethodPut {
				err = client.UpdateImageAliasType(alias.Type, "retarget", update, etag)
			} else {
				_, _, err = client.RawQuery(tt.method, "/1.0/images/"+alias.Type+"/aliases/retarget", update, etag)
			}

			require.True(t, api.StatusErrorCheck(err, 400), "Expected a type mismatch, got %v", err)

			if tt.method == http.MethodPut {
				err = client.UpdateImageAlias("retarget", update, etag)
			} else {
				_, _, err = client.RawQuery(tt.method, "/1.0/images/aliases/retarget", update, etag)
			}

			require.NoError(t, err)
			moved, _, err := client.GetImageAliasType(tt.imageType, "retarget")
			require.NoError(t, err)
			require.Equal(t, tt.target, moved.Target)
			require.Equal(t, tt.imageType, moved.Type)
			require.Equal(t, update.Description, moved.Description)

			event := waitImageAliasLifecycleEvent(t, events, api.EventLifecycleImageAliasUpdated)
			result, _, err := client.RawQuery(http.MethodGet, event.Source, nil, "")
			require.NoError(t, err)
			var affected api.ImageAliasesEntry
			err = result.MetadataAsStruct(&affected)
			require.NoError(t, err)
			require.Equal(t, *moved, affected)
		})
	}
}

func TestImageAliasLocationsAndLifecycle(t *testing.T) {
	daemon, cleanup := newTestDaemon(t)
	defer cleanup()
	err := daemon.State().DB.Cluster.Transaction(context.Background(), func(ctx context.Context, tx *db.ClusterTx) error {
		_, err := tx.Tx().ExecContext(ctx, `INSERT INTO images (fingerprint, filename, size, architecture, upload_date, project_id, type)
VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '', 1, 1, datetime('now'), 1, 0),
       ('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', '', 1, 1, datetime('now'), 1, 1)`)
		return err
	})
	require.NoError(t, err)
	client, err := lxd.ConnectLXDUnix(daemon.os.GetUnixSocket(), nil)
	require.NoError(t, err)
	listener, err := client.GetEvents()
	require.NoError(t, err)
	defer listener.Disconnect()
	events := make(chan api.Event, 32)
	_, err = listener.AddHandler([]string{api.EventTypeLifecycle}, func(event api.Event) {
		events <- event
	})
	require.NoError(t, err)

	for _, tt := range []struct {
		imageType string
		target    string
		otherType string
		other     string
	}{
		{
			imageType: "container",
			target:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			otherType: "virtual-machine",
			other:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
		{
			imageType: "virtual-machine",
			target:    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			otherType: "container",
			other:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	} {
		for _, typed := range []bool{false, true} {
			endpoint := "untyped"
			collection := "/1.0/images/aliases"
			if typed {
				endpoint = "typed"
				collection = "/1.0/images/" + tt.imageType + "/aliases"
			}

			t.Run(tt.imageType+"/"+endpoint, func(t *testing.T) {
				name := tt.imageType + "-" + endpoint
				renamed := name + "-renamed"
				for _, otherName := range []string{name, renamed} {
					err = client.CreateImageAlias(api.ImageAliasesPost{
						ImageAliasesEntry: api.ImageAliasesEntry{Name: otherName, Target: tt.other},
					})
					require.NoError(t, err)
					waitImageAliasLifecycleEvent(t, events, api.EventLifecycleImageAliasCreated)
				}

				assertAliasURL := func(aliasURL string, expectedName string) {
					t.Helper()
					result, _, err := client.RawQuery(http.MethodGet, aliasURL, nil, "")
					require.NoError(t, err)
					var affected api.ImageAliasesEntry
					err = result.MetadataAsStruct(&affected)
					require.NoError(t, err)
					require.Equal(t, expectedName, affected.Name)
					require.Equal(t, tt.imageType, affected.Type)
					require.Equal(t, tt.target, affected.Target)
				}

				post := func(path string, body any, action string, expectedName string) string {
					t.Helper()
					data, err := json.Marshal(body)
					require.NoError(t, err)
					req, err := http.NewRequest(http.MethodPost, "http://unix.socket"+path, bytes.NewReader(data))
					require.NoError(t, err)
					req.Header.Set("Content-Type", "application/json")
					resp, err := client.DoHTTP(req)
					require.NoError(t, err)
					defer resp.Body.Close()
					require.Equal(t, http.StatusCreated, resp.StatusCode)
					location := resp.Header.Get("Location")
					require.NotEmpty(t, location)
					assertAliasURL(location, expectedName)
					event := waitImageAliasLifecycleEvent(t, events, action)
					require.Equal(t, location, event.Source)
					assertAliasURL(event.Source, expectedName)
					return location
				}

				post(collection, api.ImageAliasesPost{
					ImageAliasesEntry: api.ImageAliasesEntry{Name: name, Target: tt.target},
				}, api.EventLifecycleImageAliasCreated, name)
				// Rename through an unambiguous old name on the untyped endpoint, while the destination
				// already exists for the other image type.
				oldName := name + "-old"
				err = client.RenameImageAliasType(tt.imageType, name, api.ImageAliasesEntryPost{Name: oldName})
				require.NoError(t, err)
				waitImageAliasLifecycleEvent(t, events, api.EventLifecycleImageAliasRenamed)
				renamedURL := post(collection+"/"+oldName, api.ImageAliasesEntryPost{Name: renamed}, api.EventLifecycleImageAliasRenamed, renamed)

				_, _, err = client.RawQuery(http.MethodDelete, "/1.0/images/"+tt.imageType+"/aliases/"+renamed, nil, "")
				require.NoError(t, err)
				event := waitImageAliasLifecycleEvent(t, events, api.EventLifecycleImageAliasDeleted)
				require.Equal(t, renamedURL, event.Source)
				_, _, err = client.RawQuery(http.MethodGet, event.Source, nil, "")
				require.True(t, api.StatusErrorCheck(err, http.StatusNotFound), "Expected deleted alias, got %v", err)
				other, _, err := client.GetImageAliasType(tt.otherType, renamed)
				require.NoError(t, err)
				require.Equal(t, tt.other, other.Target)
			})
		}
	}
}

func waitImageAliasLifecycleEvent(t *testing.T, events <-chan api.Event, action string) api.EventLifecycle {
	t.Helper()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case event := <-events:
			var lifecycleEvent api.EventLifecycle
			err := json.Unmarshal(event.Metadata, &lifecycleEvent)
			require.NoError(t, err)
			if lifecycleEvent.Action == action {
				return lifecycleEvent
			}

		case <-timeout.C:
			t.Fatalf("Timed out waiting for lifecycle action %q", action)
		}
	}
}

func TestUpdateImageAliasLegacyType(t *testing.T) {
	daemon, cleanup := newTestDaemon(t)
	defer cleanup()
	containerTarget := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	legacyTarget := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	err := daemon.State().DB.Cluster.Transaction(context.Background(), func(ctx context.Context, tx *db.ClusterTx) error {
		_, err := tx.Tx().ExecContext(ctx, `INSERT INTO images (fingerprint, filename, size, architecture, upload_date, project_id, type)
VALUES (?, '', 1, 1, datetime('now'), 1, 0),
       (?, '', 1, 1, datetime('now'), 1, 2)`, containerTarget, legacyTarget)
		return err
	})
	require.NoError(t, err)
	client, err := lxd.ConnectLXDUnix(daemon.os.GetUnixSocket(), nil)
	require.NoError(t, err)
	listener, err := client.GetEvents()
	require.NoError(t, err)
	defer listener.Disconnect()
	events := make(chan api.Event, 16)
	_, err = listener.AddHandler([]string{api.EventTypeLifecycle}, func(event api.Event) {
		events <- event
	})
	require.NoError(t, err)

	for _, tt := range []struct {
		name    string
		method  string
		initial string
		update  api.ImageAliasesEntryPut
	}{
		{
			name:    "put",
			method:  http.MethodPut,
			initial: containerTarget,
			update:  api.ImageAliasesEntryPut{Target: legacyTarget, Description: "Legacy PUT target"},
		},
		{
			name:    "patch-target",
			method:  http.MethodPatch,
			initial: containerTarget,
			update:  api.ImageAliasesEntryPut{Target: legacyTarget, Description: "Legacy PATCH target"},
		},
		{
			name:    "patch-description",
			method:  http.MethodPatch,
			initial: legacyTarget,
			update:  api.ImageAliasesEntryPut{Description: "Legacy description-only PATCH"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := client.CreateImageAlias(api.ImageAliasesPost{
				ImageAliasesEntry: api.ImageAliasesEntry{Name: tt.name, Target: tt.initial},
			})
			require.NoError(t, err)
			waitImageAliasLifecycleEvent(t, events, api.EventLifecycleImageAliasCreated)

			body := map[string]string{"description": tt.update.Description}
			if tt.update.Target != "" {
				body["target"] = tt.update.Target
			}

			_, _, err = client.RawQuery(tt.method, "/1.0/images/aliases/"+tt.name, body, "")
			require.NoError(t, err)
			event := waitImageAliasLifecycleEvent(t, events, api.EventLifecycleImageAliasUpdated)
			result, _, err := client.RawQuery(http.MethodGet, event.Source, nil, "")
			require.NoError(t, err)
			var affected api.ImageAliasesEntry
			err = result.MetadataAsStruct(&affected)
			require.NoError(t, err)
			require.Equal(t, tt.name, affected.Name)
			require.Equal(t, "container", affected.Type)
			require.Equal(t, legacyTarget, affected.Target)
			require.Equal(t, tt.update.Description, affected.Description)
		})
	}
}

func TestImageCopySharedAliasAuthorization(t *testing.T) {
	t.Setenv("LXD_DIR", t.TempDir())
	daemon, cleanup := newTestDaemon(t)
	defer cleanup()
	client, err := lxd.ConnectLXDUnix(daemon.os.GetUnixSocket(), nil)
	require.NoError(t, err)
	err = os.MkdirAll(daemon.State().ImagesStoragePath("default"), 0o700)
	require.NoError(t, err)
	sourceProject := "copy-source"
	err = client.CreateProject(api.ProjectsPost{
		Name:       sourceProject,
		ProjectPut: api.ProjectPut{Config: map[string]string{"features.images": "true", "features.profiles": "false"}},
	})
	require.NoError(t, err)
	err = client.CreateAuthGroup(api.AuthGroupsPost{AuthGroupPost: api.AuthGroupPost{Name: "image-copiers"}})
	require.NoError(t, err)
	containerTarget := strings.Repeat("a", 64)
	vmTarget := strings.Repeat("b", 64)
	err = daemon.State().DB.Cluster.Transaction(context.Background(), func(ctx context.Context, tx *db.ClusterTx) error {
		_, err := tx.Tx().ExecContext(ctx, `INSERT INTO images (fingerprint, filename, size, architecture, upload_date, project_id, type)
SELECT ?, '', 1, 1, datetime('now'), id, 0 FROM projects WHERE name = ?
UNION ALL SELECT ?, '', 1, 1, datetime('now'), id, 1 FROM projects WHERE name = ?`, containerTarget, sourceProject, vmTarget, sourceProject)
		if err != nil {
			return err
		}

		for _, fingerprint := range []string{containerTarget, vmTarget} {
			err = tx.AddImageToLocalNode(ctx, sourceProject, fingerprint)
			if err != nil {
				return err
			}
		}

		_, err = tx.Tx().ExecContext(ctx, `INSERT INTO identities (identifier, auth_method, type, name, metadata)
VALUES ('image-copier@example.com', 2, 5, 'image copier', '{}');
INSERT INTO identities_auth_groups (identity_id, auth_group_id)
SELECT identities.id, auth_groups.id FROM identities, auth_groups
WHERE identities.identifier = 'image-copier@example.com' AND auth_groups.name = 'image-copiers'`)
		return err
	})
	require.NoError(t, err)
	for _, fingerprint := range []string{containerTarget, vmTarget} {
		err = client.UseProject(sourceProject).CreateImageAlias(api.ImageAliasesPost{
			ImageAliasesEntry: api.ImageAliasesEntry{Name: "release", Target: fingerprint},
		})
		require.NoError(t, err)
		err = os.WriteFile(filepath.Join(daemon.State().ImagesStoragePath(sourceProject), fingerprint), []byte(fingerprint), 0o600)
		require.NoError(t, err)
	}

	// A fingerprint-shaped alias must not redirect a previously authorized copy.
	err = client.UseProject(sourceProject).CreateImageAlias(api.ImageAliasesPost{
		ImageAliasesEntry: api.ImageAliasesEntry{Name: containerTarget, Target: vmTarget},
	})
	require.NoError(t, err)

	for _, tt := range []struct {
		name            string
		imageType       string
		allowVM         bool
		wantFingerprint string
	}{
		{name: "denied-vm", imageType: "virtual-machine"},
		{name: "container", imageType: "container", wantFingerprint: containerTarget},
		{name: "untyped", wantFingerprint: containerTarget},
		{name: "allowed-vm", imageType: "virtual-machine", allowVM: true, wantFingerprint: vmTarget},
	} {
		t.Run(tt.name, func(t *testing.T) {
			targetProject := "copy-" + tt.name
			err := client.CreateProject(api.ProjectsPost{
				Name:       targetProject,
				ProjectPut: api.ProjectPut{Config: map[string]string{"features.images": "true", "features.profiles": "false"}},
			})
			require.NoError(t, err)
			permissions := []api.Permission{
				{EntityType: "project", EntityReference: entity.ProjectURL(sourceProject).String(), Entitlement: "can_view"},
				{EntityType: "project", EntityReference: entity.ProjectURL(targetProject).String(), Entitlement: "can_view"},
				{EntityType: "project", EntityReference: entity.ProjectURL(targetProject).String(), Entitlement: "can_create_images"},
				{EntityType: "image", EntityReference: entity.ImageURL(sourceProject, containerTarget).String(), Entitlement: "can_view"},
			}

			if tt.allowVM {
				permissions = append(permissions, api.Permission{EntityType: "image", EntityReference: entity.ImageURL(sourceProject, vmTarget).String(), Entitlement: "can_view"})
			}

			err = client.UpdateAuthGroup("image-copiers", api.AuthGroupPut{Permissions: permissions}, "")
			require.NoError(t, err)
			body := map[string]any{"source": map[string]string{
				"type": "image", "project": sourceProject, "alias": "release", "image_type": tt.imageType,
			}}
			data, err := json.Marshal(body)
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/1.0/images?project="+targetProject, bytes.NewReader(data))
			req.Header.Set("Content-Type", "application/json")
			metrics.TrackStartedRequest(req, entity.TypeImage)
			err = request.SetRequestor(req, daemon.requestorHook, request.RequestorArgs{
				Trusted: true, Username: "image-copier@example.com", Protocol: api.AuthenticationMethodOIDC,
			})
			require.NoError(t, err)
			recorder := httptest.NewRecorder()
			err = imagesPost(daemon, req).Render(recorder, req)
			require.NoError(t, err)
			if tt.wantFingerprint == "" {
				require.Equal(t, http.StatusNotFound, recorder.Code, recorder.Body.String())
			} else {
				require.Equal(t, http.StatusAccepted, recorder.Code, recorder.Body.String())
				var result api.Response
				err = json.Unmarshal(recorder.Body.Bytes(), &result)
				require.NoError(t, err)
				op, _, err := client.RawQuery(http.MethodGet, result.Operation+"/wait?timeout=10", nil, "")
				require.NoError(t, err)
				var operation api.Operation
				err = op.MetadataAsStruct(&operation)
				require.NoError(t, err)
				require.Equal(t, api.Success, operation.StatusCode, operation.Err)
			}

			images, err := client.UseProject(targetProject).GetImages()
			require.NoError(t, err)
			if tt.wantFingerprint == "" {
				require.Empty(t, images, "Denied image copies must not populate the target project")
			} else {
				require.Len(t, images, 1)
				require.Equal(t, tt.wantFingerprint, images[0].Fingerprint)
			}
		})
	}
}
