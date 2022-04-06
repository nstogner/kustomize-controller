/*
Copyright 2020 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	securejoin "github.com/cyphar/filepath-securejoin"
	"go.mozilla.org/sops/v3"
	"go.mozilla.org/sops/v3/aes"
	"go.mozilla.org/sops/v3/cmd/sops/common"
	"go.mozilla.org/sops/v3/cmd/sops/formats"
	"go.mozilla.org/sops/v3/keyservice"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/kustomize/api/konfig"
	"sigs.k8s.io/kustomize/api/resource"
	kustypes "sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/yaml"

	kustomizev1 "github.com/fluxcd/kustomize-controller/api/v1beta2"
	"github.com/fluxcd/kustomize-controller/internal/sops/age"
	"github.com/fluxcd/kustomize-controller/internal/sops/azkv"
	intkeyservice "github.com/fluxcd/kustomize-controller/internal/sops/keyservice"
	"github.com/fluxcd/kustomize-controller/internal/sops/pgp"
)

const (
	// DecryptionProviderSOPS is the SOPS provider name.
	DecryptionProviderSOPS = "sops"
	// DecryptionPGPExt is the extension of the file containing an armored PGP
	//key.
	DecryptionPGPExt = ".asc"
	// DecryptionAgeExt is the extension of the file containing an age key
	// file.
	DecryptionAgeExt = ".agekey"
	// DecryptionVaultTokenFileName is the name of the file containing the
	// Hashicorp Vault token.
	DecryptionVaultTokenFileName = "sops.vault-token"
	// DecryptionAzureAuthFile is the name of the file containing the Azure
	// credentials.
	DecryptionAzureAuthFile = "sops.azure-kv"
)

const (
	// maxDotenvSize is the max allowed dotenv file size in bytes.
	maxDotenvSize = 1 << 12
)

// sopsFormatToString is the counterpart to
// https://github.com/mozilla/sops/blob/v3.7.2/cmd/sops/formats/formats.go#L16
var sopsFormatToString = map[formats.Format]string{
	formats.Binary: "binary",
	formats.Dotenv: "dotenv",
	formats.Ini:    "INI",
	formats.Json:   "JSON",
	formats.Yaml:   "YAML",
}

// KustomizeDecryptor performs decryption operations for a
// v1beta2.Kustomization.
// The only supported decryption provider at present is
// DecryptionProviderSOPS.
type KustomizeDecryptor struct {
	// workDir is the chroot for file system operations. Any (relative) path or
	// symlink is not allowed to traverse outside this path.
	workDir string
	// client is the Kubernetes client used to e.g. retrieve Secrets with.
	client client.Client
	// kustomization is the v1beta2.Kustomization we are decrypting for.
	// The v1beta2.Decryption of the object is used to ImportKeys().
	kustomization kustomizev1.Kustomization

	// gnuPGHome is the absolute path of the GnuPG home directory used to
	// decrypt PGP data. When empty, the systems' GnuPG keyring is used.
	// When set, ImportKeys() imports found PGP keys into this keyring.
	gnuPGHome pgp.GnuPGHome
	// ageIdentities is the set of age identities available to the decryptor.
	ageIdentities age.ParsedIdentities
	// vaultToken is the Hashicorp Vault token used to authenticate towards
	// any Vault server.
	vaultToken string
	// azureToken is the Azure credential token used to authenticate towards
	// any Azure Key Vault.
	azureToken *azkv.Token

	// keyServices are the SOPS keyservice.KeyServiceClient's available to the
	// decryptor.
	keyServices      []keyservice.KeyServiceClient
	localServiceOnce sync.Once
}

// NewDecryptor creates a new KustomizeDecryptor for the given kustomization.
// gnuPGHome can be empty, in which case the systems' keyring is used.
func NewDecryptor(workDir string, client client.Client, kustomization kustomizev1.Kustomization, gnuPGHome string) *KustomizeDecryptor {
	return &KustomizeDecryptor{
		workDir:       workDir,
		client:        client,
		kustomization: kustomization,
		gnuPGHome:     pgp.GnuPGHome(gnuPGHome),
	}
}

// NewTempDecryptor creates a new KustomizeDecryptor, with a temporary GnuPG
// home directory to KustomizeDecryptor.ImportKeys() into.
func NewTempDecryptor(workDir string, client client.Client, kustomization kustomizev1.Kustomization) (*KustomizeDecryptor, func(), error) {
	gnuPGHome, err := pgp.NewGnuPGHome()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create decryptor: %w", err)
	}
	cleanup := func() { os.RemoveAll(gnuPGHome.String()) }
	return NewDecryptor(workDir, client, kustomization, gnuPGHome.String()), cleanup, nil
}

// ImportKeys imports the DecryptionProviderSOPS keys from the data values of
// the Secret referenced in the Kustomization's v1beta2.Decryption spec.
// It returns an error if the Secret cannot be retrieved, or if one of the
// imports fails.
// Imports do not have an effect after the first call to DataWithFormat(),
// which initializes and caches SOPS' (local) key service server.
// For the import of PGP keys, the KustomizeDecryptor must be configured with
// an absolute GnuPG home directory path.
func (kd *KustomizeDecryptor) ImportKeys(ctx context.Context) error {
	if kd.kustomization.Spec.Decryption == nil || kd.kustomization.Spec.Decryption.SecretRef == nil {
		return nil
	}

	provider := kd.kustomization.Spec.Decryption.Provider
	switch provider {
	case DecryptionProviderSOPS:
		secretName := types.NamespacedName{
			Namespace: kd.kustomization.GetNamespace(),
			Name:      kd.kustomization.Spec.Decryption.SecretRef.Name,
		}

		var secret corev1.Secret
		if err := kd.client.Get(ctx, secretName, &secret); err != nil {
			if apierrors.IsNotFound(err) {
				return err
			}
			return fmt.Errorf("cannot get %s decryption Secret '%s': %w", provider, secretName, err)
		}

		var err error
		for name, value := range secret.Data {
			switch filepath.Ext(name) {
			case DecryptionPGPExt:
				if err = kd.gnuPGHome.Import(value); err != nil {
					return fmt.Errorf("failed to import '%s' data from %s decryption Secret '%s': %w", name, provider, secretName, err)
				}
			case DecryptionAgeExt:
				if err = kd.ageIdentities.Import(string(value)); err != nil {
					return fmt.Errorf("failed to import '%s' data from %s decryption Secret '%s': %w", name, provider, secretName, err)
				}
			case filepath.Ext(DecryptionVaultTokenFileName):
				// Make sure we have the absolute name
				if name == DecryptionVaultTokenFileName {
					token := string(value)
					token = strings.Trim(strings.TrimSpace(token), "\n")
					kd.vaultToken = token
				}
			case filepath.Ext(DecryptionAzureAuthFile):
				// Make sure we have the absolute name
				if name == DecryptionAzureAuthFile {
					conf := azkv.AADConfig{}
					if err = azkv.LoadAADConfigFromBytes(value, &conf); err != nil {
						return fmt.Errorf("failed to import '%s' data from %s decryption Secret '%s': %w", name, provider, secretName, err)
					}
					if kd.azureToken, err = azkv.TokenFromAADConfig(conf); err != nil {
						return fmt.Errorf("failed to import '%s' data from %s decryption Secret '%s': %w", name, provider, secretName, err)
					}
				}
			}
		}
	}
	return nil
}

func (kd *KustomizeDecryptor) DataWithFormat(data []byte, inputFormat, outputFormat formats.Format) ([]byte, error) {
	store := common.StoreForFormat(inputFormat)

	tree, err := store.LoadEncryptedFile(data)
	if err != nil {
		return nil, fmt.Errorf("cannot load encrypted %v data: %w", inputFormat, err)
	}

	metadataKey, err := tree.Metadata.GetDataKeyWithKeyServices(kd.keyServiceServer())
	if err != nil {
		if userErr, ok := err.(sops.UserError); ok {
			err = fmt.Errorf(userErr.UserError())
		}
		return nil, fmt.Errorf("cannot get sops data key: %w", err)
	}

	cipher := aes.NewCipher()
	if _, err := tree.Decrypt(metadataKey, cipher); err != nil {
		return nil, fmt.Errorf("cannot AES decrypt: %w", err)
	}

	outputStore := common.StoreForFormat(outputFormat)
	out, err := outputStore.EmitPlainFile(tree.Branches)
	if err != nil {
		return nil, fmt.Errorf("cannot emit decrypted %v file: %w", outputFormat, err)
	}
	return out, err
}

func (kd *KustomizeDecryptor) DecryptResource(res *resource.Resource) (*resource.Resource, error) {
	if kd.kustomization.Spec.Decryption == nil || kd.kustomization.Spec.Decryption.Provider == "" {
		return nil, nil
	}

	switch kd.kustomization.Spec.Decryption.Provider {
	case DecryptionProviderSOPS:
		switch {
		case isSOPSEncryptedResource(res):
			// As we are expecting to decrypt right before applying, we do not
			// care about keeping any other data (e.g. comments) around.
			// We can therefore simply work with JSON, which saves us from e.g.
			// JSON -> YAML -> JSON transformations.
			out, err := res.MarshalJSON()
			if err != nil {
				return nil, err
			}

			data, err := kd.DataWithFormat(out, formats.Json, formats.Json)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt and format data as %s: %w",
					sopsFormatToString[formats.Json], err)
			}

			err = res.UnmarshalJSON(data)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal decrypted JSON data: %w", err)
			}
			return res, nil
		case res.GetKind() == "Secret":
			dataMap := res.GetDataMap()
			for key, value := range dataMap {
				data, err := base64.StdEncoding.DecodeString(value)
				if err != nil {
					return nil, fmt.Errorf("failed to base64 decode '%s' value: %w", key, err)
				}
				if bytes.Contains(data, []byte("sops")) && bytes.Contains(data, []byte("ENC[")) {
					inputFormat := formats.Yaml
					outputFormat := formats.FormatForPath(key)
					out, err := kd.DataWithFormat(data, inputFormat, outputFormat)
					if err != nil {
						return nil, fmt.Errorf("failed to format %v data as %v: %w", inputFormat, outputFormat, err)
					}
					dataMap[key] = base64.StdEncoding.EncodeToString(out)
				}
			}
			res.SetDataMap(dataMap)
			return res, nil
		}
	}
	return nil, nil
}

func (kd *KustomizeDecryptor) DecryptDotenvFiles(path string) error {
	decrypted, visited := make(map[string]struct{}), make(map[string]struct{})
	visit := kd.decryptKustomizationEnvSources(decrypted)
	return recurseKustomizationFiles(kd.workDir, path, visit, visited)
}

func (kd *KustomizeDecryptor) decryptKustomizationEnvSources(visited map[string]struct{}) visitKustomization {
	return func(root, path string, kus *kustypes.Kustomization) error {
		for _, gen := range kus.SecretGenerator {
			for _, envFile := range gen.EnvSources {
				envFileParts := strings.Split(envFile, "=")
				if len(envFileParts) > 1 {
					envFile = envFileParts[1]
				}
				if !filepath.IsAbs(envFile) {
					envFile = filepath.Join(path, envFile)
				}

				absEnvFile, err := secureAbsPath(root, envFile)
				if err != nil {
					return err
				}
				if _, ok := visited[absEnvFile]; ok {
					continue
				}
				visited[absEnvFile] = struct{}{}

				if err := kd.decryptDotenvFile(absEnvFile); err != nil {
					return err
				}
			}
		}
		return nil
	}
}

// decryptDotenvFile attempts to decrypt the dotenv file at the given path.
// The file is not allowed to exceed the maxDotenvSize.
func (kd *KustomizeDecryptor) decryptDotenvFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if size := fi.Size(); size > maxDotenvSize {
		return fmt.Errorf("size %d exceeds %d bytes max", size, maxDotenvSize)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Contains(data, []byte("sops_mac=ENC[")) {
		return nil
	}

	out, err := kd.DataWithFormat(data, formats.Dotenv, formats.Dotenv)
	if err != nil {
		return err
	}

	err = os.WriteFile(path, out, 0644)
	if err != nil {
		return fmt.Errorf("error writing to file: %w", err)
	}
	return nil
}

// keyServiceServer returns the SOPS (local) key service keyServices used to serve
// decryption requests. The keyServices is only configured on the first call.
func (kd *KustomizeDecryptor) keyServiceServer() []keyservice.KeyServiceClient {
	kd.localServiceOnce.Do(func() {
		serverOpts := []intkeyservice.ServerOption{
			intkeyservice.WithGnuPGHome(kd.gnuPGHome),
			intkeyservice.WithVaultToken(kd.vaultToken),
			intkeyservice.WithAgeIdentities(kd.ageIdentities),
		}
		if kd.azureToken != nil {
			serverOpts = append(serverOpts, intkeyservice.WithAzureToken{Token: kd.azureToken})
		}
		server := intkeyservice.NewServer(serverOpts...)
		kd.keyServices = append(kd.keyServices, intkeyservice.NewLocalClient(server))
	})
	return kd.keyServices
}

// IsEncryptedSecret checks if the given object is a Kubernetes Secret encrypted
// with Mozilla SOPS.
func IsEncryptedSecret(object *unstructured.Unstructured) bool {
	if object.GetKind() == "Secret" && object.GetAPIVersion() == "v1" {
		if _, found, _ := unstructured.NestedFieldNoCopy(object.Object, "sops"); found {
			return true
		}
	}
	return false
}

// loadKustomizationFile tries to load a Kustomization file from the given
// directory path.
// The path must be absolute, and the Kustomization must be a regular file.
// If multiple Kustomization files are found, the request is ambiguous and an
// error is returned.
func loadKustomizationFile(path string) (*kustypes.Kustomization, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("path must be absolute")
	}

	var loadPath string
	for _, fName := range konfig.RecognizedKustomizationFileNames() {
		fPath := filepath.Join(path, fName)
		fi, err := os.Lstat(fPath)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("failed to stat %s: %w", fName, err)
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("expected %s to be a regular file", fName)
		}
		if loadPath != "" {
			return nil, fmt.Errorf("found multiple kustomization files")
		}
		loadPath = fPath
	}
	if loadPath == "" {
		return nil, fmt.Errorf("no kustomization file found")
	}

	data, err := os.ReadFile(loadPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read kustomization file: %w", err)
	}

	kus := kustypes.Kustomization{
		TypeMeta: kustypes.TypeMeta{
			APIVersion: kustypes.KustomizationVersion,
			Kind:       kustypes.KustomizationKind,
		},
	}
	if err := yaml.Unmarshal(data, &kus); err != nil {
		return nil, fmt.Errorf("failed to unmarshal kustomization file: %w", err)
	}
	return &kus, nil
}

// visitKustomization is called by recurseKustomizationFiles after every
// successful Kustomization file load.
type visitKustomization func(root, path string, kus *kustypes.Kustomization) error

// errRecurseIgnore is a wrapping error to signal to recurseKustomizationFiles
// the error can be ignored during recursion. For example, because the
// Kustomization file can not be loaded for a subsequent call.
type errRecurseIgnore struct {
	Err error
}

// Unwrap returns the actual underlying error.
func (e *errRecurseIgnore) Unwrap() error {
	return e.Err
}

// Error returns the error string of the underlying error.
func (e *errRecurseIgnore) Error() string {
	return e.Err.Error()
}

// recurseKustomizationFiles attempts to recursively load and visit
// Kustomization files.
// The provided path is allowed to be relative, in which case it is safely
// joined with root. When absolute, it must be inside root.
func recurseKustomizationFiles(root, path string, visit visitKustomization, visited map[string]struct{}) error {
	// Resolve the absolute path
	absPath, err := secureAbsPath(root, path)
	if err != nil {
		return err
	}

	if _, ok := visited[absPath]; ok {
		// Short-circuit
		return nil
	}
	visited[absPath] = struct{}{}

	// Confirm we are dealing with a directory
	fi, err := os.Lstat(absPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			err = &errRecurseIgnore{Err: err}
		}
		return err
	}
	if !fi.IsDir() {
		return &errRecurseIgnore{Err: fmt.Errorf("not a directory")}
	}

	// Attempt to load the Kustomization file from the directory
	kus, err := loadKustomizationFile(absPath)
	if err != nil {
		return err
	}

	// Visit the Kustomization
	if err = visit(root, path, kus); err != nil {
		return err
	}

	// Recurse over other resources in Kustomization,
	// repeating the above logic per item
	for _, res := range kus.Resources {
		if !filepath.IsAbs(res) {
			res = filepath.Join(path, res)
		}
		if err = recurseKustomizationFiles(root, res, visit, visited); err != nil {
			// When the resource does not exist at the compiled path, it's
			// either an invalid reference, or a URL.
			// If the reference is valid but does not point to a directory,
			// we have run into a dead end as well.
			// In all other cases, the error is of (possible) importance to
			// the user, and we should return it.
			if _, ok := err.(*errRecurseIgnore); !ok {
				return err
			}
		}
	}
	return nil
}

// isSOPSEncryptedResource detects if the given resource is a SOPS' encrypted
// resource by looking for ".sops" and ".sops.mac" fields.
func isSOPSEncryptedResource(res *resource.Resource) bool {
	if res == nil {
		return false
	}
	sopsField := res.Field("sops")
	if sopsField.IsNilOrEmpty() {
		return false
	}
	macField := sopsField.Value.Field("mac")
	return !macField.IsNilOrEmpty()
}

// secureAbsPath returns the absolute path for the provided path, guaranteed to
// be scoped inside the provided root.
// When the given path is absolute, the root is stripped before secure joining
// it on root.
func secureAbsPath(root, path string) (string, error) {
	if filepath.IsAbs(path) {
		path = stripRoot(root, path)
	}
	secureAbsPath, err := securejoin.SecureJoin(root, path)
	if err != nil {
		return "", err
	}
	return secureAbsPath, nil
}

func stripRoot(root, path string) string {
	sepStr := string(filepath.Separator)
	root, path = filepath.Clean(sepStr+root), filepath.Clean(sepStr+path)
	switch {
	case path == root:
		path = sepStr
	case root == sepStr:
		// noop
	case strings.HasPrefix(path, root+sepStr):
		path = strings.TrimPrefix(path, root+sepStr)
	}
	return filepath.Clean(path)
}
