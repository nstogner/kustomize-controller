/*
Copyright 2021 The Flux authors

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
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	kustomizev1 "github.com/fluxcd/kustomize-controller/api/v1beta2"
	"github.com/fluxcd/pkg/apis/meta"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	"github.com/hashicorp/vault/api"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/kustomize/api/provider"
	"sigs.k8s.io/kustomize/api/resource"
)

func TestKustomizationReconciler_Decryptor(t *testing.T) {
	g := NewWithT(t)

	cli, err := api.NewClient(api.DefaultConfig())
	g.Expect(err).NotTo(HaveOccurred(), "failed to create vault client")

	// create a master key on the vault transit engine
	path, data := "sops/keys/firstkey", map[string]interface{}{"type": "rsa-4096"}
	_, err = cli.Logical().Write(path, data)
	g.Expect(err).NotTo(HaveOccurred(), "failed to write key")

	// encrypt the testdata vault secret
	cmd := exec.Command("sops", "--hc-vault-transit", cli.Address()+"/v1/sops/keys/firstkey", "--encrypt", "--encrypted-regex", "^(data|stringData)$", "--in-place", "./testdata/sops/secret.vault.yaml")
	err = cmd.Run()
	g.Expect(err).NotTo(HaveOccurred(), "failed to encrypt file")

	// defer the testdata vault secret decryption, to leave a clean testdata vault secret
	defer func() {
		cmd := exec.Command("sops", "--hc-vault-transit", cli.Address()+"/v1/sops/keys/firstkey", "--decrypt", "--encrypted-regex", "^(data|stringData)$", "--in-place", "./testdata/sops/secret.vault.yaml")
		err = cmd.Run()
	}()

	id := "sops-" + randStringRunes(5)

	err = createNamespace(id)
	g.Expect(err).NotTo(HaveOccurred(), "failed to create test namespace")

	err = createKubeConfigSecret(id)
	g.Expect(err).NotTo(HaveOccurred(), "failed to create kubeconfig secret")

	artifactName := "sops-" + randStringRunes(5)
	artifactChecksum, err := createArtifact(testServer, "testdata/sops", artifactName)
	g.Expect(err).ToNot(HaveOccurred())

	overlayArtifactName := "sops-" + randStringRunes(5)
	overlayChecksum, err := createArtifact(testServer, "testdata/test-dotenv", overlayArtifactName)
	g.Expect(err).ToNot(HaveOccurred())

	repositoryName := types.NamespacedName{
		Name:      fmt.Sprintf("sops-%s", randStringRunes(5)),
		Namespace: id,
	}

	overlayRepositoryName := types.NamespacedName{
		Name:      fmt.Sprintf("sops-%s", randStringRunes(5)),
		Namespace: id,
	}

	err = applyGitRepository(repositoryName, artifactName, "main/"+artifactChecksum)
	g.Expect(err).NotTo(HaveOccurred())

	err = applyGitRepository(overlayRepositoryName, overlayArtifactName, "main/"+overlayChecksum)
	g.Expect(err).NotTo(HaveOccurred())

	pgpKey, err := os.ReadFile("testdata/sops/pgp.asc")
	g.Expect(err).ToNot(HaveOccurred())
	ageKey, err := os.ReadFile("testdata/sops/age.txt")
	g.Expect(err).ToNot(HaveOccurred())

	sopsSecretKey := types.NamespacedName{
		Name:      "sops-" + randStringRunes(5),
		Namespace: id,
	}

	sopsSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sopsSecretKey.Name,
			Namespace: sopsSecretKey.Namespace,
		},
		StringData: map[string]string{
			"pgp.asc":          string(pgpKey),
			"age.agekey":       string(ageKey),
			"sops.vault-token": "secret",
		},
	}

	g.Expect(k8sClient.Create(context.Background(), sopsSecret)).To(Succeed())

	kustomizationKey := types.NamespacedName{
		Name:      fmt.Sprintf("sops-%s", randStringRunes(5)),
		Namespace: id,
	}
	kustomization := &kustomizev1.Kustomization{
		ObjectMeta: metav1.ObjectMeta{
			Name:      kustomizationKey.Name,
			Namespace: kustomizationKey.Namespace,
		},
		Spec: kustomizev1.KustomizationSpec{
			Interval: metav1.Duration{Duration: 2 * time.Minute},
			Path:     "./",
			KubeConfig: &kustomizev1.KubeConfig{
				SecretRef: meta.LocalObjectReference{
					Name: "kubeconfig",
				},
			},
			SourceRef: kustomizev1.CrossNamespaceSourceReference{
				Name:      repositoryName.Name,
				Namespace: repositoryName.Namespace,
				Kind:      sourcev1.GitRepositoryKind,
			},
			Decryption: &kustomizev1.Decryption{
				Provider: "sops",
				SecretRef: &meta.LocalObjectReference{
					Name: sopsSecretKey.Name,
				},
			},
			TargetNamespace: id,
		},
	}
	g.Expect(k8sClient.Create(context.TODO(), kustomization)).To(Succeed())

	g.Eventually(func() bool {
		var obj kustomizev1.Kustomization
		_ = k8sClient.Get(context.Background(), client.ObjectKeyFromObject(kustomization), &obj)
		return obj.Status.LastAppliedRevision == "main/"+artifactChecksum
	}, timeout, time.Second).Should(BeTrue())

	overlayKustomizationName := fmt.Sprintf("sops-%s", randStringRunes(5))
	overlayKs := kustomization.DeepCopy()
	overlayKs.ResourceVersion = ""
	overlayKs.Name = overlayKustomizationName
	overlayKs.Spec.SourceRef.Name = overlayRepositoryName.Name
	overlayKs.Spec.SourceRef.Namespace = overlayRepositoryName.Namespace
	overlayKs.Spec.Path = "./testdata/test-dotenv/overlays"

	g.Expect(k8sClient.Create(context.TODO(), overlayKs)).To(Succeed())

	g.Eventually(func() bool {
		var obj kustomizev1.Kustomization
		_ = k8sClient.Get(context.Background(), client.ObjectKeyFromObject(overlayKs), &obj)
		return obj.Status.LastAppliedRevision == "main/"+overlayChecksum
	}, timeout, time.Second).Should(BeTrue())

	t.Run("decrypts SOPS secrets", func(t *testing.T) {
		var pgpSecret corev1.Secret
		g.Expect(k8sClient.Get(context.TODO(), types.NamespacedName{Name: "sops-pgp", Namespace: id}, &pgpSecret)).To(Succeed())
		g.Expect(pgpSecret.Data["secret"]).To(Equal([]byte(`my-sops-pgp-secret`)))

		var ageSecret corev1.Secret
		g.Expect(k8sClient.Get(context.TODO(), types.NamespacedName{Name: "sops-age", Namespace: id}, &ageSecret)).To(Succeed())
		g.Expect(ageSecret.Data["secret"]).To(Equal([]byte(`my-sops-age-secret`)))

		var daySecret corev1.Secret
		g.Expect(k8sClient.Get(context.TODO(), types.NamespacedName{Name: "sops-day", Namespace: id}, &daySecret)).To(Succeed())
		g.Expect(string(daySecret.Data["secret"])).To(Equal("day=Tuesday\n"))

		var yearSecret corev1.Secret
		g.Expect(k8sClient.Get(context.TODO(), types.NamespacedName{Name: "sops-year", Namespace: id}, &yearSecret)).To(Succeed())
		g.Expect(string(yearSecret.Data["year"])).To(Equal("2017"))

		var unencryptedSecret corev1.Secret
		g.Expect(k8sClient.Get(context.TODO(), types.NamespacedName{Name: "unencrypted-sops-year", Namespace: id}, &unencryptedSecret)).To(Succeed())
		g.Expect(string(unencryptedSecret.Data["year"])).To(Equal("2021"))

		var year1Secret corev1.Secret
		g.Expect(k8sClient.Get(context.TODO(), types.NamespacedName{Name: "sops-year1", Namespace: id}, &year1Secret)).To(Succeed())
		g.Expect(string(year1Secret.Data["year"])).To(Equal("year1"))

		var year2Secret corev1.Secret
		g.Expect(k8sClient.Get(context.TODO(), types.NamespacedName{Name: "sops-year2", Namespace: id}, &year2Secret)).To(Succeed())
		g.Expect(string(year2Secret.Data["year"])).To(Equal("year2"))

		var encodedSecret corev1.Secret
		g.Expect(k8sClient.Get(context.TODO(), types.NamespacedName{Name: "sops-month", Namespace: id}, &encodedSecret)).To(Succeed())
		g.Expect(string(encodedSecret.Data["month.yaml"])).To(Equal("month: May\n"))

		var hcvaultSecret corev1.Secret
		g.Expect(k8sClient.Get(context.TODO(), types.NamespacedName{Name: "sops-hcvault", Namespace: id}, &hcvaultSecret)).To(Succeed())
		g.Expect(string(hcvaultSecret.Data["secret"])).To(Equal("my-sops-vault-secret\n"))
	})

	t.Run("does not emit change events for identical secrets", func(t *testing.T) {
		resultK := &kustomizev1.Kustomization{}
		revision := "v2.0.0"
		err = applyGitRepository(repositoryName, artifactName, revision)
		g.Expect(err).NotTo(HaveOccurred())

		g.Eventually(func() bool {
			_ = k8sClient.Get(context.Background(), client.ObjectKeyFromObject(kustomization), resultK)
			return resultK.Status.LastAttemptedRevision == revision
		}, timeout, time.Second).Should(BeTrue())

		events := getEvents(resultK.GetName(), map[string]string{"kustomize.toolkit.fluxcd.io/revision": revision})
		g.Expect(len(events)).To(BeIdenticalTo(1))
		g.Expect(events[0].Message).Should(ContainSubstring("Reconciliation finished"))
		g.Expect(events[0].Message).ShouldNot(ContainSubstring("configured"))
	})
}

func TestKustomizeDecryptor_ImportKeys(t *testing.T) {
	g := NewWithT(t)

	const provider = "sops"

	pgpKey, err := os.ReadFile("testdata/sops/pgp.asc")
	g.Expect(err).ToNot(HaveOccurred())
	ageKey, err := os.ReadFile("testdata/sops/age.txt")
	g.Expect(err).ToNot(HaveOccurred())

	tests := []struct {
		name        string
		decryption  *kustomizev1.Decryption
		secret      *corev1.Secret
		wantErr     bool
		inspectFunc func(g *GomegaWithT, decryptor *KustomizeDecryptor)
	}{
		{
			name: "PGP key",
			decryption: &kustomizev1.Decryption{
				Provider: provider,
				SecretRef: &meta.LocalObjectReference{
					Name: "pgp-secret",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pgp-secret",
					Namespace: provider,
				},
				Data: map[string][]byte{
					"pgp" + DecryptionPGPExt: pgpKey,
				},
			},
		},
		{
			name: "PGP key import error",
			decryption: &kustomizev1.Decryption{
				Provider: provider,
				SecretRef: &meta.LocalObjectReference{
					Name: "pgp-secret",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pgp-secret",
					Namespace: provider,
				},
				Data: map[string][]byte{
					"pgp" + DecryptionPGPExt: []byte("not-a-valid-armored-key"),
				},
			},
			wantErr: true,
		},
		{
			name: "age key",
			decryption: &kustomizev1.Decryption{
				Provider: provider,
				SecretRef: &meta.LocalObjectReference{
					Name: "age-secret",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "age-secret",
					Namespace: provider,
				},
				Data: map[string][]byte{
					"age" + DecryptionAgeExt: ageKey,
				},
			},
			inspectFunc: func(g *GomegaWithT, decryptor *KustomizeDecryptor) {
				g.Expect(decryptor.ageIdentities).To(HaveLen(1))
			},
		},
		{
			name: "age key import error",
			decryption: &kustomizev1.Decryption{
				Provider: provider,
				SecretRef: &meta.LocalObjectReference{
					Name: "age-secret",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "age-secret",
					Namespace: provider,
				},
				Data: map[string][]byte{
					"age" + DecryptionAgeExt: []byte("not-a-valid-key"),
				},
			},
			wantErr: true,
			inspectFunc: func(g *GomegaWithT, decryptor *KustomizeDecryptor) {
				g.Expect(decryptor.ageIdentities).To(HaveLen(0))
			},
		},
		{
			name: "HC Vault token",
			decryption: &kustomizev1.Decryption{
				Provider: provider,
				SecretRef: &meta.LocalObjectReference{
					Name: "hcvault-secret",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "hcvault-secret",
					Namespace: provider,
				},
				Data: map[string][]byte{
					DecryptionVaultTokenFileName: []byte("some-hcvault-token"),
				},
			},
			inspectFunc: func(g *GomegaWithT, decryptor *KustomizeDecryptor) {
				g.Expect(decryptor.vaultToken).To(Equal("some-hcvault-token"))
			},
		},
		{
			name: "Azure Key Vault token",
			decryption: &kustomizev1.Decryption{
				Provider: provider,
				SecretRef: &meta.LocalObjectReference{
					Name: "azkv-secret",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "azkv-secret",
					Namespace: provider,
				},
				Data: map[string][]byte{
					DecryptionAzureAuthFile: []byte(`tenantId: some-tenant-id
clientId: some-client-id
clientSecret: some-client-secret`),
				},
			},
			inspectFunc: func(g *GomegaWithT, decryptor *KustomizeDecryptor) {
				g.Expect(decryptor.azureToken).ToNot(BeNil())
			},
		},
		{
			name: "Azure Key Vault token load config error",
			decryption: &kustomizev1.Decryption{
				Provider: provider,
				SecretRef: &meta.LocalObjectReference{
					Name: "azkv-secret",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "azkv-secret",
					Namespace: provider,
				},
				Data: map[string][]byte{
					DecryptionAzureAuthFile: []byte(`{"malformed\: JSON"}`),
				},
			},
			wantErr: true,
			inspectFunc: func(g *GomegaWithT, decryptor *KustomizeDecryptor) {
				g.Expect(decryptor.azureToken).To(BeNil())
			},
		},
		{
			name: "Azure Key Vault unsupported config",
			decryption: &kustomizev1.Decryption{
				Provider: provider,
				SecretRef: &meta.LocalObjectReference{
					Name: "azkv-secret",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "azkv-secret",
					Namespace: provider,
				},
				Data: map[string][]byte{
					DecryptionAzureAuthFile: []byte(`tenantId: incomplete`),
				},
			},
			wantErr: true,
			inspectFunc: func(g *GomegaWithT, decryptor *KustomizeDecryptor) {
				g.Expect(decryptor.azureToken).To(BeNil())
			},
		},
		{
			name: "multiple Secret data entries",
			decryption: &kustomizev1.Decryption{
				Provider: provider,
				SecretRef: &meta.LocalObjectReference{
					Name: "multiple-secret",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "multiple-secret",
					Namespace: provider,
				},
				Data: map[string][]byte{
					"age" + DecryptionAgeExt:     ageKey,
					DecryptionVaultTokenFileName: []byte("some-hcvault-token"),
				},
			},
			inspectFunc: func(g *GomegaWithT, decryptor *KustomizeDecryptor) {
				g.Expect(decryptor.vaultToken).ToNot(BeEmpty())
				g.Expect(decryptor.ageIdentities).To(HaveLen(1))
			},
		},
		{
			name:       "no Decryption spec",
			decryption: nil,
			wantErr:    false,
		},
		{
			name: "no Decryption Secret",
			decryption: &kustomizev1.Decryption{
				Provider: DecryptionProviderSOPS,
			},
			wantErr: false,
		},
		{
			name: "non-existing Decryption Secret",
			decryption: &kustomizev1.Decryption{
				Provider: DecryptionProviderSOPS,
				SecretRef: &meta.LocalObjectReference{
					Name: "does-not-exist",
				},
			},
			wantErr: true,
		},
		{
			name: "unimplemented Decryption Provider",
			decryption: &kustomizev1.Decryption{
				Provider: "not-supported",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			cb := fake.NewClientBuilder()
			if tt.secret != nil {
				cb.WithObjects(tt.secret)
			}
			kustomization := kustomizev1.Kustomization{
				ObjectMeta: metav1.ObjectMeta{
					Name:      provider + "-" + tt.name,
					Namespace: provider,
				},
				Spec: kustomizev1.KustomizationSpec{
					Interval:   metav1.Duration{Duration: 2 * time.Minute},
					Path:       "./",
					Decryption: tt.decryption,
				},
			}

			kd, cleanup, err := NewTempDecryptor("", cb.Build(), kustomization)
			g.Expect(err).ToNot(HaveOccurred())
			t.Cleanup(cleanup)

			match := Succeed()
			if tt.wantErr {
				match = HaveOccurred()
			}
			g.Expect(kd.ImportKeys(context.TODO())).To(match)

			if tt.inspectFunc != nil {
				tt.inspectFunc(g, kd)
			}
		})
	}
}

func TestKustomizeDecryptor_DecryptResource(t *testing.T) {
	var (
		resourceFactory = provider.NewDefaultDepProvider().GetResourceFactory()

		emptyResource = resourceFactory.FromMap(map[string]interface{}{})
	)

	tests := []struct {
		name                   string
		decryption             *kustomizev1.Decryption
		configureDecryptorFunc func(g *GomegaWithT, decryptor *KustomizeDecryptor)
		resource               *resource.Resource
		wantResource           *resource.Resource
		inspectFunc            func(g *GomegaWithT, decryptor *KustomizeDecryptor)
	}{
		{
			name:         "no Decryption spec",
			decryption:   nil,
			resource:     emptyResource.DeepCopy(),
			wantResource: nil,
		},
		{
			name: "unimplemented Decryption Provider",
			decryption: &kustomizev1.Decryption{
				Provider: "not-supported",
			},
			resource:     emptyResource.DeepCopy(),
			wantResource: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			kustomization := kustomizev1.Kustomization{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "decrypt-" + tt.name,
					Namespace: "decrypt",
				},
				Spec: kustomizev1.KustomizationSpec{
					Interval:   metav1.Duration{Duration: 2 * time.Minute},
					Path:       "./",
					Decryption: tt.decryption,
				},
			}

			kd, cleanup, err := NewTempDecryptor("", fake.NewClientBuilder().Build(), kustomization)
			g.Expect(err).ToNot(HaveOccurred())
			t.Cleanup(cleanup)

			if tt.configureDecryptorFunc != nil {
				tt.configureDecryptorFunc(g, kd)
			}

			g.Expect(kd.DecryptResource(tt.resource)).To(Equal(tt.wantResource))

			if tt.inspectFunc != nil {
				tt.inspectFunc(g, kd)
			}
		})
	}
}
