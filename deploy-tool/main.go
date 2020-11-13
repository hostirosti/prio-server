package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"os/exec"
	"time"

	_ "github.com/abetterinternet/prio-server/deploy-tool/cert"
	"github.com/abetterinternet/prio-server/deploy-tool/config"
)

// TestPHADecryptionKey is a libprio-rs encoded ECIES private key. It MUST match
// the constant DEFAULT_PHA_ECIES_PRIVATE_KEY in facilitator/src/test_utils.rs.
// It is present here so that a test environment can be configured to use
// predictable keys for packet decryption.
const TestPHADecryptionKey = "BIl6j+J6dYttxALdjISDv6ZI4/VWVEhUzaS05Lg" +
	"rsfswmbLOgNt9HUC2E0w+9RqZx3XMkdEHBHfNuCSMpOwofVSq3TfyKwn0NrftKisKKVSaTOt5" +
	"seJ67P5QL4hxgPWvxw=="

// This tool consumes the output of `terraform apply`, generating keys and then
// populating specific manifests and Kubernetes secrets with appropriate values.
// We do this in this tool because if we generated secrets via Terraform
// resources, the secret values would appear in the Terraform state file. The
// struct definitions here MUST be kept in sync with the output variable in
// terraform/modules/facilitator/facilitator.tf and the corresponding structs in
// facilitator/src/manifest.rs.

// BatchSigningPublicKey represents a public key used for batch signing.
type BatchSigningPublicKey struct {
	// PublicKey is the PEM armored base64 encoding of the ASN.1 encoding of the
	// PKIX SubjectPublicKeyInfo structure. It must be a P-256 key.
	PublicKey string `json:"public-key"`
	// Expiration is the ISO 8601 encoded UTC date at which this key expires.
	Expiration string `json:"expiration"`
}

// PacketEncryptionCertificate represents a certificate containing a public key
// used for packet encryption.
type PacketEncryptionCertificate struct {
	// Certificate is the PEM armored X.509 certificate.
	Certificate string `json:"certificate"`
}

// SpecificManifest represents the manifest file advertised by a data share
// processor. See the design document for the full specification.
// https://docs.google.com/document/d/1MdfM3QT63ISU70l63bwzTrxr93Z7Tv7EDjLfammzo6Q/edit#heading=h.3j8dgxqo5h68
type SpecificManifest struct {
	// Format is the version of the manifest.
	Format int64 `json:"format"`
	// IngestionBucket is the region+name of the bucket that the data share
	// processor which owns the manifest reads ingestion batches from.
	IngestionBucket string `json:"ingestion-bucket"`
	// IngestionIdentity is the ARN of the AWS IAM role that should be assumed
	// by an ingestion server to write to this data share processor's ingestion
	// bucket, if the ingestor does not have an AWS account of their own.
	IngestionIdentity string `json:"ingestion-identity"`
	// PeerValidationBucket is the region+name of the bucket that the data share
	// processor which owns the manifest reads peer validation batches from.
	PeerValidationBucket string `json:"peer-validation-bucket"`
	// BatchSigningPublicKeys maps key identifiers to batch signing public keys.
	// These are the keys that peers reading batches emitted by this data share
	// processor use to verify signatures.
	BatchSigningPublicKeys map[string]BatchSigningPublicKey `json:"batch-signing-public-keys"`
	// PacketEncryptionCertificates maps key identifiers to packet encryption
	// certificates. The values are PEM encoded X.509 certificates, which
	// contain the public key corresponding to the private key that the data
	// share processor which owns the manifest uses to decrypt ingestion share
	// packets.
	PacketEncryptionCertificates map[string]PacketEncryptionCertificate `json:"packet-encryption-certificates"`
}

// TerraformOutput represents the JSON output from `terraform apply` or
// `terraform output --json`. This struct must match the output variables
// defined in terraform/main.tf, though it only need describe the output
// variables this program is interested in.
type TerraformOutput struct {
	ManifestBucket struct {
		Value string
	} `json:"manifest_bucket"`
	SpecificManifests struct {
		Value map[string]struct {
			KubernetesNamespace string           `json:"kubernetes-namespace"`
			CertificateFQDN     string           `json:"certificate-fqdn"`
			SpecificManifest    SpecificManifest `json:"specific-manifest"`
		}
	} `json:"specific_manifests"`
	UseTestPHADecryptionKey struct {
		Value bool
	} `json:"use_test_pha_decryption_key"`
}

type privateKeyMarshaler func(*ecdsa.PrivateKey) ([]byte, error)

// marshalX962UncompressedPrivateKey encodes a P-256 private key into the format
// expected by libprio-rs encrypt::PrivateKey, which is the X9.62 uncompressed
// public key concatenated with the secret scalar.
func marshalX962UncompressedPrivateKey(ecdsaKey *ecdsa.PrivateKey) ([]byte, error) {
	marshaledPublicKey := elliptic.Marshal(elliptic.P256(), ecdsaKey.PublicKey.X, ecdsaKey.PublicKey.Y)
	return append(marshaledPublicKey, ecdsaKey.D.Bytes()...), nil
}

// marshalPKCS8PrivateKey encodes a P-256 private key into a PKCS#8 document.
// This function adapts x509.MarshalPKCS8PrivateKey to the privateKeyMarshaler
// type.
func marshalPKCS8PrivateKey(ecdsaKey *ecdsa.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(ecdsaKey)
}

// marshalTestPHADecryptionKey ignores the provided key and returns the
// default PHA decryption key in the same format as
// marshalX962UncompressedPrivateKey. This is intended for test environments so
// they can use predictable keys.
func marshalTestPHADecryptionKey(ecdsaKey *ecdsa.PrivateKey) ([]byte, error) {
	return base64.StdEncoding.DecodeString(TestPHADecryptionKey)
}

// generateAndDeployKeyPair generates a P-256 key pair and stores the base64
// encoded PKCS#8 encoding of that key in a Kubernetes secret with the provided
// keyName, in the provided namespace. Returns the private key so the caller may
// use it to populate specific manifests.
func generateAndDeployKeyPair(namespace, keyName string, keyMarshaler privateKeyMarshaler) (*ecdsa.PrivateKey, error) {
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate P-256 key: %w", err)
	}

	marshaledPrivateKey, err := keyMarshaler(p256Key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key to PKCS#8 document: %w", err)
	}

	// Put the private keys into Kubernetes secrets. There's no straightforward
	// way to update a secret value using kubectl, so we use the trick from[1].
	// There's no particular reason to use `-o=json` but we must set some output
	// format or nothing is written to stdout.
	// [1] https://blog.atomist.com/updating-a-kubernetes-secret-or-configmap/
	//
	// We can't provide the base64 encoding of the key to --from-literal because
	// then kubectl would base64 the base64, so we have to write the b64 to a
	// temp file and then provide that to --from-file.
	log.Printf("updating Kubernetes secret %s/%s", namespace, keyName)
	tempFile, err := ioutil.TempFile("", "pkcs8-private-key-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	defer tempFile.Close()
	defer os.Remove(tempFile.Name())

	base64PrivateKey := base64.StdEncoding.EncodeToString(marshaledPrivateKey)
	if err := ioutil.WriteFile(tempFile.Name(), []byte(base64PrivateKey), 0600); err != nil {
		return nil, fmt.Errorf("failed to write out PKCS#8 private key: %v", err)
	}

	secretArgument := fmt.Sprintf("--from-file=secret_key=%s", tempFile.Name())
	kubectlCreate := exec.Command("kubectl", "-n", namespace, "create",
		"secret", "generic", keyName, secretArgument, "--dry-run=client", "-o=json")
	kubectlApply := exec.Command("kubectl", "apply", "-f", "-")
	read, write := io.Pipe()
	kubectlApply.Stdin = read
	kubectlCreate.Stdout = write

	// Do this async because if we don't close `kubectl create`'s stdout,
	// `kubectl apply` will never make progress.
	go func() {
		defer write.Close()
		if err := kubectlCreate.Run(); err != nil {
			log.Fatalf("failed to run kubectl create: %v", err)
		}
	}()

	if output, err := kubectlApply.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to run kubectl apply: %v\nCombined output: %s", err, output)
	}

	return p256Key, nil
}

// getConfigFilePath gets the configuration file path from the DEPLOY_CONFIG_PATH environment variable.
// this function defaults to ./config.toml if that env variable is empty.
func getConfigFilePath() string {
	val, exists := os.LookupEnv("DEPLOY_CONFIG_PATH")
	if !exists {
		return "./config.toml"
	}
	return val
}

func main() {
	_, err := config.Read(getConfigFilePath())
	if err != nil {
		log.Fatalf("failed to parse config.toml: %v", err)
	}

	var terraformOutput TerraformOutput

	if err := json.NewDecoder(os.Stdin).Decode(&terraformOutput); err != nil {
		log.Fatalf("failed to parse specific manifests: %v", err)
	}

	// 	rootPrivateKeyPem := []byte(`
	// -----BEGIN PRIVATE KEY-----
	// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgobBK2mNUb+Th+LPp
	// 3QPst1AI473ZVqYFuHGxTXzM/LqhRANCAATcY6HLr0i1fOo14bVbeU9skB3V3E03
	// 1QYcV6i2igZt8Lmsq99LUYtAx2a9UbtM3Lv0SgsBp3BpiY4iq/GppSBh
	// -----END PRIVATE KEY-----
	// `)

	// 	rootCertificatePEM := []byte(`
	// -----BEGIN CERTIFICATE-----
	// MIIBZTCCAQqgAwIBAgIQdKvyQQeQOXCIGmjEN6JmgTAKBggqhkjOPQQDAjAZMRcw
	// FQYDVQQDEw5GYWtlIHJvb3QgY2VydDAeFw0xOTExMTQyMTAyMjBaFw0yMTExMTMy
	// MTAyMjBaMBkxFzAVBgNVBAMTDkZha2Ugcm9vdCBjZXJ0MFkwEwYHKoZIzj0CAQYI
	// KoZIzj0DAQcDQgAE3GOhy69ItXzqNeG1W3lPbJAd1dxNN9UGHFeotooGbfC5rKvf
	// S1GLQMdmvVG7TNy79EoLAadwaYmOIqvxqaUgYaM0MDIwDgYDVR0PAQH/BAQDAgEG
	// MA8GA1UdEwEB/wQFMAMBAf8wDwYDVR0OBAgEBgECAwQFBjAKBggqhkjOPQQDAgNJ
	// ADBGAiEA6PFEs30r4+FVkhMYv5MrDJ/PrrxZSuofxg+SMJUe4dcCIQCjTHjspOw4
	// +yxqu6qqoil9cYCsrJxcAWc7j6w1EDoOxA==
	// -----END CERTIFICATE-----

	intermediatePrivateKeyPEM := []byte(`
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg6SD5JpzgPdj8cD9s
/Oq/0zsyF/Oztry+DoZIGX8AWtihRANCAARDTSXSluzGh9UJZCenshEnHigGlnAA
QB73md4N4xkNo8Db5tzem1FK8q768sgoYKnOM72Ezg0NP5YmpMH5VqhW
-----END PRIVATE KEY-----
`)

	intermediatePrivateKeyBlock, _ := pem.Decode(intermediatePrivateKeyPEM)
	if intermediatePrivateKeyBlock == nil || intermediatePrivateKeyBlock.Type != "PRIVATE KEY" {
		log.Fatal("failed to parse PEM intermediate private key")
	}

	intermediatePrivateKey, err := x509.ParsePKCS8PrivateKey(intermediatePrivateKeyBlock.Bytes)
	if err != nil {
		log.Fatalf("failed to parse DER intermediate private key: %s", err)
	}

	intermediateCertificatePEM := []byte(`
-----BEGIN CERTIFICATE-----
MIIBgjCCASmgAwIBAgIRAO5mrlkXz2jzw9hw1BqtdIMwCgYIKoZIzj0EAwIwGTEX
MBUGA1UEAxMORmFrZSByb290IGNlcnQwHhcNMTkxMTE0MjEwMjIwWhcNMjExMTEz
MjEwMjIwWjAhMR8wHQYDVQQDExZGYWtlIGludGVybWVkaWF0ZSBjZXJ0MFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEQ00l0pbsxofVCWQnp7IRJx4oBpZwAEAe95ne
DeMZDaPA2+bc3ptRSvKu+vLIKGCpzjO9hM4NDT+WJqTB+VaoVqNKMEgwDgYDVR0P
AQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwDwYDVR0OBAgEBgcICQoLDDAR
BgNVHSMECjAIgAYBAgMEBQYwCgYIKoZIzj0EAwIDRwAwRAIgLUZei8554YPf9hmy
8csOQ2r2zmx3VE0AcKe7qPVaHrICIHpscgtZ3zkrgOPcCoTMxHNSfLN2wM4iEsSz
9k5RMpgB
-----END CERTIFICATE-----
`)

	intermediateCertificateBlock, _ := pem.Decode(intermediateCertificatePEM)
	if intermediateCertificateBlock == nil || intermediateCertificateBlock.Type != "CERTIFICATE" {
		log.Fatal("failed to parse PEM intermediate certificate")
	}

	intermediateCertificate, err := x509.ParseCertificate(intermediateCertificateBlock.Bytes)
	if err != nil {
		log.Fatalf("failed to parse DER intermediate certificate: %s", err)
	}

	keyUsage := x509.KeyUsageDigitalSignature
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	certificatesByNamespace := map[string]PacketEncryptionCertificate{}

	for dataShareProcessorName, manifestWrapper := range terraformOutput.SpecificManifests.Value {
		newBatchSigningPublicKeys := map[string]BatchSigningPublicKey{}
		for name, batchSigningPublicKey := range manifestWrapper.SpecificManifest.BatchSigningPublicKeys {
			if batchSigningPublicKey.PublicKey != "" {
				newBatchSigningPublicKeys[name] = batchSigningPublicKey
				continue
			}
			log.Printf("generating ECDSA P256 key %s", name)
			privateKey, err := generateAndDeployKeyPair(manifestWrapper.KubernetesNamespace, name, marshalPKCS8PrivateKey)
			if err != nil {
				log.Fatalf("%s", err)
			}

			pkixPublic, err := x509.MarshalPKIXPublicKey(privateKey.Public())
			if err != nil {
				log.Fatalf("failed to marshal ECDSA public key to PKIX: %v", err)
			}

			block := pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: pkixPublic,
			}

			expiration := time.
				Now().
				AddDate(0, 0, 90). // key expires in 90 days
				UTC().
				Format(time.RFC3339)
			newBatchSigningPublicKeys[name] = BatchSigningPublicKey{
				PublicKey:  string(pem.EncodeToMemory(&block)),
				Expiration: expiration,
			}
		}

		manifestWrapper.SpecificManifest.BatchSigningPublicKeys = newBatchSigningPublicKeys

		newCertificates := map[string]PacketEncryptionCertificate{}
		for name, packetEncryptionCertificate := range manifestWrapper.SpecificManifest.PacketEncryptionCertificates {
			if packetEncryptionCertificate.Certificate != "" {
				newCertificates[name] = packetEncryptionCertificate
				continue
			}

			// Packet encryption keys are shared among the data share processors
			// in a namespace, so avoid creating and certifying the key twice
			if certificate, ok := certificatesByNamespace[manifestWrapper.KubernetesNamespace]; ok {
				newCertificates[name] = certificate
				continue
			}

			log.Printf("generating and certifying P256 key %s", name)
			keyMarshaler := marshalX962UncompressedPrivateKey
			if terraformOutput.UseTestPHADecryptionKey.Value {
				// If we are configuring a special test environment, we populate
				// Kubernetes secrets with a fixed packet decryption key. This
				// means that the public key in the certificate in the manifest
				// won't match the actual packet decryption key, but in this
				// test setup, nothing currently consults those certificates.
				keyMarshaler = marshalTestPHADecryptionKey
			}
			privKey, err := generateAndDeployKeyPair(manifestWrapper.KubernetesNamespace, name, keyMarshaler)
			if err != nil {
				log.Fatalf("%s", err)
			}

			leafSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
			if err != nil {
				log.Fatalf("failed to generate serial number for leaf: %v", err)
			}

			leafTemplate := x509.Certificate{
				SerialNumber: leafSerialNumber,
				Subject: pkix.Name{
					Organization: []string{"Fake leaf cert"},
				},
				DNSNames:              []string{manifestWrapper.CertificateFQDN},
				NotBefore:             notBefore,
				NotAfter:              notAfter,
				KeyUsage:              keyUsage,
				IsCA:                  false,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
			}

			leafCertDerBytes, err := x509.CreateCertificate(rand.Reader, &leafTemplate, intermediateCertificate, &privKey.PublicKey, intermediatePrivateKey)
			if err != nil {
				log.Fatalf("failed to create fake leaf certificate: %v", err)
			}

			leafCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCertDerBytes})

			certificate := fmt.Sprintf("%s%s", leafCertPEM, intermediateCertificatePEM)

			packetEncryptionCertificate := PacketEncryptionCertificate{Certificate: certificate}

			certificatesByNamespace[manifestWrapper.KubernetesNamespace] = packetEncryptionCertificate
			newCertificates[name] = packetEncryptionCertificate
		}

		manifestWrapper.SpecificManifest.PacketEncryptionCertificates = newCertificates

		// Put the specific manifests into the manifest bucket. Users of this
		// tool already need to have gsutil and valid Google Cloud credentials
		// to be able to use the Makefile, so execing out to gsutil saves us the
		// trouble of pulling in the gcloud SDK.
		destination := fmt.Sprintf("gs://%s/%s-manifest.json",
			terraformOutput.ManifestBucket.Value, dataShareProcessorName)
		log.Printf("uploading specific manifest %s", destination)
		gsutil := exec.Command("gsutil",
			"-h", "Content-Type:application/json",
			"-h", "Cache-Control:no-cache",
			"cp", "-", destination)
		stdin, err := gsutil.StdinPipe()
		if err != nil {
			log.Fatalf("could not get pipe to gsutil stdin: %v", err)
		}

		// Do this async because if we don't close gsutil's stdin, it will
		// never be able to get started.
		go func() {
			defer stdin.Close()
			log.Printf("uploading manifest %+v", manifestWrapper.SpecificManifest)
			manifestEncoder := json.NewEncoder(stdin)
			if err := manifestEncoder.Encode(manifestWrapper.SpecificManifest); err != nil {
				log.Fatalf("failed to encode manifest into gsutil stdin: %v", err)
			}
		}()

		if output, err := gsutil.CombinedOutput(); err != nil {
			log.Fatalf("gsutil failed: %v\noutput: %s", err, output)
		}
	}
}
