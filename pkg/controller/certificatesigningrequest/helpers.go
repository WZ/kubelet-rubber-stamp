package certificatesigningrequest

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"reflect"
	"os"
	"strings"

	capi "k8s.io/api/certificates/v1beta1"
)

const (
	CSRCommonNameEnvVar = "WATCH_CSR_COMMON_NAME"
    DefaultCSRCommonName = "node"
	CSROrgEnvVar = "WATCH_CSR_ORG"
	DefaultCSROrg = "system:nodes"
)

func getCertApprovalCondition(status *capi.CertificateSigningRequestStatus) (approved bool, denied bool) {
	for _, c := range status.Conditions {
		if c.Type == capi.CertificateApproved {
			approved = true
		}
		if c.Type == capi.CertificateDenied {
			denied = true
		}
	}
	return
}

func isApproved(csr *capi.CertificateSigningRequest) bool {
	approved, denied := getCertApprovalCondition(&csr.Status)
	return approved && !denied
}

// parseCSR extracts the CSR from the API object and decodes it.
func parseCSR(obj *capi.CertificateSigningRequest) (*x509.CertificateRequest, error) {
	// extract PEM from request object
	pemBytes := obj.Spec.Request
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("PEM block type must be CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	return csr, nil
}

// func hasExactUsages(csr *capi.CertificateSigningRequest, usages []capi.KeyUsage) bool {
// 	if len(usages) != len(csr.Spec.Usages) {
// 		return false
// 	}

// 	usageMap := map[capi.KeyUsage]struct{}{}
// 	for _, u := range usages {
// 		usageMap[u] = struct{}{}
// 	}

// 	for _, u := range csr.Spec.Usages {
// 		if _, ok := usageMap[u]; !ok {
// 			return false
// 		}
// 	}

// 	return true
// }

// var kubeletServerUsages = []capi.KeyUsage{
// 	capi.UsageKeyEncipherment,
// 	capi.UsageDigitalSignature,
// 	capi.UsageServerAuth,
// }

func isNodeServingCert(csr *capi.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool {
	if !reflect.DeepEqual([]string{GetCSROrgName()}, x509cr.Subject.Organization) {
		log.Printf("Org does not match: %s\n", x509cr.Subject.Organization)
		return false
	}
	// if (len(x509cr.DNSNames) < 1) || (len(x509cr.IPAddresses) < 1) {
	// 	log.Printf("dns names size and IP Addresses must be greater than 1\n")
	// 	return false
	// }
	// if !hasExactUsages(csr, kubeletServerUsages) {
	// 	log.Println("Usage does not match")
	// 	return false
	// }
	commonNames := strings.Split(GetCSRCommonName(), ",")
	commonNamesMap := make(map[string]bool)
	for _, commonName := range commonNames {
		commonNamesMap[strings.TrimSpace(commonName)] = true
	}
	if !commonNamesMap[x509cr.Subject.CommonName] {
		log.Printf("CN does not match: %s\n", x509cr.Subject.CommonName)
		return false
	}
	return true
}

func GetCSROrgName() (string) {
	csrOrgName, found := os.LookupEnv(CSROrgEnvVar)
	if !found {
		return DefaultCSROrg
	}
	if len(csrOrgName) == 0 {
		return DefaultCSROrg
	}
	return csrOrgName
}

func GetCSRCommonName() (string) {
	csrCommonName, found := os.LookupEnv(CSRCommonNameEnvVar)
	if !found {
		return DefaultCSRCommonName
	}
	if len(csrCommonName) == 0 {
		return DefaultCSRCommonName
	}
	return csrCommonName
}
