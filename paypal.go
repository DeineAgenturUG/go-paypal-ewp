package Ewp

import (
	"crypto/x509"
	"crypto/rsa"
	"encoding/pem"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"reflect"
	"strings"
	"strconv"

	"github.com/DeineAgenturUG/pkcs7"
)

const tagName = "ppewp"

const ppCertPEM = `live_api
-----BEGIN CERTIFICATE-----
MIIDgzCCAuygAwIBAgIBADANBgkqhkiG9w0BAQUFADCBjjELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRQwEgYDVQQKEwtQ
YXlQYWwgSW5jLjETMBEGA1UECxQKbGl2ZV9jZXJ0czERMA8GA1UEAxQIbGl2ZV9h
cGkxHDAaBgkqhkiG9w0BCQEWDXJlQHBheXBhbC5jb20wHhcNMDQwMjEzMTAxMzE1
WhcNMzUwMjEzMTAxMzE1WjCBjjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYw
FAYDVQQHEw1Nb3VudGFpbiBWaWV3MRQwEgYDVQQKEwtQYXlQYWwgSW5jLjETMBEG
A1UECxQKbGl2ZV9jZXJ0czERMA8GA1UEAxQIbGl2ZV9hcGkxHDAaBgkqhkiG9w0B
CQEWDXJlQHBheXBhbC5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMFH
Tt38RMxLXJyO2SmS+Ndl72T7oKJ4u4uw+6awntALWh03PewmIJuzbALScsTS4sZo
S1fKciBGoh11gIfHzylvkdNe/hJl66/RGqrj5rFb08sAABNTzDTiqqNpJeBsYs/c
2aiGozptX2RlnBktH+SUNpAajW724Nv2Wvhif6sFAgMBAAGjge4wgeswHQYDVR0O
BBYEFJaffLvGbxe9WT9S1wob7BDWZJRrMIG7BgNVHSMEgbMwgbCAFJaffLvGbxe9
WT9S1wob7BDWZJRroYGUpIGRMIGOMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0Ex
FjAUBgNVBAcTDU1vdW50YWluIFZpZXcxFDASBgNVBAoTC1BheVBhbCBJbmMuMRMw
EQYDVQQLFApsaXZlX2NlcnRzMREwDwYDVQQDFAhsaXZlX2FwaTEcMBoGCSqGSIb3
DQEJARYNcmVAcGF5cGFsLmNvbYIBADAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEB
BQUAA4GBAIFfOlaagFrl71+jq6OKidbWFSE+Q4FqROvdgIONth+8kSK//Y/4ihuE
4Ymvzn5ceE3S/iBSQQMjyvb+s2TWbQYDwcp129OPIbD9epdr4tJOUNiSojw7BHwY
RiPh58S1xGlFgHFXwrEBb3dgNbMUa+u4qectsMAXpVHnD9wIyfmH
-----END CERTIFICATE-----`

var ppCert *x509.Certificate

func init() {
	block, _ := pem.Decode([]byte(ppCertPEM))
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	var err error
	ppCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

}

type CryptData struct {
	Cmd             string  `ppewp:"name:cmd;type:string;default:_xclick"`       // cmd = '_xclick',
	Business        string  `ppewp:"name:business;type:string"`                  // business = 'mein@paypalaccount.de',
	ItemName        string  `ppewp:"name:item_name;type:string"`                 //Test Gegenstand', // Name der Bestellung
	ItemNumber      string  `ppewp:"name:item_number;type:string"`               // OderID or ItemID
	Amount          float64 `ppewp:"name:amount;type:float64"`                   //00.01', // Wert
	ReturnUrl       string  `ppewp:"name:return;type:string;omitempty"`          //http://www.beispiel.de/paypal_ok.php', // URL fuer erfolgreiche Zahlung
	ReturnUrlCancel string  `ppewp:"name:cancel_return;type:string;omitempty"`   //http://www.beispiel.de/paypal_cancel.php', // URL fuer Zahlungsabbruch
	NotifyUrl       string  `ppewp:"name:notify_url;type:string;omitempty"`      //',
	NoNote          int     `ppewp:"name:no_note;type:string;default:0"`         //1', // Keine Notizen vom Kauefer moeglich
	NoShipping      int     `ppewp:"name:no_shipping;type:string;default:0"`     //1',
	CurrencyCode    string  `ppewp:"name:currency_code;type:string;default:USD"` //EUR',
	Lc              string  `ppewp:"name:lc;type:string;omitempty"`              //DE',
	Rm              int     `ppewp:"name:rm;type:string;default:0"`              //2', // Der return-URL werden die Paramater als POST uebergeben
	Bn              string  `ppewp:"name:bn;type:string;default:PP-BuyNowPP"`    //PP-BuyNowBF',
	Custom          string  `ppewp:"name:custom;type:string;omitempty"`          //Irgendwas was mitgeschickt werden soll',
	Invoice         string  `ppewp:"name:invoice;type:string;omitempty"`         //',
	ImageUrl        string  `ppewp:"name:image_url;type:string;omitempty"`       //',
	CppLogoImage    string  `ppewp:"name:cpp_logo_image;type:string;omitempty"`  //',
}

type EwpOptions struct {
	Certificate           string // Certificate resource
	PrivateKey            string // Private key resource (matching certificate)
	PrivateKeyPassphrase  string // Passphrase for the Private key resource (matching certificate)
	PaypalCertificateFile string // Path to PayPal public certificate file - if need - the current of date 2018-02-18 is included
	CertificateID         string // ID assigned by PayPal to the $certificate.
}

type Ewp struct {
	certificate   *x509.Certificate // Certificate resource
	privateKey    *rsa.PrivateKey   // Private key resource (matching certificate)
	certificateID *string           // ID assigned by PayPal to the $certificate.
	error         error             // error messages
}

func NewPaypalEwp(options EwpOptions) *Ewp {
	var ewp = &Ewp{}
	ewp.LoadKeyPair(options)

	return ewp
}

func (pe *Ewp) GetError() error {
	return pe.error
}

func (pe *Ewp) LoadKeyPair(options EwpOptions) {
	pe.certificateID = &options.CertificateID

	if options.PaypalCertificateFile != "" {
		certPEM, err := ioutil.ReadFile(options.PaypalCertificateFile)
		if err != nil {
			pe.error = err
			return
		}
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			panic("failed to parse certificate PEM")
		}
		ppCert, pe.error = x509.ParseCertificate(block.Bytes)
		if pe.error != nil {
			return
		}
	}

	certPEM, err := ioutil.ReadFile(options.Certificate)
	if err != nil {
		pe.error = err
		return
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	pe.certificate, pe.error = x509.ParseCertificate(block.Bytes)
	if pe.error != nil {
		return
	}

	keyFilePEM, err := ioutil.ReadFile(options.PrivateKey)
	if err != nil {
		pe.error = err
		return
	}
	var keyPasswd []byte
	if options.PrivateKeyPassphrase != "" {
		keyPasswd = []byte(options.PrivateKeyPassphrase)
	}

	pe.privateKey, pe.error = ParseRsaPrivateKeyFromPemStr(keyFilePEM, &keyPasswd)
}

func (pe *Ewp) Generate(data *CryptData) string {
	var encData []string
	var output []byte

	encData = append(encData, "cert_id=" + *pe.certificateID)

	rt := reflect.TypeOf(data)
	// Check if it's a pointer
	if rt.Kind() != reflect.Ptr {

		pe.error = errors.New("It's not a pointer!")
		return ""
	}

	elField := rt.Elem()

	// Check if it's a struct
	if elField.Kind() != reflect.Struct {
		pe.error = errors.New("it's not a struct!")
		return ""
	}

	for i := 0; i < elField.NumField(); i++ {
		field := elField.Field(i)
		// value := refValue.Field(i)
		kind := field.Type.Kind()
		tagVals := parseTagSetting(field.Tag)

		var s string
		switch kind {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			s = strconv.FormatInt(reflect.ValueOf(data).Elem().Field(i).Int(), 10)
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			s = strconv.FormatUint(reflect.ValueOf(data).Elem().Field(i).Uint(), 10)
		case reflect.Float32, reflect.Float64:
			s = strconv.FormatFloat(reflect.ValueOf(data).Elem().Field(i).Float(), 'f', 2, 64)
		case reflect.Bool:
			if reflect.ValueOf(data).Elem().Field(i).Bool() {
				s = "True"
			} else {
				s = "False"
			}
		case reflect.String:
			s = reflect.ValueOf(data).Elem().Field(i).String()
		}

		if _, ok := tagVals["OMITEMPTY"]; ok && s == "" {
			continue
		}

		if s == "" {
			s = tagVals["DEFAULT"];
		}

		encData = append(encData, tagVals["NAME"]+"="+s)

		//fmt.Printf("%s (%v) = %#v >> %#v\n", reflect.ValueOf(data).Elem().Field(i).Type().Name(), kind, tagVals, s)

	}

	encFilled := strings.Join(encData, "\n")

	//fmt.Printf("%#v\n\n", encFilled)

	signedData, err := pkcs7.NewSignedData([]byte(encFilled))
	if err != nil {
		pe.error = err
		return ""
	}

	err = signedData.AddSigner(pe.certificate, pe.privateKey, pkcs7.SignerInfoConfig{})
	if err != nil {
		pe.error = err
		return ""
	}

	//signedData.Detach()

	byteFinish, err := signedData.Finish()
	if err != nil {
		pe.error = err
		return ""
	}

	var cryptCerts []*x509.Certificate
	cryptCerts = append(cryptCerts, ppCert)

	output, pe.error = pkcs7.Encrypt(
		byteFinish,
		cryptCerts,
	)
	return "-----BEGIN PKCS7-----\n" + chunkSplit(base64.StdEncoding.EncodeToString(output), 64, "\n") + "-----END PKCS7-----"
}

func ParseRsaPrivateKeyFromPemStr(privatePEM []byte, passphrase *[]byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privatePEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	if x509.IsEncryptedPEMBlock(block) {
		x509.DecryptPEMBlock(block, *passphrase)
		block, _ = pem.Decode(privatePEM)
		if block == nil {
			return nil, errors.New("failed to parse PEM block containing the secured key")
		}
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func parseTagSetting(tags reflect.StructTag) map[string]string {
	setting := map[string]string{}
	for _, str := range []string{tags.Get(tagName)} {
		tags := strings.Split(str, ";")
		for _, value := range tags {
			v := strings.Split(value, ":")
			k := strings.TrimSpace(strings.ToUpper(v[0]))
			if len(v) >= 2 {
				setting[k] = strings.Join(v[1:], ":")
			} else {
				setting[k] = k
			}
		}
	}
	return setting
}

func chunkSplit(body string, limit int, end string) string {

	var charSlice []rune

	// push characters to slice
	for _, char := range body {
		charSlice = append(charSlice, char)
	}

	var result string = ""

	for len(charSlice) >= 1 {
		// convert slice/array back to string
		// but insert end at specified limit

		result = result + string(charSlice[:limit]) + end

		// discard the elements that were copied over to result
		charSlice = charSlice[limit:]

		// change the limit
		// to cater for the last few words in
		// charSlice
		if len(charSlice) < limit {
			limit = len(charSlice)
		}

	}

	return result

}
