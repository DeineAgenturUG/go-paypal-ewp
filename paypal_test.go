package Ewp

import (
	"testing"
	"fmt"
)

func TestEncryption(t *testing.T) {

	mdata := &CryptData{
		Business: "example@example.com",
		ItemName: "demo",
		ItemNumber: "demo123",
		Amount: 123.20,
		Invoice: "ONL-OrderID",
		ReturnUrl: "https://www.google.com/",

	}

	m := NewPaypalEwp(EwpOptions{Certificate:"fixtures/demo.pem", PrivateKey:"fixtures/demo.key", PaypalCertificateFile: "fixtures/paypal.pem", CertificateID: "PAYPAL-CertID"})
	fmt.Printf(">>>%#v", m.GetError())
	fmt.Println("Result:")
	fmt.Println(m.Generate(mdata))
	fmt.Printf(">>>%#v", m.GetError())
}