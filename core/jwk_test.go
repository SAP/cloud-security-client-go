// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"crypto/rsa"
	"math/big"
	"testing"
)

func TestJSONWebKey_assertKeyType(t *testing.T) {
	type fields struct {
		Kty string
		E   string
		N   string
		Use string
		Key interface{}
	}
	tests := []struct {
		name      string
		fields    fields
		wantErr   bool
		resultKey interface{}
	}{
		{
			name: "Correct RSA",
			fields: fields{
				Kty: "RSA",
				E:   "AQAB",
				N:   "1RuNn4zZdsuUqAgygOXXfUpUssi9J7wzrtcU1GiFKMjHNRITWSbB5Au-DRCY6QyJSe9MUcHP-wzo3NMIPVKjQ4tt9dqpqTpwyXfSLcM99TNVdZAsTBteo5ISECbs1Ej2qPr9ibMGqE-yH3oxLZeuk_JxZedKm2NARo5noUwhSbt4XYqhvaLXo-KVAOgC-sUtcu4upDFokgAzHZZ__yrcVvTeD1XirILaZmCN2rPymdDN7kBAurKMsFXLsR44tHFAWa6nXOTU1YPZwY67Fd1jjJjoX-enXmQigOv2IuT7N5JhPe9y-ne3Mb7yiz5ujAmRluwCny1pcO4x65fW-yMaQQ",
				Use: "sig",
			},
			wantErr:   false,
			resultKey: GetRSAKey(),
		},
		{
			name: "Wrong Kty",
			fields: fields{
				Kty: "EC",
			},
			wantErr:   true,
			resultKey: nil,
		},
		{
			name: "Malformatted RSA",
			fields: fields{
				Kty: "RSA",
				E:   "foo",
				N:   "barrr",
			},
			wantErr:   true,
			resultKey: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwk := &JSONWebKey{
				Kty: tt.fields.Kty,
				E:   tt.fields.E,
				N:   tt.fields.N,
				Use: tt.fields.Use,
			}
			if err := jwk.assertKeyType(); (err != nil) != tt.wantErr {
				t.Errorf("assertKeyType() error = %v, wantErr %v", err, tt.wantErr)
			}

		})
	}
}

func GetRSAKey() rsa.PublicKey {
	i := big.Int{}
	i.SetString("28547174295404837502870526269557059025763169428104401615133732852407464264610688313439167422186542256831509782136542669480344911669197051460171002407841693670950171710427571721301677524950383874466778810400018711419938324118051366877825628293374521379188030525227451757875132427515979758653615069895735891310837333855185622304627116111493876043332530749466202906712556968662067993705806352035450224802697497028402855568401115555511296460567061348599906055216417879362599826353475344169190303186265036289761361834820847678418829693804403765470540595734675303912769560187573732430985576783697924640433445997365770503193", 10)
	return rsa.PublicKey{
		N: &i,
		E: 65537,
	}
}
