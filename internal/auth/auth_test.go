package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {

	tests := []struct {
		name     string
		header   http.Header
		wantErr  bool
		expected string
	}{
		{
			name:     "Missing Authorization header",
			header:   http.Header{},
			wantErr:  true,
			expected: "",
		},
		{
			name: "Incorrect Header for Authorization",
			header: http.Header{
				"NotAuthorization": []string{"ApiKey 1234"},
			},
			wantErr:  true,
			expected: "",
		},
		{
			name: "Missing Authorization Header Value",
			header: http.Header{
				"Authorization": []string{""},
			},
			wantErr:  true,
			expected: "",
		},
		{
			name: "Invalid Authorization Header",
			header: http.Header{
				"Authorization": []string{"Invalid"},
			},
			wantErr:  true,
			expected: "",
		},
		{
			name: "Incorrect Authorization Type",
			header: http.Header{
				"Authorization": []string{"Bearer 2930cakra39dkar9"},
			},
			wantErr:  true,
			expected: "",
		},
		{
			name: "Malformed Authorization Header",
			header: http.Header{
				"Authorization": []string{"ApiKey293022kda0"},
			},
			wantErr:  true,
			expected: "",
		},
		{
			name: "Valid Authorization Header",
			header: http.Header{
				"Authorization": []string{"ApiKey 1234"},
			},
			wantErr:  false,
			expected: "1234",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(test.header)
			if (err != nil) != test.wantErr {
				t.Errorf("GetAPIKey error == %v, expected %v", err, test.wantErr)
			}
			if apiKey != test.expected {
				t.Errorf(
					"Incorrect API Key, expected: %s,  actual: %s", test.expected, apiKey,
				)
			}
		})
	}

}
