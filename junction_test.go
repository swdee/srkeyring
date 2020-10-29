package srkeyring

import (
	"reflect"
	"testing"
)

func TestNewJunction(t *testing.T) {

	tests := []struct {
		name     string
		part     string
		expected *junction
	}{
		{
			name: "Soft path",
			part: "joe",
			expected: &junction{
				path:      "joe",
				chainCode: [32]byte{12, 106, 111, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				hard:      false,
			},
		},
		{
			name: "Hard path",
			part: "/joe",
			expected: &junction{
				path:      "joe",
				chainCode: [32]byte{12, 106, 111, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				hard:      true,
			},
		},
		{
			name: "Long path causing hash",
			part: "Each derived keypair is coupled with a path ( which means it belongs to a certain network), which prevent it to be used in another network",
			expected: &junction{
				path:      "Each derived keypair is coupled with a path ( which means it belongs to a certain network), which prevent it to be used in another network",
				chainCode: [32]byte{142, 20, 254, 131, 131, 103, 80, 71, 19, 166, 248, 34, 30, 67, 213, 27, 12, 164, 204, 139, 70, 110, 249, 1, 153, 252, 82, 23, 14, 230, 91, 114},
				hard:      false,
			},
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			res, err := newJunction(tt.part)

			if err != nil {
				t.Fatalf("Error creating junction: %v", err)
			}

			if !reflect.DeepEqual(res, tt.expected) {
				t.Errorf("Invalid result, expected %v, got %v", tt.expected, res)
			}
		})
	}
}
