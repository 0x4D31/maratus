package report

import "testing"

func TestDisplayFunctionNameDemanglesCommonItaniumSymbols(t *testing.T) {
	tests := map[string]string{
		"_Z4execPKc":                          "exec(...)",
		"_Z11ColdWalletsv":                    "ColdWallets()",
		"_ZN5Tools4execEPKc":                  "Tools::exec(...)",
		"_ZN6System18executeAppleScriptERKSs": "System::executeAppleScript(...)",
		"sub_100003f10":                       "sub_100003f10",
		"$s3huy14runAppleScript6scriptySS_tF": "$s3huy14runAppleScript6scriptySS_tF",
	}
	for input, want := range tests {
		if got := displayFunctionName(input); got != want {
			t.Fatalf("displayFunctionName(%q) = %q, want %q", input, got, want)
		}
	}
}
