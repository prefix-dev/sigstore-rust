//! Tests for different Sigstore bundle versions (v0.1, v0.2, v0.3)
//!
//! These tests use real bundle fixtures from sigstore-rs and sigstore-python.

use sigstore_bundle::{validate_bundle, validate_bundle_with_options, ValidationOptions};
use sigstore_types::{Bundle, BundleExt};

/// v0.1 bundle with x509CertificateChain (from sigstore-rs)
const V01_BUNDLE: &str = r#"{
	"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
	"verificationMaterial": {
		"tlogEntries": [
			{
				"logIndex": "6800908",
				"logId": {
					"keyId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="
				},
				"kindVersion": {
					"kind": "intoto",
					"version": "0.0.2"
				},
				"integratedTime": "1668034836",
				"inclusionPromise": {
					"signedEntryTimestamp": "MEYCIQCEx8HKsx9hobZjrNqHCSEJvjMEhc2wU2mUwkI7ButQHAIhAPevmw7piNjE2N1OWHmp9S5kBvlVIg93qu4i9yRaswur"
				},
				"canonicalizedBody": "eyJhcGlWZXJzaW9uIjoiMC4wLjIiLCJraW5kIjoiaW50b3RvIn0="
			}
		],
		"timestampVerificationData": {
			"rfc3161Timestamps": []
		},
		"x509CertificateChain": {
			"certificates": [
				{
					"rawBytes": "MIICnzCCAiagAwIBAgIUBnmZRtdkOtfO/Lyg435CR+VIi+AwCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjIxMTA5MjMwMDM1WhcNMjIxMTA5MjMxMDM1WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeUE6Ox/414K0dBx3c3W+tQ7NTSlIVV24YSbBl6VyuIV/i15KClSjUo2qQuKSU4EzmHf2+EMj/YHYHeBADkDxj6OCAUUwggFBMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU/VGCUHVX5bXhet21itbj5WvhZqAwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0RAQH/BBUwE4ERYnJpYW5AZGVoYW1lci5jb20wLAYKKwYBBAGDvzABAQQeaHR0cHM6Ly9naXRodWIuY29tL2xvZ2luL29hdXRoMIGKBgorBgEEAdZ5AgQCBHwEegB4AHYA3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4AAAGEXp+1XQAABAMARzBFAiEAkdI694/8B2rOdiyYPlEncfRwkubodOZ4jlm4g5285LkCIHRpmGh4p5Oc+Vk+AKHMdt0VtD2/+caHWye1VqD4rGcCMAoGCCqGSM49BAMDA2cAMGQCMAyK8tQ5mPCCiLjiIsVsIZPYvhvDR3DFli5AQzjSCzcES/h5fB3GpeDdBOu9tukaowIwNkoEYZHOtkacLerL52eYSpVjfXsA0gBMqAnmLGwXtzkVKqqzUmbZhCv8m85bfuIR"
				}
			]
		}
	},
	"dsseEnvelope": {
		"payload": "eyJ0ZXN0IjogInBheWxvYWQifQ==",
		"payloadType": "application/vnd.in-toto+json",
		"signatures": [
			{
				"sig": "MEUCIFc/ByLhCkR2YtAMbmJp202ZmZ4XVGXFKi7r+q7lsNDPAiEA/JwX2PilCLvkqE9NJMFKNn2C2j8cH/zyFhQ65wri2HY=",
				"keyid": ""
			}
		]
	}
}"#;

/// v0.3 bundle with single certificate and inclusion proof (from sigstore-rs)
const V03_BUNDLE_WITH_PROOF: &str = r#"{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{"certificate":{"rawBytes":"MIIGszCCBjqgAwIBAgIULS74/iEp5l/IHhz93YTruZvZruMwCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjUwMTI4MTAyODE1WhcNMjUwMTI4MTAzODE1WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiTUq2zRHkVxfiGYGbqRUuXy1Jl0gAoaXFeOgej+iHaCzp5QQZlMGr7qonV+GwtSGf4ranURsxzebDXmbb7GvMqOCBVkwggVVMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQURau/CMWTV4tz8fGU2/U0vnIrmQ4wHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wYgYDVR0RAQH/BFgwVoZUaHR0cHM6Ly9naXRodWIuY29tL3dvbGZ2L3NpZ3N0b3JlLXRlc3QvLmdpdGh1Yi93b3JrZmxvd3MvYWN0aW9uLnlhbWxAcmVmcy9oZWFkcy9tYWluMDkGCisGAQQBg78wAQEEK2h0dHBzOi8vdG9rZW4uYWN0aW9ucy5naXRodWJ1c2VyY29udGVudC5jb20wEgYKKwYBBAGDvzABAgQEcHVzaDA2BgorBgEEAYO/MAEDBChhNzc4YjE5MDMxMWE1NmYwNGFjOTE1YzNlMjJjZTc4OTFjOWVlZGJmMB4GCisGAQQBg78wAQQEEFBhY2thZ2UgYW5kIHNpZ24wIQYKKwYBBAGDvzABBQQTd29sZnYvc2lnc3RvcmUtdGVzdDAdBgorBgEEAYO/MAEGBA9yZWZzL2hlYWRzL21haW4wOwYKKwYBBAGDvzABCAQtDCtodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tMGQGCisGAQQBg78wAQkEVgxUaHR0cHM6Ly9naXRodWIuY29tL3dvbGZ2L3NpZ3N0b3JlLXRlc3QvLmdpdGh1Yi93b3JrZmxvd3MvYWN0aW9uLnlhbWxAcmVmcy9oZWFkcy9tYWluMDgGCisGAQQBg78wAQoEKgwoYTc3OGIxOTAzMTFhNTZmMDRhYzkxNWMzZTIyY2U3ODkxYzllZWRiZjAdBgorBgEEAYO/MAELBA8MDWdpdGh1Yi1ob3N0ZWQwNgYKKwYBBAGDvzABDAQoDCZodHRwczovL2dpdGh1Yi5jb20vd29sZnYvc2lnc3RvcmUtdGVzdDA4BgorBgEEAYO/MAENBCoMKGE3NzhiMTkwMzExYTU2ZjA0YWM5MTVjM2UyMmNlNzg5MWM5ZWVkYmYwHwYKKwYBBAGDvzABDgQRDA9yZWZzL2hlYWRzL21haW4wGQYKKwYBBAGDvzABDwQLDAk4NTkyOTgwNTIwKAYKKwYBBAGDvzABEAQaDBhodHRwczovL2dpdGh1Yi5jb20vd29sZnYwFgYKKwYBBAGDvzABEQQIDAY4ODUwNTQwZAYKKwYBBAGDvzABEgRWDFRodHRwczovL2dpdGh1Yi5jb20vd29sZnYvc2lnc3RvcmUtdGVzdC8uZ2l0aHViL3dvcmtmbG93cy9hY3Rpb24ueWFtbEByZWZzL2hlYWRzL21haW4wOAYKKwYBBAGDvzABEwQqDChhNzc4YjE5MDMxMWE1NmYwNGFjOTE1YzNlMjJjZTc4OTFjOWVlZGJmMBQGCisGAQQBg78wARQEBgwEcHVzaDBaBgorBgEEAYO/MAEVBEwMSmh0dHBzOi8vZ2l0aHViLmNvbS93b2xmdi9zaWdzdG9yZS10ZXN0L2FjdGlvbnMvcnVucy8xMzAwODQyOTE1OS9hdHRlbXB0cy8xMBYGCisGAQQBg78wARYECAwGcHVibGljMIGKBgorBgEEAdZ5AgQCBHwEegB4AHYA3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4AAAGUrHRhegAABAMARzBFAiEAkHyX4AXMBvr6kbwMzeXlCCADNFj8uK68vY/k+EeuAekCICKft8LIujEfkuNe0IU/C7M8LHejMwkL777M+8hErYGaMAoGCCqGSM49BAMDA2cAMGQCMCcGilRua0pKsQqRhMCYjZRiF+M2p03qgcvGh3DiRkXpRUXNxGELNRQmGoq6UK6TnwIwcj3i3b4REE/mJdM/FBS/kHaHbU2gtm4L3jeUY0Q2j7YUsfyPvr7G7oZf4aTpk2AW"},"tlogEntries":[{"logIndex":"166143216","logId":{"keyId":"wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="},"kindVersion":{"kind":"dsse","version":"0.0.1"},"integratedTime":"1738060096","inclusionPromise":{"signedEntryTimestamp":"MEQCIFdvIafa5jqan78r7Ypre1hdOCE1lnZ5LT0lYEtlCYnAAiBHWRe5/97eWPqVypxIzKbDUVtK7Y3rJmYT0DCOuRtY5g=="},"inclusionProof":{"logIndex":"44238954","rootHash":"TiowMOu0x46fW4pXrRyW7TeVb6f1/VDnDZWcP1xL/HU=","treeSize":"44238955","hashes":["iMecnh5ol+AiQUqe67cka5QnpS7+Uac/PP2yxDQ7KnQ=","VXEdyQrtr/iiIQPJ76SNiRpLd8/wXguekWT+nmHbP84=","lkPY9Ya80uK1vUlI2ekwn125ntq+s+Hx32de1Zre35s=","FXn3gvhalfR91NP/m43gQswlqzo8LYuMe95EdKvsD7c=","kHIAOKN34D4Q4Mu3aTF4dLRO7QKWDSrkRXJ8wj0a2j0=","sTh7uuXvFFqHGFy/+afvnA9fsSMiHIZoWRAdHhNZMFQ=","ABrujg3xYGHOAy9tkUTpYsPw8qCs6bGbyGms261oTf4=","WYCyxkm3nLuN6MubBiGGY9Z5Try/M4gliHJK7VMo7V4=","jU9+tgjTIKUYGeU7T7RjqyL+F+gFV9tCdwX2GZ1UtQs=","vemyaMj0Na1LMjbB/9Dmkq8T+jAb3o+yCESgAayUABU="],"checkpoint":{"envelope":"rekor.sigstore.dev - 1193050959916656506\n44238955\nTiowMOu0x46fW4pXrRyW7TeVb6f1/VDnDZWcP1xL/HU=\n\n— rekor.sigstore.dev wNI9ajBEAiBF3lyT0Jg0paKCvqJQ0t97+hcneAqZHeiRuLinOba/YQIgG65ZKAhE+byLy+VQ4/14FwvJG0FMhq4CNoDONpzvOMc=\n"}},"canonicalizedBody":"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiZHNzZSIsInNwZWMiOnsiZW52ZWxvcGVIYXNoIjp7ImFsZ29yaXRobSI6InNoYTI1NiIsInZhbHVlIjoiZDhiYjhkM2FkMTRmNTYxODQxOTMzODExYjkwZTNiOGY4ZGJjODFhMTQ2NDlkOThkNGI3Zjg0YjM1M2ZmODM0NSJ9LCJwYXlsb2FkSGFzaCI6eyJhbGdvcml0aG0iOiJzaGEyNTYiLCJ2YWx1ZSI6ImZhZDU0M2M3YTFlOWFjZmE0Y2I2ZWNkN2UxNGZiN2UzY2QxMzVjMDllZmU4ZGRjOTY4ZDQ5NGJjMjIyMTM2ZGQifSwic2lnbmF0dXJlcyI6W3sic2lnbmF0dXJlIjoiTUVVQ0lRQ0VKTzkxb21WUHc2WVJDVEVlN3YzRllObzZMeFBTSlozMitScUZoeXFONVFJZ1dXdzk2THhWSzhPVGZ5N1I5SFRlVnhuSTg3bnI4aHg1Tm4wRGdCNDkzbE09IiwidmVyaWZpZXIiOiJMUzB0TFMxQ1JVZEpUaUJEUlZKVVNVWkpRMEZVUlMwdExTMHRDazFKU1VkemVrTkRRbXB4WjBGM1NVSkJaMGxWVEZNM05DOXBSWEExYkM5SlNHaDZPVE5aVkhKMVduWmFjblZOZDBObldVbExiMXBKZW1vd1JVRjNUWGNLVG5wRlZrMUNUVWRCTVZWRlEyaE5UV015Ykc1ak0xSjJZMjFWZFZwSFZqSk5ValIzU0VGWlJGWlJVVVJGZUZaNllWZGtlbVJIT1hsYVV6RndZbTVTYkFwamJURnNXa2RzYUdSSFZYZElhR05PVFdwVmQwMVVTVFJOVkVGNVQwUkZNVmRvWTA1TmFsVjNUVlJKTkUxVVFYcFBSRVV4VjJwQlFVMUdhM2RGZDFsSUNrdHZXa2w2YWpCRFFWRlpTVXR2V2tsNmFqQkVRVkZqUkZGblFVVnBWRlZ4TW5wU1NHdFdlR1pwUjFsSFluRlNWWFZZZVRGS2JEQm5RVzloV0VabFQyY0taV29yYVVoaFEzcHdOVkZSV214TlIzSTNjVzl1Vml0SGQzUlRSMlkwY21GdVZWSnplSHBsWWtSWWJXSmlOMGQyVFhGUFEwSldhM2RuWjFaV1RVRTBSd3BCTVZWa1JIZEZRaTkzVVVWQmQwbElaMFJCVkVKblRsWklVMVZGUkVSQlMwSm5aM0pDWjBWR1FsRmpSRUY2UVdSQ1owNVdTRkUwUlVablVWVlNZWFV2Q2tOTlYxUldOSFI2T0daSFZUSXZWVEIyYmtseWJWRTBkMGgzV1VSV1VqQnFRa0puZDBadlFWVXpPVkJ3ZWpGWmEwVmFZalZ4VG1wd1MwWlhhWGhwTkZrS1drUTRkMWxuV1VSV1VqQlNRVkZJTDBKR1ozZFdiMXBWWVVoU01HTklUVFpNZVRsdVlWaFNiMlJYU1hWWk1qbDBURE5rZG1KSFdqSk1NMDV3V2pOT01BcGlNMHBzVEZoU2JHTXpVWFpNYldSd1pFZG9NVmxwT1ROaU0wcHlXbTE0ZG1RelRYWlpWMDR3WVZjNWRVeHViR2hpVjNoQlkyMVdiV041T1c5YVYwWnJDbU41T1hSWlYyeDFUVVJyUjBOcGMwZEJVVkZDWnpjNGQwRlJSVVZMTW1nd1pFaENlazlwT0haa1J6bHlXbGMwZFZsWFRqQmhWemwxWTNrMWJtRllVbThLWkZkS01XTXlWbmxaTWpsMVpFZFdkV1JETldwaU1qQjNSV2RaUzB0M1dVSkNRVWRFZG5wQlFrRm5VVVZqU0ZaNllVUkJNa0puYjNKQ1owVkZRVmxQTHdwTlFVVkVRa05vYUU1Nll6Ulpha1UxVFVSTmVFMVhSVEZPYlZsM1RrZEdhazlVUlRGWmVrNXNUV3BLYWxwVVl6UlBWRVpxVDFkV2JGcEhTbTFOUWpSSENrTnBjMGRCVVZGQ1p6YzRkMEZSVVVWRlJrSm9XVEowYUZveVZXZFpWelZyU1VoT2NGb3lOSGRKVVZsTFMzZFpRa0pCUjBSMmVrRkNRbEZSVkdReU9YTUtXbTVaZG1NeWJHNWpNMUoyWTIxVmRHUkhWbnBrUkVGa1FtZHZja0puUlVWQldVOHZUVUZGUjBKQk9YbGFWMXA2VERKb2JGbFhVbnBNTWpGb1lWYzBkd3BQZDFsTFMzZFpRa0pCUjBSMmVrRkNRMEZSZEVSRGRHOWtTRkozWTNwdmRrd3pVblpoTWxaMVRHMUdhbVJIYkhaaWJrMTFXakpzTUdGSVZtbGtXRTVzQ21OdFRuWmlibEpzWW01UmRWa3lPWFJOUjFGSFEybHpSMEZSVVVKbk56aDNRVkZyUlZabmVGVmhTRkl3WTBoTk5reDVPVzVoV0ZKdlpGZEpkVmt5T1hRS1RETmtkbUpIV2pKTU0wNXdXak5PTUdJelNteE1XRkpzWXpOUmRreHRaSEJrUjJneFdXazVNMkl6U25KYWJYaDJaRE5OZGxsWFRqQmhWemwxVEc1c2FBcGlWM2hCWTIxV2JXTjVPVzlhVjBaclkzazVkRmxYYkhWTlJHZEhRMmx6UjBGUlVVSm5OemgzUVZGdlJVdG5kMjlaVkdNelQwZEplRTlVUVhwTlZFWm9DazVVV20xTlJGSm9XWHByZUU1WFRYcGFWRWw1V1RKVk0wOUVhM2haZW14c1dsZFNhVnBxUVdSQ1oyOXlRbWRGUlVGWlR5OU5RVVZNUWtFNFRVUlhaSEFLWkVkb01WbHBNVzlpTTA0d1dsZFJkMDVuV1V0TGQxbENRa0ZIUkhaNlFVSkVRVkZ2UkVOYWIyUklVbmRqZW05MlRESmtjR1JIYURGWmFUVnFZakl3ZGdwa01qbHpXbTVaZG1NeWJHNWpNMUoyWTIxVmRHUkhWbnBrUkVFMFFtZHZja0puUlVWQldVOHZUVUZGVGtKRGIwMUxSMFV6VG5wb2FVMVVhM2ROZWtWNENsbFVWVEphYWtFd1dWZE5OVTFVVm1wTk1sVjVUVzFPYkU1Nlp6Vk5WMDAxV2xkV2ExbHRXWGRJZDFsTFMzZFpRa0pCUjBSMmVrRkNSR2RSVWtSQk9Ya0tXbGRhZWt3eWFHeFpWMUo2VERJeGFHRlhOSGRIVVZsTFMzZFpRa0pCUjBSMmVrRkNSSGRSVEVSQmF6Uk9WR3Q1VDFSbmQwNVVTWGRMUVZsTFMzZFpRZ3BDUVVkRWRucEJRa1ZCVVdGRVFtaHZaRWhTZDJONmIzWk1NbVJ3WkVkb01WbHBOV3BpTWpCMlpESTVjMXB1V1hkR1oxbExTM2RaUWtKQlIwUjJla0ZDQ2tWUlVVbEVRVmswVDBSVmQwNVVVWGRhUVZsTFMzZFpRa0pCUjBSMmVrRkNSV2RTVjBSR1VtOWtTRkozWTNwdmRrd3laSEJrUjJneFdXazFhbUl5TUhZS1pESTVjMXB1V1haak1teHVZek5TZG1OdFZYUmtSMVo2WkVNNGRWb3liREJoU0ZacFRETmtkbU50ZEcxaVJ6a3pZM2s1YUZrelVuQmlNalIxWlZkR2RBcGlSVUo1V2xkYWVrd3lhR3haVjFKNlRESXhhR0ZYTkhkUFFWbExTM2RaUWtKQlIwUjJla0ZDUlhkUmNVUkRhR2hPZW1NMFdXcEZOVTFFVFhoTlYwVXhDazV0V1hkT1IwWnFUMVJGTVZsNlRteE5ha3BxV2xSak5FOVVSbXBQVjFac1drZEtiVTFDVVVkRGFYTkhRVkZSUW1jM09IZEJVbEZGUW1kM1JXTklWbm9LWVVSQ1lVSm5iM0pDWjBWRlFWbFBMMDFCUlZaQ1JYZE5VMjFvTUdSSVFucFBhVGgyV2pKc01HRklWbWxNYlU1MllsTTVNMkl5ZUcxa2FUbDZZVmRrZWdwa1J6bDVXbE14TUZwWVRqQk1Na1pxWkVkc2RtSnVUWFpqYmxaMVkzazRlRTE2UVhkUFJGRjVUMVJGTVU5VE9XaGtTRkpzWWxoQ01HTjVPSGhOUWxsSENrTnBjMGRCVVZGQ1p6YzRkMEZTV1VWRFFYZEhZMGhXYVdKSGJHcE5TVWRMUW1kdmNrSm5SVVZCWkZvMVFXZFJRMEpJZDBWbFowSTBRVWhaUVROVU1IY0tZWE5pU0VWVVNtcEhValJqYlZkak0wRnhTa3RZY21wbFVFc3pMMmcwY0hsblF6aHdOMjgwUVVGQlIxVnlTRkpvWldkQlFVSkJUVUZTZWtKR1FXbEZRUXByU0hsWU5FRllUVUoyY2paclluZE5lbVZZYkVORFFVUk9SbW80ZFVzMk9IWlpMMnNyUldWMVFXVnJRMGxEUzJaME9FeEpkV3BGWm10MVRtVXdTVlV2Q2tNM1RUaE1TR1ZxVFhkclREYzNOMDByT0doRmNsbEhZVTFCYjBkRFEzRkhVMDAwT1VKQlRVUkJNbU5CVFVkUlEwMURZMGRwYkZKMVlUQndTM05SY1ZJS2FFMURXV3BhVW1sR0swMHljREF6Y1dkamRrZG9NMFJwVW10WWNGSlZXRTU0UjBWTVRsSlJiVWR2Y1RaVlN6WlVibmRKZDJOcU0ya3pZalJTUlVVdmJRcEtaRTB2UmtKVEwydElZVWhpVlRKbmRHMDBURE5xWlZWWk1GRXlhamRaVlhObWVWQjJjamRITjI5YVpqUmhWSEJyTWtGWENpMHRMUzB0UlU1RUlFTkZVbFJKUmtsRFFWUkZMUzB0TFMwSyJ9XX19"}],"timestampVerificationData":{"rfc3161Timestamps":[]}},"dsseEnvelope":{"payload":"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJzdWJqZWN0IjpbeyJuYW1lIjoic2lnbmVkLXBhY2thZ2UtMS4yLjAtaGIwZjRkY2FfMC5jb25kYSIsImRpZ2VzdCI6eyJzaGEyNTYiOiI1OWVkODFlZTdhMjQ4NWM0NzU4OGViZGJhZDE0NzY0YmY3MjJjOTM0MzhiNDNmZTk1M2E2NTE3NDdiYzYyYWQ3In19XSwicHJlZGljYXRlVHlwZSI6Imh0dHBzOi8vc2xzYS5kZXYvc3BlYy92MS4wL3Byb3ZlbmFuY2UiLCJwcmVkaWNhdGUiOnt9fQ==","payloadType":"application/vnd.in-toto+json","signatures":[{"sig":"MEUCIQCEJO91omVPw6YRCTEe7v3FYNo6LxPSJZ32+RqFhyqN5QIgWWw96LxVK8OTfy7R9HTeVxnI87nr8hx5Nn0DgB493lM=","keyid":""}]}}"#;

/// v0.3 bundle with timestamp verification data (no inclusion proof to avoid verification)
const V03_BUNDLE_WITH_TIMESTAMP: &str = r#"{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "MIIDBDCCAoqgAwIBAgIUYlZafqye+P/bWSMSdvxrr7y+NUEwCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjUwNjA5MjEwNjI1WhcNMjUwNjA5MjExNjI1WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwDj9XB2rrkUTaCgPE3OGPJ+176EZM3u2SK2XLKoMUQn79zywhocahVPybzn/6nMkWkew8SFaDhkL4PCAENNzcqOCAakwggGlMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUQ/OiAAk5AAqjN5apYfVwt/M4S5UwHwYDVR0jBBgwFoAUcYYwphR8Ym/599b0BRp/X//rb6wwWQYDVR0RAQH/BE8wTYFLaW5zZWN1cmUtY2xvdWR0b3Atc2hhcmVkLXVzZXJAY2xvdWR0b3AtcHJvZC11cy1lYXN0LmlhbS5nc2VydmljZWFjY291bnQuY29tMCkGCisGAQQBg78wAQEEG2h0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbTArBgorBgEEAYO/MAEIBB0MG2h0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbTCBigYKKwYBBAHWeQIEAgR8BHoAeAB2ACswvNxoiMni4dgmKV50H0g5MZYC8pwzy15DQP6yrIZ6AAABl1aEEo4AAAQDAEcwRQIhAJzFA8xqE8owuQqk9ao7NLQy/YoTsy23A+ZU3cdL+MM1AiAZyN3FSWf13Fl3oL+P5jAvv0xRyqGrWEyZJw4KO7XhnDAKBggqhkjOPQQDAwNoADBlAjA9OgkRsqwLbt59TB0Jb15NBBQiaNBRRqUdo2FuSrvEWWDnnynmqo0GygnbCmz2CJwCMQDFCWJExAUGX7v5UQUzDz1pc1b0WvX1wAP2fhbgir2yZZRcsr4OdWz31arOo6USvVI="}, "tlogEntries": [{"logIndex": "689", "logId": {"keyId": "8w1amZ2S5mJIQkQmPxdMuOrL/oJkvFg9MnQXmeOCXck="}, "kindVersion": {"kind": "dsse", "version": "0.0.2"}, "integratedTime": "1749502788", "inclusionPromise": {"signedEntryTimestamp": "dGVzdA=="}, "canonicalizedBody": "eyJhcGlWZXJzaW9uIjoiMC4wLjIiLCJraW5kIjoiZHNzZSJ9"}], "timestampVerificationData": {"rfc3161Timestamps": [{"signedTimestamp": "MIIE5zADAgEA"}]}}, "dsseEnvelope": {"payload": "eyJ0ZXN0IjogInBheWxvYWQifQ==", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "MEYCIQCqztBBMzbbe7jSz5qP8OwSxJX0EoESHh9wmnEycS7wKwIhALwPHiktogQcx+xVLXHlINzu25rTS5nXFBw8Kqqzy8fd"}]}}"#;

// ==== v0.1 Bundle Tests ====

#[test]
fn test_parse_v01_bundle() {
    let bundle = Bundle::from_json(V01_BUNDLE).expect("Failed to parse v0.1 bundle");

    // Check media type
    assert_eq!(
        bundle.media_type,
        "application/vnd.dev.sigstore.bundle+json;version=0.1"
    );

    // Check version
    let version = bundle.version().expect("Failed to get version");
    assert_eq!(version, sigstore_types::MediaType::Bundle0_1);

    // Check it has x509CertificateChain (not single certificate)
    let vm = bundle.verification_material.as_ref().unwrap();
    match &vm.content {
        Some(sigstore_types::bundle::VerificationMaterialContent::X509CertificateChain(chain)) => {
            assert!(
                !chain.certificates.is_empty(),
                "Certificate chain should not be empty"
            );
        }
        _ => panic!("Expected X509CertificateChain for v0.1 bundle"),
    }

    // Should have inclusion promise
    assert!(bundle.has_inclusion_promise());
}

#[test]
fn test_validate_v01_bundle() {
    let bundle = Bundle::from_json(V01_BUNDLE).expect("Failed to parse bundle");

    // v0.1 requires inclusion promise, not proof
    // This should fail with default options because we require proof
    let options = ValidationOptions {
        require_inclusion_proof: false, // v0.1 uses promise, not proof
        require_timestamp: false,
    };

    let result = validate_bundle_with_options(&bundle, &options);
    assert!(result.is_ok(), "v0.1 validation failed: {:?}", result.err());
}

#[test]
fn test_v01_bundle_certificate_extraction() {
    let bundle = Bundle::from_json(V01_BUNDLE).expect("Failed to parse bundle");

    let cert = bundle
        .signing_certificate()
        .expect("Should have signing certificate");

    // Certificate is already raw DER bytes - no base64 decoding needed
    let cert_der = cert.as_bytes();
    assert!(!cert_der.is_empty());
}

// ==== v0.3 Bundle Tests ====

#[test]
fn test_parse_v03_bundle() {
    let bundle = Bundle::from_json(V03_BUNDLE_WITH_PROOF).expect("Failed to parse v0.3 bundle");

    // Check media type
    assert_eq!(
        bundle.media_type,
        "application/vnd.dev.sigstore.bundle.v0.3+json"
    );

    // Check version
    let version = bundle.version().expect("Failed to get version");
    assert_eq!(version, sigstore_types::MediaType::Bundle0_3);

    // Check it has single certificate (not chain)
    let vm = bundle.verification_material.as_ref().unwrap();
    match &vm.content {
        Some(sigstore_types::bundle::VerificationMaterialContent::Certificate(cert)) => {
            assert!(
                !cert.raw_bytes.is_empty(),
                "Certificate should not be empty"
            );
        }
        _ => panic!("Expected single Certificate for v0.3 bundle"),
    }

    // Should have inclusion proof
    assert!(bundle.has_inclusion_proof());
}

#[test]
fn test_validate_v03_bundle_with_proof() {
    let bundle = Bundle::from_json(V03_BUNDLE_WITH_PROOF).expect("Failed to parse bundle");

    // v0.3 requires inclusion proof
    let result = validate_bundle(&bundle);
    assert!(result.is_ok(), "v0.3 validation failed: {:?}", result.err());
}

#[test]
fn test_v03_bundle_with_timestamp() {
    let bundle = Bundle::from_json(V03_BUNDLE_WITH_TIMESTAMP).expect("Failed to parse bundle");

    // Should have timestamp verification data
    let vm = bundle.verification_material.as_ref().unwrap();
    let tvd = vm.timestamp_verification_data.as_ref().unwrap();
    assert!(
        !tvd.rfc3161_timestamps.is_empty(),
        "Should have RFC3161 timestamps"
    );

    // Validate with timestamp requirement but skip proof (since we use simplified test data)
    let options = ValidationOptions {
        require_inclusion_proof: false, // Skip for this test since we use simplified body
        require_timestamp: true,
    };

    let result = validate_bundle_with_options(&bundle, &options);
    assert!(
        result.is_ok(),
        "Validation with timestamp failed: {:?}",
        result.err()
    );
}

#[test]
fn test_v03_bundle_serialization_roundtrip() {
    let bundle = Bundle::from_json(V03_BUNDLE_WITH_PROOF).expect("Failed to parse bundle");

    // Serialize
    let json = bundle.to_json().expect("Failed to serialize");

    // Parse again
    let bundle2 = Bundle::from_json(&json).expect("Failed to re-parse");

    // Compare
    assert_eq!(bundle.media_type, bundle2.media_type);
    let vm1 = bundle.verification_material.as_ref().unwrap();
    let vm2 = bundle2.verification_material.as_ref().unwrap();
    assert_eq!(vm1.tlog_entries.len(), vm2.tlog_entries.len());
}

// ==== Version Comparison Tests ====

#[test]
fn test_v01_vs_v03_certificate_format() {
    let v01 = Bundle::from_json(V01_BUNDLE).expect("Failed to parse v0.1");
    let v03 = Bundle::from_json(V03_BUNDLE_WITH_PROOF).expect("Failed to parse v0.3");

    // v0.1 uses X509CertificateChain
    let vm01 = v01.verification_material.as_ref().unwrap();
    assert!(matches!(
        &vm01.content,
        Some(sigstore_types::bundle::VerificationMaterialContent::X509CertificateChain(_))
    ));

    // v0.3 uses single Certificate
    let vm03 = v03.verification_material.as_ref().unwrap();
    assert!(matches!(
        &vm03.content,
        Some(sigstore_types::bundle::VerificationMaterialContent::Certificate(_))
    ));
}

#[test]
fn test_media_type_parsing() {
    let v01 = Bundle::from_json(V01_BUNDLE).expect("Failed to parse v0.1");
    let v03 = Bundle::from_json(V03_BUNDLE_WITH_PROOF).expect("Failed to parse v0.3");

    assert_eq!(v01.version().unwrap(), sigstore_types::MediaType::Bundle0_1);
    assert_eq!(v03.version().unwrap(), sigstore_types::MediaType::Bundle0_3);
}

// ==== Error Cases ====

#[test]
fn test_v03_without_proof_fails_validation() {
    // Create a v0.3 bundle without inclusion proof
    let json = r#"{
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": "dGVzdA=="},
            "tlogEntries": [{
                "logIndex": "1",
                "logId": {"keyId": "dGVzdA=="},
                "kindVersion": {"kind": "dsse", "version": "0.0.1"},
                "integratedTime": "1234567890",
                "canonicalizedBody": "dGVzdA=="
            }]
        },
        "dsseEnvelope": {
            "payload": "dGVzdA==",
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"sig": "dGVzdA=="}]
        }
    }"#;

    let bundle = Bundle::from_json(json).expect("Failed to parse bundle");

    // Should fail because v0.3 requires inclusion proof
    let result = validate_bundle(&bundle);
    assert!(result.is_err(), "Should fail without inclusion proof");
}

#[test]
fn test_v03_with_certificate_chain_fails() {
    // v0.3 should not use x509CertificateChain
    // Using valid 32-byte hashes for SHA-256 (44 chars in base64)
    let fake_hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let json = format!(
        r#"{{
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {{
            "x509CertificateChain": {{
                "certificates": [{{"rawBytes": "dGVzdA=="}}]
            }},
            "tlogEntries": [{{
                "logIndex": "1",
                "logId": {{"keyId": "dGVzdA=="}},
                "kindVersion": {{"kind": "dsse", "version": "0.0.1"}},
                "integratedTime": "1234567890",
                "inclusionProof": {{
                    "logIndex": "1",
                    "rootHash": "{}",
                    "treeSize": "2",
                    "hashes": [],
                    "checkpoint": {{"envelope": "test\n1\n{}\n"}}
                }},
                "canonicalizedBody": "dGVzdA=="
            }}]
        }},
        "dsseEnvelope": {{
            "payload": "dGVzdA==",
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{{"sig": "dGVzdA=="}}]
        }}
    }}"#,
        fake_hash, fake_hash
    );

    let bundle = Bundle::from_json(&json).expect("Failed to parse bundle");

    // Should fail because v0.3 requires single certificate
    let result = validate_bundle(&bundle);
    assert!(result.is_err(), "v0.3 should fail with certificate chain");
    let err_msg = format!("{:?}", result.err());
    assert!(
        err_msg.contains("single certificate"),
        "Error should mention single certificate requirement"
    );
}

#[test]
fn test_invalid_media_type() {
    let json = r#"{
        "mediaType": "application/invalid",
        "verificationMaterial": {
            "certificate": {"rawBytes": "dGVzdA=="},
            "tlogEntries": []
        },
        "dsseEnvelope": {
            "payload": "dGVzdA==",
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"sig": "dGVzdA=="}]
        }
    }"#;

    let bundle = Bundle::from_json(json).expect("Failed to parse bundle");

    // Should fail with invalid media type
    let result = validate_bundle(&bundle);
    assert!(result.is_err(), "Should fail with invalid media type");
}
