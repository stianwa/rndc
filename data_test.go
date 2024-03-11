package rndc

var testData = map[string][]byte{
	"initRequest": {
		0x00, 0x00, 0x00, 0xd2, 0x00, 0x00, 0x00, 0x01,
		0x05, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x02, 0x00,
		0x00, 0x00, 0x63, 0x04, 0x68, 0x73, 0x68, 0x61,
		0x01, 0x00, 0x00, 0x00, 0x59, 0xa3, 0x73, 0x4d,
		0x65, 0x55, 0x6a, 0x43, 0x31, 0x56, 0x37, 0x6c,
		0x76, 0x78, 0x57, 0x55, 0x5a, 0x75, 0x79, 0x6c,
		0x53, 0x71, 0x65, 0x77, 0x4a, 0x6d, 0x6b, 0x64,
		0x6e, 0x66, 0x7a, 0x67, 0x71, 0x45, 0x6d, 0x79,
		0x48, 0x68, 0x4f, 0x57, 0x53, 0x47, 0x74, 0x76,
		0x77, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x5f,
		0x63, 0x74, 0x72, 0x6c, 0x02, 0x00, 0x00, 0x00,
		0x3c, 0x04, 0x5f, 0x73, 0x65, 0x72, 0x01, 0x00,
		0x00, 0x00, 0x0a, 0x33, 0x39, 0x31, 0x36, 0x34,
		0x30, 0x36, 0x32, 0x37, 0x34, 0x04, 0x5f, 0x74,
		0x69, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x31,
		0x37, 0x31, 0x30, 0x31, 0x34, 0x39, 0x30, 0x32,
		0x31, 0x04, 0x5f, 0x65, 0x78, 0x70, 0x01, 0x00,
		0x00, 0x00, 0x0a, 0x31, 0x37, 0x31, 0x30, 0x31,
		0x34, 0x39, 0x30, 0x38, 0x31, 0x05, 0x5f, 0x64,
		0x61, 0x74, 0x61, 0x02, 0x00, 0x00, 0x00, 0x0e,
		0x04, 0x74, 0x79, 0x70, 0x65, 0x01, 0x00, 0x00,
		0x00, 0x04, 0x6e, 0x75, 0x6c, 0x6c,
	},
	"initRequestExpect": []byte(`{"_auth":{"hsha":"\ufffdsMeUjC1V7lvxWUZuylSqewJmkdnfzgqEmyHhOWSGtvw=\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000"},"_ctrl":{"_exp":"1710149081","_ser":"3916406274","_tim":"1710149021"},"_data":{"type":"null"}}`),
	"initResponse": {
		0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x05, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x02, 0x00,
		0x00, 0x00, 0x63, 0x04, 0x68, 0x73, 0x68, 0x61,
		0x01, 0x00, 0x00, 0x00, 0x59, 0xa3, 0x35, 0x53,
		0x56, 0x6d, 0x7a, 0x4f, 0x31, 0x41, 0x6e, 0x5a,
		0x6b, 0x33, 0x57, 0x63, 0x6c, 0x61, 0x33, 0x48,
		0x34, 0x4d, 0x41, 0x57, 0x56, 0x34, 0x78, 0x64,
		0x44, 0x72, 0x2f, 0x43, 0x2f, 0x41, 0x74, 0x74,
		0x68, 0x74, 0x79, 0x68, 0x68, 0x43, 0x66, 0x54,
		0x73, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x5f,
		0x63, 0x74, 0x72, 0x6c, 0x02, 0x00, 0x00, 0x00,
		0x5d, 0x04, 0x5f, 0x73, 0x65, 0x72, 0x01, 0x00,
		0x00, 0x00, 0x0a, 0x33, 0x39, 0x31, 0x36, 0x34,
		0x30, 0x36, 0x32, 0x37, 0x34, 0x04, 0x5f, 0x74,
		0x69, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x31,
		0x37, 0x31, 0x30, 0x31, 0x34, 0x39, 0x30, 0x32,
		0x31, 0x04, 0x5f, 0x65, 0x78, 0x70, 0x01, 0x00,
		0x00, 0x00, 0x0a, 0x31, 0x37, 0x31, 0x30, 0x31,
		0x34, 0x39, 0x30, 0x38, 0x31, 0x04, 0x5f, 0x72,
		0x70, 0x6c, 0x01, 0x00, 0x00, 0x00, 0x01, 0x31,
		0x06, 0x5f, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x01,
		0x00, 0x00, 0x00, 0x0a, 0x31, 0x35, 0x36, 0x31,
		0x39, 0x39, 0x38, 0x36, 0x36, 0x39, 0x05, 0x5f,
		0x64, 0x61, 0x74, 0x61, 0x02, 0x00, 0x00, 0x00,
		0x1b, 0x04, 0x74, 0x79, 0x70, 0x65, 0x01, 0x00,
		0x00, 0x00, 0x04, 0x6e, 0x75, 0x6c, 0x6c, 0x06,
		0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x01, 0x00,
		0x00, 0x00, 0x01, 0x30,
	},
	"initResponseExpect": []byte(`{"_auth":{"hsha":"\ufffd5SVmzO1AnZk3Wcla3H4MAWV4xdDr/C/AtthtyhhCfTs=\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000"},"_ctrl":{"_exp":"1710149081","_nonce":"1561998669","_rpl":"1","_ser":"3916406274","_tim":"1710149021"},"_data":{"result":"0","type":"null"}}`),
	"commandStatusRequest": {
		0x00, 0x00, 0x00, 0xea,
		0x00, 0x00, 0x00, 0x01, 0x05, 0x5f, 0x61, 0x75,
		0x74, 0x68, 0x02, 0x00, 0x00, 0x00, 0x63, 0x04,
		0x68, 0x73, 0x68, 0x61, 0x01, 0x00, 0x00, 0x00,
		0x59, 0xa3, 0x7a, 0x35, 0x6c, 0x52, 0x56, 0x38,
		0x69, 0x33, 0x6b, 0x39, 0x6d, 0x47, 0x4f, 0x63,
		0x30, 0x62, 0x50, 0x46, 0x57, 0x33, 0x33, 0x71,
		0x56, 0x58, 0x72, 0x6c, 0x4a, 0x6f, 0x6a, 0x35,
		0x6e, 0x67, 0x71, 0x6c, 0x52, 0x46, 0x41, 0x79,
		0x69, 0x66, 0x4d, 0x6b, 0x6b, 0x3d, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x05, 0x5f, 0x63, 0x74, 0x72, 0x6c,
		0x02, 0x00, 0x00, 0x00, 0x52, 0x04, 0x5f, 0x73,
		0x65, 0x72, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x33,
		0x39, 0x31, 0x36, 0x34, 0x30, 0x36, 0x32, 0x37,
		0x35, 0x04, 0x5f, 0x74, 0x69, 0x6d, 0x01, 0x00,
		0x00, 0x00, 0x0a, 0x31, 0x37, 0x31, 0x30, 0x31,
		0x34, 0x39, 0x30, 0x32, 0x31, 0x04, 0x5f, 0x65,
		0x78, 0x70, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x31,
		0x37, 0x31, 0x30, 0x31, 0x34, 0x39, 0x30, 0x38,
		0x31, 0x06, 0x5f, 0x6e, 0x6f, 0x6e, 0x63, 0x65,
		0x01, 0x00, 0x00, 0x00, 0x0a, 0x31, 0x35, 0x36,
		0x31, 0x39, 0x39, 0x38, 0x36, 0x36, 0x39, 0x05,
		0x5f, 0x64, 0x61, 0x74, 0x61, 0x02, 0x00, 0x00,
		0x00, 0x10, 0x04, 0x74, 0x79, 0x70, 0x65, 0x01,
		0x00, 0x00, 0x00, 0x06, 0x73, 0x74, 0x61, 0x74,
		0x75, 0x73,
	},
	"commandStatusRequestExpect": []byte(`{"_auth":{"hsha":"\ufffdz5lRV8i3k9mGOc0bPFW33qVXrlJoj5ngqlRFAyifMkk=\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000"},"_ctrl":{"_exp":"1710149081","_nonce":"1561998669","_ser":"3916406275","_tim":"1710149021"},"_data":{"type":"status"}}`),
	"commandStatusResponse": {
		0x00, 0x00, 0x03, 0x72, 0x00, 0x00, 0x00, 0x01,
		0x05, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x02, 0x00,
		0x00, 0x00, 0x63, 0x04, 0x68, 0x73, 0x68, 0x61,
		0x01, 0x00, 0x00, 0x00, 0x59, 0xa3, 0x63, 0x4c,
		0x35, 0x69, 0x6a, 0x55, 0x2f, 0x77, 0x73, 0x50,
		0x35, 0x37, 0x4f, 0x75, 0x67, 0x53, 0x70, 0x6d,
		0x2f, 0x39, 0x6d, 0x61, 0x4f, 0x30, 0x57, 0x47,
		0x38, 0x35, 0x46, 0x2b, 0x65, 0x73, 0x61, 0x52,
		0x33, 0x76, 0x4c, 0x31, 0x5a, 0x4f, 0x61, 0x61,
		0x41, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x5f,
		0x63, 0x74, 0x72, 0x6c, 0x02, 0x00, 0x00, 0x00,
		0x5d, 0x04, 0x5f, 0x73, 0x65, 0x72, 0x01, 0x00,
		0x00, 0x00, 0x0a, 0x33, 0x39, 0x31, 0x36, 0x34,
		0x30, 0x36, 0x32, 0x37, 0x35, 0x04, 0x5f, 0x74,
		0x69, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x31,
		0x37, 0x31, 0x30, 0x31, 0x34, 0x39, 0x30, 0x32,
		0x31, 0x04, 0x5f, 0x65, 0x78, 0x70, 0x01, 0x00,
		0x00, 0x00, 0x0a, 0x31, 0x37, 0x31, 0x30, 0x31,
		0x34, 0x39, 0x30, 0x38, 0x31, 0x04, 0x5f, 0x72,
		0x70, 0x6c, 0x01, 0x00, 0x00, 0x00, 0x01, 0x31,
		0x06, 0x5f, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x01,
		0x00, 0x00, 0x00, 0x0a, 0x31, 0x35, 0x36, 0x31,
		0x39, 0x39, 0x38, 0x36, 0x36, 0x39, 0x05, 0x5f,
		0x64, 0x61, 0x74, 0x61, 0x02, 0x00, 0x00, 0x02,
		0x8d, 0x04, 0x74, 0x79, 0x70, 0x65, 0x01, 0x00,
		0x00, 0x00, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75,
		0x73, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74,
		0x01, 0x00, 0x00, 0x00, 0x01, 0x30, 0x04, 0x74,
		0x65, 0x78, 0x74, 0x01, 0x00, 0x00, 0x02, 0x66,
		0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3a,
		0x20, 0x42, 0x49, 0x4e, 0x44, 0x20, 0x39, 0x2e,
		0x31, 0x38, 0x2e, 0x32, 0x34, 0x20, 0x28, 0x45,
		0x78, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x20,
		0x53, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x20,
		0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x29,
		0x20, 0x3c, 0x69, 0x64, 0x3a, 0x3e, 0x0a, 0x72,
		0x75, 0x6e, 0x6e, 0x69, 0x6e, 0x67, 0x20, 0x6f,
		0x6e, 0x20, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68,
		0x6f, 0x73, 0x74, 0x3a, 0x20, 0x4c, 0x69, 0x6e,
		0x75, 0x78, 0x20, 0x78, 0x38, 0x36, 0x5f, 0x36,
		0x34, 0x20, 0x36, 0x2e, 0x37, 0x2e, 0x37, 0x2d,
		0x32, 0x30, 0x30, 0x2e, 0x66, 0x63, 0x33, 0x39,
		0x2e, 0x78, 0x38, 0x36, 0x5f, 0x36, 0x34, 0x20,
		0x23, 0x31, 0x20, 0x53, 0x4d, 0x50, 0x20, 0x50,
		0x52, 0x45, 0x45, 0x4d, 0x50, 0x54, 0x5f, 0x44,
		0x59, 0x4e, 0x41, 0x4d, 0x49, 0x43, 0x20, 0x46,
		0x72, 0x69, 0x20, 0x4d, 0x61, 0x72, 0x20, 0x20,
		0x31, 0x20, 0x31, 0x36, 0x3a, 0x35, 0x33, 0x3a,
		0x35, 0x39, 0x20, 0x55, 0x54, 0x43, 0x20, 0x32,
		0x30, 0x32, 0x34, 0x0a, 0x62, 0x6f, 0x6f, 0x74,
		0x20, 0x74, 0x69, 0x6d, 0x65, 0x3a, 0x20, 0x53,
		0x61, 0x74, 0x2c, 0x20, 0x30, 0x39, 0x20, 0x4d,
		0x61, 0x72, 0x20, 0x32, 0x30, 0x32, 0x34, 0x20,
		0x32, 0x31, 0x3a, 0x35, 0x35, 0x3a, 0x32, 0x36,
		0x20, 0x47, 0x4d, 0x54, 0x0a, 0x6c, 0x61, 0x73,
		0x74, 0x20, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
		0x75, 0x72, 0x65, 0x64, 0x3a, 0x20, 0x53, 0x75,
		0x6e, 0x2c, 0x20, 0x31, 0x30, 0x20, 0x4d, 0x61,
		0x72, 0x20, 0x32, 0x30, 0x32, 0x34, 0x20, 0x30,
		0x39, 0x3a, 0x31, 0x35, 0x3a, 0x33, 0x31, 0x20,
		0x47, 0x4d, 0x54, 0x0a, 0x63, 0x6f, 0x6e, 0x66,
		0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f,
		0x6e, 0x20, 0x66, 0x69, 0x6c, 0x65, 0x3a, 0x20,
		0x2f, 0x65, 0x74, 0x63, 0x2f, 0x6e, 0x61, 0x6d,
		0x65, 0x64, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x20,
		0x28, 0x2f, 0x76, 0x61, 0x72, 0x2f, 0x6e, 0x61,
		0x6d, 0x65, 0x64, 0x2f, 0x63, 0x68, 0x72, 0x6f,
		0x6f, 0x74, 0x2f, 0x65, 0x74, 0x63, 0x2f, 0x6e,
		0x61, 0x6d, 0x65, 0x64, 0x2e, 0x63, 0x6f, 0x6e,
		0x66, 0x29, 0x0a, 0x43, 0x50, 0x55, 0x73, 0x20,
		0x66, 0x6f, 0x75, 0x6e, 0x64, 0x3a, 0x20, 0x31,
		0x36, 0x0a, 0x77, 0x6f, 0x72, 0x6b, 0x65, 0x72,
		0x20, 0x74, 0x68, 0x72, 0x65, 0x61, 0x64, 0x73,
		0x3a, 0x20, 0x31, 0x36, 0x0a, 0x55, 0x44, 0x50,
		0x20, 0x6c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x65,
		0x72, 0x73, 0x20, 0x70, 0x65, 0x72, 0x20, 0x69,
		0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65,
		0x3a, 0x20, 0x31, 0x36, 0x0a, 0x6e, 0x75, 0x6d,
		0x62, 0x65, 0x72, 0x20, 0x6f, 0x66, 0x20, 0x7a,
		0x6f, 0x6e, 0x65, 0x73, 0x3a, 0x20, 0x31, 0x30,
		0x33, 0x20, 0x28, 0x39, 0x37, 0x20, 0x61, 0x75,
		0x74, 0x6f, 0x6d, 0x61, 0x74, 0x69, 0x63, 0x29,
		0x0a, 0x64, 0x65, 0x62, 0x75, 0x67, 0x20, 0x6c,
		0x65, 0x76, 0x65, 0x6c, 0x3a, 0x20, 0x30, 0x0a,
		0x78, 0x66, 0x65, 0x72, 0x73, 0x20, 0x72, 0x75,
		0x6e, 0x6e, 0x69, 0x6e, 0x67, 0x3a, 0x20, 0x30,
		0x0a, 0x78, 0x66, 0x65, 0x72, 0x73, 0x20, 0x64,
		0x65, 0x66, 0x65, 0x72, 0x72, 0x65, 0x64, 0x3a,
		0x20, 0x30, 0x0a, 0x73, 0x6f, 0x61, 0x20, 0x71,
		0x75, 0x65, 0x72, 0x69, 0x65, 0x73, 0x20, 0x69,
		0x6e, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x65,
		0x73, 0x73, 0x3a, 0x20, 0x30, 0x0a, 0x71, 0x75,
		0x65, 0x72, 0x79, 0x20, 0x6c, 0x6f, 0x67, 0x67,
		0x69, 0x6e, 0x67, 0x20, 0x69, 0x73, 0x20, 0x4f,
		0x46, 0x46, 0x0a, 0x72, 0x65, 0x63, 0x75, 0x72,
		0x73, 0x69, 0x76, 0x65, 0x20, 0x63, 0x6c, 0x69,
		0x65, 0x6e, 0x74, 0x73, 0x3a, 0x20, 0x30, 0x2f,
		0x39, 0x30, 0x30, 0x2f, 0x31, 0x30, 0x30, 0x30,
		0x0a, 0x74, 0x63, 0x70, 0x20, 0x63, 0x6c, 0x69,
		0x65, 0x6e, 0x74, 0x73, 0x3a, 0x20, 0x30, 0x2f,
		0x31, 0x35, 0x30, 0x0a, 0x54, 0x43, 0x50, 0x20,
		0x68, 0x69, 0x67, 0x68, 0x2d, 0x77, 0x61, 0x74,
		0x65, 0x72, 0x3a, 0x20, 0x30, 0x0a, 0x73, 0x65,
		0x72, 0x76, 0x65, 0x72, 0x20, 0x69, 0x73, 0x20,
		0x75, 0x70, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x72,
		0x75, 0x6e, 0x6e, 0x69, 0x6e, 0x67,
	},
	"commandStatusResponseExpect": []byte(`{"_auth":{"hsha":"\ufffdcL5ijU/wsP57OugSpm/9maO0WG85F+esaR3vL1ZOaaA=\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000"},"_ctrl":{"_exp":"1710149081","_nonce":"1561998669","_rpl":"1","_ser":"3916406275","_tim":"1710149021"},"_data":{"result":"0","text":"version: BIND 9.18.24 (Extended Support Version) \u003cid:\u003e\nrunning on localhost: Linux x86_64 6.7.7-200.fc39.x86_64 #1 SMP PREEMPT_DYNAMIC Fri Mar  1 16:53:59 UTC 2024\nboot time: Sat, 09 Mar 2024 21:55:26 GMT\nlast configured: Sun, 10 Mar 2024 09:15:31 GMT\nconfiguration file: /etc/named.conf (/var/named/chroot/etc/named.conf)\nCPUs found: 16\nworker threads: 16\nUDP listeners per interface: 16\nnumber of zones: 103 (97 automatic)\ndebug level: 0\nxfers running: 0\nxfers deferred: 0\nsoa queries in progress: 0\nquery logging is OFF\nrecursive clients: 0/900/1000\ntcp clients: 0/150\nTCP high-water: 0\nserver is up and running","type":"status"}}`),
}
