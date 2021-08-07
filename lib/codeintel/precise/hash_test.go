package precise

import (
	"testing"
)

var testCasesUUIDs = map[ID]int{
	ID("0137b75b-c9a7-4c05-aae3-9dc41b914a04"): 13,
	ID("05aa486e-f664-4ce6-9ae9-786611d471e9"): 11,
	ID("08a13505-0b20-426a-a3c3-f8f349941b3b"): 11,
	ID("08bb8161-8728-4e7b-9c3a-9a2a4a6b6eae"): 2,
	ID("0bcf76e2-6de7-4503-b6f3-2df7c530969c"): 3,
	ID("0cf0e38b-36bd-42f3-8f94-5078b8bfccb8"): 2,
	ID("0fde6eff-ff98-4818-9338-1fd74fdedd8e"): 17,
	ID("12b310d3-7e9c-49d9-8e1e-26b9f3d2b1b2"): 18,
	ID("1741a48b-244c-4b1c-9257-69e60c2b3e07"): 8,
	ID("178c0748-1c12-4e81-8d69-efa5f1acc27a"): 17,
	ID("17daa15c-e758-4847-95c6-f86ce1ee29b3"): 13,
	ID("180a8e68-8dbd-4589-8daa-785134bc9f8c"): 14,
	ID("18fe43d3-cb82-4b4d-bdec-8551abc20188"): 15,
	ID("1b2b152b-cef3-4401-9695-6cfdb0b2815d"): 3,
	ID("1b92aa0a-840b-4be2-9d7a-d4289907e14f"): 14,
	ID("1c6a56ae-bd17-4e04-9a96-a84ba00e9195"): 9,
	ID("1dc8832d-73cb-4681-88c5-e30559d84448"): 18,
	ID("233ad582-e655-4b3c-aec3-e529a2ffc430"): 9,
	ID("24266871-673f-4a63-a6dd-dca40a165f5d"): 19,
	ID("24483b1e-f68d-4701-9d4e-74487dd34857"): 12,
	ID("245de8c8-f8ea-4aed-a0ba-525c91042a5f"): 8,
	ID("25159339-d03f-4c8e-98a5-3effa8bc8a0f"): 6,
	ID("26178d12-c2b2-4dff-8777-d454b92b9ea7"): 15,
	ID("288252dc-05a4-4647-8217-fcd0d14e168b"): 17,
	ID("29ee2d87-bf5e-468f-bbb6-eefa194c0fe5"): 16,
	ID("2c6e5b58-846f-4a1f-ab56-e15919b5e0b5"): 9,
	ID("33f4bb10-9f30-4cdd-ad10-1681d9a158ad"): 9,
	ID("3464da04-e016-47fe-868b-3c994be33318"): 7,
	ID("347cb0fe-c0c3-4c0d-a6ac-4c04b68bcdbc"): 0,
	ID("38220238-87d1-4fbc-badd-8bd5180f5743"): 1,
	ID("39d635f5-6a9e-4d3b-b294-f296afdb26d4"): 14,
	ID("3ad3e9c4-b443-4892-ad20-57a132e2b23b"): 18,
	ID("3fb852f9-f01a-4443-b966-ab8ebc429349"): 13,
	ID("41c06bad-6ef6-491b-ad77-654e3b95e76e"): 3,
	ID("48a88fd7-f95b-4871-aa38-0ab579fbc3b0"): 17,
	ID("4da4a0f9-4f10-423c-b3dc-f7dd0b67140f"): 13,
	ID("4f3b3d2a-5a90-48c3-aac5-b93adef4c033"): 5,
	ID("5011104e-266d-4d5d-854a-e12468066e65"): 2,
	ID("55279ecf-83ff-4959-a99a-917925f27357"): 17,
	ID("5b680e9c-ba9d-4b8c-b57f-ade8879fcdfe"): 7,
	ID("5e9ef6cd-f4e9-40cf-8132-74f69786d4f9"): 6,
	ID("5efd4d37-1052-474e-b7f1-87df47bfecc8"): 7,
	ID("600d2926-a5d8-4be3-ad6f-74d1e091c7d9"): 16,
	ID("60ec53e7-42cc-45cf-8e1f-8bf617c1b53b"): 16,
	ID("61adc9f2-fd76-4fe8-ad02-5871b499e965"): 1,
	ID("6267187f-2f42-4d81-9eac-e2eb1c40948c"): 6,
	ID("674135ac-d4b9-4114-a869-ec99d4cc6360"): 2,
	ID("67a2dfb2-0dfb-45ac-bbbb-56eb358208e8"): 12,
	ID("67c32649-eb9f-4721-b8d1-0bbc433f9217"): 7,
	ID("6d618539-d3cd-4b8f-b7e8-aa13d309f1d2"): 19,
	ID("6fe3a09c-e108-4b50-ae90-6d3dadea8fa3"): 1,
	ID("74afde92-3b22-49a5-8794-a1f417de92a7"): 16,
	ID("74b320bf-4ede-4269-979d-ffd1bc100e04"): 4,
	ID("77006505-09de-4a84-9f96-7f65c3ea10a1"): 14,
	ID("7a14c4b1-9f4e-4946-b427-37dfab0aa960"): 9,
	ID("7a46463d-c919-45bc-9b4a-d54de5583f7f"): 3,
	ID("7b5a11d9-f7a2-4c03-a802-a528a416a8ce"): 2,
	ID("81e7f5d0-0dd5-4cf0-b1f2-9de83a6d4761"): 17,
	ID("8701ac08-f869-40d4-ace7-3ef7dd2997cb"): 12,
	ID("89b21d63-cc56-447e-8a04-bb151f3c09f2"): 13,
	ID("89c238a9-a9d2-4618-abad-6a27dd0f96f7"): 0,
	ID("8b2b3aec-149c-4b41-afd7-bacefd3b9533"): 6,
	ID("8c71529e-3f28-404a-937c-2def513872c0"): 4,
	ID("8cc9cb17-47d3-4b27-b9b3-3a1e8f08aed5"): 12,
	ID("8e3120ec-c0db-4488-b67f-441ad2b0676e"): 17,
	ID("92583b1a-9299-470b-a4de-607fbc5a6e91"): 16,
	ID("92cfd109-5a65-4913-a5bf-d5258fdcd1ed"): 17,
	ID("9bd99bad-9855-479e-9775-e4850cb33567"): 15,
	ID("9e227c1d-8be9-4cb1-8390-0b14be7a5e40"): 15,
	ID("9f5d16d2-087b-4089-9faa-24bd511f830f"): 2,
	ID("a1aca464-83eb-4ef8-b70e-b02c73fda854"): 5,
	ID("a3714206-4e28-49b8-90c1-e3dc882ad508"): 12,
	ID("a42a5ca5-67c5-4716-b25c-678f613de39b"): 5,
	ID("ac8f675e-7c0d-4068-8921-11429fa037ba"): 16,
	ID("b16b162f-8841-43cc-96b3-706fbec3f5eb"): 8,
	ID("b42486f2-ac98-4a36-bafd-4ff7524f0686"): 6,
	ID("b5ab78b0-4cf4-40f5-bf6f-d6412e98461a"): 4,
	ID("b6e423cd-f052-457a-8826-8bb18e4b38f3"): 19,
	ID("b8bb97f0-50d7-400b-8a18-899491d98c9f"): 11,
	ID("c2e6d56c-5094-4f98-8c2e-f6935f4376cc"): 16,
	ID("cbfc1a17-4a46-440e-a77c-658f00fa769b"): 6,
	ID("cca74f08-8b2a-4f9f-a059-964a2ae8b8cc"): 5,
	ID("cf2aee64-e0e1-4570-a104-2db7e4befc48"): 1,
	ID("d04e169d-5e61-491a-8314-3fea308623a1"): 12,
	ID("d2421fb7-3b3b-4547-9ec0-d9163c3633b4"): 18,
	ID("d3d58031-a099-4519-814a-eb8194a28d97"): 14,
	ID("d3e406d5-a359-4b88-b0d3-db025a957811"): 3,
	ID("d3f07658-2629-45ad-9159-86b738f0b6bf"): 18,
	ID("d905e503-24da-4983-b537-14652745e625"): 9,
	ID("dc53d94d-d7cc-4038-bdd0-a7331c034484"): 5,
	ID("e2574dd3-80f3-4a98-b8fc-73616edc90f5"): 9,
	ID("e59b8eaf-d04d-43cd-bf0b-a6af3154e44e"): 8,
	ID("e9f3ee64-b64d-473d-9c17-d89071cbd223"): 6,
	ID("f2969c9b-b6bf-456b-8969-d38d837c791a"): 9,
	ID("f579f9db-02f5-434a-8af5-2dac5fe44780"): 0,
	ID("f5eab38b-cb20-45b2-b3f2-55531239ca35"): 10,
	ID("f693c26b-7689-40b3-8852-2b38d9295f6c"): 12,
	ID("f7c1f6b3-eecd-44fb-b38d-6942e730ebc4"): 8,
	ID("fcffc897-0c62-433c-ae7c-b5f5f2933f6c"): 4,
	ID("fe84ef0e-c8ec-42ee-ba03-45a017fda5e6"): 9,
}

var testCaseSmallNumbers = map[ID]int{
	ID("0"):  8,
	ID("1"):  9,
	ID("2"):  10,
	ID("3"):  11,
	ID("4"):  12,
	ID("5"):  13,
	ID("6"):  14,
	ID("7"):  15,
	ID("8"):  16,
	ID("9"):  17,
	ID("10"): 7,
	ID("11"): 8,
	ID("12"): 9,
	ID("13"): 10,
	ID("14"): 11,
	ID("15"): 12,
	ID("16"): 13,
	ID("17"): 14,
	ID("18"): 15,
	ID("19"): 16,
	ID("20"): 18,
	ID("21"): 19,
	ID("22"): 0,
	ID("23"): 1,
	ID("24"): 2,
	ID("25"): 3,
	ID("26"): 4,
	ID("27"): 5,
	ID("28"): 6,
	ID("29"): 7,
	ID("30"): 9,
	ID("31"): 10,
	ID("32"): 11,
	ID("33"): 12,
	ID("34"): 13,
	ID("35"): 14,
	ID("36"): 15,
	ID("37"): 16,
	ID("38"): 17,
	ID("39"): 18,
	ID("40"): 0,
	ID("41"): 1,
	ID("42"): 2,
	ID("43"): 3,
	ID("44"): 4,
	ID("45"): 5,
	ID("46"): 6,
	ID("47"): 7,
	ID("48"): 8,
	ID("49"): 9,
	ID("50"): 11,
	ID("51"): 12,
	ID("52"): 13,
	ID("53"): 14,
	ID("54"): 15,
	ID("55"): 16,
	ID("56"): 17,
	ID("57"): 18,
	ID("58"): 19,
	ID("59"): 0,
	ID("60"): 2,
	ID("61"): 3,
	ID("62"): 4,
	ID("63"): 5,
	ID("64"): 6,
	ID("65"): 7,
	ID("66"): 8,
	ID("67"): 9,
	ID("68"): 10,
	ID("69"): 11,
	ID("70"): 13,
	ID("71"): 14,
	ID("72"): 15,
	ID("73"): 16,
	ID("74"): 17,
	ID("75"): 18,
	ID("76"): 19,
	ID("77"): 0,
	ID("78"): 1,
	ID("79"): 2,
	ID("80"): 4,
	ID("81"): 5,
	ID("82"): 6,
	ID("83"): 7,
	ID("84"): 8,
	ID("85"): 9,
	ID("86"): 10,
	ID("87"): 11,
	ID("88"): 12,
	ID("89"): 13,
	ID("90"): 15,
	ID("91"): 16,
	ID("92"): 17,
	ID("93"): 18,
	ID("94"): 19,
	ID("95"): 0,
	ID("96"): 1,
	ID("97"): 2,
	ID("98"): 3,
	ID("99"): 4,
}

var testCasesCoprimes = map[ID]int{
	ID("7"):    15,
	ID("20"):   18,
	ID("33"):   12,
	ID("46"):   6,
	ID("59"):   0,
	ID("72"):   15,
	ID("85"):   9,
	ID("98"):   3,
	ID("111"):  17,
	ID("124"):  11,
	ID("137"):  5,
	ID("150"):  0,
	ID("163"):  14,
	ID("176"):  8,
	ID("189"):  2,
	ID("202"):  8,
	ID("215"):  2,
	ID("228"):  16,
	ID("241"):  11,
	ID("254"):  5,
	ID("267"):  19,
	ID("280"):  14,
	ID("293"):  8,
	ID("306"):  13,
	ID("319"):  7,
	ID("332"):  2,
	ID("345"):  16,
	ID("358"):  10,
	ID("371"):  5,
	ID("384"):  19,
	ID("397"):  13,
	ID("410"):  19,
	ID("423"):  13,
	ID("436"):  7,
	ID("449"):  1,
	ID("462"):  16,
	ID("475"):  10,
	ID("488"):  4,
	ID("501"):  10,
	ID("514"):  4,
	ID("527"):  18,
	ID("540"):  13,
	ID("553"):  7,
	ID("566"):  1,
	ID("579"):  15,
	ID("592"):  10,
	ID("605"):  15,
	ID("618"):  9,
	ID("631"):  4,
	ID("644"):  18,
	ID("657"):  12,
	ID("670"):  7,
	ID("683"):  1,
	ID("696"):  15,
	ID("709"):  0,
	ID("722"):  15,
	ID("735"):  9,
	ID("748"):  3,
	ID("761"):  18,
	ID("774"):  12,
	ID("787"):  6,
	ID("800"):  12,
	ID("813"):  6,
	ID("826"):  0,
	ID("839"):  14,
	ID("852"):  9,
	ID("865"):  3,
	ID("878"):  17,
	ID("891"):  12,
	ID("904"):  17,
	ID("917"):  11,
	ID("930"):  6,
	ID("943"):  0,
	ID("956"):  14,
	ID("969"):  8,
	ID("982"):  3,
	ID("995"):  17,
	ID("1008"): 11,
	ID("1021"): 6,
	ID("1034"): 0,
	ID("1047"): 14,
	ID("1060"): 9,
	ID("1073"): 3,
	ID("1086"): 17,
	ID("1099"): 11,
	ID("1112"): 17,
	ID("1125"): 11,
	ID("1138"): 5,
	ID("1151"): 0,
	ID("1164"): 14,
	ID("1177"): 8,
	ID("1190"): 3,
	ID("1203"): 8,
	ID("1216"): 2,
	ID("1229"): 16,
	ID("1242"): 11,
	ID("1255"): 5,
	ID("1268"): 19,
	ID("1281"): 14,
	ID("1294"): 8,
}

func TestHashKeyUUIDs(t *testing.T) {
	for id, expectedHash := range testCasesUUIDs {
		if value := HashKey(id, 20); value != expectedHash {
			t.Errorf("unexpected hash result for %s. want=%d have=%d", id, expectedHash, value)
		}
	}
}

func TestHashKeySmallNumberss(t *testing.T) {
	for id, expectedHash := range testCaseSmallNumbers {
		if value := HashKey(id, 20); value != expectedHash {
			t.Errorf("unexpected hash result for %s. want=%d have=%d", id, expectedHash, value)
		}
	}
}

func TestHashKeyCoprimes(t *testing.T) {
	for id, expectedHash := range testCasesCoprimes {
		if value := HashKey(id, 20); value != expectedHash {
			t.Errorf("unexpected hash result for %s. want=%d have=%d", id, expectedHash, value)
		}
	}
}