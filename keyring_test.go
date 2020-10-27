package srwallet

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// Note: test vectors used are generated from the Rust implementation of
// subkey v2.0.0 from command line
// https://github.com/paritytech/substrate/tree/master/bin/utils/subkey

const (
	SeedNotAvailable = "_seed_not_available_"
)

func TestKeyRingFromURI(t *testing.T) {

	tests := []struct {
		name   string
		suri   string
		seed   string
		public string
		ss58   string
		net    Network
		valid  bool
	}{

		{
			name:   "Mnemonic 12 Words",
			suri:   "zebra extra skill occur rose muscle reveal robust cigar tilt jungle coral",
			seed:   "0x207e1f885ec7d61421e8ae9eab882d33a1569073c73433c7e7b3042a213bd201",
			public: "0x38c9aaacbf915cdd41e91eb13d3921af7d478e8c9dea39d469805b0ad9c8ff75",
			ss58:   "5DMASqMppiJJZtcSTibW9n6zMyZy71cxSrumEVwcxeFapGZs",
			net:    NetSubstrate,
			valid:  true,
		},
		{
			name:   "Mnemonic 15 Words",
			suri:   "sell where brave oyster update bubble master slab enable furnace ancient ill minor slush mimic",
			seed:   "0x85b1f171aacdbc3795e0e183941aac1c6b815281bbe8bcb75f4eaa5540715a82",
			public: "0x4e2d6e3a0b4021e59020d1f5a30f810f57681e87d2a7d07c266223c369ca701c",
			ss58:   "5DqD63qUHCfTmXLiE1Qd4WSzbYsQQn4cNsjBtHVy5VabNdLr",
			net:    NetSubstrate,
			valid:  true,
		},
		{
			name:   "Mnemonic 18 Words",
			suri:   "drop shoulder tunnel deer actor field enhance penalty rug lady group bean poet differ circle hold input example",
			seed:   "0x002089f945ea12d7265c4f07f3de03c33690e91ff0eda42858d3e906a182ee7d",
			public: "0x2e9177b3e7f40d98394bbbe342712387a69b8c6543fdedb1e34ecb69eb6b0067",
			ss58:   "5D7mGmooYD8VTeigoe1eviiG5YMvFkGuakxvwLDxvyGw6dsm",
			net:    NetSubstrate,
			valid:  true,
		},
		{
			name:   "Mnemonic 21 Words",
			suri:   "model churn flush parent gain shop oval elbow balcony funny logic arrive grid flight reward labor narrow hire coast exclude knee",
			seed:   "0xd78b826f662291ddf5671179c7a6e216caddef6a88c8ceb71799999c4659674b",
			public: "0x08542ab1b1abead33c7363ec4868ad0fba8c4504852d3988672af1419f7d8509",
			ss58:   "5CFdF3gPSAfhuZYcqU5bbnZFh2f8tSZKTV4o6oazU4Ru2cAE",
			net:    NetSubstrate,
			valid:  true,
		},
		{
			name:   "Mnemonic 24 Words",
			suri:   "equal spread inflict bright april route frequent now remember nation token economy similar receive awesome outdoor hard legal turn blade shy define seek bind",
			seed:   "0xf0979b57980e4b484465d26a3fe0b56e7165824034da96cfe588c02cfa69c85c",
			public: "0xdec80fe0805bdf8feffb8b8a4ca561d444ff9b60c2fa34f18f7a6900bedacb79",
			ss58:   "5H6ovDkC6bA2kqH3yrc6WSiyyAGeffojPGDuZHtghfsbDvED",
			net:    NetSubstrate,
			valid:  true,
		},
		{
			name:   "Mnemonic 12 Words With Password",
			suri:   "zebra extra skill occur rose muscle reveal robust cigar tilt jungle coral///pass1234",
			seed:   "0xc72e70f7b35310453060126a9745248e8af2bf5191872081f8330fe46f0ed1da",
			public: "0xd03e41b1f7a6d17a2bf411aa9339b2cfa19c1c50fa36bd0f47df0841bb59af7e",
			ss58:   "5GmkK1KwzDR5NMqxeAaTKDLXhym8QJ3pu8RsjxVaEGAxVsAo",
			net:    NetSubstrate,
			valid:  true,
		},

		{
			name:   "Secret Seed 1",
			suri:   "0x7202a4eba69bb283e8e9a3f5f6f0fc64bb02e6d20fb4b6bde13caec148f2cca7",
			seed:   "0x7202a4eba69bb283e8e9a3f5f6f0fc64bb02e6d20fb4b6bde13caec148f2cca7",
			public: "0xe424e71512d1c55a36ba34f75c0fa81a0afa96b79cdf81b6ed0316498f245f5f",
			ss58:   "5HDqjiNqof8sJLpbNeggYWEJxzHGUahxxt2VLTWy9zgK7nPT",
			net:    NetSubstrate,
			valid:  true,
		},

		{
			name:   "Secret Seed 2",
			suri:   "0xd9f1f67b3c603b5f3230e4c084eabe68dc40e0b2fdcb18d05bde61ffca69a4d2",
			seed:   "0xd9f1f67b3c603b5f3230e4c084eabe68dc40e0b2fdcb18d05bde61ffca69a4d2",
			public: "0x788665a332c5fcfbce881f6bca64b38027f95777f8fb94ff3e2804d0875c0e0b",
			ss58:   "5EnjXZ2mSFYFjJZqveuQzcWSfKLcM722a9wxTF3N12KxXEQE",
			net:    NetSubstrate,
			valid:  true,
		},
		{
			name:   "Secret Seed 3",
			suri:   "0x93a68bd8142c68cd7e3f667c6a696d57a3364f97fe95c9700088984c6d523e4f",
			seed:   "0x93a68bd8142c68cd7e3f667c6a696d57a3364f97fe95c9700088984c6d523e4f",
			public: "0x88c7b487cea1e01392d62e70bfac6e321a1c7a276d57d92ede5062ed90e38079",
			ss58:   "5FA3hDvvp85LEijvPpZZ2eEUvwpxhzy9PCSe6jLiboUx2kA3",
			net:    NetSubstrate,
			valid:  true,
		},

		// rust subkey implementation does not support this (full 64 bytes of a
		// SecretKey as phrase of Secret URI), but does support inputting the
		// first 32 bytes which is the MiniSecretKey
		{
			name:   "Secret Seed Long",
			suri:   "0x7590d644baa64600735ab927b6c353b9594a2cf42fe4d57c2d0e639615b37a6a4993f62e38b81c50688a92ab9b656228a9fd9648f152bb7f41a14b7eaa1c3045",
			seed:   "0x7590d644baa64600735ab927b6c353b9594a2cf42fe4d57c2d0e639615b37a6a",
			public: "0xc61c17f9a3d48ff3f0700081ac7a9c92ef05758d5cc069c41247e4392eb71e00",
			ss58:   "5GYTgcrom3pxWyHCcPPZX6iBB8xWJPARgLAng7MK4ZFaBAza",
			net:    NetSubstrate,
			valid:  true,
		},

		{
			name:   "SS58 Public key 1",
			suri:   "5FA3hDvvp85LEijvPpZZ2eEUvwpxhzy9PCSe6jLiboUx2kA3",
			seed:   SeedNotAvailable,
			public: "0x88c7b487cea1e01392d62e70bfac6e321a1c7a276d57d92ede5062ed90e38079",
			ss58:   "5FA3hDvvp85LEijvPpZZ2eEUvwpxhzy9PCSe6jLiboUx2kA3",
			net:    NetSubstrate,
			valid:  true,
		},

		{
			name:   "SS58 Public key 2",
			suri:   "5DProiES98spRAHhKe3XcGW2carGJAAvHRi35zqpUnZB2RLy",
			seed:   SeedNotAvailable,
			public: "0x3ad8056e0f84fabb8e845e19f12664c910db18b2505a2f329ceeca6a4e0f676c",
			ss58:   "5DProiES98spRAHhKe3XcGW2carGJAAvHRi35zqpUnZB2RLy",
			net:    NetSubstrate,
			valid:  true,
		},
		{
			name:   "SS58 Public key 3",
			suri:   "5DMRrgkfMW4c7sy21ZtBRskKFfVR3T19rmk39Uc1TXJGjKjm",
			seed:   SeedNotAvailable,
			public: "0x38fd8ba8746bef1a0f82809b9b6c123b92b3348637d6ca43b4a9955f20c0e67e",
			ss58:   "5DMRrgkfMW4c7sy21ZtBRskKFfVR3T19rmk39Uc1TXJGjKjm",
			net:    NetSubstrate,
			valid:  true,
		},

		{
			name:   "Mnemonic 12 Words with Soft Path",
			suri:   "zebra extra skill occur rose muscle reveal robust cigar tilt jungle coral/john/account/1",
			seed:   SeedNotAvailable,
			public: "0x74ed93d6a98589a7fdfca305fda9223c8f6ab180efc353bb3e5c590ecc1eba4e",
			ss58:   "5Ei1zCfgteYZ1xv3g9nkRmAFPCSegbKRfAX1XXCMZTg2fDHJ",
			net:    NetSubstrate,
			valid:  true,
		},

		{
			name:   "Mnemonic 24 Words with Soft Path",
			suri:   "glory still valve hair table canyon next ancient vacant hello viable record inside need keen column safe mixture pink cute over buffalo between glove/william/merchant/4",
			seed:   SeedNotAvailable,
			public: "0x8e6d3ed95db62e30623ec3ed28e9fcc186050cd16c996304fa46e2c92707ba35",
			ss58:   "5FHT7JYssN9Vy2PaqMQaNVD17PTRo2Z8kpZW4hk5stzCEfJ6",
			net:    NetSubstrate,
			valid:  true,
		},

		{
			name:   "Mnemonic 12 Words with Hard Path",
			suri:   "zebra extra skill occur rose muscle reveal robust cigar tilt jungle coral//john//account//1",
			seed:   "0xaeb2086a38710871b7774cd2401e38741d64ad9b9209806173971224f50497cb",
			public: "0xcac784bf6c8d59058e0833e43a7c967236ca617efc3a52fc261ea3ae5caa1b74",
			ss58:   "5GeaoJxfADGYHQAZpiwuYJb4EDpoi21fumSU2be6JJ4r5pT5",
			net:    NetSubstrate,
			valid:  true,
		},

		{
			name:   "Mnemonic 12 Words to compare",
			suri:   "zebra extra skill occur rose muscle reveal robust cigar tilt jungle coral",
			seed:   "0x207e1f885ec7d61421e8ae9eab882d33a1569073c73433c7e7b3042a213bd201",
			public: "0x38c9aaacbf915cdd41e91eb13d3921af7d478e8c9dea39d469805b0ad9c8ff75",
			ss58:   "5DMASqMppiJJZtcSTibW9n6zMyZy71cxSrumEVwcxeFapGZs",
			net:    NetSubstrate,
			valid:  true,
		},

		{
			name:   "Mnemonic 24 Words with Hard Path",
			suri:   "glory still valve hair table canyon next ancient vacant hello viable record inside need keen column safe mixture pink cute over buffalo between glove//william//merchant//4",
			seed:   "0x1d6f556684f4820662e712f15d65aeec13a60ef852f1b9591eee1d50c60ae6c8",
			public: "0x00b60ef44c4dc597b346e4249fe739eb6a24c685bb832d0b30344feaa6461621",
			ss58:   "5C5dwTm9vKsZvCyLFPTw87TFFJ3CGsPN3D898YcSZBrB2aWF",
			net:    NetSubstrate,
			valid:  true,
		},

		{
			name:   "Mnemonic 12 Words with Mixed Hard and Soft Path",
			suri:   "zebra extra skill occur rose muscle reveal robust cigar tilt jungle coral//john//ecommerce/1",
			seed:   SeedNotAvailable,
			public: "0xaebb1535c604b3570761e651ec71520541214d62d26d4c591cbc3d056b400329",
			ss58:   "5G1omHQZh6ikqLMvcu8Qjm2ufEYtwHcbB5H6Ernjv5B4VVsA",
			net:    NetSubstrate,
			valid:  true,
		},

		{
			name:   "Mnemonic 24 Words with Mixed Hard and Soft Path",
			suri:   "jump practice jar laundry skate typical cream sound deputy milk myself student feel pumpkin turn crouch piece total behave ability recipe problem maple buffalo/john//ecommerce/1",
			seed:   SeedNotAvailable,
			public: "0xfab6328bc9044a6638842c47139e062cb6c4a3879d34b3565f77be24ee8a8f7b",
			ss58:   "5HjRxBjX8dCgp3GCnURzM9jWikH812KSHJiRCKmnuD58GX8m",
			net:    NetSubstrate,
			valid:  true,
		},
		{
			name:   "Secret Seed with Soft Path",
			suri:   "0x7202a4eba69bb283e8e9a3f5f6f0fc64bb02e6d20fb4b6bde13caec148f2cca7/william/merchant/4",
			seed:   SeedNotAvailable,
			public: "0x06fb0d716d993000a966ffa43d14c1fa489ae22473a597e0206a6e70f885ae22",
			ss58:   "5CDrisDrtfZ7XURW3WLZHa1tj9PKrcgwKxDjY86HeyP3gQsf",
			net:    NetSubstrate,
			valid:  true,
		},
		{
			name:   "Secret Seed with Hard Path",
			suri:   "0x7202a4eba69bb283e8e9a3f5f6f0fc64bb02e6d20fb4b6bde13caec148f2cca7//john//account//1",
			seed:   "0xfb41ee7a829d945f313d5920a6a198dd2a3c5a29ca5a420cae300a0645bad4ae",
			public: "0xd4d72d70331d1697670496a9b9768a905bb2841bf73011731cb22d9d3f063e66",
			ss58:   "5Gsmvt3rgeZT2p2CzZhcPLY8AT3y8bpFg2BLEodgj8LeTYDJ",
			net:    NetSubstrate,
			valid:  true,
		},
		{
			name:   "Secret Seed with Mixed Hard and Soft Path",
			suri:   "0x7202a4eba69bb283e8e9a3f5f6f0fc64bb02e6d20fb4b6bde13caec148f2cca7/john//account/3",
			seed:   SeedNotAvailable,
			public: "0x2e30c33f476090a2596512ddad111925058e9831211e169b86e223a95d2c203f",
			ss58:   "5D7GYayh56P5kNVF2xD32GRsJFHDosTQKzMwThpyb5Fr5v3p",
			net:    NetSubstrate,
			valid:  true,
		},

		{
			name:   "SS58 Public key with Soft Path",
			suri:   "5FA3hDvvp85LEijvPpZZ2eEUvwpxhzy9PCSe6jLiboUx2kA3/william/merchant/4",
			seed:   SeedNotAvailable,
			public: "0x44d3daa4329577491e40ee1aa7993f361ce400481229e2ced48eda95ab14095a",
			ss58:   "5Dcx3gn724fqkEUv6mhjiT4tF2DmKvmWHkhWrUY2bWP923gQ",
			net:    NetSubstrate,
			valid:  true,
		},

		{
			name:   "SS58 Public key with Hard Path",
			suri:   "5FA3hDvvp85LEijvPpZZ2eEUvwpxhzy9PCSe6jLiboUx2kA3//john//account//1",
			seed:   "",
			public: "",
			ss58:   "",
			net:    NetSubstrate,
			valid:  false,
		},
		{
			name:   "SS58 Public key with Mixed Hard and Soft Path",
			suri:   "5FA3hDvvp85LEijvPpZZ2eEUvwpxhzy9PCSe6jLiboUx2kA3/john//account/3",
			seed:   "",
			public: "",
			ss58:   "",
			net:    NetSubstrate,
			valid:  false,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kr, err := KeyRingFromURI(tt.suri, tt.net)

			if err != nil {
				if !tt.valid {
					// invalid suri, test completed successfully on expected error
					return
				}

				t.Fatalf("Error generating keyring: %v", err)
			}

			// check public address
			if kr.PublicHex() != tt.public {
				t.Errorf("Invalid public key, expected %v, got %v", tt.public, kr.PublicHex())
			}

			// check seed
			if tt.seed != SeedNotAvailable {
				seed, err := kr.SeedHex()

				if err != nil {
					t.Fatalf("Error getting seed hex: %v", err)
				}

				if seed != tt.seed {
					t.Errorf("Invalid seed, expected %v, got %v", tt.seed, seed)
				}
			}
		})
	}
}

// msgTests are vectors for signing and verifying message signatures
var msgTests = []struct {
	name string
	suri string
	net  Network
	msg  []byte
	sig  string
	ss58 string
}{
	{
		name: "Message 1",
		suri: "zebra extra skill occur rose muscle reveal robust cigar tilt jungle coral",
		net:  NetSubstrate,
		msg:  []byte("test message"),
		sig:  "5e2da2d9b0aca37d3eed5c16d3882d01e664eb1a635d4fddbb79a4a584915e13d0346e48f6c6886b6d352953ad46864303acb6049e3201cc882b11367f31d98d",
		ss58: "5DMASqMppiJJZtcSTibW9n6zMyZy71cxSrumEVwcxeFapGZs",
	},
	{
		name: "Message 2",
		suri: "road unhappy relief august shoulder dose identify switch ozone monster sniff label pool dizzy once latin bunker solve harvest eagle boring tank awesome museum",
		net:  NetSubstrate,
		msg:  []byte("hello over there"),
		sig:  "8acbc31d06f93dd6aa009c00218238b5a154bd6fe688a7081543602a624f325348b86d1e9430d147d6e0d8633e4f6c6d86b25f6d8450a3c9a4381d4fa6558f83",
		ss58: "5DLnV45a5qTUdetG1cQd6z6LF9HqJWsZepKXNcmTyXkUu6LX",
	},
	{
		name: "Message 3",
		suri: "occur myself unveil gun flight valid trash sail crack desk rhythm add//joe//account/1///pass1234",
		net:  NetSubstrate,
		msg:  []byte("10th planet"),
		sig:  "d0084134a76d1fc912aa853537fadb93c89f6be59aecda97e231998cb524361124a50c6424bb6b172af5ed94f9de0e8f6bf61875626d52e6667f8a8fbc4f4984",
		ss58: "5GUA4Uj57vh94fPcji4ctGsnQRY6dFHt1PdPE5YuSggscgpt",
	},
}

func TestSign(t *testing.T) {

	for _, tt := range msgTests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kr, err := KeyRingFromURI(tt.suri, tt.net)

			if err != nil {
				t.Fatalf("Error generating key ring: %v", err)
			}

			ss58, err := kr.SS58Address()

			if err != nil {
				t.Fatalf("Error getting ss58 Address: %v", err)
			}

			if ss58 != tt.ss58 {
				t.Fatalf("SS58 Address does not match, expected %v, got %v", tt.ss58, ss58)
			}

			sig, err := kr.Sign(kr.SigningContext(tt.msg))

			if err != nil {
				t.Fatalf("Error signing message: %v", err)
			}

			if !kr.Verify(kr.SigningContext(tt.msg), sig) {
				t.Errorf("Error invalid signature for message")
			}
		})
	}
}

func TestVerify(t *testing.T) {

	for _, tt := range msgTests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kr, err := KeyRingFromURI(tt.ss58, tt.net)

			if err != nil {
				t.Fatalf("Error generating key ring: %v", err)
			}

			sig, err := hex.DecodeString(tt.sig)

			if err != nil {
				t.Fatalf("Invalid hex decode: %v", err)
			}

			var sigB [64]byte
			copy(sigB[:], sig)

			if !kr.Verify(kr.SigningContext(tt.msg), sigB) {
				t.Errorf("Error signature does not verify")
			}
		})
	}
}

// TestKeyRingSharing runs an integration test consisting of two parties, (i) the
// keyring "Owner", and (ii) a "Website" with HD key to receive payments from.
func TestKeyRingSharing(t *testing.T) {

	tests := []struct {
		name   string
		params func() (owner, website, pay *keyRingParams)
	}{
		{
			name:   "Params 1",
			params: getKeyRingParams1,
		},
		{
			name:   "Params 2",
			params: getKeyRingParams2,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			owner, web, pay := tt.params()
			commonKeyRingSharing(t, owner, web, pay)
		})
	}
}

// commonKeyRingSharing provides common functions to running multiple sharing
// tests using different KeyRing parameters
func commonKeyRingSharing(t *testing.T, ownerParams, websiteParams, payParams *keyRingParams) {

	// create Owner master keyring
	_, err := createKeyRing(ownerParams)

	if err != nil {
		t.Fatalf("Error generating Owner keyring: %v", err)
	}

	// owner then generates hard key for Website to use
	websiteKr, err := createKeyRing(websiteParams)

	if err != nil {
		t.Fatalf("Error generating Website keyring: %v", err)
	}

	// owner takes websiteKr public key as ss58 address and shares that
	// with the Website administrator who generates a unique address to receive
	// payment too
	payKr, err := createKeyRing(payParams)

	if err != nil {
		t.Fatalf("Error generating Payment keyring: %v", err)
	}

	// the customer makes payment to the payAddr
	payAddr, err := payKr.SS58Address()

	if err != nil {
		t.Fatalf("Error generating Payment SS58 Address: %v", err)
	}

	if payAddr != payParams.ss58 {
		t.Errorf("Invalid payment address, expected %v, got %v", payParams.ss58, payAddr)
	}

	// Using the websiteKr generate the pay address, which proves we can
	// claim these funds
	webSeedHex, err := websiteKr.SeedHex()

	if err != nil {
		t.Fatalf("Error getting Website wallet seed: %v", err)
	}

	websiteClaimSuri := fmt.Sprintf(websiteParams.suriPath, webSeedHex)
	websiteClaimWallet, err := KeyRingFromURI(websiteClaimSuri, NetSubstrate)

	if err != nil {
		t.Fatalf("Error generating Website claim keyring: %v", err)
	}

	websiteClaimAddr, err := websiteClaimWallet.SS58Address()

	if err != nil {
		t.Fatalf("Error generating Website claim SS58 Address: %v", err)
	}

	if websiteClaimAddr != payParams.ss58 {
		t.Errorf("Invalid Website claim address, expected %v, got %v", payParams.ss58, websiteClaimAddr)
	}

	// Using the ownerKr generate the pay address, proving we can claim
	// these funds
	ownerClaimSuri := fmt.Sprintf(ownerParams.suriPath, ownerParams.seed)

	ownerClaimWallet, err := KeyRingFromURI(ownerClaimSuri, NetSubstrate)

	if err != nil {
		t.Fatalf("Error generating Wwner claim keywring: %v", err)
	}

	ownerClaimAddr, err := ownerClaimWallet.SS58Address()

	if err != nil {
		t.Fatalf("Error generating Wwner Claim SS58 Address: %v", err)
	}

	if ownerClaimAddr != payParams.ss58 {
		t.Errorf("Invalid Owner claim address, expected %v, got %v", payParams.ss58, ownerClaimAddr)
	}
}

// keyRingParams define parameters for createKeyRing()
type keyRingParams struct {
	// suriPath is the Sprintf format string to use for suri construction path
	// for generating the claim/pay address
	suriPath string
	// suri is the SecretURI to generated wallet from
	suri string
	// net is the Network to use when generating wallet
	net Network
	// public is expected public key hex encoded
	public string
	// ss58 is the expected SS58 encoded public key
	ss58 string
	// seed is the expected hex encoded seed
	seed string
}

func getKeyRingParams1() (owner, website, pay *keyRingParams) {

	owner = &keyRingParams{
		suriPath: "%s//website/payment/42",
		suri:     "ball salmon member claw ignore virus such fiber settle brain exact gasp",
		net:      NetSubstrate,
		public:   "0x74e547d29920767fc0eb797f184955f624fcc97a7e3e879b405be85eeee96903",
		ss58:     "5EhyXFQ9KcD28jLMG92exuNciZcxBgbf78FVWrHh5YS5Czug",
		seed:     "0xc9933cfd5062176aa69eae3bc584114a38139530d0de242dea6484a142b55f3a",
	}

	website = &keyRingParams{
		suriPath: "%s/payment/42",
		suri:     fmt.Sprintf("%s//website", owner.seed),
		net:      NetSubstrate,
		public:   "0xf80241969be849eef0c50c11c54604197e3f119dbb61ee120737942c2cbae963",
		ss58:     "5HftQKGjZUA5da11bw9fAK4cpTNWrKWEnbc91AgMMPyQtfxC",
		seed:     "0x23d2ae93b27a340a94c286b5760e13435545664b87ee13c086a4ad1b4ce4c68a",
	}

	pay = &keyRingParams{
		suriPath: "",
		suri:     fmt.Sprintf("%s/payment/42", website.ss58),
		net:      NetSubstrate,
		public:   "0xc65f6a5657ecd41a3e83b2896d417a3a761239ce8039a98ccd6ec0d5e7a39431",
		ss58:     "5GYogYb4JGK73JvjxHGtNGtWaPpnMPfd9eVGyyG5UrVc4mye",
		seed:     "",
	}

	return
}

func getKeyRingParams2() (owner, website, pay *keyRingParams) {

	owner = &keyRingParams{
		suriPath: "%s//website/payment/56",
		suri:     "return adult session save cruise finger stem hotel food say grant muscle///pass1234",
		net:      NetSubstrate,
		public:   "0xf44d0f1186700b4d5e804086a5cac9abd568a23af4a00695251dc8893155ca21",
		ss58:     "5Hb2S2UvbAALCmHKCdB7hZd6un8KF5qNbY4cwxaFiUuGuZMT",
		seed:     "0x8577f977bd802723541d4b516f2afa1aea94301fbc2ba805bf8b0a4d37088871",
	}

	website = &keyRingParams{
		suriPath: "%s/payment/56",
		suri:     fmt.Sprintf("%s//website", owner.seed),
		net:      NetSubstrate,
		public:   "0xe694c3e4c07e43b882b2ff1e239a5b4407dfcbf1114c3ce8f13190d76708466b",
		ss58:     "5HH34cf7E8S1oKqGDA5FGojqZXZSkxB3U9GChfEt6PEzVqKZ",
		seed:     "0xd195124dd461d988720bb273c058c55a39bcb45adfe457178ac2f981c1c805e8",
	}

	pay = &keyRingParams{
		suriPath: "",
		suri:     fmt.Sprintf("%s/payment/56", website.ss58),
		net:      NetSubstrate,
		public:   "0x6a0b8913b41eb405f7e2461e014acfdf0e1ee756e127ea6b446e2e4501e7df17",
		ss58:     "5ETkMpEd5Af7d3aMBpwNVv8sRa4Y1aRBvNSfycZq1ekWPGrN",
		seed:     "",
	}

	return
}

// createKeyRing with given parameters and test they match expected values
func createKeyRing(p *keyRingParams) (*KeyRing, error) {

	wallet, err := KeyRingFromURI(p.suri, p.net)

	if err != nil {
		return nil, fmt.Errorf("Error generating Owner keyring: %w", err)
	}

	ss58Key, err := wallet.SS58Address()

	if err != nil {
		return nil, fmt.Errorf("Error generating Owner wallet SS58 Address: %w", err)
	}

	if p.seed != "" {
		seed, err := wallet.SeedHex()

		if err != nil {
			return nil, fmt.Errorf("Error getting seed: %w", err)
		}

		if seed != p.seed {
			return nil, fmt.Errorf("Unexpected seed: %s", seed)
		}
	}

	// check ownerWallet against expected values
	if wallet.PublicHex() != p.public {
		return nil, fmt.Errorf("Unexpected public address: %s", wallet.PublicHex())
	}

	if ss58Key != p.ss58 {
		return nil, fmt.Errorf("Unexpected SS58 address: %s", ss58Key)
	}

	return wallet, nil
}

// vrfMsgTests are vectors for VRF signing and verifying of message proofs
// output and proof fields generated from rust library using "seed"
var vrfMsgTests = []struct {
	name   string
	suri   string
	net    Network
	msg    []byte
	ss58   string
	output string
	proof  string
}{
	{
		name:   "Message 1",
		suri:   "zebra extra skill occur rose muscle reveal robust cigar tilt jungle coral",
		net:    NetSubstrate,
		msg:    []byte("test message"),
		ss58:   "5DMASqMppiJJZtcSTibW9n6zMyZy71cxSrumEVwcxeFapGZs",
		output: "9642ba293adcd5fa308f443fb110750dc2c83c67f4d8ed1738bdbd66345b1b4f",
		proof:  "41fd3bee4394b0dceba0edc4dd835d1b80763cf5a2753b21012d8bf417c4a703aacbfe8649a49cac3690d17fa44be77bd9200978e235f40dd8351e91480cf400",
	},
	{
		name:   "Message 2",
		suri:   "glory still valve hair table canyon next ancient vacant hello viable record inside need keen column safe mixture pink cute over buffalo between glove//william//merchant//4",
		net:    NetSubstrate,
		msg:    []byte("setec astronomy"),
		ss58:   "5C5dwTm9vKsZvCyLFPTw87TFFJ3CGsPN3D898YcSZBrB2aWF",
		output: "e86d5dcddb950942573a459e58f4fc47c9d024dc77bd0a13e14b03f6ff027d7f",
		proof:  "5f9fc4c101a15e6c66f16b72761a47a17fe68b3e2b568bfe884b476369d8a30a26d8b53bbc8340672246725b7f56dca2a94058dba84b299bb3873d0706c5f90c",
	},
}

func TestVrfSign(t *testing.T) {

	for _, tt := range vrfMsgTests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kr, err := KeyRingFromURI(tt.suri, tt.net)

			if err != nil {
				t.Fatalf("Error generating key ring: %v", err)
			}

			ss58, err := kr.SS58Address()

			if err != nil {
				t.Fatalf("Error getting ss58 Address: %v", err)
			}

			if ss58 != tt.ss58 {
				t.Fatalf("SS58 Address does not match, expected %v, got %v", tt.ss58, ss58)
			}

			out, proof, err := kr.VrfSign(kr.SigningContext(tt.msg))

			if err != nil {
				t.Fatalf("Error during VrfSign: %v", err)
			}

			valid, err := kr.VrfVerify(kr.SigningContext(tt.msg), out, proof)

			if err != nil {
				t.Fatalf("Error during VrfVerify: %v", err)
			}

			if !valid {
				t.Errorf("Error invalid output and proof")
			}
		})
	}
}

func TestVrfVerify(t *testing.T) {

	for _, tt := range vrfMsgTests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kr, err := KeyRingFromURI(tt.ss58, tt.net)

			if err != nil {
				t.Fatalf("Error generating key ring: %v", err)
			}

			output, err := hex.DecodeString(tt.output)

			if err != nil {
				t.Fatalf("Invalid hex decode for output: %v", err)
			}

			proof, err := hex.DecodeString(tt.proof)

			if err != nil {
				t.Fatalf("Invalid hex decode for proof: %v", err)
			}

			var outB [32]byte
			var proofB [64]byte
			copy(outB[:], output)
			copy(proofB[:], proof)

			valid, err := kr.VrfVerify(kr.SigningContext(tt.msg), outB, proofB)

			if err != nil {
				t.Fatalf("Error during VrfVerify: %v", err)
			}

			if !valid {
				t.Errorf("Error invalid output and proof")
			}
		})
	}
}

func BenchmarkSign(b *testing.B) {
	b.ReportAllocs()

	kr, err := KeyRingFromURI(msgTests[0].suri, msgTests[0].net)

	if err != nil {
		b.Fatalf("Error generating Keyring: %v", err)
	}

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		_, err := kr.Sign(kr.SigningContext(msgTests[0].msg))

		if err != nil {
			b.Fatalf("Error signing message: %v", err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	b.ReportAllocs()

	kr, err := KeyRingFromURI(msgTests[0].ss58, msgTests[0].net)

	if err != nil {
		b.Fatalf("Error generating Keyring: %v", err)
	}

	raw, err := hex.DecodeString(msgTests[0].sig)

	if err != nil {
		b.Fatalf("Error decoding hex signature: %v", err)
	}

	var sig [64]byte
	copy(sig[:], raw)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		_ = kr.Verify(kr.SigningContext(msgTests[0].msg), sig)
	}
}

func BenchmarkVrfSign(b *testing.B) {
	b.ReportAllocs()

	kr, err := KeyRingFromURI(vrfMsgTests[0].suri, vrfMsgTests[0].net)

	if err != nil {
		b.Fatalf("Error generating Keyring: %v", err)
	}

	t := kr.SigningContext(vrfMsgTests[0].msg)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		_, _, err := kr.VrfSign(t)

		if err != nil {
			b.Fatalf("Error signing message: %v", err)
		}
	}
}

func BenchmarkVrfVerify(b *testing.B) {
	b.ReportAllocs()

	kr, err := KeyRingFromURI(vrfMsgTests[0].suri, vrfMsgTests[0].net)

	if err != nil {
		b.Fatalf("Error generating Keyring: %v", err)
	}

	outraw, err := hex.DecodeString(vrfMsgTests[0].output)

	if err != nil {
		b.Fatalf("Error decoding hex output: %v", err)
	}

	var output [32]byte
	copy(output[:], outraw)

	proofraw, err := hex.DecodeString(vrfMsgTests[0].proof)

	if err != nil {
		b.Fatalf("Error decoding hex proof: %v", err)
	}

	var proof [64]byte
	copy(proof[:], proofraw)

	t := kr.SigningContext(vrfMsgTests[0].msg)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		_, err := kr.VrfVerify(t, output, proof)

		if err != nil {
			b.Fatalf("Error verifying message: %v", err)
		}
	}
}
