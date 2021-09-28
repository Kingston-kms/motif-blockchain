package launcher

import (

	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"path"
	"strings"
	"time" 

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"gopkg.in/urfave/cli.v1"

	"github.com/motifd/motif-blockchain/inter/validatorpk"
	"github.com/motifd/motif-blockchain/valkeystore"
	"github.com/motifd/motif-blockchain/valkeystore/encryption"
	
	"github.com/ethereum/go-ethereum/accounts/keystore" 
	"github.com/motifd/motif-blockchain/inter" 
	"github.com/ethereum/go-ethereum/common/hexutil"  







 
	"math/big"
	"os" 
	"github.com/Fantom-foundation/lachesis-base/inter/idx"
	"github.com/Fantom-foundation/lachesis-base/hash" 
	"github.com/ethereum/go-ethereum/core/types" 
	"github.com/motifd/motif-blockchain/motif"
	"github.com/motifd/motif-blockchain/motif/genesis"
	"github.com/motifd/motif-blockchain/motif/genesis/driver"
	"github.com/motifd/motif-blockchain/motif/genesis/driverauth"
	"github.com/motifd/motif-blockchain/motif/genesis/evmwriter"
	"github.com/motifd/motif-blockchain/motif/genesis/gpos"
	"github.com/motifd/motif-blockchain/motif/genesis/netinit"
	"github.com/motifd/motif-blockchain/motif/genesis/sfc" 
	"github.com/motifd/motif-blockchain/motif/genesisstore" 
	 futils "github.com/motifd/motif-blockchain/utils"
)

var (
	TestGenesisTime = inter.Timestamp(uint64(time.Now().UnixNano()))

	validatorCommand = cli.Command{
		Name:     "validator",
		Usage:    "Manage validators",
		Category: "VALIDATOR COMMANDS",
		Description: `

Create a new validator private key.

It supports interactive mode, when you are prompted for password as well as
non-interactive mode where passwords are supplied via a given password file.
Non-interactive mode is only meant for scripted use on test networks or known
safe environments.

Make sure you remember the password you gave when creating a new validator key.
Without it you are not able to unlock your validator key.

Note that exporting your key in unencrypted format is NOT supported.

Keys are stored under <DATADIR>/keystore/validator.
It is safe to transfer the entire directory or the individual keys therein
between Motif nodes by simply copying.

Make sure you backup your keys regularly.`,
		Subcommands: []cli.Command{
			{
				Name:   "new",
				Usage:  "Create a new validator key",
				Action: utils.MigrateFlags(validatorKeyCreate),
				Flags: []cli.Flag{
					utils.DataDirFlag,
					utils.KeyStoreDirFlag,
					utils.PasswordFileFlag,
				},
				Description: `
    motif validator new

Creates a new validator private key and prints the public key.

The key is saved in encrypted format, you are prompted for a passphrase.

You must remember this passphrase to unlock your key in the future.

For non-interactive use the passphrase can be specified with the --validator.password flag:

Note, this is meant to be used for testing only, it is a bad idea to save your
password to file or expose in any other way.
`,
			},
			{
				Name:   "convert",
				Usage:  "Convert an account key to a validator key",
				Action: utils.MigrateFlags(validatorKeyConvert),
				Flags: []cli.Flag{
					utils.DataDirFlag,
					utils.KeyStoreDirFlag,
				},
				ArgsUsage: "<account address> <validator pubkey>",
				Description: `
    motif validator convert

Converts an account private key to a validator private key and saves in the validator keystore.
`,
			},
		},
	}
)

// validatorKeyCreate creates a new validator key into the keystore defined by the CLI flags.
func validatorKeyCreate(ctx *cli.Context) error {
	cfg := makeAllConfigs(ctx)
	utils.SetNodeConfig(ctx, &cfg.Node)

	scryptN, scryptP, keydir, err := cfg.Node.AccountConfig()

	password := getPassPhrase("Your new validator key is locked with a password. Please give a password. Do not forget this password.", true, 0, utils.MakePasswordList(ctx))

	
	if err != nil {
		utils.Fatalf("Failed to read configuration: %v", err)
	}


	/// CREATE VALIDATOR 1 ///  
 
	account, err := keystore.StoreKey(keydir, password, scryptN, scryptP)
	fmt.Printf("Path of the secret key file: %s\n\n", account.URL.Path)
	if err != nil {
		utils.Fatalf("Failed to create account: %v", err)
	}
	fmt.Printf("\nYour new key was generated\n\n")
	fmt.Printf("Public address of the key:   %s\n", account.Address.Hex())
	fmt.Printf("Path of the secret key file: %s\n\n", account.URL.Path) 
 

	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		utils.Fatalf("Failed to create account: %v", err)
	}
	privateKey := crypto.FromECDSA(privateKeyECDSA)
	publicKey := validatorpk.PubKey{
		Raw:  crypto.FromECDSAPub(&privateKeyECDSA.PublicKey),
		Type: validatorpk.Types.Secp256k1,
	}

	valKeystore := valkeystore.NewDefaultFileRawKeystore(path.Join(getValKeystoreDir(cfg.Node), "validator"))
	err = valKeystore.Add(publicKey, privateKey, password)
	if err != nil {
		utils.Fatalf("Failed to create account: %v", err)
	}

	// Sanity check
	_, err = valKeystore.Get(publicKey, password)
	if err != nil {
		utils.Fatalf("Failed to decrypt the account: %v", err)
	}

	valaddress := crypto.PubkeyToAddress(privateKeyECDSA.PublicKey)

	fmt.Printf("\nYour new key was generated\n\n")
	fmt.Printf("Public key:                  %s\n", publicKey.String())
	fmt.Printf("Path of the secret key file: %s\n\n", valKeystore.PathOf(publicKey))
	fmt.Printf("ETH Private key:                  %s\n", hexutil.Encode(privateKey) ) 
	fmt.Printf("ETH Wallet Address:                  %s\n", valaddress ) 




	/// CREATE VALIDATOR 2 /// 
	keydir2 := "/Users/cnrck/Desktop/dev/motif/blockchain/motif-blockchain/build/validator2data/keystore"
	account2, err := keystore.StoreKey(keydir2, password, scryptN, scryptP)
	fmt.Printf("Path of the secret key file: %s\n\n", account2.URL.Path)
	if err != nil {
		utils.Fatalf("Failed to create account: %v", err)
	}
	fmt.Printf("\nYour new key was generated\n\n")
	fmt.Printf("Public address of the key:   %s\n", account2.Address.Hex())
	fmt.Printf("Path of the secret key file: %s\n\n", account2.URL.Path) 
 

	privateKeyECDSA2, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		utils.Fatalf("Failed to create account: %v", err)
	}
	privateKey2 := crypto.FromECDSA(privateKeyECDSA2)
	publicKey2 := validatorpk.PubKey{
		Raw:  crypto.FromECDSAPub(&privateKeyECDSA2.PublicKey),
		Type: validatorpk.Types.Secp256k1,
	}

	valKeystore2 := valkeystore.NewDefaultFileRawKeystore(path.Join(keydir2, "validator"))
	err = valKeystore2.Add(publicKey2, privateKey2, password)
	if err != nil {
		utils.Fatalf("Failed to create account: %v", err)
	}

	// Sanity check
	_, err = valKeystore2.Get(publicKey2, password)
	if err != nil {
		utils.Fatalf("Failed to decrypt the account: %v", err)
	}

	valaddress2 := crypto.PubkeyToAddress(privateKeyECDSA2.PublicKey)

	fmt.Printf("\nYour new key was generated 2\n\n")
	fmt.Printf("Public key 2:                  %s\n", publicKey2.String())
	fmt.Printf("Path of the secret key file 2: %s\n\n", valKeystore2.PathOf(publicKey2))
	fmt.Printf("ETH Private key 2:                  %s\n", hexutil.Encode(privateKey2) ) 
	fmt.Printf("ETH Wallet Address 2:                  %s\n", valaddress2 ) 




	// CREATE GENSTORE /// 
	///////// INITIAL...REMOVE BELOW AFTER CREATION ///////// 
		
		genStore := genesisstore.NewMemStore() 
		genStore.SetRules(motif.MainNetRules())
		totalSupply := new(big.Int) 
		validatorID := idx.ValidatorID(1) 
		validatorID2 := idx.ValidatorID(1) 
 
		genStore.SetEvmAccount(valaddress, genesis.Account{
			Code:    []byte{},
			Balance: futils.ToMotif(10000000),//10M
			Nonce:   0,
		})

		genStore.SetEvmAccount(account.Address, genesis.Account{
			Code:    []byte{},
			Balance: futils.ToMotif(10000000), //10M
			Nonce:   0,
		})


		///-> ADD DELEGATION to 2 VALIDATOR ADDRESES ////
		genStore.SetDelegation(valaddress, validatorID, genesis.Delegation{
			Stake:              futils.ToMotif(1000000), //1M
			Rewards:            new(big.Int),
			LockedStake:        new(big.Int),
			LockupFromEpoch:    0,
			LockupEndTime:      0,
			LockupDuration:     0,
			EarlyUnlockPenalty: new(big.Int),
		})

		genStore.SetDelegation(valaddress2, validatorID2, genesis.Delegation{
			Stake:              futils.ToMotif(1000000), //1M
			Rewards:            new(big.Int),
			LockedStake:        new(big.Int),
			LockupFromEpoch:    0,
			LockupEndTime:      0,
			LockupDuration:     0,
			EarlyUnlockPenalty: new(big.Int),
		})
		
		totalSupply.Add(totalSupply, futils.ToMotif(10000000) )
		var owner common.Address  
		owner = valaddress

		///-> CREATE 2 VALIDATORS ////
		validators := make(gpos.Validators, 0, validatorID) 
		validators = append(validators, gpos.Validator{
			ID:      validatorID,
			Address: valaddress,
			PubKey: validatorpk.PubKey{
				Raw:  crypto.FromECDSAPub(&privateKeyECDSA.PublicKey),
				Type: validatorpk.Types.Secp256k1,
			},
			CreationTime:     TestGenesisTime,
			CreationEpoch:    0,
			DeactivatedTime:  0,
			DeactivatedEpoch: 0,
			Status:           0,
		}) 

		validators = append(validators, gpos.Validator{
			ID:      validatorID2,
			Address: valaddress2,
			PubKey: validatorpk.PubKey{
				Raw:  crypto.FromECDSAPub(&privateKeyECDSA2.PublicKey),
				Type: validatorpk.Types.Secp256k1,
			},
			CreationTime:     TestGenesisTime,
			CreationEpoch:    0,
			DeactivatedTime:  0,
			DeactivatedEpoch: 0,
			Status:           0,
		})
		///-< ADD 2 VALIDATORS ////


		genStore.SetMetadata(genesisstore.Metadata{
			Validators:    validators,
			FirstEpoch:    2,
			Time:          TestGenesisTime,
			PrevEpochTime: TestGenesisTime - inter.Timestamp(time.Hour),
			ExtraData:     []byte(""),
			DriverOwner:   owner,
			TotalSupply:   totalSupply,
		})
		genStore.SetBlock(0, genesis.Block{
			Time:        TestGenesisTime - inter.Timestamp(time.Minute),
			Atropos:     hash.Event{},
			Txs:         types.Transactions{},
			InternalTxs: types.Transactions{},
			Root:        hash.Hash{},
			Receipts:    []*types.ReceiptForStorage{},
		})
		// pre deploy NetworkInitializer
		genStore.SetEvmAccount(netinit.ContractAddress, genesis.Account{
			Code:    netinit.GetContractBin(),
			Balance: new(big.Int),
			Nonce:   0,
		})
		// pre deploy NodeDriver
		genStore.SetEvmAccount(driver.ContractAddress, genesis.Account{
			Code:    driver.GetContractBin(),
			Balance: new(big.Int),
			Nonce:   0,
		})
		// pre deploy NodeDriverAuth
		genStore.SetEvmAccount(driverauth.ContractAddress, genesis.Account{
			Code:    driverauth.GetContractBin(),
			Balance: new(big.Int),
			Nonce:   0,
		})
		// pre deploy SFC
		genStore.SetEvmAccount(sfc.ContractAddress, genesis.Account{
			Code:    sfc.GetContractBin(),
			Balance: new(big.Int),
			Nonce:   0,
		})
		// set non-zero code for pre-compiled contracts
		genStore.SetEvmAccount(evmwriter.ContractAddress, genesis.Account{
			Code:    []byte{0},
			Balance: new(big.Int),
			Nonce:   0,
		})
		fmt.Print("start writing genesis---->")
		testGenesisStore := genStore
		myFile, err := os.Create("/root/motif/motif-blockchain/build/motif.g")
		if err != nil {
	        panic(err)
	    }
		genesisstore.WriteGenesisStore(myFile, testGenesisStore)
		fmt.Print("end writing genesis!!!")
 	
 // 	///////// INITIAL...REMOVE TOP AFTER CREATION ///////// 



	return nil
}

// validatorKeyConvert converts account key to validator key.
func validatorKeyConvert(ctx *cli.Context) error {
	if len(ctx.Args()) < 2 {
		utils.Fatalf("This command requires 2 arguments.")
	}
	cfg := makeAllConfigs(ctx)
	utils.SetNodeConfig(ctx, &cfg.Node)

	_, _, keydir, _ := cfg.Node.AccountConfig()

	pubkeyStr := ctx.Args().Get(1)
	pubkey, err := validatorpk.FromString(pubkeyStr)
	if err != nil {
		utils.Fatalf("Failed to decode the validator pubkey: %v", err)
	}

	var acckeypath string
	if strings.HasPrefix(ctx.Args().First(), "0x") {
		acckeypath, err = FindAccountKeypath(common.HexToAddress(ctx.Args().First()), keydir)
		if err != nil {
			utils.Fatalf("Failed to find the account: %v", err)
		}
	} else {
		acckeypath = ctx.Args().First()
	}

	valkeypath := path.Join(keydir, "validator", common.Bytes2Hex(pubkey.Bytes()))
	err = encryption.MigrateAccountToValidatorKey(acckeypath, valkeypath, pubkey)
	if err != nil {
		utils.Fatalf("Failed to migrate the account key: %v", err)
	}
	fmt.Println("\nYour key was converted and saved to " + valkeypath)
	return nil
}
