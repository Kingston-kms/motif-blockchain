package driver

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// GetContractBin is NodeDriver contract genesis implementation bin code
// Has to be compiled with flag bin-runtime
// Built from motif-sfc c1d33c81f74abf82c0e22807f16e609578e10ad8, solc 0.5.17+commit.d19bba13.Emscripten.clang, optimize-runs 10000
func GetContractBin() []byte {
	return hexutil.MustDecode("0x608060405234801561001057600080fd5b50600436106101005760003560e01c80634feb92f311610097578063da7fc24f11610066578063da7fc24f1461046e578063e08d7e66146104a1578063e30443bc14610511578063ebdf104c1461054a57610100565b80634feb92f3146102f5578063a4066fbe146103a0578063b9cc6b1c146103c3578063d6a0c7af1461043357610100565b8063242a6e3f116100d3578063242a6e3f146101e7578063267ab4461461025e57806339e503ab1461027b578063485cc955146102ba57610100565b806307690b2a146101055780630aeeca001461014257806318f628d41461015f5780631e702f83146101c4575b600080fd5b6101406004803603604081101561011b57600080fd5b5073ffffffffffffffffffffffffffffffffffffffff813581169160200135166106b0565b005b6101406004803603602081101561015857600080fd5b50356107b4565b610140600480360361012081101561017657600080fd5b5073ffffffffffffffffffffffffffffffffffffffff8135169060208101359060408101359060608101359060808101359060a08101359060c08101359060e0810135906101000135610856565b610140600480360360408110156101da57600080fd5b508035906020013561097a565b610140600480360360408110156101fd57600080fd5b8135919081019060408101602082013564010000000081111561021f57600080fd5b82018360208201111561023157600080fd5b8035906020019184600183028401116401000000008311171561025357600080fd5b509092509050610a47565b6101406004803603602081101561027457600080fd5b5035610b37565b6101406004803603606081101561029157600080fd5b5073ffffffffffffffffffffffffffffffffffffffff8135169060208101359060400135610bd9565b610140600480360360408110156102d057600080fd5b5073ffffffffffffffffffffffffffffffffffffffff81358116916020013516610ce4565b610140600480360361010081101561030c57600080fd5b73ffffffffffffffffffffffffffffffffffffffff8235169160208101359181019060608101604082013564010000000081111561034957600080fd5b82018360208201111561035b57600080fd5b8035906020019184600183028401116401000000008311171561037d57600080fd5b919350915080359060208101359060408101359060608101359060800135610e8c565b610140600480360360408110156103b657600080fd5b5080359060200135610fe4565b610140600480360360208110156103d957600080fd5b8101906020810181356401000000008111156103f457600080fd5b82018360208201111561040657600080fd5b8035906020019184600183028401116401000000008311171561042857600080fd5b50909250905061108a565b6101406004803603604081101561044957600080fd5b5073ffffffffffffffffffffffffffffffffffffffff81358116916020013516611178565b6101406004803603602081101561048457600080fd5b503573ffffffffffffffffffffffffffffffffffffffff16611260565b610140600480360360208110156104b757600080fd5b8101906020810181356401000000008111156104d257600080fd5b8201836020820111156104e457600080fd5b8035906020019184602083028401116401000000008311171561050657600080fd5b509092509050611354565b6101406004803603604081101561052757600080fd5b5073ffffffffffffffffffffffffffffffffffffffff813516906020013561144a565b6101406004803603608081101561056057600080fd5b81019060208101813564010000000081111561057b57600080fd5b82018360208201111561058d57600080fd5b803590602001918460208302840111640100000000831117156105af57600080fd5b9193909290916020810190356401000000008111156105cd57600080fd5b8201836020820111156105df57600080fd5b8035906020019184602083028401116401000000008311171561060157600080fd5b91939092909160208101903564010000000081111561061f57600080fd5b82018360208201111561063157600080fd5b8035906020019184602083028401116401000000008311171561065357600080fd5b91939092909160208101903564010000000081111561067157600080fd5b82018360208201111561068357600080fd5b803590602001918460208302840111640100000000831117156106a557600080fd5b509092509050611531565b60345473ffffffffffffffffffffffffffffffffffffffff16331461071c576040805162461bcd60e51b815260206004820152601960248201527f63616c6c6572206973206e6f7420746865206261636b656e6400000000000000604482015290519081900360640190fd5b603554604080517f07690b2a00000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff85811660048301528481166024830152915191909216916307690b2a91604480830192600092919082900301818387803b15801561079857600080fd5b505af11580156107ac573d6000803e3d6000fd5b505050505050565b60345473ffffffffffffffffffffffffffffffffffffffff163314610820576040805162461bcd60e51b815260206004820152601960248201527f63616c6c6572206973206e6f7420746865206261636b656e6400000000000000604482015290519081900360640190fd5b6040805182815290517f0151256d62457b809bbc891b1f81c6dd0b9987552c70ce915b519750cd434dd19181900360200190a150565b33156108a9576040805162461bcd60e51b815260206004820152600c60248201527f6e6f742063616c6c61626c650000000000000000000000000000000000000000604482015290519081900360640190fd5b603454604080517f18f628d400000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff8c81166004830152602482018c9052604482018b9052606482018a90526084820189905260a4820188905260c4820187905260e482018690526101048201859052915191909216916318f628d49161012480830192600092919082900301818387803b15801561095757600080fd5b505af115801561096b573d6000803e3d6000fd5b50505050505050505050505050565b33156109cd576040805162461bcd60e51b815260206004820152600c60248201527f6e6f742063616c6c61626c650000000000000000000000000000000000000000604482015290519081900360640190fd5b603454604080517f1e702f830000000000000000000000000000000000000000000000000000000081526004810185905260248101849052905173ffffffffffffffffffffffffffffffffffffffff90921691631e702f839160448082019260009290919082900301818387803b15801561079857600080fd5b60345473ffffffffffffffffffffffffffffffffffffffff163314610ab3576040805162461bcd60e51b815260206004820152601960248201527f63616c6c6572206973206e6f7420746865206261636b656e6400000000000000604482015290519081900360640190fd5b827f0f0ef1ab97439def0a9d2c6d9dc166207f1b13b99e62b442b2993d6153c63a6e838360405180806020018281038252848482818152602001925080828437600083820152604051601f9091017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0169092018290039550909350505050a2505050565b60345473ffffffffffffffffffffffffffffffffffffffff163314610ba3576040805162461bcd60e51b815260206004820152601960248201527f63616c6c6572206973206e6f7420746865206261636b656e6400000000000000604482015290519081900360640190fd5b6040805182815290517f2ccdfd47cf0c1f1069d949f1789bb79b2f12821f021634fc835af1de66ea2feb9181900360200190a150565b60345473ffffffffffffffffffffffffffffffffffffffff163314610c45576040805162461bcd60e51b815260206004820152601960248201527f63616c6c6572206973206e6f7420746865206261636b656e6400000000000000604482015290519081900360640190fd5b603554604080517f39e503ab00000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff86811660048301526024820186905260448201859052915191909216916339e503ab91606480830192600092919082900301818387803b158015610cc757600080fd5b505af1158015610cdb573d6000803e3d6000fd5b50505050505050565b600054610100900460ff1680610cfd5750610cfd611734565b80610d0b575060005460ff16155b610d465760405162461bcd60e51b815260040180806020018281038252602e81526020018061173b602e913960400191505060405180910390fd5b600054610100900460ff16158015610dac57600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ff909116610100171660011790555b603480547fffffffffffffffffffffffff00000000000000000000000000000000000000001673ffffffffffffffffffffffffffffffffffffffff85169081179091556040517f64ee8f7bfc37fc205d7194ee3d64947ab7b57e663cd0d1abd3ef24503583069390600090a2603580547fffffffffffffffffffffffff00000000000000000000000000000000000000001673ffffffffffffffffffffffffffffffffffffffff84161790558015610e8757600080547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ff1690555b505050565b3315610edf576040805162461bcd60e51b815260206004820152600c60248201527f6e6f742063616c6c61626c650000000000000000000000000000000000000000604482015290519081900360640190fd5b603460009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16634feb92f38a8a8a8a8a8a8a8a8a6040518a63ffffffff1660e01b8152600401808a73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001898152602001806020018781526020018681526020018581526020018481526020018381526020018281038252898982818152602001925080828437600081840152601f19601f8201169050808301925050509a5050505050505050505050600060405180830381600087803b15801561095757600080fd5b60345473ffffffffffffffffffffffffffffffffffffffff163314611050576040805162461bcd60e51b815260206004820152601960248201527f63616c6c6572206973206e6f7420746865206261636b656e6400000000000000604482015290519081900360640190fd5b60408051828152905183917fb975807576e3b1461be7de07ebf7d20e4790ed802d7a0c4fdd0a1a13df72a935919081900360200190a25050565b60345473ffffffffffffffffffffffffffffffffffffffff1633146110f6576040805162461bcd60e51b815260206004820152601960248201527f63616c6c6572206973206e6f7420746865206261636b656e6400000000000000604482015290519081900360640190fd5b7f47d10eed096a44e3d0abc586c7e3a5d6cb5358cc90e7d437cd0627f7e765fb99828260405180806020018281038252848482818152602001925080828437600083820152604051601f9091017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0169092018290039550909350505050a15050565b60345473ffffffffffffffffffffffffffffffffffffffff1633146111e4576040805162461bcd60e51b815260206004820152601960248201527f63616c6c6572206973206e6f7420746865206261636b656e6400000000000000604482015290519081900360640190fd5b603554604080517fd6a0c7af00000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff858116600483015284811660248301529151919092169163d6a0c7af91604480830192600092919082900301818387803b15801561079857600080fd5b60345473ffffffffffffffffffffffffffffffffffffffff1633146112cc576040805162461bcd60e51b815260206004820152601960248201527f63616c6c6572206973206e6f7420746865206261636b656e6400000000000000604482015290519081900360640190fd5b60405173ffffffffffffffffffffffffffffffffffffffff8216907f64ee8f7bfc37fc205d7194ee3d64947ab7b57e663cd0d1abd3ef24503583069390600090a2603480547fffffffffffffffffffffffff00000000000000000000000000000000000000001673ffffffffffffffffffffffffffffffffffffffff92909216919091179055565b33156113a7576040805162461bcd60e51b815260206004820152600c60248201527f6e6f742063616c6c61626c650000000000000000000000000000000000000000604482015290519081900360640190fd5b6034546040517fe08d7e660000000000000000000000000000000000000000000000000000000081526020600482018181526024830185905273ffffffffffffffffffffffffffffffffffffffff9093169263e08d7e6692869286929182916044909101908590850280828437600081840152601f19601f8201169050808301925050509350505050600060405180830381600087803b15801561079857600080fd5b60345473ffffffffffffffffffffffffffffffffffffffff1633146114b6576040805162461bcd60e51b815260206004820152601960248201527f63616c6c6572206973206e6f7420746865206261636b656e6400000000000000604482015290519081900360640190fd5b603554604080517fe30443bc00000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff8581166004830152602482018590529151919092169163e30443bc91604480830192600092919082900301818387803b15801561079857600080fd5b3315611584576040805162461bcd60e51b815260206004820152600c60248201527f6e6f742063616c6c61626c650000000000000000000000000000000000000000604482015290519081900360640190fd5b603460009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1663ebdf104c89898989898989896040518963ffffffff1660e01b8152600401808060200180602001806020018060200185810385528d8d82818152602001925060200280828437600083820152601f017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe01690910186810385528b8152602090810191508c908c0280828437600083820152601f017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0169091018681038452898152602090810191508a908a0280828437600083820152601f017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0169091018681038352878152602090810191508890880280828437600081840152601f19601f8201169050808301925050509c50505050505050505050505050600060405180830381600087803b15801561171257600080fd5b505af1158015611726573d6000803e3d6000fd5b505050505050505050505050565b303b159056fe436f6e747261637420696e7374616e63652068617320616c7265616479206265656e20696e697469616c697a6564a265627a7a72315820c104d892d4e3c03aad6bd8ed35e468c04e4818cd1a7591ff495bce6f49cffa2364736f6c63430005110032")
}

// ContractAddress is the NodeDriver contract address
var ContractAddress = common.HexToAddress("0xd100a01e00000000000000000000000000000000")
