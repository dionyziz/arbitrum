/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Signer, BytesLike, BigNumberish } from 'ethers'
import { Provider, TransactionRequest } from '@ethersproject/providers'
import {
  Contract,
  ContractFactory,
  PayableOverrides,
} from '@ethersproject/contracts'

import type { TestConstructorBuddy } from '../TestConstructorBuddy'

export class TestConstructorBuddy__factory extends ContractFactory {
  constructor(signer?: Signer) {
    super(_abi, _bytecode, signer)
  }

  deploy(
    _inbox: string,
    _l2Deployer: string,
    _maxSubmissionCost: BigNumberish,
    _maxGas: BigNumberish,
    _gasPrice: BigNumberish,
    _deployCode: BytesLike,
    overrides?: PayableOverrides
  ): Promise<TestConstructorBuddy> {
    return super.deploy(
      _inbox,
      _l2Deployer,
      _maxSubmissionCost,
      _maxGas,
      _gasPrice,
      _deployCode,
      overrides || {}
    ) as Promise<TestConstructorBuddy>
  }
  getDeployTransaction(
    _inbox: string,
    _l2Deployer: string,
    _maxSubmissionCost: BigNumberish,
    _maxGas: BigNumberish,
    _gasPrice: BigNumberish,
    _deployCode: BytesLike,
    overrides?: PayableOverrides
  ): TransactionRequest {
    return super.getDeployTransaction(
      _inbox,
      _l2Deployer,
      _maxSubmissionCost,
      _maxGas,
      _gasPrice,
      _deployCode,
      overrides || {}
    )
  }
  attach(address: string): TestConstructorBuddy {
    return super.attach(address) as TestConstructorBuddy
  }
  connect(signer: Signer): TestConstructorBuddy__factory {
    return super.connect(signer) as TestConstructorBuddy__factory
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): TestConstructorBuddy {
    return new Contract(address, _abi, signerOrProvider) as TestConstructorBuddy
  }
}

const _abi = [
  {
    inputs: [
      {
        internalType: 'address',
        name: '_inbox',
        type: 'address',
      },
      {
        internalType: 'address',
        name: '_l2Deployer',
        type: 'address',
      },
      {
        internalType: 'uint256',
        name: '_maxSubmissionCost',
        type: 'uint256',
      },
      {
        internalType: 'uint256',
        name: '_maxGas',
        type: 'uint256',
      },
      {
        internalType: 'uint256',
        name: '_gasPrice',
        type: 'uint256',
      },
      {
        internalType: 'bytes',
        name: '_deployCode',
        type: 'bytes',
      },
    ],
    stateMutability: 'payable',
    type: 'constructor',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'uint256',
        name: 'seqNum',
        type: 'uint256',
      },
      {
        indexed: false,
        internalType: 'address',
        name: 'l2Address',
        type: 'address',
      },
    ],
    name: 'DeployBuddyContract',
    type: 'event',
  },
  {
    inputs: [],
    name: 'codeHash',
    outputs: [
      {
        internalType: 'bytes32',
        name: '',
        type: 'bytes32',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'bool',
        name: 'success',
        type: 'bool',
      },
    ],
    name: 'finalizeBuddyDeploy',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [],
    name: 'inbox',
    outputs: [
      {
        internalType: 'contract IInbox',
        name: '',
        type: 'address',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'uint256',
        name: 'maxSubmissionCost',
        type: 'uint256',
      },
      {
        internalType: 'uint256',
        name: 'maxGas',
        type: 'uint256',
      },
      {
        internalType: 'uint256',
        name: 'gasPriceBid',
        type: 'uint256',
      },
      {
        internalType: 'bytes',
        name: 'contractInitCode',
        type: 'bytes',
      },
    ],
    name: 'initiateBuddyDeploy',
    outputs: [
      {
        internalType: 'uint256',
        name: '',
        type: 'uint256',
      },
    ],
    stateMutability: 'payable',
    type: 'function',
  },
  {
    inputs: [],
    name: 'l2Buddy',
    outputs: [
      {
        internalType: 'address',
        name: '',
        type: 'address',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'l2Connection',
    outputs: [
      {
        internalType: 'enum L1Buddy.L2Connection',
        name: '',
        type: 'uint8',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'l2Deployer',
    outputs: [
      {
        internalType: 'contract BuddyDeployer',
        name: '',
        type: 'address',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
]

const _bytecode =
  '0x6080604052604051610e58380380610e58833981810160405260c081101561002657600080fd5b815160208301516040808501516060860151608087015160a08801805194519698959793969295919492938201928464010000000082111561006757600080fd5b90830190602082018581111561007c57600080fd5b825164010000000081118282018810171561009657600080fd5b82525081516020918201929091019080838360005b838110156100c35781810151838201526020016100ab565b50505050905090810190601f1680156100f05780820380516001836020036101000a031916815260200191505b50604052505060008054600180546001600160a01b0319166001600160a01b038b8116919091179091556001600160a81b0319909116610100918916919091021790555061014b84848484610157602090811b61042b17901c565b50505050505050610569565b6000600260005460ff16600281111561016c57fe5b14156101b3576040805162461bcd60e51b8152602060048201526011602482015270185b1c9958591e4818dbdb9b9958dd1959607a1b604482015290519081900360640190fd5b60035415806101c9575081516020830120600354145b61021a576040805162461bcd60e51b815260206004820152601e60248201527f4f6e6c792072657472792069662073616d65206465706c6f7920636f64650000604482015290519081900360640190fd5b60405160206024820181815284516044840152845160609363658c6a1d60e11b9387939283926064019185019080838360005b8381101561026557818101518382015260200161024d565b50505050905090810190601f1680156102925780820380516001836020036101000a031916815260200191505b5060408051601f19818403018152919052602080820180516001600160e01b03166001600160e01b0319909716969096179095528751888601206003819055600054919650610301956001600160a01b0361010090930492909216945030935091506107ea6104f2821b17901c565b600280546001600160a01b0319166001600160a01b0392909216919091179055600080546001919060ff1916828002179055506000600160009054906101000a90046001600160a01b03166001600160a01b031663679b6ded34600060019054906101000a90046001600160a01b031660008b33338d8d8b6040518a63ffffffff1660e01b815260040180896001600160a01b03166001600160a01b03168152602001888152602001878152602001866001600160a01b03166001600160a01b03168152602001856001600160a01b03166001600160a01b0316815260200184815260200183815260200180602001828103825283818151815260200191508051906020019080838360005b8381101561042557818101518382015260200161040d565b50505050905090810190601f1680156104525780820380516001836020036101000a031916815260200191505b5099505050505050505050506020604051808303818588803b15801561047757600080fd5b505af115801561048b573d6000803e3d6000fd5b50505050506040513d60208110156104a257600080fd5b5051600254604080516001600160a01b0390921682525191925082917fa4ecfc4590bc6dc48c2533a8826bc2d61903cf3febf621d6d17202f68023c18f9181900360200190a29695505050505050565b604080517fff000000000000000000000000000000000000000000000000000000000000006020808301919091526001600160601b0319606087901b1660218301526001600160a01b0385166035830152605580830185905283518084039091018152607590920190925280519101209392505050565b6108e0806105786000396000f3fe6080604052600436106100605760003560e01c806306cad3381461006557806318edaaf2146100935780634caa1a75146100ba5780635ca00351146100eb5780639861c663146101a4578063a4322980146101dd578063fb0e722b146101f2575b600080fd5b34801561007157600080fd5b506100916004803603602081101561008857600080fd5b50351515610207565b005b34801561009f57600080fd5b506100a8610416565b60408051918252519081900360200190f35b3480156100c657600080fd5b506100cf61041c565b604080516001600160a01b039092168252519081900360200190f35b6100a86004803603608081101561010157600080fd5b8135916020810135916040820135919081019060808101606082013564010000000081111561012f57600080fd5b82018360208201111561014157600080fd5b8035906020019184600183028401116401000000008311171561016357600080fd5b91908080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525092955061042b945050505050565b3480156101b057600080fd5b506101b96107be565b604051808260028111156101c957fe5b60ff16815260200191505060405180910390f35b3480156101e957600080fd5b506100cf6107c7565b3480156101fe57600080fd5b506100cf6107db565b600160005460ff16600281111561021a57fe5b146102565760405162461bcd60e51b815260040180806020018281038252602181526020018061088a6021913960400191505060405180910390fd5b600154604080516373c6754960e11b815290516000926001600160a01b03169163e78cea92916004808301926020929190829003018186803b15801561029b57600080fd5b505afa1580156102af573d6000803e3d6000fd5b505050506040513d60208110156102c557600080fd5b50516040805163ab5d894360e01b815290516001600160a01b039092169163ab5d894391600480820192602092909190829003018186803b15801561030957600080fd5b505afa15801561031d573d6000803e3d6000fd5b505050506040513d602081101561033357600080fd5b505160005460408051634032458160e11b815290519293506001600160a01b03610100909204821692918416916380648b0291600480820192602092909190829003018186803b15801561038657600080fd5b505afa15801561039a573d6000803e3d6000fd5b505050506040513d60208110156103b057600080fd5b50516001600160a01b0316146103f75760405162461bcd60e51b81526004018080602001828103825260228152602001806108686022913960400191505060405180910390fd5b811561040a5761040561084e565b610412565b610412610856565b5050565b60035481565b6002546001600160a01b031681565b6000600260005460ff16600281111561044057fe5b1415610487576040805162461bcd60e51b8152602060048201526011602482015270185b1c9958591e4818dbdb9b9958dd1959607a1b604482015290519081900360640190fd5b600354158061049d575081516020830120600354145b6104ee576040805162461bcd60e51b815260206004820152601e60248201527f4f6e6c792072657472792069662073616d65206465706c6f7920636f64650000604482015290519081900360640190fd5b60405160206024820181815284516044840152845160609363658c6a1d60e11b9387939283926064019185019080838360005b83811015610539578181015183820152602001610521565b50505050905090810190601f1680156105665780820380516001836020036101000a031916815260200191505b5060408051601f19818403018152919052602080820180516001600160e01b03166001600160e01b03199097169690961790955287519488019490942060038190556000549495506105cd946001600160a01b0361010090910416935030925090506107ea565b600280546001600160a01b0319166001600160a01b0392909216919091179055600080546001919060ff1916828002179055506000600160009054906101000a90046001600160a01b03166001600160a01b031663679b6ded34600060019054906101000a90046001600160a01b031660008b33338d8d8b6040518a63ffffffff1660e01b815260040180896001600160a01b03166001600160a01b03168152602001888152602001878152602001866001600160a01b03166001600160a01b03168152602001856001600160a01b03166001600160a01b0316815260200184815260200183815260200180602001828103825283818151815260200191508051906020019080838360005b838110156106f15781810151838201526020016106d9565b50505050905090810190601f16801561071e5780820380516001836020036101000a031916815260200191505b5099505050505050505050506020604051808303818588803b15801561074357600080fd5b505af1158015610757573d6000803e3d6000fd5b50505050506040513d602081101561076e57600080fd5b5051600254604080516001600160a01b0390921682525191925082917fa4ecfc4590bc6dc48c2533a8826bc2d61903cf3febf621d6d17202f68023c18f9181900360200190a29695505050505050565b60005460ff1681565b60005461010090046001600160a01b031681565b6001546001600160a01b031681565b604080516001600160f81b03196020808301919091526bffffffffffffffffffffffff19606087901b1660218301526001600160a01b0385166035830152605580830185905283518084039091018152607590920190925280519101209392505050565b610856610858565b565b6000805460ff1916600217905556fe57726f6e67204c3220616464726573732074726967676572696e67206f7574626f78436f6e6e656374696f6e206e6f7420696e20696e69746961746564207374617465a264697066735822122084e8facf90b5b394659474cc7a9a03113cea5ff9b86ac2b4cab597f8b71acab164736f6c634300060b0033'
