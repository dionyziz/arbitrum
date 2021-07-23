/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Signer } from 'ethers'
import { Provider, TransactionRequest } from '@ethersproject/providers'
import { Contract, ContractFactory, Overrides } from '@ethersproject/contracts'

import type { RollupCore } from '../RollupCore'

export class RollupCore__factory extends ContractFactory {
  constructor(signer?: Signer) {
    super(_abi, _bytecode, signer)
  }

  deploy(overrides?: Overrides): Promise<RollupCore> {
    return super.deploy(overrides || {}) as Promise<RollupCore>
  }
  getDeployTransaction(overrides?: Overrides): TransactionRequest {
    return super.getDeployTransaction(overrides || {})
  }
  attach(address: string): RollupCore {
    return super.attach(address) as RollupCore
  }
  connect(signer: Signer): RollupCore__factory {
    return super.connect(signer) as RollupCore__factory
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): RollupCore {
    return new Contract(address, _abi, signerOrProvider) as RollupCore
  }
}

const _abi = [
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'uint256',
        name: 'nodeNum',
        type: 'uint256',
      },
      {
        indexed: false,
        internalType: 'bytes32',
        name: 'afterSendAcc',
        type: 'bytes32',
      },
      {
        indexed: false,
        internalType: 'uint256',
        name: 'afterSendCount',
        type: 'uint256',
      },
      {
        indexed: false,
        internalType: 'bytes32',
        name: 'afterLogAcc',
        type: 'bytes32',
      },
      {
        indexed: false,
        internalType: 'uint256',
        name: 'afterLogCount',
        type: 'uint256',
      },
    ],
    name: 'NodeConfirmed',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'uint256',
        name: 'nodeNum',
        type: 'uint256',
      },
      {
        indexed: true,
        internalType: 'bytes32',
        name: 'parentNodeHash',
        type: 'bytes32',
      },
      {
        indexed: false,
        internalType: 'bytes32',
        name: 'nodeHash',
        type: 'bytes32',
      },
      {
        indexed: false,
        internalType: 'bytes32',
        name: 'executionHash',
        type: 'bytes32',
      },
      {
        indexed: false,
        internalType: 'uint256',
        name: 'inboxMaxCount',
        type: 'uint256',
      },
      {
        indexed: false,
        internalType: 'uint256',
        name: 'afterInboxBatchEndCount',
        type: 'uint256',
      },
      {
        indexed: false,
        internalType: 'bytes32',
        name: 'afterInboxBatchAcc',
        type: 'bytes32',
      },
      {
        indexed: false,
        internalType: 'bytes32[3][2]',
        name: 'assertionBytes32Fields',
        type: 'bytes32[3][2]',
      },
      {
        indexed: false,
        internalType: 'uint256[4][2]',
        name: 'assertionIntFields',
        type: 'uint256[4][2]',
      },
    ],
    name: 'NodeCreated',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'uint256',
        name: 'nodeNum',
        type: 'uint256',
      },
    ],
    name: 'NodeRejected',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'address',
        name: 'challengeContract',
        type: 'address',
      },
      {
        indexed: false,
        internalType: 'address',
        name: 'asserter',
        type: 'address',
      },
      {
        indexed: false,
        internalType: 'address',
        name: 'challenger',
        type: 'address',
      },
      {
        indexed: false,
        internalType: 'uint256',
        name: 'challengedNode',
        type: 'uint256',
      },
    ],
    name: 'RollupChallengeStarted',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: 'bytes32',
        name: 'machineHash',
        type: 'bytes32',
      },
    ],
    name: 'RollupCreated',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'address',
        name: 'user',
        type: 'address',
      },
      {
        indexed: false,
        internalType: 'uint256',
        name: 'initialBalance',
        type: 'uint256',
      },
      {
        indexed: false,
        internalType: 'uint256',
        name: 'finalBalance',
        type: 'uint256',
      },
    ],
    name: 'UserStakeUpdated',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'address',
        name: 'user',
        type: 'address',
      },
      {
        indexed: false,
        internalType: 'uint256',
        name: 'initialBalance',
        type: 'uint256',
      },
      {
        indexed: false,
        internalType: 'uint256',
        name: 'finalBalance',
        type: 'uint256',
      },
    ],
    name: 'UserWithdrawableFundsUpdated',
    type: 'event',
  },
  {
    inputs: [
      {
        internalType: 'address',
        name: '',
        type: 'address',
      },
    ],
    name: '_stakerMap',
    outputs: [
      {
        internalType: 'uint256',
        name: 'index',
        type: 'uint256',
      },
      {
        internalType: 'uint256',
        name: 'latestStakedNode',
        type: 'uint256',
      },
      {
        internalType: 'uint256',
        name: 'amountStaked',
        type: 'uint256',
      },
      {
        internalType: 'address',
        name: 'currentChallenge',
        type: 'address',
      },
      {
        internalType: 'bool',
        name: 'isStaked',
        type: 'bool',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'address',
        name: 'staker',
        type: 'address',
      },
    ],
    name: 'amountStaked',
    outputs: [
      {
        internalType: 'uint256',
        name: '',
        type: 'uint256',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'address',
        name: 'staker',
        type: 'address',
      },
    ],
    name: 'currentChallenge',
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
    name: 'firstUnresolvedNode',
    outputs: [
      {
        internalType: 'uint256',
        name: '',
        type: 'uint256',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'uint256',
        name: 'nodeNum',
        type: 'uint256',
      },
    ],
    name: 'getNode',
    outputs: [
      {
        internalType: 'contract INode',
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
        name: 'index',
        type: 'uint256',
      },
    ],
    name: 'getNodeHash',
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
        internalType: 'uint256',
        name: 'stakerNum',
        type: 'uint256',
      },
    ],
    name: 'getStakerAddress',
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
    inputs: [
      {
        internalType: 'address',
        name: 'staker',
        type: 'address',
      },
    ],
    name: 'isStaked',
    outputs: [
      {
        internalType: 'bool',
        name: '',
        type: 'bool',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'address',
        name: 'staker',
        type: 'address',
      },
    ],
    name: 'isZombie',
    outputs: [
      {
        internalType: 'bool',
        name: '',
        type: 'bool',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'lastStakeBlock',
    outputs: [
      {
        internalType: 'uint256',
        name: '',
        type: 'uint256',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'latestConfirmed',
    outputs: [
      {
        internalType: 'uint256',
        name: '',
        type: 'uint256',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'latestNodeCreated',
    outputs: [
      {
        internalType: 'uint256',
        name: '',
        type: 'uint256',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'address',
        name: 'staker',
        type: 'address',
      },
    ],
    name: 'latestStakedNode',
    outputs: [
      {
        internalType: 'uint256',
        name: '',
        type: 'uint256',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'stakerCount',
    outputs: [
      {
        internalType: 'uint256',
        name: '',
        type: 'uint256',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'address',
        name: 'owner',
        type: 'address',
      },
    ],
    name: 'withdrawableFunds',
    outputs: [
      {
        internalType: 'uint256',
        name: '',
        type: 'uint256',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'uint256',
        name: 'zombieNum',
        type: 'uint256',
      },
    ],
    name: 'zombieAddress',
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
    name: 'zombieCount',
    outputs: [
      {
        internalType: 'uint256',
        name: '',
        type: 'uint256',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'uint256',
        name: 'zombieNum',
        type: 'uint256',
      },
    ],
    name: 'zombieLatestStakedNode',
    outputs: [
      {
        internalType: 'uint256',
        name: '',
        type: 'uint256',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
]

const _bytecode =
  '0x608060405234801561001057600080fd5b50610580806100206000396000f3fe608060405234801561001057600080fd5b50600436106100f65760003560e01c80638640ce5f116100925780638640ce5f1461022757806391c657e81461022f578063d01e660214610255578063d735e21d14610272578063dff697871461027a578063e8bd492214610282578063ef40a670146102de578063f33e1fac14610304578063f8d1f19414610321576100f6565b80632f30cabd146100fb5780633e96576e146101335780634f0f4aa9146101595780636177fd181461019257806362a82d7d146101cc57806363721d6b146101e957806365f7f80d146101f157806369fd251c146101f95780637ba9534a1461021f575b600080fd5b6101216004803603602081101561011157600080fd5b50356001600160a01b031661033e565b60408051918252519081900360200190f35b6101216004803603602081101561014957600080fd5b50356001600160a01b031661035d565b6101766004803603602081101561016f57600080fd5b503561037b565b604080516001600160a01b039092168252519081900360200190f35b6101b8600480360360208110156101a857600080fd5b50356001600160a01b0316610396565b604080519115158252519081900360200190f35b610176600480360360208110156101e257600080fd5b50356103be565b6101216103e8565b6101216103ee565b6101766004803603602081101561020f57600080fd5b50356001600160a01b03166103f4565b610121610415565b61012161041b565b6101b86004803603602081101561024557600080fd5b50356001600160a01b0316610421565b6101766004803603602081101561026b57600080fd5b503561047b565b6101216104aa565b6101216104b0565b6102a86004803603602081101561029857600080fd5b50356001600160a01b03166104b6565b604080519586526020860194909452848401929092526001600160a01b0316606084015215156080830152519081900360a00190f35b610121600480360360208110156102f457600080fd5b50356001600160a01b03166104f2565b6101216004803603602081101561031a57600080fd5b5035610510565b6101216004803603602081101561033757600080fd5b5035610538565b6001600160a01b0381166000908152600960205260409020545b919050565b6001600160a01b031660009081526007602052604090206001015490565b6000908152600460205260409020546001600160a01b031690565b6001600160a01b0316600090815260076020526040902060030154600160a01b900460ff1690565b6000600682815481106103cd57fe5b6000918252602090912001546001600160a01b031692915050565b60085490565b60005490565b6001600160a01b039081166000908152600760205260409020600301541690565b60025490565b60035490565b6000805b600854811015610472576008818154811061043c57fe5b60009182526020909120600290910201546001600160a01b038481169116141561046a576001915050610358565b600101610425565b50600092915050565b60006008828154811061048a57fe5b60009182526020909120600290910201546001600160a01b031692915050565b60015490565b60065490565b6007602052600090815260409020805460018201546002830154600390930154919290916001600160a01b03811690600160a01b900460ff1685565b6001600160a01b031660009081526007602052604090206002015490565b60006008828154811061051f57fe5b9060005260206000209060020201600101549050919050565b6000908152600560205260409020549056fea2646970667358221220ea3e6178571512665b480e80e028b6c13891dc41b427a23a0bcfe63237ed1a2064736f6c634300060b0033'
