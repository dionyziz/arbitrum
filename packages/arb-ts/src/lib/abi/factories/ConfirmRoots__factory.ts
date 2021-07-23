/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Signer } from 'ethers'
import { Provider, TransactionRequest } from '@ethersproject/providers'
import { Contract, ContractFactory, Overrides } from '@ethersproject/contracts'

import type { ConfirmRoots } from '../ConfirmRoots'

export class ConfirmRoots__factory extends ContractFactory {
  constructor(signer?: Signer) {
    super(_abi, _bytecode, signer)
  }

  deploy(_rollup: string, overrides?: Overrides): Promise<ConfirmRoots> {
    return super.deploy(_rollup, overrides || {}) as Promise<ConfirmRoots>
  }
  getDeployTransaction(
    _rollup: string,
    overrides?: Overrides
  ): TransactionRequest {
    return super.getDeployTransaction(_rollup, overrides || {})
  }
  attach(address: string): ConfirmRoots {
    return super.attach(address) as ConfirmRoots
  }
  connect(signer: Signer): ConfirmRoots__factory {
    return super.connect(signer) as ConfirmRoots__factory
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): ConfirmRoots {
    return new Contract(address, _abi, signerOrProvider) as ConfirmRoots
  }
}

const _abi = [
  {
    inputs: [
      {
        internalType: 'contract Rollup',
        name: '_rollup',
        type: 'address',
      },
    ],
    stateMutability: 'nonpayable',
    type: 'constructor',
  },
  {
    inputs: [
      {
        internalType: 'bytes32',
        name: '',
        type: 'bytes32',
      },
      {
        internalType: 'uint256',
        name: '',
        type: 'uint256',
      },
    ],
    name: 'confirmRoots',
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
    name: 'rollup',
    outputs: [
      {
        internalType: 'contract Rollup',
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
        name: 'nodeNum',
        type: 'uint256',
      },
      {
        internalType: 'bytes32',
        name: 'beforeSendAcc',
        type: 'bytes32',
      },
      {
        internalType: 'bytes',
        name: 'sendsData',
        type: 'bytes',
      },
      {
        internalType: 'uint256[]',
        name: 'sendLengths',
        type: 'uint256[]',
      },
      {
        internalType: 'uint256',
        name: 'afterSendCount',
        type: 'uint256',
      },
      {
        internalType: 'bytes32',
        name: 'afterLogAcc',
        type: 'bytes32',
      },
      {
        internalType: 'uint256',
        name: 'afterLogCount',
        type: 'uint256',
      },
    ],
    name: 'setupConfirmData',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
]

const _bytecode =
  '0x608060405234801561001057600080fd5b506040516106b23803806106b28339818101604052602081101561003357600080fd5b5051600080546001600160a01b039092166001600160a01b031990921691909117905561064d806100656000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c80638f4ada031461004657806397a06bf71461011e578063cb23bcb514610155575b600080fd5b61011c600480360360e081101561005c57600080fd5b813591602081013591810190606081016040820135600160201b81111561008257600080fd5b82018360208201111561009457600080fd5b803590602001918460018302840111600160201b831117156100b557600080fd5b919390929091602081019035600160201b8111156100d257600080fd5b8201836020820111156100e457600080fd5b803590602001918460208302840111600160201b8311171561010557600080fd5b919350915080359060208101359060400135610179565b005b6101416004803603604081101561013457600080fd5b50803590602001356103bd565b604080519115158252519081900360200190f35b61015d6103dd565b604080516001600160a01b039092168252519081900360200190f35b6000805460408051634f0f4aa960e01b8152600481018d905290516001600160a01b0390921691634f0f4aa991602480820192602092909190829003018186803b1580156101c657600080fd5b505afa1580156101da573d6000803e3d6000fd5b505050506040513d60208110156101f057600080fd5b5051604080516020601f8b01819004810282018101909252898152919250600091610268918b908b908190840183828082843760009201919091525050604080516020808d0282810182019093528c82529093508c92508b9182918501908490808284376000920191909152508f92506103ec915050565b90506102778a828688876104ed565b826001600160a01b03166397bdc5106040518163ffffffff1660e01b815260040160206040518083038186803b1580156102b057600080fd5b505afa1580156102c4573d6000803e3d6000fd5b505050506040513d60208110156102da57600080fd5b50511461031d576040805162461bcd60e51b815260206004820152600c60248201526b434f4e4649524d5f4441544160a01b604482015290519081900360640190fd5b856000805b828110156103ad5761038b8e8d848e8e8e8781811061033d57fe5b9050602002013592610351939291906105ef565b8080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525061053492505050565b89898281811061039757fe5b6020029190910135929092019150600101610322565b5050505050505050505050505050565b600160209081526000928352604080842090915290825290205460ff1681565b6000546001600160a01b031681565b81518351600091829184835b8381101561049f57600088828151811061040e57fe5b6020026020010151905083818701111561045e576040805162461bcd60e51b815260206004820152600c60248201526b2220aa20afa7ab22a9292aa760a11b604482015290519081900360640190fd5b6020868b01810182902060408051808401969096528581019190915280518086038201815260609095019052835193019290922091909401936001016103f8565b508184146104e2576040805162461bcd60e51b815260206004820152600b60248201526a08882a882be988a9c8ea8960ab1b604482015290519081900360640190fd5b979650505050505050565b60408051602080820197909752808201959095526060850192909252608084019290925260a0808401929092528051808403909201825260c0909201909152805191012090565b80516000908290829061054357fe5b01602001516001600160f81b031916141561059257600061056b82604163ffffffff61059616565b6000908152600160208181526040808420878552909152909120805460ff19169091179055505b5050565b600081602001835110156105e6576040805162461bcd60e51b815260206004820152601260248201527152656164206f7574206f6620626f756e647360701b604482015290519081900360640190fd5b50016020015190565b600080858511156105fe578182fd5b8386111561060a578182fd5b505082019391909203915056fea26469706673582212207d4d9d83bd66736f3281f4d95e4b3ed5a73a0bd81d5e98b23b912ffd227d283b64736f6c634300060b0033'
