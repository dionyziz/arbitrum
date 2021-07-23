/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import {
  ethers,
  EventFilter,
  Signer,
  BigNumber,
  BigNumberish,
  PopulatedTransaction,
} from 'ethers'
import {
  Contract,
  ContractTransaction,
  Overrides,
  PayableOverrides,
  CallOverrides,
} from '@ethersproject/contracts'
import { BytesLike } from '@ethersproject/bytes'
import { Listener, Provider } from '@ethersproject/providers'
import { FunctionFragment, EventFragment, Result } from '@ethersproject/abi'

interface AeWETHInterface extends ethers.utils.Interface {
  functions: {
    'DOMAIN_SEPARATOR()': FunctionFragment
    'allowance(address,address)': FunctionFragment
    'approve(address,uint256)': FunctionFragment
    'balanceOf(address)': FunctionFragment
    'bridgeBurn(address,uint256)': FunctionFragment
    'bridgeMint(address,uint256)': FunctionFragment
    'decimals()': FunctionFragment
    'decreaseAllowance(address,uint256)': FunctionFragment
    'deposit()': FunctionFragment
    'depositTo(address)': FunctionFragment
    'increaseAllowance(address,uint256)': FunctionFragment
    'initialize(string,string,uint8,address,address)': FunctionFragment
    'l1Address()': FunctionFragment
    'l2Gateway()': FunctionFragment
    'name()': FunctionFragment
    'nonces(address)': FunctionFragment
    'permit(address,address,uint256,uint256,uint8,bytes32,bytes32)': FunctionFragment
    'symbol()': FunctionFragment
    'totalSupply()': FunctionFragment
    'transfer(address,uint256)': FunctionFragment
    'transferAndCall(address,uint256,bytes)': FunctionFragment
    'transferFrom(address,address,uint256)': FunctionFragment
    'withdraw(uint256)': FunctionFragment
    'withdrawTo(address,uint256)': FunctionFragment
  }

  encodeFunctionData(
    functionFragment: 'DOMAIN_SEPARATOR',
    values?: undefined
  ): string
  encodeFunctionData(
    functionFragment: 'allowance',
    values: [string, string]
  ): string
  encodeFunctionData(
    functionFragment: 'approve',
    values: [string, BigNumberish]
  ): string
  encodeFunctionData(functionFragment: 'balanceOf', values: [string]): string
  encodeFunctionData(
    functionFragment: 'bridgeBurn',
    values: [string, BigNumberish]
  ): string
  encodeFunctionData(
    functionFragment: 'bridgeMint',
    values: [string, BigNumberish]
  ): string
  encodeFunctionData(functionFragment: 'decimals', values?: undefined): string
  encodeFunctionData(
    functionFragment: 'decreaseAllowance',
    values: [string, BigNumberish]
  ): string
  encodeFunctionData(functionFragment: 'deposit', values?: undefined): string
  encodeFunctionData(functionFragment: 'depositTo', values: [string]): string
  encodeFunctionData(
    functionFragment: 'increaseAllowance',
    values: [string, BigNumberish]
  ): string
  encodeFunctionData(
    functionFragment: 'initialize',
    values: [string, string, BigNumberish, string, string]
  ): string
  encodeFunctionData(functionFragment: 'l1Address', values?: undefined): string
  encodeFunctionData(functionFragment: 'l2Gateway', values?: undefined): string
  encodeFunctionData(functionFragment: 'name', values?: undefined): string
  encodeFunctionData(functionFragment: 'nonces', values: [string]): string
  encodeFunctionData(
    functionFragment: 'permit',
    values: [
      string,
      string,
      BigNumberish,
      BigNumberish,
      BigNumberish,
      BytesLike,
      BytesLike
    ]
  ): string
  encodeFunctionData(functionFragment: 'symbol', values?: undefined): string
  encodeFunctionData(
    functionFragment: 'totalSupply',
    values?: undefined
  ): string
  encodeFunctionData(
    functionFragment: 'transfer',
    values: [string, BigNumberish]
  ): string
  encodeFunctionData(
    functionFragment: 'transferAndCall',
    values: [string, BigNumberish, BytesLike]
  ): string
  encodeFunctionData(
    functionFragment: 'transferFrom',
    values: [string, string, BigNumberish]
  ): string
  encodeFunctionData(
    functionFragment: 'withdraw',
    values: [BigNumberish]
  ): string
  encodeFunctionData(
    functionFragment: 'withdrawTo',
    values: [string, BigNumberish]
  ): string

  decodeFunctionResult(
    functionFragment: 'DOMAIN_SEPARATOR',
    data: BytesLike
  ): Result
  decodeFunctionResult(functionFragment: 'allowance', data: BytesLike): Result
  decodeFunctionResult(functionFragment: 'approve', data: BytesLike): Result
  decodeFunctionResult(functionFragment: 'balanceOf', data: BytesLike): Result
  decodeFunctionResult(functionFragment: 'bridgeBurn', data: BytesLike): Result
  decodeFunctionResult(functionFragment: 'bridgeMint', data: BytesLike): Result
  decodeFunctionResult(functionFragment: 'decimals', data: BytesLike): Result
  decodeFunctionResult(
    functionFragment: 'decreaseAllowance',
    data: BytesLike
  ): Result
  decodeFunctionResult(functionFragment: 'deposit', data: BytesLike): Result
  decodeFunctionResult(functionFragment: 'depositTo', data: BytesLike): Result
  decodeFunctionResult(
    functionFragment: 'increaseAllowance',
    data: BytesLike
  ): Result
  decodeFunctionResult(functionFragment: 'initialize', data: BytesLike): Result
  decodeFunctionResult(functionFragment: 'l1Address', data: BytesLike): Result
  decodeFunctionResult(functionFragment: 'l2Gateway', data: BytesLike): Result
  decodeFunctionResult(functionFragment: 'name', data: BytesLike): Result
  decodeFunctionResult(functionFragment: 'nonces', data: BytesLike): Result
  decodeFunctionResult(functionFragment: 'permit', data: BytesLike): Result
  decodeFunctionResult(functionFragment: 'symbol', data: BytesLike): Result
  decodeFunctionResult(functionFragment: 'totalSupply', data: BytesLike): Result
  decodeFunctionResult(functionFragment: 'transfer', data: BytesLike): Result
  decodeFunctionResult(
    functionFragment: 'transferAndCall',
    data: BytesLike
  ): Result
  decodeFunctionResult(
    functionFragment: 'transferFrom',
    data: BytesLike
  ): Result
  decodeFunctionResult(functionFragment: 'withdraw', data: BytesLike): Result
  decodeFunctionResult(functionFragment: 'withdrawTo', data: BytesLike): Result

  events: {
    'Approval(address,address,uint256)': EventFragment
    'Transfer(address,address,uint256,bytes)': EventFragment
  }

  getEvent(nameOrSignatureOrTopic: 'Approval'): EventFragment
  getEvent(nameOrSignatureOrTopic: 'Transfer'): EventFragment
}

export class AeWETH extends Contract {
  connect(signerOrProvider: Signer | Provider | string): this
  attach(addressOrName: string): this
  deployed(): Promise<this>

  on(event: EventFilter | string, listener: Listener): this
  once(event: EventFilter | string, listener: Listener): this
  addListener(eventName: EventFilter | string, listener: Listener): this
  removeAllListeners(eventName: EventFilter | string): this
  removeListener(eventName: any, listener: Listener): this

  interface: AeWETHInterface

  functions: {
    DOMAIN_SEPARATOR(overrides?: CallOverrides): Promise<[string]>

    'DOMAIN_SEPARATOR()'(overrides?: CallOverrides): Promise<[string]>

    allowance(
      owner: string,
      spender: string,
      overrides?: CallOverrides
    ): Promise<[BigNumber]>

    'allowance(address,address)'(
      owner: string,
      spender: string,
      overrides?: CallOverrides
    ): Promise<[BigNumber]>

    approve(
      spender: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    'approve(address,uint256)'(
      spender: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    balanceOf(account: string, overrides?: CallOverrides): Promise<[BigNumber]>

    'balanceOf(address)'(
      account: string,
      overrides?: CallOverrides
    ): Promise<[BigNumber]>

    bridgeBurn(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    'bridgeBurn(address,uint256)'(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    bridgeMint(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    'bridgeMint(address,uint256)'(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    decimals(overrides?: CallOverrides): Promise<[number]>

    'decimals()'(overrides?: CallOverrides): Promise<[number]>

    decreaseAllowance(
      spender: string,
      subtractedValue: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    'decreaseAllowance(address,uint256)'(
      spender: string,
      subtractedValue: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    deposit(overrides?: PayableOverrides): Promise<ContractTransaction>

    'deposit()'(overrides?: PayableOverrides): Promise<ContractTransaction>

    depositTo(
      account: string,
      overrides?: PayableOverrides
    ): Promise<ContractTransaction>

    'depositTo(address)'(
      account: string,
      overrides?: PayableOverrides
    ): Promise<ContractTransaction>

    increaseAllowance(
      spender: string,
      addedValue: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    'increaseAllowance(address,uint256)'(
      spender: string,
      addedValue: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    initialize(
      name_: string,
      symbol_: string,
      decimals_: BigNumberish,
      l2Gateway_: string,
      l1Address_: string,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    'initialize(string,string,uint8,address,address)'(
      name_: string,
      symbol_: string,
      decimals_: BigNumberish,
      l2Gateway_: string,
      l1Address_: string,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    l1Address(overrides?: CallOverrides): Promise<[string]>

    'l1Address()'(overrides?: CallOverrides): Promise<[string]>

    l2Gateway(overrides?: CallOverrides): Promise<[string]>

    'l2Gateway()'(overrides?: CallOverrides): Promise<[string]>

    name(overrides?: CallOverrides): Promise<[string]>

    'name()'(overrides?: CallOverrides): Promise<[string]>

    nonces(owner: string, overrides?: CallOverrides): Promise<[BigNumber]>

    'nonces(address)'(
      owner: string,
      overrides?: CallOverrides
    ): Promise<[BigNumber]>

    permit(
      owner: string,
      spender: string,
      value: BigNumberish,
      deadline: BigNumberish,
      v: BigNumberish,
      r: BytesLike,
      s: BytesLike,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    'permit(address,address,uint256,uint256,uint8,bytes32,bytes32)'(
      owner: string,
      spender: string,
      value: BigNumberish,
      deadline: BigNumberish,
      v: BigNumberish,
      r: BytesLike,
      s: BytesLike,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    symbol(overrides?: CallOverrides): Promise<[string]>

    'symbol()'(overrides?: CallOverrides): Promise<[string]>

    totalSupply(overrides?: CallOverrides): Promise<[BigNumber]>

    'totalSupply()'(overrides?: CallOverrides): Promise<[BigNumber]>

    transfer(
      recipient: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    'transfer(address,uint256)'(
      recipient: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    transferAndCall(
      _to: string,
      _value: BigNumberish,
      _data: BytesLike,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    'transferAndCall(address,uint256,bytes)'(
      _to: string,
      _value: BigNumberish,
      _data: BytesLike,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    transferFrom(
      sender: string,
      recipient: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    'transferFrom(address,address,uint256)'(
      sender: string,
      recipient: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    withdraw(
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    'withdraw(uint256)'(
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    withdrawTo(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>

    'withdrawTo(address,uint256)'(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<ContractTransaction>
  }

  DOMAIN_SEPARATOR(overrides?: CallOverrides): Promise<string>

  'DOMAIN_SEPARATOR()'(overrides?: CallOverrides): Promise<string>

  allowance(
    owner: string,
    spender: string,
    overrides?: CallOverrides
  ): Promise<BigNumber>

  'allowance(address,address)'(
    owner: string,
    spender: string,
    overrides?: CallOverrides
  ): Promise<BigNumber>

  approve(
    spender: string,
    amount: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  'approve(address,uint256)'(
    spender: string,
    amount: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  balanceOf(account: string, overrides?: CallOverrides): Promise<BigNumber>

  'balanceOf(address)'(
    account: string,
    overrides?: CallOverrides
  ): Promise<BigNumber>

  bridgeBurn(
    account: string,
    amount: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  'bridgeBurn(address,uint256)'(
    account: string,
    amount: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  bridgeMint(
    account: string,
    amount: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  'bridgeMint(address,uint256)'(
    account: string,
    amount: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  decimals(overrides?: CallOverrides): Promise<number>

  'decimals()'(overrides?: CallOverrides): Promise<number>

  decreaseAllowance(
    spender: string,
    subtractedValue: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  'decreaseAllowance(address,uint256)'(
    spender: string,
    subtractedValue: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  deposit(overrides?: PayableOverrides): Promise<ContractTransaction>

  'deposit()'(overrides?: PayableOverrides): Promise<ContractTransaction>

  depositTo(
    account: string,
    overrides?: PayableOverrides
  ): Promise<ContractTransaction>

  'depositTo(address)'(
    account: string,
    overrides?: PayableOverrides
  ): Promise<ContractTransaction>

  increaseAllowance(
    spender: string,
    addedValue: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  'increaseAllowance(address,uint256)'(
    spender: string,
    addedValue: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  initialize(
    name_: string,
    symbol_: string,
    decimals_: BigNumberish,
    l2Gateway_: string,
    l1Address_: string,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  'initialize(string,string,uint8,address,address)'(
    name_: string,
    symbol_: string,
    decimals_: BigNumberish,
    l2Gateway_: string,
    l1Address_: string,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  l1Address(overrides?: CallOverrides): Promise<string>

  'l1Address()'(overrides?: CallOverrides): Promise<string>

  l2Gateway(overrides?: CallOverrides): Promise<string>

  'l2Gateway()'(overrides?: CallOverrides): Promise<string>

  name(overrides?: CallOverrides): Promise<string>

  'name()'(overrides?: CallOverrides): Promise<string>

  nonces(owner: string, overrides?: CallOverrides): Promise<BigNumber>

  'nonces(address)'(
    owner: string,
    overrides?: CallOverrides
  ): Promise<BigNumber>

  permit(
    owner: string,
    spender: string,
    value: BigNumberish,
    deadline: BigNumberish,
    v: BigNumberish,
    r: BytesLike,
    s: BytesLike,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  'permit(address,address,uint256,uint256,uint8,bytes32,bytes32)'(
    owner: string,
    spender: string,
    value: BigNumberish,
    deadline: BigNumberish,
    v: BigNumberish,
    r: BytesLike,
    s: BytesLike,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  symbol(overrides?: CallOverrides): Promise<string>

  'symbol()'(overrides?: CallOverrides): Promise<string>

  totalSupply(overrides?: CallOverrides): Promise<BigNumber>

  'totalSupply()'(overrides?: CallOverrides): Promise<BigNumber>

  transfer(
    recipient: string,
    amount: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  'transfer(address,uint256)'(
    recipient: string,
    amount: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  transferAndCall(
    _to: string,
    _value: BigNumberish,
    _data: BytesLike,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  'transferAndCall(address,uint256,bytes)'(
    _to: string,
    _value: BigNumberish,
    _data: BytesLike,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  transferFrom(
    sender: string,
    recipient: string,
    amount: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  'transferFrom(address,address,uint256)'(
    sender: string,
    recipient: string,
    amount: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  withdraw(
    amount: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  'withdraw(uint256)'(
    amount: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  withdrawTo(
    account: string,
    amount: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  'withdrawTo(address,uint256)'(
    account: string,
    amount: BigNumberish,
    overrides?: Overrides
  ): Promise<ContractTransaction>

  callStatic: {
    DOMAIN_SEPARATOR(overrides?: CallOverrides): Promise<string>

    'DOMAIN_SEPARATOR()'(overrides?: CallOverrides): Promise<string>

    allowance(
      owner: string,
      spender: string,
      overrides?: CallOverrides
    ): Promise<BigNumber>

    'allowance(address,address)'(
      owner: string,
      spender: string,
      overrides?: CallOverrides
    ): Promise<BigNumber>

    approve(
      spender: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<boolean>

    'approve(address,uint256)'(
      spender: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<boolean>

    balanceOf(account: string, overrides?: CallOverrides): Promise<BigNumber>

    'balanceOf(address)'(
      account: string,
      overrides?: CallOverrides
    ): Promise<BigNumber>

    bridgeBurn(
      account: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<void>

    'bridgeBurn(address,uint256)'(
      account: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<void>

    bridgeMint(
      account: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<void>

    'bridgeMint(address,uint256)'(
      account: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<void>

    decimals(overrides?: CallOverrides): Promise<number>

    'decimals()'(overrides?: CallOverrides): Promise<number>

    decreaseAllowance(
      spender: string,
      subtractedValue: BigNumberish,
      overrides?: CallOverrides
    ): Promise<boolean>

    'decreaseAllowance(address,uint256)'(
      spender: string,
      subtractedValue: BigNumberish,
      overrides?: CallOverrides
    ): Promise<boolean>

    deposit(overrides?: CallOverrides): Promise<void>

    'deposit()'(overrides?: CallOverrides): Promise<void>

    depositTo(account: string, overrides?: CallOverrides): Promise<void>

    'depositTo(address)'(
      account: string,
      overrides?: CallOverrides
    ): Promise<void>

    increaseAllowance(
      spender: string,
      addedValue: BigNumberish,
      overrides?: CallOverrides
    ): Promise<boolean>

    'increaseAllowance(address,uint256)'(
      spender: string,
      addedValue: BigNumberish,
      overrides?: CallOverrides
    ): Promise<boolean>

    initialize(
      name_: string,
      symbol_: string,
      decimals_: BigNumberish,
      l2Gateway_: string,
      l1Address_: string,
      overrides?: CallOverrides
    ): Promise<void>

    'initialize(string,string,uint8,address,address)'(
      name_: string,
      symbol_: string,
      decimals_: BigNumberish,
      l2Gateway_: string,
      l1Address_: string,
      overrides?: CallOverrides
    ): Promise<void>

    l1Address(overrides?: CallOverrides): Promise<string>

    'l1Address()'(overrides?: CallOverrides): Promise<string>

    l2Gateway(overrides?: CallOverrides): Promise<string>

    'l2Gateway()'(overrides?: CallOverrides): Promise<string>

    name(overrides?: CallOverrides): Promise<string>

    'name()'(overrides?: CallOverrides): Promise<string>

    nonces(owner: string, overrides?: CallOverrides): Promise<BigNumber>

    'nonces(address)'(
      owner: string,
      overrides?: CallOverrides
    ): Promise<BigNumber>

    permit(
      owner: string,
      spender: string,
      value: BigNumberish,
      deadline: BigNumberish,
      v: BigNumberish,
      r: BytesLike,
      s: BytesLike,
      overrides?: CallOverrides
    ): Promise<void>

    'permit(address,address,uint256,uint256,uint8,bytes32,bytes32)'(
      owner: string,
      spender: string,
      value: BigNumberish,
      deadline: BigNumberish,
      v: BigNumberish,
      r: BytesLike,
      s: BytesLike,
      overrides?: CallOverrides
    ): Promise<void>

    symbol(overrides?: CallOverrides): Promise<string>

    'symbol()'(overrides?: CallOverrides): Promise<string>

    totalSupply(overrides?: CallOverrides): Promise<BigNumber>

    'totalSupply()'(overrides?: CallOverrides): Promise<BigNumber>

    transfer(
      recipient: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<boolean>

    'transfer(address,uint256)'(
      recipient: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<boolean>

    transferAndCall(
      _to: string,
      _value: BigNumberish,
      _data: BytesLike,
      overrides?: CallOverrides
    ): Promise<boolean>

    'transferAndCall(address,uint256,bytes)'(
      _to: string,
      _value: BigNumberish,
      _data: BytesLike,
      overrides?: CallOverrides
    ): Promise<boolean>

    transferFrom(
      sender: string,
      recipient: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<boolean>

    'transferFrom(address,address,uint256)'(
      sender: string,
      recipient: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<boolean>

    withdraw(amount: BigNumberish, overrides?: CallOverrides): Promise<void>

    'withdraw(uint256)'(
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<void>

    withdrawTo(
      account: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<void>

    'withdrawTo(address,uint256)'(
      account: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<void>
  }

  filters: {
    Approval(
      owner: string | null,
      spender: string | null,
      value: null
    ): EventFilter

    Transfer(
      from: string | null,
      to: string | null,
      value: null,
      data: null
    ): EventFilter
  }

  estimateGas: {
    DOMAIN_SEPARATOR(overrides?: CallOverrides): Promise<BigNumber>

    'DOMAIN_SEPARATOR()'(overrides?: CallOverrides): Promise<BigNumber>

    allowance(
      owner: string,
      spender: string,
      overrides?: CallOverrides
    ): Promise<BigNumber>

    'allowance(address,address)'(
      owner: string,
      spender: string,
      overrides?: CallOverrides
    ): Promise<BigNumber>

    approve(
      spender: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>

    'approve(address,uint256)'(
      spender: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>

    balanceOf(account: string, overrides?: CallOverrides): Promise<BigNumber>

    'balanceOf(address)'(
      account: string,
      overrides?: CallOverrides
    ): Promise<BigNumber>

    bridgeBurn(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>

    'bridgeBurn(address,uint256)'(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>

    bridgeMint(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>

    'bridgeMint(address,uint256)'(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>

    decimals(overrides?: CallOverrides): Promise<BigNumber>

    'decimals()'(overrides?: CallOverrides): Promise<BigNumber>

    decreaseAllowance(
      spender: string,
      subtractedValue: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>

    'decreaseAllowance(address,uint256)'(
      spender: string,
      subtractedValue: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>

    deposit(overrides?: PayableOverrides): Promise<BigNumber>

    'deposit()'(overrides?: PayableOverrides): Promise<BigNumber>

    depositTo(account: string, overrides?: PayableOverrides): Promise<BigNumber>

    'depositTo(address)'(
      account: string,
      overrides?: PayableOverrides
    ): Promise<BigNumber>

    increaseAllowance(
      spender: string,
      addedValue: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>

    'increaseAllowance(address,uint256)'(
      spender: string,
      addedValue: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>

    initialize(
      name_: string,
      symbol_: string,
      decimals_: BigNumberish,
      l2Gateway_: string,
      l1Address_: string,
      overrides?: Overrides
    ): Promise<BigNumber>

    'initialize(string,string,uint8,address,address)'(
      name_: string,
      symbol_: string,
      decimals_: BigNumberish,
      l2Gateway_: string,
      l1Address_: string,
      overrides?: Overrides
    ): Promise<BigNumber>

    l1Address(overrides?: CallOverrides): Promise<BigNumber>

    'l1Address()'(overrides?: CallOverrides): Promise<BigNumber>

    l2Gateway(overrides?: CallOverrides): Promise<BigNumber>

    'l2Gateway()'(overrides?: CallOverrides): Promise<BigNumber>

    name(overrides?: CallOverrides): Promise<BigNumber>

    'name()'(overrides?: CallOverrides): Promise<BigNumber>

    nonces(owner: string, overrides?: CallOverrides): Promise<BigNumber>

    'nonces(address)'(
      owner: string,
      overrides?: CallOverrides
    ): Promise<BigNumber>

    permit(
      owner: string,
      spender: string,
      value: BigNumberish,
      deadline: BigNumberish,
      v: BigNumberish,
      r: BytesLike,
      s: BytesLike,
      overrides?: Overrides
    ): Promise<BigNumber>

    'permit(address,address,uint256,uint256,uint8,bytes32,bytes32)'(
      owner: string,
      spender: string,
      value: BigNumberish,
      deadline: BigNumberish,
      v: BigNumberish,
      r: BytesLike,
      s: BytesLike,
      overrides?: Overrides
    ): Promise<BigNumber>

    symbol(overrides?: CallOverrides): Promise<BigNumber>

    'symbol()'(overrides?: CallOverrides): Promise<BigNumber>

    totalSupply(overrides?: CallOverrides): Promise<BigNumber>

    'totalSupply()'(overrides?: CallOverrides): Promise<BigNumber>

    transfer(
      recipient: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>

    'transfer(address,uint256)'(
      recipient: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>

    transferAndCall(
      _to: string,
      _value: BigNumberish,
      _data: BytesLike,
      overrides?: Overrides
    ): Promise<BigNumber>

    'transferAndCall(address,uint256,bytes)'(
      _to: string,
      _value: BigNumberish,
      _data: BytesLike,
      overrides?: Overrides
    ): Promise<BigNumber>

    transferFrom(
      sender: string,
      recipient: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>

    'transferFrom(address,address,uint256)'(
      sender: string,
      recipient: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>

    withdraw(amount: BigNumberish, overrides?: Overrides): Promise<BigNumber>

    'withdraw(uint256)'(
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>

    withdrawTo(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>

    'withdrawTo(address,uint256)'(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<BigNumber>
  }

  populateTransaction: {
    DOMAIN_SEPARATOR(overrides?: CallOverrides): Promise<PopulatedTransaction>

    'DOMAIN_SEPARATOR()'(
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>

    allowance(
      owner: string,
      spender: string,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>

    'allowance(address,address)'(
      owner: string,
      spender: string,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>

    approve(
      spender: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    'approve(address,uint256)'(
      spender: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    balanceOf(
      account: string,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>

    'balanceOf(address)'(
      account: string,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>

    bridgeBurn(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    'bridgeBurn(address,uint256)'(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    bridgeMint(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    'bridgeMint(address,uint256)'(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    decimals(overrides?: CallOverrides): Promise<PopulatedTransaction>

    'decimals()'(overrides?: CallOverrides): Promise<PopulatedTransaction>

    decreaseAllowance(
      spender: string,
      subtractedValue: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    'decreaseAllowance(address,uint256)'(
      spender: string,
      subtractedValue: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    deposit(overrides?: PayableOverrides): Promise<PopulatedTransaction>

    'deposit()'(overrides?: PayableOverrides): Promise<PopulatedTransaction>

    depositTo(
      account: string,
      overrides?: PayableOverrides
    ): Promise<PopulatedTransaction>

    'depositTo(address)'(
      account: string,
      overrides?: PayableOverrides
    ): Promise<PopulatedTransaction>

    increaseAllowance(
      spender: string,
      addedValue: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    'increaseAllowance(address,uint256)'(
      spender: string,
      addedValue: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    initialize(
      name_: string,
      symbol_: string,
      decimals_: BigNumberish,
      l2Gateway_: string,
      l1Address_: string,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    'initialize(string,string,uint8,address,address)'(
      name_: string,
      symbol_: string,
      decimals_: BigNumberish,
      l2Gateway_: string,
      l1Address_: string,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    l1Address(overrides?: CallOverrides): Promise<PopulatedTransaction>

    'l1Address()'(overrides?: CallOverrides): Promise<PopulatedTransaction>

    l2Gateway(overrides?: CallOverrides): Promise<PopulatedTransaction>

    'l2Gateway()'(overrides?: CallOverrides): Promise<PopulatedTransaction>

    name(overrides?: CallOverrides): Promise<PopulatedTransaction>

    'name()'(overrides?: CallOverrides): Promise<PopulatedTransaction>

    nonces(
      owner: string,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>

    'nonces(address)'(
      owner: string,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>

    permit(
      owner: string,
      spender: string,
      value: BigNumberish,
      deadline: BigNumberish,
      v: BigNumberish,
      r: BytesLike,
      s: BytesLike,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    'permit(address,address,uint256,uint256,uint8,bytes32,bytes32)'(
      owner: string,
      spender: string,
      value: BigNumberish,
      deadline: BigNumberish,
      v: BigNumberish,
      r: BytesLike,
      s: BytesLike,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    symbol(overrides?: CallOverrides): Promise<PopulatedTransaction>

    'symbol()'(overrides?: CallOverrides): Promise<PopulatedTransaction>

    totalSupply(overrides?: CallOverrides): Promise<PopulatedTransaction>

    'totalSupply()'(overrides?: CallOverrides): Promise<PopulatedTransaction>

    transfer(
      recipient: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    'transfer(address,uint256)'(
      recipient: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    transferAndCall(
      _to: string,
      _value: BigNumberish,
      _data: BytesLike,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    'transferAndCall(address,uint256,bytes)'(
      _to: string,
      _value: BigNumberish,
      _data: BytesLike,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    transferFrom(
      sender: string,
      recipient: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    'transferFrom(address,address,uint256)'(
      sender: string,
      recipient: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    withdraw(
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    'withdraw(uint256)'(
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    withdrawTo(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>

    'withdrawTo(address,uint256)'(
      account: string,
      amount: BigNumberish,
      overrides?: Overrides
    ): Promise<PopulatedTransaction>
  }
}
