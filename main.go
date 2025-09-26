package main

import (
    "context"
    "crypto/ecdsa"
    "fmt"
    "log"
    "math/big"
    "strings"
    "time"

    "github.com/ethereum/go-ethereum"
    "github.com/ethereum/go-ethereum/accounts/abi"
    "github.com/ethereum/go-ethereum/accounts/abi/bind"
    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/core/types"
    "github.com/ethereum/go-ethereum/crypto"
    "github.com/ethereum/go-ethereum/ethclient"
)

type TokenCollector struct {
    client      *ethclient.Client
    privateKeys []string
    masterAddr  common.Address
    gasPrice    *big.Int
}

type CollectionResult struct {
    FromAddress string
    TxHash      string
    Amount      *big.Int
    Success     bool
    Error       error
}

func NewTokenCollector(rpcURL string, masterAddress string, gasPrice *big.Int) (*TokenCollector, error) {
    client, err := ethclient.Dial(rpcURL)
    if err != nil {
        return nil, err
    }

    return &TokenCollector{
        client:   client,
        masterAddr: common.HexToAddress(masterAddress),
        gasPrice: gasPrice,
    }, nil
}

func (tc *TokenCollector) AddWallet(privateKey string) {
    tc.privateKeys = append(tc.privateKeys, privateKey)
}

// ERC20代币归集
func (tc *TokenCollector) CollectERC20Tokens(tokenAddress common.Address, minAmount *big.Int) []CollectionResult {
    var results []CollectionResult

    // ERC20 ABI
    erc20ABI := `[
        {
            "constant": true,
            "inputs": [{"name": "_owner", "type": "address"}],
            "name": "balanceOf",
            "outputs": [{"name": "balance", "type": "uint256"}],
            "type": "function"
        },
        {
            "constant": false,
            "inputs": [
                {"name": "_to", "type": "address"},
                {"name": "_value", "type": "uint256"}
            ],
            "name": "transfer",
            "outputs": [{"name": "", "type": "bool"}],
            "type": "function"
        },
        {
            "constant": true,
            "inputs": [],
            "name": "decimals",
            "outputs": [{"name": "", "type": "uint8"}],
            "type": "function"
        }
    ]`

    parsedABI, err := abi.JSON(strings.NewReader(erc20ABI))
    if err != nil {
        log.Fatalf("Failed to parse ABI: %v", err)
    }

    tokenContract := bind.NewBoundContract(tokenAddress, parsedABI, tc.client, tc.client, tc.client)

    for _, privKey := range tc.privateKeys {
        result := tc.collectFromWallet(privKey, tokenAddress, tokenContract, minAmount)
        results = append(results, result)
        
        // 避免nonce冲突
        time.Sleep(2 * time.Second)
    }

    return results
}

func (tc *TokenCollector) collectFromWallet(privateKeyHex string, tokenAddr common.Address, contract *bind.BoundContract, minAmount *big.Int) CollectionResult {
    // 解析私钥
    privateKey, err := crypto.HexToECDSA(privateKeyHex)
    if err != nil {
        return CollectionResult{Error: err}
    }

    publicKey := privateKey.Public()
    publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
    if !ok {
        return CollectionResult{Error: fmt.Errorf("cannot assert type: publicKey is not of type *ecdsa.PublicKey")}
    }

    fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

    // 检查代币余额
    var balance *big.Int
    err = contract.Call(&bind.CallOpts{}, &balance, "balanceOf", fromAddress)
    if err != nil {
        return CollectionResult{
            FromAddress: fromAddress.Hex(),
            Error:       err,
        }
    }

    // 如果余额低于最小金额，跳过
    if balance.Cmp(minAmount) < 0 {
        return CollectionResult{
            FromAddress: fromAddress.Hex(),
            Amount:      balance,
            Success:     false,
            Error:       fmt.Errorf("balance too low: %s", balance.String()),
        }
    }

    // 获取nonce
    nonce, err := tc.client.PendingNonceAt(context.Background(), fromAddress)
    if err != nil {
        return CollectionResult{
            FromAddress: fromAddress.Hex(),
            Error:       err,
        }
    }

    // 构建转账交易
    transferData, err := contract.Transact(&bind.TransactOpts{
        From:     fromAddress,
        Nonce:    big.NewInt(int64(nonce)),
        GasLimit: 100000,
        GasPrice: tc.gasPrice,
        Signer: func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
            if address != fromAddress {
                return nil, fmt.Errorf("not authorized to sign this account")
            }
            chainID, err := tc.client.NetworkID(context.Background())
            if err != nil {
                return nil, err
            }
            return types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
        },
    }, "transfer", tc.masterAddr, balance)

    if err != nil {
        return CollectionResult{
            FromAddress: fromAddress.Hex(),
            Amount:      balance,
            Error:       err,
        }
    }

    return CollectionResult{
        FromAddress: fromAddress.Hex(),
        TxHash:      transferData.Hash().Hex(),
        Amount:      balance,
        Success:     true,
    }
}

// ETH归集
func (tc *TokenCollector) CollectETH(minAmount *big.Int, reserveAmount *big.Int) []CollectionResult {
    var results []CollectionResult

    for _, privKey := range tc.privateKeys {
        result := tc.collectETHFromWallet(privKey, minAmount, reserveAmount)
        results = append(results, result)
        time.Sleep(2 * time.Second)
    }

    return results
}

func (tc *TokenCollector) collectETHFromWallet(privateKeyHex string, minAmount, reserveAmount *big.Int) CollectionResult {
    privateKey, err := crypto.HexToECDSA(privateKeyHex)
    if err != nil {
        return CollectionResult{Error: err}
    }

    publicKey := privateKey.Public()
    publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
    if !ok {
        return CollectionResult{Error: fmt.Errorf("cannot assert type")}
    }

    fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

    // 获取ETH余额
    balance, err := tc.client.BalanceAt(context.Background(), fromAddress, nil)
    if err != nil {
        return CollectionResult{FromAddress: fromAddress.Hex(), Error: err}
    }

    // 计算gas费用
    gasLimit := uint64(21000)
    gasCost := new(big.Int).Mul(big.NewInt(int64(gasLimit)), tc.gasPrice)

    // 计算可转账金额
    transferAmount := new(big.Int).Sub(balance, gasCost)
    transferAmount.Sub(transferAmount, reserveAmount)

    if transferAmount.Cmp(minAmount) < 0 {
        return CollectionResult{
            FromAddress: fromAddress.Hex(),
            Amount:      balance,
            Success:     false,
            Error:       fmt.Errorf("insufficient balance after gas and reserve"),
        }
    }

    // 获取nonce
    nonce, err := tc.client.PendingNonceAt(context.Background(), fromAddress)
    if err != nil {
        return CollectionResult{FromAddress: fromAddress.Hex(), Error: err}
    }

    // 构建交易
    tx := types.NewTransaction(nonce, tc.masterAddr, transferAmount, gasLimit, tc.gasPrice, nil)

    // 签名交易
    chainID, err := tc.client.NetworkID(context.Background())
    if err != nil {
        return CollectionResult{FromAddress: fromAddress.Hex(), Error: err}
    }

    signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
    if err != nil {
        return CollectionResult{FromAddress: fromAddress.Hex(), Error: err}
    }

    // 发送交易
    err = tc.client.SendTransaction(context.Background(), signedTx)
    if err != nil {
        return CollectionResult{
            FromAddress: fromAddress.Hex(),
            Amount:      transferAmount,
            Error:       err,
        }
    }

    return CollectionResult{
        FromAddress: fromAddress.Hex(),
        TxHash:      signedTx.Hash().Hex(),
        Amount:      transferAmount,
        Success:     true,
    }
}

func main() {
    // 初始化收集器
    collector, err := NewTokenCollector(
        "https://mainnet.infura.io/v3/YOUR_INFURA_KEY",
        "0xMASTER_WALLET_ADDRESS",
        big.NewInt(20000000000), // 20 gwei
    )
    if err != nil {
        log.Fatal(err)
    }

    // 添加需要归集的钱包私钥
    privateKeys := []string{
        "PRIVATE_KEY_1",
        "PRIVATE_KEY_2",
        // ... 更多私钥
    }

    for _, key := range privateKeys {
        collector.AddWallet(key)
    }

    // 归集ERC20代币
    tokenAddress := common.HexToAddress("0xTOKEN_CONTRACT_ADDRESS")
    minTokenAmount := big.NewInt(1000000000000000000) // 1 token (18 decimals)

    fmt.Println("开始归集ERC20代币...")
    results := collector.CollectERC20Tokens(tokenAddress, minTokenAmount)

    for _, result := range results {
        if result.Success {
            fmt.Printf("成功: %s -> %s, 金额: %s\n", 
                result.FromAddress, result.TxHash, result.Amount.String())
        } else {
            fmt.Printf("失败: %s, 错误: %v\n", result.FromAddress, result.Error)
        }
    }

    // 归集ETH
    fmt.Println("\n开始归集ETH...")
    minETHAmount := big.NewInt(100000000000000000)  // 0.1 ETH
    reserveETH := big.NewInt(50000000000000000)     // 保留0.05 ETH作为gas费

    ethResults := collector.CollectETH(minETHAmount, reserveETH)

    for _, result := range ethResults {
        if result.Success {
            fmt.Printf("ETH归集成功: %s -> %s, 金额: %s\n", 
                result.FromAddress, result.TxHash, result.Amount.String())
        } else {
            fmt.Printf("ETH归集失败: %s, 错误: %v\n", result.FromAddress, result.Error)
        }
    }
}
