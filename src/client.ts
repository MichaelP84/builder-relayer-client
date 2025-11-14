import { Wallet } from "@ethersproject/wallet";
import { JsonRpcSigner } from "@ethersproject/providers";
import { WalletClient, zeroAddress } from "viem";
import { createAbstractSigner, IAbstractSigner } from "@polymarket/builder-abstract-signer";
import { GET, POST, HttpClient, RequestOptions } from "./http-helpers";
import {
    GetDeployedResponse,
    NoncePayload,
    RelayerTransaction,
    RelayerTransactionResponse,
    SafeCreateTransactionArgs,
    SafeTransaction,
    SafeTransactionArgs,
    TransactionType,
} from "./types";
import {
    GET_DEPLOYED,
    GET_NONCE,
    GET_TRANSACTION,
    GET_TRANSACTIONS,
    SUBMIT_TRANSACTION,
} from "./endpoints";
import {
    buildSafeTransactionRequest,
    buildSafeCreateTransactionRequest,
    deriveSafe,
} from "./builder";
import { sleep } from "./utils";
import { ClientRelayerTransactionResponse } from "./response";
import { ContractConfig, getContractConfig } from "./config";
import { BuilderConfig, BuilderHeaderPayload } from "@polymarket/builder-signing-sdk";
import { SAFE_DEPLOYED, SAFE_NOT_DEPLOYED, SIGNER_UNAVAILABLE } from "./errors";

// Type imports for Privy (optional - only used if WalletWithMetadata is provided)
type PrivyClient = any;
type WalletWithMetadata = {
    address: string;
    id?: string | null | undefined;
    delegated?: boolean | undefined;
    [key: string]: any;
};

/**
 * Privy signer adapter that implements IAbstractSigner interface
 * Uses Privy's server-side signing API to sign messages and typed data
 */
class PrivySigner implements IAbstractSigner {
    private wallet: WalletWithMetadata;
    private privyClient: PrivyClient;
    private address: string;
    private authorizationPrivateKey?: string;

    constructor(
        wallet: WalletWithMetadata,
        privyClient: PrivyClient,
        authorizationPrivateKey?: string,
    ) {
        if (!wallet.delegated) {
            throw new Error("Wallet must be delegated to sign transactions");
        }
        if (!wallet.address) {
            throw new Error("Wallet must have an address");
        }
        this.wallet = wallet;
        this.privyClient = privyClient;
        this.address = wallet.address.toLowerCase();
        this.authorizationPrivateKey = authorizationPrivateKey;
    }

    async getAddress(): Promise<string> {
        return this.address;
    }

    async signMessage(message: string | Uint8Array): Promise<string> {
        const walletId = this.wallet.id;
        if (!walletId) {
            throw new Error("Wallet ID is required for signing");
        }

        // Use Privy's ethereum().signMessage() method with authorization context
        const response = await this.privyClient
            .wallets()
            .ethereum()
            .signMessage(walletId, {
                message,
                authorization_context: this.authorizationPrivateKey
                    ? {
                          authorization_private_keys: [this.authorizationPrivateKey],
                      }
                    : {},
            });

        if (!response || !response.signature) {
            throw new Error("Failed to sign message with Privy");
        }

        return response.signature;
    }

    async signTypedData(
        domain: {
            name?: string;
            version?: string;
            chainId?: number | bigint;
            verifyingContract?: string;
            salt?: string;
        },
        types: Record<string, Array<{ name: string; type: string }>>,
        value: Record<string, any>,
        primaryType?: string,
    ): Promise<string> {
        const walletId = this.wallet.id;
        if (!walletId) {
            throw new Error("Wallet ID is required for signing");
        }

        // Helper function to recursively convert BigInt values to strings
        const convertBigIntToString = (obj: any): any => {
            if (obj === null || obj === undefined) {
                return obj;
            }
            if (typeof obj === "bigint") {
                return obj.toString();
            }
            if (Array.isArray(obj)) {
                return obj.map(convertBigIntToString);
            }
            if (typeof obj === "object") {
                const converted: any = {};
                for (const [key, val] of Object.entries(obj)) {
                    converted[key] = convertBigIntToString(val);
                }
                return converted;
            }
            return obj;
        };

        // Convert BigInt values to strings for JSON serialization
        const sanitizedDomain = convertBigIntToString({
            ...domain,
            chainId: domain.chainId ? Number(domain.chainId) : undefined,
        });
        const sanitizedValue = convertBigIntToString(value);

        // Use Privy's ethereum().signTypedData() method with authorization context
        // The API expects params.typed_data with snake_case keys
        const response = await this.privyClient
            .wallets()
            .ethereum()
            .signTypedData(walletId, {
                params: {
                    typed_data: {
                        domain: sanitizedDomain,
                        types,
                        message: sanitizedValue,
                        primary_type: primaryType || Object.keys(types)[0],
                    },
                },
                authorization_context: this.authorizationPrivateKey
                    ? {
                          authorization_private_keys: [this.authorizationPrivateKey],
                      }
                    : {},
            });

        if (!response || !response.signature) {
            throw new Error("Failed to sign typed data with Privy");
        }

        return response.signature;
    }

    async signRawMessage(message: any): Promise<string> {
        // Convert message to hex string
        let messageHex: string;
        if (typeof message === "string") {
            messageHex = message.startsWith("0x")
                ? message
                : "0x" + Buffer.from(message, "utf8").toString("hex");
        } else if (message instanceof Uint8Array) {
            messageHex = "0x" + Buffer.from(message).toString("hex");
        } else {
            messageHex = "0x" + Buffer.from(JSON.stringify(message), "utf8").toString("hex");
        }
        return this.signMessage(messageHex);
    }

    async estimateGas(tx: any): Promise<bigint> {
        console.log("estimateGas", tx);
        // Privy doesn't provide gas estimation directly
        // This would typically be done via an RPC provider
        throw new Error(
            "Gas estimation not supported via Privy signer. Use an RPC provider instead.",
        );
    }

    async signTransaction(tx: any): Promise<string> {
        console.log("signTransaction", tx);
        // Privy doesn't support signing raw transactions directly
        // Transactions should be sent via Privy's sendTransaction method
        throw new Error(
            "Transaction signing not supported via Privy signer. Use sendTransaction instead.",
        );
    }

    async sendTransaction(tx: any): Promise<string> {
        const walletId = this.wallet.id;
        if (!walletId) {
            throw new Error("Wallet ID is required for sending transactions");
        }

        // Use Privy's ethereum().sendTransaction() method with authorization context
        const response = await this.privyClient
            .wallets()
            .ethereum()
            .sendTransaction(walletId, {
                ...tx,
                authorization_context: this.authorizationPrivateKey
                    ? {
                          authorization_private_keys: [this.authorizationPrivateKey],
                      }
                    : {},
            });

        if (!response || !response.hash) {
            throw new Error("Failed to send transaction with Privy");
        }

        return response.hash;
    }

    async waitTillMined(txHash: string): Promise<any> {
        console.log("waitTillMined", txHash);
        // Privy doesn't provide transaction waiting functionality
        // This would typically be done via an RPC provider
        throw new Error(
            "Transaction waiting not supported via Privy signer. Use an RPC provider instead.",
        );
    }
}

export class RelayClient {
    readonly relayerUrl: string;

    readonly chainId: number;

    readonly contractConfig: ContractConfig;

    readonly httpClient: HttpClient;

    readonly signer?: IAbstractSigner;

    readonly builderConfig?: BuilderConfig;

    __deployed: boolean;

    // Constructor overloads for better type inference
    constructor(
        relayerUrl: string,
        chainId: number,
        signer?: Wallet | JsonRpcSigner | WalletClient,
        builderConfig?: BuilderConfig,
    );
    constructor(
        relayerUrl: string,
        chainId: number,
        signer: WalletWithMetadata,
        builderConfig: BuilderConfig | undefined,
        privyClient: PrivyClient,
    );
    constructor(
        relayerUrl: string,
        chainId: number,
        signer: WalletWithMetadata,
        builderConfig?: BuilderConfig,
        privyClient?: PrivyClient,
    );
    constructor(
        relayerUrl: string,
        chainId: number,
        signer?: Wallet | JsonRpcSigner | WalletClient | WalletWithMetadata,
        builderConfig?: BuilderConfig,
        privyClient?: PrivyClient,
    ) {
        console.log("RelayClient constructor", relayerUrl, chainId, signer, builderConfig);
        this.relayerUrl = relayerUrl.endsWith("/") ? relayerUrl.slice(0, -1) : relayerUrl;
        this.chainId = chainId;
        this.contractConfig = getContractConfig(chainId);
        this.httpClient = new HttpClient();
        this.__deployed = false;

        if (signer != undefined) {
            // Check if it's a WalletWithMetadata (has address and delegated properties)
            if (
                typeof signer === "object" &&
                "address" in signer &&
                "delegated" in signer &&
                signer.delegated === true
            ) {
                // It's a Privy WalletWithMetadata
                if (!privyClient) {
                    throw new Error("PrivyClient is required when using WalletWithMetadata");
                }
                // Get authorization private key from environment if available
                const authorizationPrivateKey = process.env.PRIVY_KEY_QUORUM_SECRET;
                this.signer = new PrivySigner(
                    signer as WalletWithMetadata,
                    privyClient,
                    authorizationPrivateKey,
                );
            } else {
                // It's a standard signer (Wallet, JsonRpcSigner, or WalletClient)
                this.signer = createAbstractSigner(
                    chainId,
                    signer as Wallet | JsonRpcSigner | WalletClient,
                );
            }
        }

        if (builderConfig !== undefined) {
            this.builderConfig = builderConfig;
        }
    }

    public async getNonce(signerAddress: string, signerType: string): Promise<NoncePayload> {
        return this.send(`${GET_NONCE}`, GET, {
            params: { address: signerAddress, type: signerType },
        });
    }

    public async getTransaction(transactionId: string): Promise<RelayerTransaction[]> {
        return this.send(`${GET_TRANSACTION}`, GET, { params: { id: transactionId } });
    }

    public async getTransactions(): Promise<RelayerTransaction[]> {
        return this.sendAuthedRequest(GET, GET_TRANSACTIONS);
    }

    /**
     * Executes a batch of safe transactions
     * @param txns
     * @param metadata
     * @returns
     */
    public async execute(
        txns: SafeTransaction[],
        metadata?: string,
    ): Promise<RelayerTransactionResponse> {
        this.signerNeeded();
        const safe = await this.getExpectedSafe();

        const deployed = await this.getDeployed(safe);
        if (!deployed) {
            throw SAFE_NOT_DEPLOYED;
        }

        const start = Date.now();
        const from = await (this.signer as IAbstractSigner).getAddress();

        const noncePayload = await this.getNonce(from, TransactionType.SAFE);

        const args: SafeTransactionArgs = {
            transactions: txns,
            from,
            nonce: noncePayload.nonce,
            chainId: this.chainId,
        };

        const safeContractConfig = this.contractConfig.SafeContracts;

        const request = await buildSafeTransactionRequest(
            this.signer as IAbstractSigner,
            args,
            safeContractConfig,
            metadata,
        );

        console.log(
            `Client side safe request creation took: ${(Date.now() - start) / 1000} seconds`,
        );

        const requestPayload = JSON.stringify(request);

        const resp: RelayerTransactionResponse = await this.sendAuthedRequest(
            POST,
            SUBMIT_TRANSACTION,
            requestPayload,
        );

        return new ClientRelayerTransactionResponse(
            resp.transactionID,
            resp.state,
            resp.transactionHash,
            this,
        );
    }

    /**
     * Deploys a safe
     * @returns
     */
    public async deploy(): Promise<RelayerTransactionResponse> {
        this.signerNeeded();
        const safe = await this.getExpectedSafe();

        const deployed = await this.getDeployed(safe);
        if (deployed) {
            console.log("Safe already deployed", deployed);
            throw SAFE_DEPLOYED;
        }
        console.log(`Deploying safe ${safe}...`);
        return this._deploy();
    }

    private async _deploy(): Promise<RelayerTransactionResponse> {
        const start = Date.now();
        const from = await (this.signer as IAbstractSigner).getAddress();
        const args: SafeCreateTransactionArgs = {
            from: from,
            chainId: this.chainId,
            paymentToken: zeroAddress,
            payment: "0",
            paymentReceiver: zeroAddress,
        };
        const safeContractConfig = this.contractConfig.SafeContracts;

        const request = await buildSafeCreateTransactionRequest(
            this.signer as IAbstractSigner,
            safeContractConfig,
            args,
        );

        console.log(
            `Client side deploy request creation took: ${(Date.now() - start) / 1000} seconds`,
        );

        const requestPayload = JSON.stringify(request);

        const resp: RelayerTransactionResponse = await this.sendAuthedRequest(
            POST,
            SUBMIT_TRANSACTION,
            requestPayload,
        );

        return new ClientRelayerTransactionResponse(
            resp.transactionID,
            resp.state,
            resp.transactionHash,
            this,
        );
    }

    private async getDeployed(safe: string): Promise<boolean> {
        const resp: GetDeployedResponse = await this.send(`${GET_DEPLOYED}`, GET, {
            params: { address: safe },
        });
        return resp.deployed;
    }

    /**
     * Periodically polls the transaction id until it reaches a desired state
     * Returns the relayer transaction if it does each the desired state
     * Returns undefined if the transaction hits the failed state
     * Times out after maxPolls is reached
     * @param transactionId
     * @param states
     * @param failState
     * @param maxPolls
     * @param pollFrequency
     * @returns
     */
    public async pollUntilState(
        transactionId: string,
        states: string[],
        failState?: string,
        maxPolls?: number,
        pollFrequency?: number,
    ): Promise<RelayerTransaction | undefined> {
        console.log(`Waiting for transaction ${transactionId} matching states: ${states}...`);
        const maxPollCount = maxPolls != undefined ? maxPolls : 10;
        let pollFreq = 2000; // Default to polling every 2 seconds
        if (pollFrequency != undefined) {
            if (pollFrequency >= 1000) {
                pollFreq = pollFrequency;
            }
        }
        let pollCount = 0;
        while (pollCount < maxPollCount) {
            const txns = await this.getTransaction(transactionId);
            if (txns.length > 0) {
                const txn = txns[0];
                if (states.includes(txn.state)) {
                    return txn;
                }
                if (failState != undefined && txn.state == failState) {
                    console.error(
                        `txn ${transactionId} failed onchain! Transaction hash: ${txn.transactionHash}`,
                    );
                    return undefined;
                }
            }
            pollCount++;
            await sleep(pollFreq);
        }
        console.log(`Transaction not found or not in given states, timing out!`);
    }

    private async sendAuthedRequest(method: string, path: string, body?: string): Promise<any> {
        // builders auth
        if (this.canBuilderAuth()) {
            const builderHeaders = await this._generateBuilderHeaders(method, path, body);
            if (builderHeaders !== undefined) {
                return this.send(path, method, { headers: builderHeaders, data: body });
            }
        }

        return this.send(path, method, { data: body });
    }

    private async _generateBuilderHeaders(
        method: string,
        path: string,
        body?: string,
    ): Promise<BuilderHeaderPayload | undefined> {
        if (this.builderConfig !== undefined) {
            const builderHeaders = await this.builderConfig.generateBuilderHeaders(
                method,
                path,
                body,
            );
            if (builderHeaders == undefined) {
                return undefined;
            }
            return builderHeaders;
        }

        return undefined;
    }

    private canBuilderAuth(): boolean {
        return this.builderConfig != undefined && this.builderConfig.isValid();
    }

    private async send(endpoint: string, method: string, options?: RequestOptions): Promise<any> {
        const resp = await this.httpClient.send(`${this.relayerUrl}${endpoint}`, method, options);
        return resp.data;
    }

    private signerNeeded(): void {
        if (this.signer === undefined) {
            throw SIGNER_UNAVAILABLE;
        }
    }

    private async getExpectedSafe(): Promise<string> {
        const address = await (this.signer as IAbstractSigner).getAddress();
        return deriveSafe(address, this.contractConfig.SafeContracts.SafeFactory);
    }
}
