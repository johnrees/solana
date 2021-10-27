import { blob, struct, u32, offset, nu64, u8, seq, ns64 } from "@solana/buffer-layout";
import { Buffer } from "buffer";
import BN from "bn.js";
import bs58 from "bs58";
import nacl from "tweetnacl";
import { sha256 } from "@ethersproject/sha2";
import { serialize, deserialize, deserializeUnchecked } from "borsh";
const publicKey = (property = "publicKey") => blob(32, property);
const rustString = (property = "string") => {
    const rsl = struct([ u32("length"), u32("lengthPadding"), blob(offset(u32(), -8), "chars") ], property);
    const _decode = rsl.decode.bind(rsl);
    const _encode = rsl.encode.bind(rsl);
    rsl.decode = (buffer, offset) => {
        const data = _decode(buffer, offset);
        return data["chars"].toString("utf8");
    };
    rsl.encode = (str, buffer, offset) => {
        const data = {
            chars: Buffer.from(str, "utf8")
        };
        return _encode(data, buffer, offset);
    };
    rsl.alloc = str => u32().span + u32().span + Buffer.from(str, "utf8").length;
    return rsl;
};
function getAlloc(type, fields) {
    let alloc = 0;
    type.layout.fields.forEach((item => {
        if (item.span >= 0) alloc += item.span; else if ("function" === typeof item.alloc) alloc += item.alloc(fields[item.property]);
    }));
    return alloc;
}
function encodeData(type, fields) {
    const allocLength = type.layout.span >= 0 ? type.layout.span : getAlloc(type, fields);
    const data = Buffer.alloc(allocLength);
    const layoutFields = Object.assign({
        instruction: type.index
    }, fields);
    type.layout.encode(layoutFields, data);
    return data;
}
class Struct {
    constructor(properties) {
        Object.assign(this, properties);
    }
    encode() {
        return Buffer.from(serialize(SOLANA_SCHEMA, this));
    }
    static decode(data) {
        return deserialize(SOLANA_SCHEMA, this, data);
    }
    static decodeUnchecked(data) {
        return deserializeUnchecked(SOLANA_SCHEMA, this, data);
    }
}
const SOLANA_SCHEMA = new Map;
const toBuffer = arr => {
    if (Buffer.isBuffer(arr)) return arr; else if (arr instanceof Uint8Array) return Buffer.from(arr.buffer, arr.byteOffset, arr.byteLength); else return Buffer.from(arr);
};
const MAX_SEED_LENGTH = 32;
function isPublicKeyData(value) {
    return void 0 !== value._bn;
}
class PublicKey extends Struct {
    constructor(value) {
        super({});
        if (isPublicKeyData(value)) this._bn = value._bn; else {
            if ("string" === typeof value) {
                const decoded = bs58.decode(value);
                if (32 != decoded.length) throw new Error(`Invalid public key input`);
                this._bn = new BN(decoded);
            } else this._bn = new BN(value);
            if (this._bn.byteLength() > 32) throw new Error(`Invalid public key input`);
        }
    }
    equals(publicKey) {
        return this._bn.eq(publicKey._bn);
    }
    toBase58() {
        return bs58.encode(this.toBytes());
    }
    toBytes() {
        return this.toBuffer();
    }
    toBuffer() {
        const b = this._bn.toArrayLike(Buffer);
        if (32 === b.length) return b;
        const zeroPad = Buffer.alloc(32);
        b.copy(zeroPad, 32 - b.length);
        return zeroPad;
    }
    toString() {
        return this.toBase58();
    }
    static async createWithSeed(fromPublicKey, seed, programId) {
        const buffer = Buffer.concat([ fromPublicKey.toBuffer(), Buffer.from(seed), programId.toBuffer() ]);
        const hash = sha256(new Uint8Array(buffer)).slice(2);
        return new PublicKey(Buffer.from(hash, "hex"));
    }
    static async createProgramAddress(seeds, programId) {
        let buffer = Buffer.alloc(0);
        seeds.forEach((function(seed) {
            if (seed.length > MAX_SEED_LENGTH) throw new TypeError(`Max seed length exceeded`);
            buffer = Buffer.concat([ buffer, toBuffer(seed) ]);
        }));
        buffer = Buffer.concat([ buffer, programId.toBuffer(), Buffer.from("ProgramDerivedAddress") ]);
        let hash = sha256(new Uint8Array(buffer)).slice(2);
        let publicKeyBytes = new BN(hash, 16).toArray(void 0, 32);
        if (is_on_curve(publicKeyBytes)) throw new Error(`Invalid seeds, address must fall off the curve`);
        return new PublicKey(publicKeyBytes);
    }
    static async findProgramAddress(seeds, programId) {
        let nonce = 255;
        let address;
        while (0 != nonce) {
            try {
                const seedsWithNonce = seeds.concat(Buffer.from([ nonce ]));
                address = await this.createProgramAddress(seedsWithNonce, programId);
            } catch (err) {
                if (err instanceof TypeError) throw err;
                nonce--;
                continue;
            }
            return [ address, nonce ];
        }
        throw new Error(`Unable to find a viable program address nonce`);
    }
    static isOnCurve(pubkey) {
        return 1 == is_on_curve(pubkey);
    }
}
PublicKey.default = new PublicKey("11111111111111111111111111111111");
let naclLowLevel = nacl.lowlevel;
function is_on_curve(p) {
    var r = [ naclLowLevel.gf(), naclLowLevel.gf(), naclLowLevel.gf(), naclLowLevel.gf() ];
    var t = naclLowLevel.gf(), chk = naclLowLevel.gf(), num = naclLowLevel.gf(), den = naclLowLevel.gf(), den2 = naclLowLevel.gf(), den4 = naclLowLevel.gf(), den6 = naclLowLevel.gf();
    naclLowLevel.set25519(r[2], gf1);
    naclLowLevel.unpack25519(r[1], p);
    naclLowLevel.S(num, r[1]);
    naclLowLevel.M(den, num, naclLowLevel.D);
    naclLowLevel.Z(num, num, r[2]);
    naclLowLevel.A(den, r[2], den);
    naclLowLevel.S(den2, den);
    naclLowLevel.S(den4, den2);
    naclLowLevel.M(den6, den4, den2);
    naclLowLevel.M(t, den6, num);
    naclLowLevel.M(t, t, den);
    naclLowLevel.pow2523(t, t);
    naclLowLevel.M(t, t, num);
    naclLowLevel.M(t, t, den);
    naclLowLevel.M(t, t, den);
    naclLowLevel.M(r[0], t, den);
    naclLowLevel.S(chk, r[0]);
    naclLowLevel.M(chk, chk, den);
    if (neq25519(chk, num)) naclLowLevel.M(r[0], r[0], I);
    naclLowLevel.S(chk, r[0]);
    naclLowLevel.M(chk, chk, den);
    if (neq25519(chk, num)) return 0;
    return 1;
}
let gf1 = naclLowLevel.gf([ 1 ]);
let I = naclLowLevel.gf([ 41136, 18958, 6951, 50414, 58488, 44335, 6150, 12099, 55207, 15867, 153, 11085, 57099, 20417, 9344, 11139 ]);
function neq25519(a, b) {
    var c = new Uint8Array(32), d = new Uint8Array(32);
    naclLowLevel.pack25519(c, a);
    naclLowLevel.pack25519(d, b);
    return naclLowLevel.crypto_verify_32(c, 0, d, 0);
}
const FeeCalculatorLayout = nu64("lamportsPerSignature");
const NonceAccountLayout = struct([ u32("version"), u32("state"), publicKey("authorizedPubkey"), publicKey("nonce"), struct([ FeeCalculatorLayout ], "feeCalculator") ]);
const NONCE_ACCOUNT_LENGTH = NonceAccountLayout.span;
const SYSVAR_RECENT_BLOCKHASHES_PUBKEY = new PublicKey("SysvarRecentB1ockHashes11111111111111111111");
const SYSVAR_RENT_PUBKEY = new PublicKey("SysvarRent111111111111111111111111111111111");
function decodeLength(bytes) {
    let len = 0;
    let size = 0;
    for (;;) {
        let elem = bytes.shift();
        len |= (127 & elem) << 7 * size;
        size += 1;
        if (0 === (128 & elem)) break;
    }
    return len;
}
function encodeLength(bytes, len) {
    let rem_len = len;
    for (;;) {
        let elem = 127 & rem_len;
        rem_len >>= 7;
        if (0 == rem_len) {
            bytes.push(elem);
            break;
        } else {
            elem |= 128;
            bytes.push(elem);
        }
    }
}
const PUBKEY_LENGTH = 32;
class Message {
    constructor(args) {
        this.indexToProgramIds = new Map;
        this.header = args.header;
        this.accountKeys = args.accountKeys.map((account => new PublicKey(account)));
        this.recentBlockhash = args.recentBlockhash;
        this.instructions = args.instructions;
        this.instructions.forEach((ix => this.indexToProgramIds.set(ix.programIdIndex, this.accountKeys[ix.programIdIndex])));
    }
    isAccountSigner(index) {
        return index < this.header.numRequiredSignatures;
    }
    isAccountWritable(index) {
        return index < this.header.numRequiredSignatures - this.header.numReadonlySignedAccounts || index >= this.header.numRequiredSignatures && index < this.accountKeys.length - this.header.numReadonlyUnsignedAccounts;
    }
    isProgramId(index) {
        return this.indexToProgramIds.has(index);
    }
    programIds() {
        return [ ...this.indexToProgramIds.values() ];
    }
    nonProgramIds() {
        return this.accountKeys.filter(((_, index) => !this.isProgramId(index)));
    }
    serialize() {
        const numKeys = this.accountKeys.length;
        let keyCount = [];
        encodeLength(keyCount, numKeys);
        const instructions = this.instructions.map((instruction => {
            const {accounts: accounts, programIdIndex: programIdIndex} = instruction;
            const data = bs58.decode(instruction.data);
            let keyIndicesCount = [];
            encodeLength(keyIndicesCount, accounts.length);
            let dataCount = [];
            encodeLength(dataCount, data.length);
            return {
                programIdIndex: programIdIndex,
                keyIndicesCount: Buffer.from(keyIndicesCount),
                keyIndices: Buffer.from(accounts),
                dataLength: Buffer.from(dataCount),
                data: data
            };
        }));
        let instructionCount = [];
        encodeLength(instructionCount, instructions.length);
        let instructionBuffer = Buffer.alloc(PACKET_DATA_SIZE);
        Buffer.from(instructionCount).copy(instructionBuffer);
        let instructionBufferLength = instructionCount.length;
        instructions.forEach((instruction => {
            const instructionLayout = struct([ u8("programIdIndex"), blob(instruction.keyIndicesCount.length, "keyIndicesCount"), seq(u8("keyIndex"), instruction.keyIndices.length, "keyIndices"), blob(instruction.dataLength.length, "dataLength"), seq(u8("userdatum"), instruction.data.length, "data") ]);
            const length = instructionLayout.encode(instruction, instructionBuffer, instructionBufferLength);
            instructionBufferLength += length;
        }));
        instructionBuffer = instructionBuffer.slice(0, instructionBufferLength);
        const signDataLayout = struct([ blob(1, "numRequiredSignatures"), blob(1, "numReadonlySignedAccounts"), blob(1, "numReadonlyUnsignedAccounts"), blob(keyCount.length, "keyCount"), seq(publicKey("key"), numKeys, "keys"), publicKey("recentBlockhash") ]);
        const transaction = {
            numRequiredSignatures: Buffer.from([ this.header.numRequiredSignatures ]),
            numReadonlySignedAccounts: Buffer.from([ this.header.numReadonlySignedAccounts ]),
            numReadonlyUnsignedAccounts: Buffer.from([ this.header.numReadonlyUnsignedAccounts ]),
            keyCount: Buffer.from(keyCount),
            keys: this.accountKeys.map((key => toBuffer(key.toBytes()))),
            recentBlockhash: bs58.decode(this.recentBlockhash)
        };
        let signData = Buffer.alloc(2048);
        const length = signDataLayout.encode(transaction, signData);
        instructionBuffer.copy(signData, length);
        return signData.slice(0, length + instructionBuffer.length);
    }
    static from(buffer) {
        let byteArray = [ ...buffer ];
        const numRequiredSignatures = byteArray.shift();
        const numReadonlySignedAccounts = byteArray.shift();
        const numReadonlyUnsignedAccounts = byteArray.shift();
        const accountCount = decodeLength(byteArray);
        let accountKeys = [];
        for (let i = 0; i < accountCount; i++) {
            const account = byteArray.slice(0, PUBKEY_LENGTH);
            byteArray = byteArray.slice(PUBKEY_LENGTH);
            accountKeys.push(bs58.encode(Buffer.from(account)));
        }
        const recentBlockhash = byteArray.slice(0, PUBKEY_LENGTH);
        byteArray = byteArray.slice(PUBKEY_LENGTH);
        const instructionCount = decodeLength(byteArray);
        let instructions = [];
        for (let i = 0; i < instructionCount; i++) {
            const programIdIndex = byteArray.shift();
            const accountCount = decodeLength(byteArray);
            const accounts = byteArray.slice(0, accountCount);
            byteArray = byteArray.slice(accountCount);
            const dataLength = decodeLength(byteArray);
            const dataSlice = byteArray.slice(0, dataLength);
            const data = bs58.encode(Buffer.from(dataSlice));
            byteArray = byteArray.slice(dataLength);
            instructions.push({
                programIdIndex: programIdIndex,
                accounts: accounts,
                data: data
            });
        }
        const messageArgs = {
            header: {
                numRequiredSignatures: numRequiredSignatures,
                numReadonlySignedAccounts: numReadonlySignedAccounts,
                numReadonlyUnsignedAccounts: numReadonlyUnsignedAccounts
            },
            recentBlockhash: bs58.encode(Buffer.from(recentBlockhash)),
            accountKeys: accountKeys,
            instructions: instructions
        };
        return new Message(messageArgs);
    }
}
function invariant(condition, message) {
    if (!condition) throw new Error(message || "Assertion failed");
}
const DEFAULT_SIGNATURE = Buffer.alloc(64).fill(0);
const PACKET_DATA_SIZE = 1280 - 40 - 8;
const SIGNATURE_LENGTH = 64;
class TransactionInstruction {
    constructor(opts) {
        this.data = Buffer.alloc(0);
        this.programId = opts.programId;
        this.keys = opts.keys;
        if (opts.data) this.data = opts.data;
    }
}
class Transaction {
    constructor(opts) {
        this.signatures = [];
        this.instructions = [];
        opts && Object.assign(this, opts);
    }
    get signature() {
        if (this.signatures.length > 0) return this.signatures[0].signature;
        return null;
    }
    add(...items) {
        if (0 === items.length) throw new Error("No instructions");
        items.forEach((item => {
            if ("instructions" in item) this.instructions = this.instructions.concat(item.instructions); else if ("data" in item && "programId" in item && "keys" in item) this.instructions.push(item); else this.instructions.push(new TransactionInstruction(item));
        }));
        return this;
    }
    compileMessage() {
        const {nonceInfo: nonceInfo} = this;
        if (nonceInfo && this.instructions[0] != nonceInfo.nonceInstruction) {
            this.recentBlockhash = nonceInfo.nonce;
            this.instructions.unshift(nonceInfo.nonceInstruction);
        }
        const {recentBlockhash: recentBlockhash} = this;
        if (!recentBlockhash) throw new Error("Transaction recentBlockhash required");
        if (this.instructions.length < 1) console.warn("No instructions provided");
        let feePayer;
        if (this.feePayer) feePayer = this.feePayer; else if (this.signatures.length > 0 && this.signatures[0].publicKey) feePayer = this.signatures[0].publicKey; else throw new Error("Transaction fee payer required");
        for (let i = 0; i < this.instructions.length; i++) if (void 0 === this.instructions[i].programId) throw new Error(`Transaction instruction index ${i} has undefined program id`);
        const programIds = [];
        const accountMetas = [];
        this.instructions.forEach((instruction => {
            instruction.keys.forEach((accountMeta => {
                accountMetas.push({
                    ...accountMeta
                });
            }));
            const programId = instruction.programId.toString();
            if (!programIds.includes(programId)) programIds.push(programId);
        }));
        programIds.forEach((programId => {
            accountMetas.push({
                pubkey: new PublicKey(programId),
                isSigner: false,
                isWritable: false
            });
        }));
        accountMetas.sort((function(x, y) {
            const checkSigner = x.isSigner === y.isSigner ? 0 : x.isSigner ? -1 : 1;
            const checkWritable = x.isWritable === y.isWritable ? 0 : x.isWritable ? -1 : 1;
            return checkSigner || checkWritable;
        }));
        const uniqueMetas = [];
        accountMetas.forEach((accountMeta => {
            const pubkeyString = accountMeta.pubkey.toString();
            const uniqueIndex = uniqueMetas.findIndex((x => x.pubkey.toString() === pubkeyString));
            if (uniqueIndex > -1) uniqueMetas[uniqueIndex].isWritable = uniqueMetas[uniqueIndex].isWritable || accountMeta.isWritable; else uniqueMetas.push(accountMeta);
        }));
        const feePayerIndex = uniqueMetas.findIndex((x => x.pubkey.equals(feePayer)));
        if (feePayerIndex > -1) {
            const [payerMeta] = uniqueMetas.splice(feePayerIndex, 1);
            payerMeta.isSigner = true;
            payerMeta.isWritable = true;
            uniqueMetas.unshift(payerMeta);
        } else uniqueMetas.unshift({
            pubkey: feePayer,
            isSigner: true,
            isWritable: true
        });
        for (const signature of this.signatures) {
            const uniqueIndex = uniqueMetas.findIndex((x => x.pubkey.equals(signature.publicKey)));
            if (uniqueIndex > -1) {
                if (!uniqueMetas[uniqueIndex].isSigner) {
                    uniqueMetas[uniqueIndex].isSigner = true;
                    console.warn("Transaction references a signature that is unnecessary, " + "only the fee payer and instruction signer accounts should sign a transaction. " + "This behavior is deprecated and will throw an error in the next major version release.");
                }
            } else throw new Error(`unknown signer: ${signature.publicKey.toString()}`);
        }
        let numRequiredSignatures = 0;
        let numReadonlySignedAccounts = 0;
        let numReadonlyUnsignedAccounts = 0;
        const signedKeys = [];
        const unsignedKeys = [];
        uniqueMetas.forEach((({pubkey: pubkey, isSigner: isSigner, isWritable: isWritable}) => {
            if (isSigner) {
                signedKeys.push(pubkey.toString());
                numRequiredSignatures += 1;
                if (!isWritable) numReadonlySignedAccounts += 1;
            } else {
                unsignedKeys.push(pubkey.toString());
                if (!isWritable) numReadonlyUnsignedAccounts += 1;
            }
        }));
        const accountKeys = signedKeys.concat(unsignedKeys);
        const instructions = this.instructions.map((instruction => {
            const {data: data, programId: programId} = instruction;
            return {
                programIdIndex: accountKeys.indexOf(programId.toString()),
                accounts: instruction.keys.map((meta => accountKeys.indexOf(meta.pubkey.toString()))),
                data: bs58.encode(data)
            };
        }));
        instructions.forEach((instruction => {
            invariant(instruction.programIdIndex >= 0);
            instruction.accounts.forEach((keyIndex => invariant(keyIndex >= 0)));
        }));
        return new Message({
            header: {
                numRequiredSignatures: numRequiredSignatures,
                numReadonlySignedAccounts: numReadonlySignedAccounts,
                numReadonlyUnsignedAccounts: numReadonlyUnsignedAccounts
            },
            accountKeys: accountKeys,
            recentBlockhash: recentBlockhash,
            instructions: instructions
        });
    }
    _compile() {
        const message = this.compileMessage();
        const signedKeys = message.accountKeys.slice(0, message.header.numRequiredSignatures);
        if (this.signatures.length === signedKeys.length) {
            const valid = this.signatures.every(((pair, index) => signedKeys[index].equals(pair.publicKey)));
            if (valid) return message;
        }
        this.signatures = signedKeys.map((publicKey => ({
            signature: null,
            publicKey: publicKey
        })));
        return message;
    }
    serializeMessage() {
        return this._compile().serialize();
    }
    setSigners(...signers) {
        if (0 === signers.length) throw new Error("No signers");
        const seen = new Set;
        this.signatures = signers.filter((publicKey => {
            const key = publicKey.toString();
            if (seen.has(key)) return false; else {
                seen.add(key);
                return true;
            }
        })).map((publicKey => ({
            signature: null,
            publicKey: publicKey
        })));
    }
    sign(...signers) {
        if (0 === signers.length) throw new Error("No signers");
        const seen = new Set;
        const uniqueSigners = [];
        for (const signer of signers) {
            const key = signer.publicKey.toString();
            if (seen.has(key)) continue; else {
                seen.add(key);
                uniqueSigners.push(signer);
            }
        }
        this.signatures = uniqueSigners.map((signer => ({
            signature: null,
            publicKey: signer.publicKey
        })));
        const message = this._compile();
        this._partialSign(message, ...uniqueSigners);
        this._verifySignatures(message.serialize(), true);
    }
    partialSign(...signers) {
        if (0 === signers.length) throw new Error("No signers");
        const seen = new Set;
        const uniqueSigners = [];
        for (const signer of signers) {
            const key = signer.publicKey.toString();
            if (seen.has(key)) continue; else {
                seen.add(key);
                uniqueSigners.push(signer);
            }
        }
        const message = this._compile();
        this._partialSign(message, ...uniqueSigners);
    }
    _partialSign(message, ...signers) {
        const signData = message.serialize();
        signers.forEach((signer => {
            const signature = nacl.sign.detached(signData, signer.secretKey);
            this._addSignature(signer.publicKey, toBuffer(signature));
        }));
    }
    addSignature(pubkey, signature) {
        this._compile();
        this._addSignature(pubkey, signature);
    }
    _addSignature(pubkey, signature) {
        invariant(64 === signature.length);
        const index = this.signatures.findIndex((sigpair => pubkey.equals(sigpair.publicKey)));
        if (index < 0) throw new Error(`unknown signer: ${pubkey.toString()}`);
        this.signatures[index].signature = Buffer.from(signature);
    }
    verifySignatures() {
        return this._verifySignatures(this.serializeMessage(), true);
    }
    _verifySignatures(signData, requireAllSignatures) {
        for (const {signature: signature, publicKey: publicKey} of this.signatures) if (null === signature) {
            if (requireAllSignatures) return false;
        } else if (!nacl.sign.detached.verify(signData, signature, publicKey.toBuffer())) return false;
        return true;
    }
    serialize(config) {
        const {requireAllSignatures: requireAllSignatures, verifySignatures: verifySignatures} = Object.assign({
            requireAllSignatures: true,
            verifySignatures: true
        }, config);
        const signData = this.serializeMessage();
        if (verifySignatures && !this._verifySignatures(signData, requireAllSignatures)) throw new Error("Signature verification failed");
        return this._serialize(signData);
    }
    _serialize(signData) {
        const {signatures: signatures} = this;
        const signatureCount = [];
        encodeLength(signatureCount, signatures.length);
        const transactionLength = signatureCount.length + 64 * signatures.length + signData.length;
        const wireTransaction = Buffer.alloc(transactionLength);
        invariant(signatures.length < 256);
        Buffer.from(signatureCount).copy(wireTransaction, 0);
        signatures.forEach((({signature: signature}, index) => {
            if (null !== signature) {
                invariant(64 === signature.length, `signature has invalid length`);
                Buffer.from(signature).copy(wireTransaction, signatureCount.length + 64 * index);
            }
        }));
        signData.copy(wireTransaction, signatureCount.length + 64 * signatures.length);
        invariant(wireTransaction.length <= PACKET_DATA_SIZE, `Transaction too large: ${wireTransaction.length} > ${PACKET_DATA_SIZE}`);
        return wireTransaction;
    }
    get keys() {
        invariant(1 === this.instructions.length);
        return this.instructions[0].keys.map((keyObj => keyObj.pubkey));
    }
    get programId() {
        invariant(1 === this.instructions.length);
        return this.instructions[0].programId;
    }
    get data() {
        invariant(1 === this.instructions.length);
        return this.instructions[0].data;
    }
    static from(buffer) {
        let byteArray = [ ...buffer ];
        const signatureCount = decodeLength(byteArray);
        let signatures = [];
        for (let i = 0; i < signatureCount; i++) {
            const signature = byteArray.slice(0, SIGNATURE_LENGTH);
            byteArray = byteArray.slice(SIGNATURE_LENGTH);
            signatures.push(bs58.encode(Buffer.from(signature)));
        }
        return Transaction.populate(Message.from(byteArray), signatures);
    }
    static populate(message, signatures = []) {
        const transaction = new Transaction;
        transaction.recentBlockhash = message.recentBlockhash;
        if (message.header.numRequiredSignatures > 0) transaction.feePayer = message.accountKeys[0];
        signatures.forEach(((signature, index) => {
            const sigPubkeyPair = {
                signature: signature == bs58.encode(DEFAULT_SIGNATURE) ? null : bs58.decode(signature),
                publicKey: message.accountKeys[index]
            };
            transaction.signatures.push(sigPubkeyPair);
        }));
        message.instructions.forEach((instruction => {
            const keys = instruction.accounts.map((account => {
                const pubkey = message.accountKeys[account];
                return {
                    pubkey: pubkey,
                    isSigner: transaction.signatures.some((keyObj => keyObj.publicKey.toString() === pubkey.toString())) || message.isAccountSigner(account),
                    isWritable: message.isAccountWritable(account)
                };
            }));
            transaction.instructions.push(new TransactionInstruction({
                keys: keys,
                programId: message.accountKeys[instruction.programIdIndex],
                data: bs58.decode(instruction.data)
            }));
        }));
        return transaction;
    }
}
const SYSTEM_INSTRUCTION_LAYOUTS = Object.freeze({
    Create: {
        index: 0,
        layout: struct([ u32("instruction"), ns64("lamports"), ns64("space"), publicKey("programId") ])
    },
    Assign: {
        index: 1,
        layout: struct([ u32("instruction"), publicKey("programId") ])
    },
    Transfer: {
        index: 2,
        layout: struct([ u32("instruction"), ns64("lamports") ])
    },
    CreateWithSeed: {
        index: 3,
        layout: struct([ u32("instruction"), publicKey("base"), rustString("seed"), ns64("lamports"), ns64("space"), publicKey("programId") ])
    },
    AdvanceNonceAccount: {
        index: 4,
        layout: struct([ u32("instruction") ])
    },
    WithdrawNonceAccount: {
        index: 5,
        layout: struct([ u32("instruction"), ns64("lamports") ])
    },
    InitializeNonceAccount: {
        index: 6,
        layout: struct([ u32("instruction"), publicKey("authorized") ])
    },
    AuthorizeNonceAccount: {
        index: 7,
        layout: struct([ u32("instruction"), publicKey("authorized") ])
    },
    Allocate: {
        index: 8,
        layout: struct([ u32("instruction"), ns64("space") ])
    },
    AllocateWithSeed: {
        index: 9,
        layout: struct([ u32("instruction"), publicKey("base"), rustString("seed"), ns64("space"), publicKey("programId") ])
    },
    AssignWithSeed: {
        index: 10,
        layout: struct([ u32("instruction"), publicKey("base"), rustString("seed"), publicKey("programId") ])
    },
    TransferWithSeed: {
        index: 11,
        layout: struct([ u32("instruction"), ns64("lamports"), rustString("seed"), publicKey("programId") ])
    }
});
class SystemProgram {
    constructor() {}
    static createAccount(params) {
        const type = SYSTEM_INSTRUCTION_LAYOUTS.Create;
        const data = encodeData(type, {
            lamports: params.lamports,
            space: params.space,
            programId: toBuffer(params.programId.toBuffer())
        });
        return new TransactionInstruction({
            keys: [ {
                pubkey: params.fromPubkey,
                isSigner: true,
                isWritable: true
            }, {
                pubkey: params.newAccountPubkey,
                isSigner: true,
                isWritable: true
            } ],
            programId: this.programId,
            data: data
        });
    }
    static transfer(params) {
        let data;
        let keys;
        if ("basePubkey" in params) {
            const type = SYSTEM_INSTRUCTION_LAYOUTS.TransferWithSeed;
            data = encodeData(type, {
                lamports: params.lamports,
                seed: params.seed,
                programId: toBuffer(params.programId.toBuffer())
            });
            keys = [ {
                pubkey: params.fromPubkey,
                isSigner: false,
                isWritable: true
            }, {
                pubkey: params.basePubkey,
                isSigner: true,
                isWritable: false
            }, {
                pubkey: params.toPubkey,
                isSigner: false,
                isWritable: true
            } ];
        } else {
            const type = SYSTEM_INSTRUCTION_LAYOUTS.Transfer;
            data = encodeData(type, {
                lamports: params.lamports
            });
            keys = [ {
                pubkey: params.fromPubkey,
                isSigner: true,
                isWritable: true
            }, {
                pubkey: params.toPubkey,
                isSigner: false,
                isWritable: true
            } ];
        }
        return new TransactionInstruction({
            keys: keys,
            programId: this.programId,
            data: data
        });
    }
    static assign(params) {
        let data;
        let keys;
        if ("basePubkey" in params) {
            const type = SYSTEM_INSTRUCTION_LAYOUTS.AssignWithSeed;
            data = encodeData(type, {
                base: toBuffer(params.basePubkey.toBuffer()),
                seed: params.seed,
                programId: toBuffer(params.programId.toBuffer())
            });
            keys = [ {
                pubkey: params.accountPubkey,
                isSigner: false,
                isWritable: true
            }, {
                pubkey: params.basePubkey,
                isSigner: true,
                isWritable: false
            } ];
        } else {
            const type = SYSTEM_INSTRUCTION_LAYOUTS.Assign;
            data = encodeData(type, {
                programId: toBuffer(params.programId.toBuffer())
            });
            keys = [ {
                pubkey: params.accountPubkey,
                isSigner: true,
                isWritable: true
            } ];
        }
        return new TransactionInstruction({
            keys: keys,
            programId: this.programId,
            data: data
        });
    }
    static createAccountWithSeed(params) {
        const type = SYSTEM_INSTRUCTION_LAYOUTS.CreateWithSeed;
        const data = encodeData(type, {
            base: toBuffer(params.basePubkey.toBuffer()),
            seed: params.seed,
            lamports: params.lamports,
            space: params.space,
            programId: toBuffer(params.programId.toBuffer())
        });
        let keys = [ {
            pubkey: params.fromPubkey,
            isSigner: true,
            isWritable: true
        }, {
            pubkey: params.newAccountPubkey,
            isSigner: false,
            isWritable: true
        } ];
        if (params.basePubkey != params.fromPubkey) keys.push({
            pubkey: params.basePubkey,
            isSigner: true,
            isWritable: false
        });
        return new TransactionInstruction({
            keys: keys,
            programId: this.programId,
            data: data
        });
    }
    static createNonceAccount(params) {
        const transaction = new Transaction;
        if ("basePubkey" in params && "seed" in params) transaction.add(SystemProgram.createAccountWithSeed({
            fromPubkey: params.fromPubkey,
            newAccountPubkey: params.noncePubkey,
            basePubkey: params.basePubkey,
            seed: params.seed,
            lamports: params.lamports,
            space: NONCE_ACCOUNT_LENGTH,
            programId: this.programId
        })); else transaction.add(SystemProgram.createAccount({
            fromPubkey: params.fromPubkey,
            newAccountPubkey: params.noncePubkey,
            lamports: params.lamports,
            space: NONCE_ACCOUNT_LENGTH,
            programId: this.programId
        }));
        const initParams = {
            noncePubkey: params.noncePubkey,
            authorizedPubkey: params.authorizedPubkey
        };
        transaction.add(this.nonceInitialize(initParams));
        return transaction;
    }
    static nonceInitialize(params) {
        const type = SYSTEM_INSTRUCTION_LAYOUTS.InitializeNonceAccount;
        const data = encodeData(type, {
            authorized: toBuffer(params.authorizedPubkey.toBuffer())
        });
        const instructionData = {
            keys: [ {
                pubkey: params.noncePubkey,
                isSigner: false,
                isWritable: true
            }, {
                pubkey: SYSVAR_RECENT_BLOCKHASHES_PUBKEY,
                isSigner: false,
                isWritable: false
            }, {
                pubkey: SYSVAR_RENT_PUBKEY,
                isSigner: false,
                isWritable: false
            } ],
            programId: this.programId,
            data: data
        };
        return new TransactionInstruction(instructionData);
    }
    static nonceAdvance(params) {
        const type = SYSTEM_INSTRUCTION_LAYOUTS.AdvanceNonceAccount;
        const data = encodeData(type);
        const instructionData = {
            keys: [ {
                pubkey: params.noncePubkey,
                isSigner: false,
                isWritable: true
            }, {
                pubkey: SYSVAR_RECENT_BLOCKHASHES_PUBKEY,
                isSigner: false,
                isWritable: false
            }, {
                pubkey: params.authorizedPubkey,
                isSigner: true,
                isWritable: false
            } ],
            programId: this.programId,
            data: data
        };
        return new TransactionInstruction(instructionData);
    }
    static nonceWithdraw(params) {
        const type = SYSTEM_INSTRUCTION_LAYOUTS.WithdrawNonceAccount;
        const data = encodeData(type, {
            lamports: params.lamports
        });
        return new TransactionInstruction({
            keys: [ {
                pubkey: params.noncePubkey,
                isSigner: false,
                isWritable: true
            }, {
                pubkey: params.toPubkey,
                isSigner: false,
                isWritable: true
            }, {
                pubkey: SYSVAR_RECENT_BLOCKHASHES_PUBKEY,
                isSigner: false,
                isWritable: false
            }, {
                pubkey: SYSVAR_RENT_PUBKEY,
                isSigner: false,
                isWritable: false
            }, {
                pubkey: params.authorizedPubkey,
                isSigner: true,
                isWritable: false
            } ],
            programId: this.programId,
            data: data
        });
    }
    static nonceAuthorize(params) {
        const type = SYSTEM_INSTRUCTION_LAYOUTS.AuthorizeNonceAccount;
        const data = encodeData(type, {
            authorized: toBuffer(params.newAuthorizedPubkey.toBuffer())
        });
        return new TransactionInstruction({
            keys: [ {
                pubkey: params.noncePubkey,
                isSigner: false,
                isWritable: true
            }, {
                pubkey: params.authorizedPubkey,
                isSigner: true,
                isWritable: false
            } ],
            programId: this.programId,
            data: data
        });
    }
    static allocate(params) {
        let data;
        let keys;
        if ("basePubkey" in params) {
            const type = SYSTEM_INSTRUCTION_LAYOUTS.AllocateWithSeed;
            data = encodeData(type, {
                base: toBuffer(params.basePubkey.toBuffer()),
                seed: params.seed,
                space: params.space,
                programId: toBuffer(params.programId.toBuffer())
            });
            keys = [ {
                pubkey: params.accountPubkey,
                isSigner: false,
                isWritable: true
            }, {
                pubkey: params.basePubkey,
                isSigner: true,
                isWritable: false
            } ];
        } else {
            const type = SYSTEM_INSTRUCTION_LAYOUTS.Allocate;
            data = encodeData(type, {
                space: params.space
            });
            keys = [ {
                pubkey: params.accountPubkey,
                isSigner: true,
                isWritable: true
            } ];
        }
        return new TransactionInstruction({
            keys: keys,
            programId: this.programId,
            data: data
        });
    }
}
SystemProgram.programId = new PublicKey("11111111111111111111111111111111");