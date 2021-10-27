import bs58 from "bs58";
import { Buffer } from "buffer";
import "cross-fetch";
import "superstruct";
import "rpc-websockets";
import "jayson/lib/client/browser";
import "http";
import "https";
import { blob, nu64, struct, u32 } from "@solana/buffer-layout";
import BN from "bn.js";
import nacl from "tweetnacl";
import { sha256 } from "@ethersproject/sha2";
import { serialize, deserialize, deserializeUnchecked } from "borsh";
const publicKey = (property = "publicKey") => blob(32, property);
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