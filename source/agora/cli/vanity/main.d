/*******************************************************************************

    A vanity address generator

    This tool is used to generate the "well-known" keypairs used in unittests.
    Note that we generate the binary data directly to limit CTFE overhead.

    `stdout` is used for output of the address (so it can be redirected as the
    list is large), and `stderr` for debugging.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.cli.vanity.main;

import agora.crypto.ECC;
import agora.crypto.Key;
import agora.crypto.Types;

import core.atomic;
import std.parallelism;
import std.range;
import std.stdio;
import std.string;
import std.algorithm;

/// Useful constant for iteration
immutable Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static assert(Alphabet.length == 26);

/*
========== VANITY =====================
/// GCOMBBXA6ON7PT7APS4IWS4N53FCBQTLWBPIU4JR2DSOBCA72WEB4XU4: GCOMBBXA6ON7PT7APS4IWS4N53FCBQTLWBPIU4JR2DSOBCA72WEB4XU4
static immutable GCOMBBXA6ON7PT7APS4IWS4N53FCBQTLWBPIU4JR2DSOBCA72WEB4XU4 = KeyPair(PublicKey(Point([156, 192, 134, 224, 243, 155, 247, 207, 224, 124, 184, 139, 75, 141, 238, 202, 32, 194, 107, 176, 94, 138, 113, 49, 208, 228, 224, 136, 31, 213, 136, 30])), SecretKey(Scalar([125, 41, 233, 11, 233, 133, 207, 35, 253, 6, 44, 244, 136, 201, 182, 68, 93, 37, 201, 206, 51, 71, 203, 166, 225, 229, 49, 209, 242, 161, 120, 4])));

/// GDGENYO6TWO6EZG2OXEBVDCNKLHCV2UFLLZY6TJMWTGR23UMJHVHLHKJ: GDGENYO6TWO6EZG2OXEBVDCNKLHCV2UFLLZY6TJMWTGR23UMJHVHLHKJ
static immutable GDGENYO6TWO6EZG2OXEBVDCNKLHCV2UFLLZY6TJMWTGR23UMJHVHLHKJ = KeyPair(PublicKey(Point([204, 70, 225, 222, 157, 157, 226, 100, 218, 117, 200, 26, 140, 77, 82, 206, 42, 234, 133, 90, 243, 143, 77, 44, 180, 205, 29, 110, 140, 73, 234, 117])), SecretKey(Scalar([115, 95, 118, 15, 205, 199, 178, 40, 246, 217, 128, 245, 129, 168, 223, 89, 93, 102, 200, 110, 191, 25, 248, 37, 136, 99, 204, 190, 173, 144, 19, 8])));

/// GCN2C4X4ZAUTENP3VYVA3225CUNEAHDKFXDETNRBXZCXUPIJUY64UANT: GCN2C4X4ZAUTENP3VYVA3225CUNEAHDKFXDETNRBXZCXUPIJUY64UANT
static immutable GCN2C4X4ZAUTENP3VYVA3225CUNEAHDKFXDETNRBXZCXUPIJUY64UANT = KeyPair(PublicKey(Point([155, 161, 114, 252, 200, 41, 50, 53, 251, 174, 42, 13, 235, 93, 21, 26, 64, 28, 106, 45, 198, 73, 182, 33, 190, 69, 122, 61, 9, 166, 61, 202])), SecretKey(Scalar([164, 206, 34, 110, 32, 193, 201, 0, 110, 132, 233, 30, 33, 37, 73, 99, 25, 205, 114, 100, 147, 33, 17, 118, 197, 178, 165, 234, 3, 222, 99, 15])));

/// GCN3CTOPFFBHZKXUVBZHZN6UFFYFFAZCPJK36U2ZY3L53AL7APM36GYO: GCN3CTOPFFBHZKXUVBZHZN6UFFYFFAZCPJK36U2ZY3L53AL7APM36GYO
static immutable GCN3CTOPFFBHZKXUVBZHZN6UFFYFFAZCPJK36U2ZY3L53AL7APM36GYO = KeyPair(PublicKey(Point([155, 177, 77, 207, 41, 66, 124, 170, 244, 168, 114, 124, 183, 212, 41, 112, 82, 131, 34, 122, 85, 191, 83, 89, 198, 215, 221, 129, 127, 3, 217, 191])), SecretKey(Scalar([169, 30, 41, 87, 161, 183, 48, 38, 254, 47, 170, 184, 38, 248, 244, 109, 116, 171, 53, 203, 46, 6, 214, 23, 182, 79, 80, 244, 198, 181, 133, 5])));

/// GCN4CT336WB6IIKP5CDHWFYFBCNO5BG2Y4777F2QHNA5XUWSUYSQS7IP: GCN4CT336WB6IIKP5CDHWFYFBCNO5BG2Y4777F2QHNA5XUWSUYSQS7IP
static immutable GCN4CT336WB6IIKP5CDHWFYFBCNO5BG2Y4777F2QHNA5XUWSUYSQS7IP = KeyPair(PublicKey(Point([155, 193, 79, 123, 245, 131, 228, 33, 79, 232, 134, 123, 23, 5, 8, 154, 238, 132, 218, 199, 63, 255, 151, 80, 59, 65, 219, 210, 210, 166, 37, 9])), SecretKey(Scalar([33, 32, 17, 253, 27, 191, 90, 211, 79, 31, 81, 156, 192, 164, 41, 228, 239, 254, 236, 222, 189, 120, 127, 8, 247, 2, 143, 10, 25, 156, 109, 8])));

/// GCN5CVXGRUW3B6CJNHUVEJFHXG2WQNMRBQR2RN4TMJ727RF3VM2RA6LF: GCN5CVXGRUW3B6CJNHUVEJFHXG2WQNMRBQR2RN4TMJ727RF3VM2RA6LF
static immutable GCN5CVXGRUW3B6CJNHUVEJFHXG2WQNMRBQR2RN4TMJ727RF3VM2RA6LF = KeyPair(PublicKey(Point([155, 209, 86, 230, 141, 45, 176, 248, 73, 105, 233, 82, 36, 167, 185, 181, 104, 53, 145, 12, 35, 168, 183, 147, 98, 127, 175, 196, 187, 171, 53, 16])), SecretKey(Scalar([10, 80, 62, 156, 147, 169, 145, 78, 190, 212, 103, 114, 243, 38, 80, 28, 14, 156, 42, 28, 69, 168, 242, 26, 138, 233, 201, 168, 166, 10, 193, 7])));

/// GCN6C3W6DT4TP2BQBFNPDPBP7SK32CJC2ROUUBI4C7Z36TWMK6VZ3CT4: GCN6C3W6DT4TP2BQBFNPDPBP7SK32CJC2ROUUBI4C7Z36TWMK6VZ3CT4
static immutable GCN6C3W6DT4TP2BQBFNPDPBP7SK32CJC2ROUUBI4C7Z36TWMK6VZ3CT4 = KeyPair(PublicKey(Point([155, 225, 110, 222, 28, 249, 55, 232, 48, 9, 90, 241, 188, 47, 252, 149, 189, 9, 34, 212, 93, 74, 5, 28, 23, 243, 191, 78, 204, 87, 171, 157])), SecretKey(Scalar([244, 65, 235, 237, 149, 154, 211, 131, 202, 243, 249, 219, 234, 86, 109, 116, 197, 230, 106, 9, 242, 5, 66, 135, 12, 55, 14, 213, 211, 221, 215, 13])));

/// GCN7C7UCTTQQ3RN7Q7AID5ED7VJDN3XPQ6NEAOIMWNA5AWJUFFV5PRBN: GCN7C7UCTTQQ3RN7Q7AID5ED7VJDN3XPQ6NEAOIMWNA5AWJUFFV5PRBN
static immutable GCN7C7UCTTQQ3RN7Q7AID5ED7VJDN3XPQ6NEAOIMWNA5AWJUFFV5PRBN = KeyPair(PublicKey(Point([155, 241, 126, 130, 156, 225, 13, 197, 191, 135, 192, 129, 244, 131, 253, 82, 54, 238, 239, 135, 154, 64, 57, 12, 179, 65, 208, 89, 52, 41, 107, 215])), SecretKey(Scalar([194, 151, 6, 120, 48, 80, 141, 208, 62, 69, 74, 41, 149, 21, 158, 137, 94, 152, 249, 49, 207, 36, 233, 95, 142, 62, 235, 174, 31, 96, 227, 2])));
*/

immutable string[] SpecialNames = [
    // "GDGEN",
    // "GCOMB",
    // "GCN2C",
    // "GCN3C",
    // "GCN4C",
    // "GCN5C",
    // "GCN6C",
    "GCN7C",
];

void main (string[] args)
{
    stdout.writefln("========== VANITY =====================");
    string[string] addresses;
    shared size_t found;
    foreach (_; parallel(iota(42)))
    {
    NextKey:
        while (atomicLoad(found) < SpecialNames.length)
        {
            auto kp = Pair.random();

            // TODO: Use binary to avoid `toString` call
            const addr = PublicKey(kp.V).toString();

            void checkName (string name)
            {
                // stdout.writefln("--- compare [%s] [%s]", addr[0 .. 5], name);
                if (addr[0 .. 5] == name)
                {
                    // printKey(addr, kp);
                    if (name !in addresses)
                    {
                        addresses[name] = addr;
                        found.atomicOp!("+=")(1);
                        printKey(addr, kp);
                    }
                }
            }

            SpecialNames.each!( name => checkName(name));

            continue NextKey;
        }
    }

}

/// Print the key to stdout
private void printKey (const(char)[] name, Pair kp)
{
    stdout.writefln("/// %s: %s", name, PublicKey(kp.V));
    stdout.writefln("static immutable %s = KeyPair(PublicKey(Point(%s)), SecretKey(Scalar(%s)));",
                    name.strip, kp.V[], kp.v[]);
}
