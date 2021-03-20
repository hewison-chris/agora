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

immutable string[] SpecialNames = [
    "GDGEN",
    "GCOMB",
    "GCN1C",
    "GCN2C",
    "GCN3C",
    "GCN4C",
    "GCN5C",
    "GCN6C",
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
