/*******************************************************************************

    A vanity address generator

    This tool is used to generate the "well-known" keypairs used in unittests.
    Note that we generate the binary data directly to limit CTFE overhead.

    `stdout` is used for output of the address (so it can be redirected as the
    list is large), and `stderr` for debugging.

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
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

// Number of keys to generate
// FIXME: Currently this is hardcoded, and used to derive from `MaxNameSize`
//        However, depending on that constant means we can only generate entire
//        ranges, while we might want to have all keys between 'a' and 'acc'
//        for example.
// immutable size_t KeyCountTarget = totalKeyCount(MaxNameSize);
immutable size_t KeyCountTarget = nameIndex("azz") + 1;

/// Change this directly to generate different size
enum size_t MaxNameSize = 3;

/// The end marker to use after the pattern
enum char EndMarker = '0';

/// The index at which the pattern starts
enum size_t FirstIdx = "boa1xx".length;
/// The number of `EndMarker` that should be after the pattern
enum size_t MarkerCount = "00".length;

// Constant that depend on the previous constant
alias Name = char[MaxNameSize];
enum size_t LastIdx = FirstIdx + MaxNameSize;

/// Useful constant for iteration
immutable Alphabet = "acdefghjklmnpqrstuvwxyz";
static assert(Alphabet.length == 23); // No 'b', 'i', 'o' in Bech32

/// Helper function
bool isInRange (char c) @safe pure nothrow @nogc
{ return c >= Alphabet[0] && c <= Alphabet[$-1]; }

immutable string[] SpecialNames = [
    // "genes",
    // "cmmns",
    // "zval2",
    // "zval3",
    "val4",
    "val5",
    "val6",
    "val7",
];

/// Stored globally to avoid large stack / TLS issues
__gshared Scalar[KeyCountTarget + SpecialNames.length] result;
__gshared bool[KeyCountTarget + SpecialNames.length] foundMap;

void main (string[] args)
{
    shared size_t found;

    writefln("Vanity miner configured for keys [%s;%s] (total: %s keys)",
       indexName(0), indexName(KeyCountTarget - 1), KeyCountTarget);

    foreach (_; parallel(iota(42)))
    {
        while (atomicLoad(found) < result.length)
        {
            auto tmp = Pair.random();

            // TODO: Use binary to avoid `toString` call
            const addr = PublicKey(tmp.V).toString();

            if (auto index = specialNameIndex(addr))
            {
                stderr.writefln("// %s %s static immutable XX = KeyPair(PublicKey(Point(%s)), SecretKey(Scalar(%s)));",
                    addr, SecretKey(tmp.v).toString(PrintMode.Clear), tmp.V[], tmp.v[]);
                continue NextKey;
            }
        }
    }

    foreach (index, ref seed; result[0 .. KeyCountTarget])
    {
        const name = indexName(index);
        auto kp = Pair.fromScalar(seed);
        printKey(name, kp);
    }

    writeln("==================================================");
    foreach (index, ref seed; result[KeyCountTarget .. $])
    {
        auto kp = Pair.fromScalar(seed);
        printKey(SpecialNames[index], kp);
    }
}

/// Little helper function. Returns `false` if the key is already known
private bool onFound (ref shared size_t found, size_t index, Scalar value)
{
    // If already found, still print it as they are pretty rare
    if (!cas(&foundMap[index], false, true))
        return false;

    found.atomicOp!("+=")(1);
    result[index] = value;
    stderr.write("\rKeys found: ", atomicLoad(found), "/", foundMap.length);
    stderr.flush();
    return true;
}

/// Print the key to stdout
private void printKey (const(char)[] name, Pair kp)
{
    stdout.writeln(); // We were at "Keys found: XX/XX"
    stdout.writefln("/// %s: %s", name, PublicKey(kp.V));
    stdout.writefln("static immutable %s = KeyPair(PublicKey(Point(%s)), SecretKey(Scalar(%s)));",
                    name.strip.toUpper, kp.V[], kp.v[]);
}

/// Check special target: Genesis address, Commons budget, initial validators...
private size_t specialNameIndex (const(char)[] name)
{
    name = name[FirstIdx .. $];
    static foreach (idx, n; SpecialNames)
    {
        if (name.startsWith(n))
        {
            // If it ends with a number, find any character as terminating char
            static if (n[$-1] >= '0' && n[$-1] <= '9')
                return name[n.length].isInRange() ? idx + KeyCountTarget: 0;
            // Else ends with a char, so find a number as terminating char
            else
                return (name[n.length] >= '0' && name[n.length] <= '9')
                    ? idx + KeyCountTarget: 0;
        }
    }

    return 0;
}

///
// Found another candidate for special names: boa1xzval5q9lwrvhsg3wdgz8gdt9z0e8ke028u5pznlg33zpdxnm5w0sxjzmt5 SC3ADWYP7SPIAFWOH7SWHYDNBITZOOL7TUIMRTW2IRKZPNUIFFLQ2D2G

// Found another candidate for special names: boa1xzval5x7nh9fsnvs6kue6n8j75lxvl3mus3m30xjqk0u4wmkhqrk503e63x SBE3S543JDB4PBPYUNSIKOR755WP4KSQI5EY6MX3LFOI5NSE7GLATLMS

// Found another candidate for special names: boa1xzval4cdm8sj6etl5zkqhpx3qlpgwvv502fnqwrff7lnphacdwcmujfgg2j SBVWONNXGT4LVA4RB76K55V4XLGSKEHVNBC2YNPR545IBCTGEHVA5WXL

// Found another candidate for special names: boa1xzval5u6zytv0n9p5p7asfjnxymfq9a9x3m8062vce93lf66th8076alyad SAVB75Y6J2ELWFDVSPW2366TWSAILQJI7VY6LR6PCIUBS4ASSCIAJ4PK
unittest
{
    immutable seedStr = `SBVWONNXGT4LVA4RB76K55V4XLGSKEHVNBC2YNPR545IBCTGEHVA5WXL`;
    KeyPair kp = KeyPair.fromSeed(SecretKey.fromString(seedStr));
    import std.stdio;
    writefln("//%s %s\nstatic immutable %s = KeyPair(PublicKey(Point(%s)), SecretKey(Scalar(%s)));",
                kp.address, SecretKey(kp.secret).toString(PrintMode.Clear), kp.address[], kp.secret[]);
    assert(kp.secret.toString(PrintMode.Clear) == seedStr,
        kp.secret.toString(PrintMode.Clear));
}

//
unittest
{
    assert(specialNameIndex("boa1xzgenes42acdef") == KeyCountTarget + 0);
    assert(specialNameIndex("boa1xzcmmns69acdef") == KeyCountTarget + 1);
    assert(specialNameIndex("boa1xzvald2acdefgh") == KeyCountTarget + 2);
    assert(specialNameIndex("boa1xzvald3acdefgh") == KeyCountTarget + 3);
    assert(specialNameIndex("boa1xzvald4acdefgh") == KeyCountTarget + 4);
    assert(specialNameIndex("boa1xzvald5acdefgh") == KeyCountTarget + 5);
    assert(specialNameIndex("boa1xzvald6acdefgh") == KeyCountTarget + 6);
    assert(specialNameIndex("boa1xzvald7acdefgh") == KeyCountTarget + 7);

    assert(specialNameIndex("boa1xzgenesiss123a") == 0);
    assert(specialNameIndex("boa1xzcmmnsa456acd") == 0);
    assert(specialNameIndex("boa1xzvald74acdefg") == 0);
    assert(specialNameIndex("boa1xzvalds24acdef") == 0);
}

/// Returns: The total number of keys for this range and all smaller ranges
private size_t totalKeyCount (size_t count) pure nothrow @nogc @safe
{
    size_t result;
    while (count)
    {
        result += Alphabet.length ^^ count;
        --count;
    }
    return result;
}

unittest
{
    static assert(totalKeyCount(0) == 0);
    static assert(totalKeyCount(1) == 23);
    static assert(totalKeyCount(2) == 23 + 23 * 23);
    static assert(totalKeyCount(3) == 23 + 23 * 23 + 23 * 23 * 23);
}

/// Returns: The index of a given pattern
private size_t nameIndex (scope const(char)[] name) pure nothrow @nogc @safe
{
    assert(name.length <= Name.length, name);
    size_t result;
    immutable bool needOffset = name.length > 1;
    foreach (size_t index, char c; name)
    {
        assert(c.isInRange());
        const multiplier = Alphabet.indexOf(c) + (index + 1 < name.length);
        result += multiplier * Alphabet.length ^^ (name.length - 1 - index);
    }
    return result;
}

unittest
{
    // Total: 23 * 23 * 23 + 23 * 23 + 23 - 1
    size_t idx;
    Name name;

    // First range, single character
    {
        foreach (char c1; Alphabet)
        {
            name[0] = c1;
            assert(idx++ == nameIndex(name[0 .. 1]));
        }
    }

    // Next 26 * 26
    static if (Name.length >=  2)
    {
        foreach (char c1; Alphabet)
        foreach (char c2; Alphabet)
        {
            name[0 .. 2] = [c1, c2];
            assert(idx++ == nameIndex(name[0 .. 2]));
        }
    }

    // Last 26 * 26 * 26
    static if (Name.length >=  3)
    {
        foreach (char c1; Alphabet)
        foreach (char c2; Alphabet)
        foreach (char c3; Alphabet)
        {
            name = [c1, c2, c3];
            assert(idx++ == nameIndex(name));
        }
    }

    static assert(Name.length <= 3, "Add tests for `nameIndex` with `Name.length > 3`");
}

/// Returns: The name at a given index
public const(char)[] indexName (size_t index) //pure nothrow @safe
{
    Name result;
    size_t iterations = 1;

    while (index >= totalKeyCount(iterations))
        iterations++;

    for (size_t iter = 0; iter < iterations; ++iter)
    {
        result[$ - 1 - iter] = Alphabet[index % $];
        index /= Alphabet.length;
        index--;
    }
    return result[$ - iterations .. $].dup;
}

unittest
{
    // Convernience alias to shorten code
    enum AL = Alphabet.length;

    // Bounds
    assert(indexName(0) == Alphabet[0 .. 1]);
    assert(indexName(AL - 1) == Alphabet[$-1 .. $]);

    // Bech32 has no 'b' so make sure we don't assume contiguity
    assert(indexName(3) == "e"); // Would be 'd' if 'b' was in the alphabet

    static if (Name.length >= 2)
    {
        assert(indexName(AL) == "aa");
        assert(indexName(AL * 2) == "ca");
        assert(indexName(AL * 2 + 1) == "cc");
        assert(indexName(AL * 3 - 1) == "cz");
        assert(indexName(AL + AL * (AL - 1)) == "za");
        assert(indexName(AL + AL * AL - 1) == "zz");
    }
    static if (Name.length >= 3)
    {
        assert(indexName(AL + (AL * AL)) == "aaa");
        assert(indexName(AL + (AL * AL * 2)) == "caa");
        assert(indexName(AL + (AL * AL * AL)) == "zaa");
        assert(indexName(AL + (AL * AL * AL) + (AL * AL) - 1) == "zzz");
    }

    foreach (idx; 0 .. totalKeyCount(Name.length))
        assert(nameIndex(indexName(idx)) == idx);

    static assert(Name.length <= 3, "Add tests for `indexName` with `Name.length > 3`");
}
