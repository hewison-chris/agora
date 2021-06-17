/*******************************************************************************

    This is an implementation of a bitmask that once initialized will have a
    fixed number of bits for holding `true` / `false` (`1` / `0`) values.
    It allocates the required number of `ubytes` in the constructor and does not
    allow reading or writing to bits beyond the fixed count which is set during
    construction.
    This type is created for use as the validators signing bitmask and any
    changes should ensure that it does not compromise that use.

*******************************************************************************/

module agora.common.BitMask;

public struct BitMask
{
    import std.algorithm;
    import std.conv;
    import std.range;

    @safe:

    /// Pretty-print this value (to save bandwidth the shorter list is created)
    /// `3/5 !(0,2)` can be read as 3 out of 5 with indices 0 and 2 not set (i.e. `01011`)
    /// `2/5 (0,2)` can be read as 2 out of 5 with indices 0 and 2 set (i.e. `10100`)
    /// If half are set we list the set bit indices e.g. `3/6 (0,1,2)` = `111000`
    public void toString (scope void delegate (scope const char[]) @safe sink) const
    {
        import std.format;
        bool list_set = this.setCount <= this.length / 2;
        formattedWrite(sink, "%d/%d %s", this.setCount, this.length,
            list_set
                ? format!"(%s)"(this.setIndices.map!(i => i.to!string).join(","))
                : format!"!(%s)"(this.notSetIndices.map!(i => i.to!string).join(",")));
    }

    /// Also support for Vibe.d serialization to JSON
    public string toString () const
    {
        string ret;
        scope void delegate (scope const char[]) @safe sink = (scope v) { ret ~= v; };
        this.toString(sink);
        return ret;
    }

    pure:

    /// Support for Vibe.d deserialization
    public static BitMask fromString (scope const(char)[] str)
    {
        auto set = str.findSplitBefore("/")[0].to!size_t;
        auto length = str.findSplitAfter("/")[1].findSplitBefore(" ")[0].to!size_t;
        bool list_set = set <= length / 2;
        auto indices = str.findSplitAfter(list_set ? "(" : "!(")[1].findSplitBefore(")")[0]
            .split(",").map!(i => i.to!size_t);
        if (list_set)
            assert(indices.length == set);
        else
            assert(set + indices.length == length);
        auto bitmask = BitMask(length);
        iota(length).each!((size_t i)
        {
            if (indices.canFind(i) == list_set)
                bitmask[i] = true;
        });
        return bitmask;
    }

    nothrow:

    /// Count of active validators who are expected / allowed to sign the block
    public size_t length;

    /// Bytes to hold bits to indicate if a validator has signed
    private ubyte[] bytes;

    public this (size_t length) inout
    {
        this.length = length;
        if (length > 0)
            this.bytes = new inout(ubyte)[1 + ((length - 1) / 8)];
    }

    public this (size_t length, in ubyte[] bytes)
    {
        this(length);
        assert(this.bytes.length == bytes.length);
        bytes.enumerate.each!((i, b) => this.bytes[i] = b);
    }

    // set the bits that are set in given BitMask
    public auto opOpAssign (string op : "|") (in BitMask add)
    {
        assert(this.length == add.length, "BitMask assignment must be for same bit length");
        iota(this.length).each!((size_t i)
        {
            if (add[i])
                this[i] = true;
        });
        return this;
    }

    /// return the indices of bits set
    public auto setIndices () const
    {
        return iota(this.length).filter!(i => this[i]);
    }

    /// return the indices of bits not set
    public auto notSetIndices () const
    {
        return iota(this.length).filter!(i => !this[i]);
    }

    /// return the length of set bits
    public size_t setCount () const
    {
        return this.setIndices.count!(i => this[i]);
    }

    /// Support for sorting by count of set bits not value
    public int opCmp (in typeof(this) rhs) const
    {
        assert(this.length == rhs.length, "Comparing different sized BitMasks is not valid");
        return this.setCount < rhs.setCount ? -1 : 1;
    }

    @nogc:

    // support setting a bit (asserts if trying to unset a bit)
    public auto opIndexAssign(bool set, size_t bit_index)
    {
        if (bit_index >= this.length)
                assert(0, "Attempt to set index beyond length of bitmask");
        const size_t byte_index = (bit_index) / 8;
        const size_t bit_index_in_byte = bit_index % 8;
        if (set)
            this.bytes[byte_index] |= mask(bit_index_in_byte);
        else
            assert(0, "Only setting bits is allowed!");
        return this;
    }

    /// Gets a single bit's value
    public bool opIndex (size_t bit_index) const
    {
        if (bit_index >= this.length)
            assert(0, "Attempt to get index beyond length of bitmask");
        return !!(this.bytes[bit_index / 8] & mask(bit_index));
    }

    /// Gets a bit mask which only includes a given index within a ubyte
    pragma(inline, true)
    private static ubyte mask (size_t index)
    {
        return (1 << (8 - 1 - (index % 8)));
    }
}

version (unittest)
{
    import agora.serialization.Serializer;

    import std.algorithm;
    import std.range;
}

unittest
{
    auto bitmask = BitMask(10);
    assert(bitmask.toString == "0/10 ()");
    bitmask[1] = true;
    assert(bitmask.toString == "1/10 (1)");
    assert(bitmask[1]);
}

/// More set than unset
unittest
{
    auto bitmask = BitMask.fromString("3/5 !(0,2)");
    only(1,3,4).each!(i => assert(bitmask[i]));
    only(0,2).each!(i => assert(!bitmask[i]));
    assert(bitmask.length == 5);
}

/// More unset than set
unittest
{
    auto bitmask = BitMask.fromString("2/5 (0,2)");
    only(0,2).each!(i => assert(bitmask[i]));
    only(1,3,4).each!(i => assert(!bitmask[i]));
    assert(bitmask.length == 5);
    assert(bitmask.setIndices.count == 2);
    assert(bitmask.notSetIndices.count == 3);
}

/// Same set as unset
unittest
{
    auto bitmask = BitMask.fromString("3/6 (0,1,2)");
    only(0,1,2).each!(i => assert(bitmask[i]));
    only(3,4,5).each!(i => assert(!bitmask[i]));
    assert(bitmask.length == 6);
    assert(bitmask.setIndices.count == 3);
    assert(bitmask.notSetIndices.count == 3);
}

/// Test with more than 8 bits
unittest
{
    auto bitmask = BitMask.fromString("8/9 !(3)");
    assert(bitmask.length == 9);
    assert(bitmask.toString == "8/9 !(3)");
    auto bitmask_copy = BitMask(9);
    bitmask_copy |= bitmask;
    assert(!bitmask_copy[3]);
    only(0,1,2,4,5).each!(i => assert(bitmask_copy[i]));
}

/// Test serialization
unittest
{
    auto bitmask = BitMask(12);
    testSymmetry(bitmask);
    bitmask[1] = true;
    auto bitmask2 = bitmask.serializeFull.deserializeFull!BitMask;
    assert(bitmask2.length == bitmask.length);
    assert(bitmask2.setCount == bitmask.setCount);
    assert(bitmask2 == bitmask);
}
