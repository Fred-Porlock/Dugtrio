pragma circom 2.1.3;

include "/mnt/c/Users/32492/node_modules/circomlib/circuits/comparators.circom";
include "/mnt/c/Users/32492/node_modules/circomlib/circuits/gates.circom";
include "/mnt/c/Users/32492/node_modules/circomlib/circuits/mux2.circom";
include "/mnt/c/Users/32492/node_modules/circomlib/circuits/multiplexer.circom";

include "hasher.circom";

// Return -1 if x is not a power of 2. Else, return log2(x)
function logBase2(x) {
    if (x <= 0) {
        return -1;
    }
    var res = 0;
    while (x > 1) {
        if (x % 2 == 1) {
            return -1;
        }
        x = x >> 1;
        res = res + 1;
    }
    return res;
}

function ceil(n, q) {
    if (n % q == 0) {
        return n \ q;
    } else {
        return (n \ q) + 1;
    }
}

function floor(n, q) {
    return n \ q;
}

/**
DivideMod2Power: Returns quotient (in / 2^p) and remainder (in % 2^p)

Range checks:
    - 0 <= in < 2^n (Checked in Num2Bits)
    - 0 < p < n
**/
template DivideMod2Power(n, p) {
    assert(n <= 252); // n <= log(p) - 2
    assert(p < n);
    assert(p > 0);

    signal input in;
    component toBits = Num2Bits(n);
    toBits.in <== in;

    component fromBitsQ = Bits2Num(n - p);
    for (var i = 0; i < n - p; i++) {
        fromBitsQ.in[i] <== toBits.out[i + p];
    }
    signal output quotient <== fromBitsQ.out;

    component fromBitsR = Bits2Num(p);
    for (var i = 0; i < p; i++) {
        fromBitsR.in[i] <== toBits.out[i];
    }
    signal output remainder <== fromBitsR.out;
}

/**
RemainderMod4: Calculates in % 4.

Construction Params:
    - n:  The bitwidth of in. 
                
Range checks:
    - 0 <= in < 2^n (Checked in Num2Bits)
**/
template RemainderMod4(n) {
    assert(n <= 252); // n <= log(p) - 2

    signal input in;
    signal output out;

    component toBits = Num2Bits(n);
    toBits.in <== in;
    out <== 2 * toBits.out[1] + toBits.out[0];
}

/**
RangeCheck: Checks if 0 <= in <= max.

Construction params:
    - n: The bitwidth of in and max.
    - max: The maximum value that in can take.

Range checks:
    - 0 <= in (Checked in Num2Bits)
    - in <= max
**/
template RangeCheck(n, max) {
    assert(n <= 252); // n <= log(p) - 2
    assert(max >= 0);
    assert(numBits(max) <= n);

    signal input in;
    var unusedVar[n] = Num2Bits(n)(in);

    signal leq <== LessEqThan(n)([in, max]);
    leq === 1;
}

// Returns the number of bits needed to represent a number.
// Helper function intended to operate only over construction params.
function numBits(a) {
    assert(a >= 0);
    if (a == 0 || a == 1) {
        return 1;
    }
    return 1 + numBits(a >> 1);
}

/**
Num2BitsBE: Converts a number to a list of bits, in big-endian order.

Range checks:
    - 0 <= in < 2^n (Like with Num2Bits).
**/
template Num2BitsBE(n) {
    signal input in;
    signal output out[n];
    var lc1 = 0;

    var e2 = 1;
    for (var i = 0; i < n; i++) {
        var b = (n - 1) - i;
        out[b] <-- (in >> i) & 1;
        out[b] * (out[b] - 1 ) === 0;
        lc1 += out[b] * e2;
        e2 = e2 + e2;
    }

    lc1 === in;
}

/**
Bits2NumBE: Converts a list of bits to a number, in big-endian order.

Note: It is assumed that each input bit is either 0 or 1.
**/
template Bits2NumBE(n) {
    signal input in[n];
    signal output out;
    var lc1=0;

    var e2 = 1;
    for (var i = 0; i < n; i++) {
        lc1 += in[(n - 1) - i] * e2;
        e2 = e2 + e2;
    }

    lc1 ==> out;
}

/**
Segments2NumBE: Converts a list of w-bit segments to a number, in big-endian order.

Note: It is assumed that each input segment is a number between 0 and 2^w - 1.
**/
template Segments2NumBE(n, w) {
    assert(n * w <= 253); 

    signal input in[n];
    signal output out;
    var lc1=0;

    var e2 = 1;
    for (var i = 0; i < n; i++) {
        lc1 += in[(n - 1) - i] * e2;
        e2 = e2 * (1 << w);
    }

    lc1 ==> out;
}

/**
Segments2NumLE: Converts a list of w-bit segments to a number, in little-endian order.

Note: It is assumed that each input segment is a number between 0 and 2^w - 1.
**/
template Segments2NumLE(n, w) {
    assert(n * w <= 253); 

    signal input in[n];
    signal output out;
    var lc1=0;

    var e2 = 1;
    for (var i = 0; i < n; i++) {
        lc1 += in[i] * e2;
        e2 = e2 * (1 << w);
    }

    lc1 ==> out;
}

/**
AssertEqualIfEnabled: Optimized version of the official ForceEqualIfEnabled 

If enabled is 1, then in[0] == in[1]. Otherwise, in[0] and in[1] can be anything.

Original: https://github.com/iden3/circomlib/blob/master/circuits/comparators.circom#L48
**/
template AssertEqualIfEnabled() {
    signal input enabled;
    signal input in[2];

    (in[1] - in[0]) * enabled === 0;
}

/**
Sum: Calculates the sum of all the input elements.
**/
template Sum(n) {
    signal input nums[n];
    signal output sum;

    var lc;
    for (var i = 0; i < n; i++) {
        lc += nums[i];
    }
    sum <== lc;
}

/**
OneBitVector: Given an index, returns a vector of size n with a 1 in the index-th position.

out[i] = 1 if i = index, 0 otherwise.

Range checks:
    - index in [0, n). Fails otherwise.
**/
template OneBitVector(n) {
    signal input index;
    signal output out[n];

    component X = Decoder(n);
    X.inp <== index;

    X.success === 1;
    out <== X.out;
}

/**
GTBitVector: Given an index, returns a vector of size n with a 1 in all indices greater than index.

out[i] = 1 if i > index, 0 otherwise

Range checks:
    - index in [0, n). Fails otherwise.
**/
template GTBitVector(n) {
    signal input index;
    signal output out[n];

    signal eq[n] <== OneBitVector(n)(index);

    out[0] <== 0;
    for (var i = 1; i < n; i++) {
        out[i] <== eq[i - 1] + out[i - 1];
    }
}

/**
LTBitVector: Given an index, returns a vector of size n with a 1 in all indices less than index.

out[i] = 1 if i < index, 0 otherwise

Range checks:
    - index in (0, n]. Fails otherwise.
**/
template LTBitVector(n) {
    signal input index;
    signal output out[n];

    signal eq[n] <== OneBitVector(n)(index - 1);

    out[n-1] <== eq[n-1];
    for (var i = n-2; i >= 0; i--) {
        out[i] <== eq[i] + out[i + 1];
    }
}

/**
SingleMultiplexer: Given a list of inputs, selects one of them based on the value of sel.

More precisely, out = inp[sel].

Range checks:
    - 0 <= sel < nIn (Checked in OneBitVector)
**/
template SingleMultiplexer(nIn) {
    signal input inp[nIn];
    signal input sel;
    signal output out;

    component dec = OneBitVector(nIn);
    sel ==> dec.index;
    EscalarProduct(nIn)(inp, dec.out) ==> out;
}

template vectorAND(n) {
    signal input a[n];
    signal input b[n];

    signal output out[n];

    for (var i = 0; i < n; i++) {
        out[i] <== a[i] * b[i];
    }
}