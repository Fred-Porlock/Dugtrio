pragma circom 2.1.3;

include "helpers/hasher.circom";
include "/mnt/c/Users/32492/node_modules/circomlib/circuits/mux1.circom";

// MerkleTree: proves the membership of a leaf in a Merkle tree.
// input:
// * leaf: The leaf node. A hash value generated from Hasher.
// * path[4]: The sibling nodes of the path from the leaf to the root. We assume that the tree has 4 leaves, and there are 2 sibling nodes on the path. path[0] represents the position of the first sibling node (0 for left, 1 for right), path[1] is the first sibling node, and so on and so forth.
// output:
// * root: The root hash of the Merkle tree.
template MerkleTree() {
    signal input leaf;
    signal input path[4];

    // 第一层：使用条件选择器实现if-else
    component mux1 = Mux1();
    component hasher1_left = Hasher(2);
    component hasher1_right = Hasher(2);
    
    // 计算两种可能的哈希值
    hasher1_left.in[0] <== path[1];      // if path[0] === 0
    hasher1_left.in[1] <== leaf;
    
    hasher1_right.in[0] <== leaf;  // if path[0] === 1
    hasher1_right.in[1] <== path[1];
    
    // 使用选择器选择正确的结果
    mux1.c[0] <== hasher1_left.out;   // path[0] === 0时选择
    mux1.c[1] <== hasher1_right.out;  // path[0] === 1时选择
    mux1.s <== path[0];               // path[0]作为选择信号（0或1）
    
    signal intermediate_hash;
    intermediate_hash <== mux1.out;

    // 第二层：同样的逻辑
    component mux2 = Mux1();
    component hasher2_left = Hasher(2);
    component hasher2_right = Hasher(2);
    
    hasher2_left.in[0] <== path[3];           // if path[2] === 0
    hasher2_left.in[1] <== intermediate_hash;
    
    hasher2_right.in[0] <== intermediate_hash; // if path[2] === 1
    hasher2_right.in[1] <== path[3];
    
    mux2.c[0] <== hasher2_left.out;
    mux2.c[1] <== hasher2_right.out;
    mux2.s <== path[2];

    signal output root;
    root <== mux2.out;
}