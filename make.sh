#!/bin/bash

# 定义电路文件名（不含.circom扩展名）
CIRCUIT_NAME="main"
FIELD_SIZE=14

# 定义帮助信息
usage() {
    echo "Usage: $0 [--compile|--witness|--setup|--prove|--verify|--clear|--help]"
    echo "  --compile      Compile the circuit (${CIRCUIT_NAME}.circom)"
    echo "  --witness     Generate witness"
    echo "  --setup        Perform trusted setup and generate verification key"
    echo "  --prove        Generate proof"
    echo "  --verify       Verify proof"
    echo "  --clear        Clean up generated files"
    echo "  --help         Show this help message"
    exit 1
}

# 检查是否提供了参数
if [ $# -eq 0 ]; then
    usage
fi

# 根据输入参数执行不同操作
case "$1" in
    --compile)
        echo "Compiling the circuit (${CIRCUIT_NAME}.circom)..."
        # 编译电路
        circom ${CIRCUIT_NAME}.circom --r1cs --wasm --sym
        # 查看电路信息
        snarkjs info -r ${CIRCUIT_NAME}.r1cs
        ;;
    --witness)
        echo "Generating witness..."
        # 生成witness
        node ${CIRCUIT_NAME}_js/generate_witness.js ${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm input.json witness.wtns
        ;;
    --setup)
        echo "Performing trusted setup..."
        # 执行trusted setup
        snarkjs powersoftau new bn128 ${FIELD_SIZE} pot_0000.ptau -v
        snarkjs powersoftau contribute pot_0000.ptau pot_0001.ptau --name="First contribution" -v
        snarkjs powersoftau prepare phase2 pot_0001.ptau pot_final.ptau -v
        snarkjs groth16 setup ${CIRCUIT_NAME}.r1cs pot_final.ptau ${CIRCUIT_NAME}_0000.zkey
        # snarkjs zkey contribute ${CIRCUIT_NAME}_0000.zkey ${CIRCUIT_NAME}_0001.zkey --name="Second contribution" -v
        echo "Generating verification key..."
        # 导出验证密钥
        snarkjs zkey export verificationkey ${CIRCUIT_NAME}_0000.zkey verification_key.json
        ;;
    --prove)
        echo "Generating proof..."
        # 生成证明
        snarkjs groth16 prove ${CIRCUIT_NAME}_0000.zkey witness.wtns proof.json public.json
        ;;
    --verify)
        echo "Verifying proof..."
        # 验证证明
        snarkjs groth16 verify verification_key.json public.json proof.json
        ;;
    --clear)
        echo "Cleaning up generated files..."
        # 清理生成的文件
        rm -f *.r1cs *.wasm *.sym *.wtns *.ptau *.zkey proof.json public.json verification_key.json
        rm -rf ${CIRCUIT_NAME}_js
        ;;
    --help)
        usage
        ;;
    *)
        echo "Invalid option: $1"
        usage
        ;;
esac

exit 0