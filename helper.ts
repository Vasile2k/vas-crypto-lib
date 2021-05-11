
function rotateLeftInt32(num: number, pos: number): number{
    pos = (pos % 32 + 32) % 32;
    return ((num << pos) | (num >>> (32 - pos))) & (0xFFFFFFFF);
}

function rotateRightInt32(num: number, pos: number): number{
    pos = (pos % 32 + 32) % 32;
    return ((num >>> pos) | (num << (32 - pos))) & (0xFFFFFFFF);
}

// For internal use only so no need to check sizes
function xor(block1: Uint8Array, block2: Uint8Array): Uint8Array{
    let blockFinal = new Uint8Array(block1);
    for(let i = 0; i < blockFinal.length; ++i){
        blockFinal[i] ^= block2[i];
    }
    return blockFinal;
}

export {
    rotateLeftInt32, rotateRightInt32, xor
};
