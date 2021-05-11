"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.xor = exports.rotateRightInt32 = exports.rotateLeftInt32 = void 0;
function rotateLeftInt32(num, pos) {
    pos = (pos % 32 + 32) % 32;
    return ((num << pos) | (num >>> (32 - pos))) & (0xFFFFFFFF);
}
exports.rotateLeftInt32 = rotateLeftInt32;
function rotateRightInt32(num, pos) {
    pos = (pos % 32 + 32) % 32;
    return ((num >>> pos) | (num << (32 - pos))) & (0xFFFFFFFF);
}
exports.rotateRightInt32 = rotateRightInt32;
// For internal use only so no need to check sizes
function xor(block1, block2) {
    let blockFinal = new Uint8Array(block1);
    for (let i = 0; i < blockFinal.length; ++i) {
        blockFinal[i] ^= block2[i];
    }
    return blockFinal;
}
exports.xor = xor;
//# sourceMappingURL=helper.js.map