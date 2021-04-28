
function rotateLeftInt32(num: number, pos: number): number{
    pos = (pos % 32 + 32) % 32;
    return ((num << pos) | (num >>> (32 - pos))) & (0xFFFFFFFF);
}

function rotateRightInt32(num: number, pos: number): number{
    pos = (pos % 32 + 32) % 32;
    return ((num >>> pos) | (num << (32 - pos))) & (0xFFFFFFFF);
}

export {
    rotateLeftInt32, rotateRightInt32
};
