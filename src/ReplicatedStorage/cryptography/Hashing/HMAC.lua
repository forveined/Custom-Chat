--[=[
	Cryptography library: HMAC
	
	Return type: string or function
	Example usage:
		local Message = buffer.fromstring("Hello World")
		local Key = buffer.fromstring("Key")
		local BlockSize = 64 -- SHA256 block length (= string.len(SHA256(...)))
		
		local Result = HMAC(Message, Key, SHA2.SHA256, BlockSize)
--]=]

--!strict
--!optimize 2
--!native

export type HashFunction = (...any) -> (string, buffer)

local function HexToBinary(HexBuffer: buffer)
	local HexBufferLength = buffer.len(HexBuffer)
	
	local Size = bit32.rshift(HexBufferLength, 1)
	local BinaryBuffer = buffer.create(Size)

	for Index = 0, HexBufferLength - 1, 2 do
		local HighByte = buffer.readu8(HexBuffer, Index)
		local LowByte = buffer.readu8(HexBuffer, Index + 1)

		local HexString = string.char(HighByte) .. string.char(LowByte)
		buffer.writeu8(BinaryBuffer, Index // 2, tonumber(HexString, 16) or 0)
	end

	return BinaryBuffer
end

local function FromByteAndSize(Byte: number, Size: number)
	local Buffer = buffer.create(Size)
	buffer.fill(Buffer, 0, Byte)
	return Buffer
end

local function XORBuffer(LeftBuffer: buffer, RightBuffer: buffer)
	local Size = math.min(buffer.len(LeftBuffer), buffer.len(RightBuffer))
	local NewBuffer = buffer.create(Size)
	
	for Index = 0, Size - 1 do
		local LeftValue = buffer.readu8(LeftBuffer, Index)
		local RightValue = buffer.readu8(RightBuffer, Index)
		buffer.writeu8(NewBuffer, Index, bit32.bxor(LeftValue, RightValue))
	end
	
	return NewBuffer
end

local function ConcatenateBuffers(LeftBuffer: buffer, RightBuffer: buffer)
	local LeftBufLen = buffer.len(LeftBuffer)
	local Buffer = buffer.create(LeftBufLen + buffer.len(RightBuffer))
	
	buffer.copy(Buffer, 0, LeftBuffer)
	buffer.copy(Buffer, LeftBufLen, RightBuffer)
	
	return Buffer
end

local function ToBigEndian(Buffer: buffer)
	-- The hashing algorithms only ever write to buffers
	-- with writeu32, so if the buffer size isn't a multiple
	-- of four, we don't know if the remaining bytes have to
	-- be swapped
	for Index = 0, buffer.len(Buffer) - 1, 4 do
		buffer.writeu32(Buffer, Index, bit32.byteswap(buffer.readu32(Buffer, Index)))
	end
end

local function ComputeBlockSizedKey(Key: buffer, HashFunction: HashFunction, BlockSizeBytes: number): buffer
	local KeyLength = buffer.len(Key)

	if KeyLength > BlockSizeBytes then
		local _, Digest = HashFunction(Key)
		ToBigEndian(Digest)

		local PaddedKey = buffer.create(BlockSizeBytes)
		buffer.copy(PaddedKey, 0, Digest)

		return PaddedKey
	elseif KeyLength < BlockSizeBytes then
		local PaddedKey = buffer.create(BlockSizeBytes)
		buffer.copy(PaddedKey, 0, Key)

		return PaddedKey
	end

	return Key
end

local function HMAC(Message: buffer, Key: buffer, HashFunction: HashFunction, BlockSizeBytes: number): (string, buffer)
	local StringDigest, BufferDigest = HashFunction(buffer.fromstring("Hello World"))

	if not StringDigest or type(StringDigest) ~= "string" then
		error(`Incompatible hash function. Expected HashFunction to return a string and a buffer, expected string but got {typeof(StringDigest)}`, 2)
	end

	if not BufferDigest or type(BufferDigest) ~= "buffer" then
		error(`Incompatible hash function. Expected HashFunction to return a string and a buffer, expected buffer but got {typeof(BufferDigest)}`, 2)
	end

	local BlockSizedKey = ComputeBlockSizedKey(Key, HashFunction, BlockSizeBytes)

	local OuterPaddedKey = XORBuffer(BlockSizedKey, FromByteAndSize(0x5C, BlockSizeBytes))
	local InnerPaddedKey = XORBuffer(BlockSizedKey, FromByteAndSize(0x36, BlockSizeBytes))
	
	local HashedMessageWithInnerKey = HexToBinary(buffer.fromstring((HashFunction(ConcatenateBuffers(InnerPaddedKey, Message)))))
	local FinalMessage = ConcatenateBuffers(OuterPaddedKey, HashedMessageWithInnerKey)
	return HashFunction(FinalMessage)
end

return HMAC
