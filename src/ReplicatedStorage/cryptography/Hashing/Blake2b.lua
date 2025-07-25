--[=[
	Cryptography library: BLAKE2b

	Sizes:
		Digest: 2-64 bytes
		Key: 0-128 bytes
	
	Return type: string
	Example usage:
		local Message = buffer.fromstring("Hello World")
		
		--------Usage Case 1--------
		local Result = BLAKE2b(Message)
		
		--------Usage Case 2--------
		local Result = BLAKE2b(Message, 64)
		
		--------Usage Case 3--------
		local OptionalKey = buffer.fromstring("MyKey")
		local Result = BLAKE2b(Message, 64, OptionalKey)
--]=]

--!strict
--!optimize 2
--!native

local BLOCK_SIZE_BYTES = 128
local DEFAULT_OUTPUT_BYTES = 64

local BLAKE2B_MIN_OUTPUT_BYTES = 1
local BLAKE2B_MAX_OUTPUT_BYTES = 64
local BLAKE2B_MAX_KEY_BYTES = 64

local INIT_VECTORS = buffer.create(64) do
	local InitializationConstants = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
		0xf3bcc908, 0x84caa73b, 0xfe94f82b, 0x5f1d36f1, 0xade682d1, 0x2b3e6c1f, 0xfb41bd6b, 0x137e2179
	}
	for Index, Constant in ipairs(InitializationConstants) do
		local BufferOffset = (Index - 1) * 4
		buffer.writeu32(INIT_VECTORS, BufferOffset, Constant)
	end
end

local PERMUTATION_TABLE = buffer.create(192) do
	local SchedulePatterns = {
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		15, 11, 5, 9, 10, 16, 14, 7, 2, 13, 1, 3, 12, 8, 6, 4,
		12, 9, 13, 1, 6, 3, 16, 14, 11, 15, 4, 7, 8, 2, 10, 5,
		8, 10, 4, 2, 14, 13, 12, 15, 3, 7, 6, 11, 5, 1, 16, 9,
		10, 1, 6, 8, 3, 5, 11, 16, 15, 2, 12, 13, 7, 9, 4, 14,
		3, 13, 7, 11, 1, 12, 9, 4, 5, 14, 8, 6, 16, 15, 2, 10,
		13, 6, 2, 16, 15, 14, 5, 11, 1, 8, 7, 4, 10, 3, 9, 12,
		14, 12, 8, 15, 13, 2, 4, 10, 6, 1, 16, 5, 9, 7, 3, 11,
		7, 16, 15, 10, 12, 4, 1, 9, 13, 3, 14, 8, 2, 5, 11, 6,
		11, 3, 9, 5, 8, 7, 2, 6, 16, 12, 10, 15, 4, 13, 14, 1,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		15, 11, 5, 9, 10, 16, 14, 7, 2, 13, 1, 3, 12, 8, 6, 4
	}
	for Index, Pattern in ipairs(SchedulePatterns) do
		local BufferOffset = (Index - 1) * 1
		buffer.writeu8(PERMUTATION_TABLE, BufferOffset, Pattern)
	end
end

local WH9, WH10, WH11, WH12, WH13, WH14, WH15, WH16 = buffer.readu32(INIT_VECTORS, 0), buffer.readu32(INIT_VECTORS, 4), buffer.readu32(INIT_VECTORS, 8), buffer.readu32(INIT_VECTORS, 12), buffer.readu32(INIT_VECTORS, 16), buffer.readu32(INIT_VECTORS, 20), buffer.readu32(INIT_VECTORS, 24), buffer.readu32(INIT_VECTORS, 28)
local WL9, WL10, WL11, WL12, WL13, WL14, WL15, WL16 = buffer.readu32(INIT_VECTORS, 32), buffer.readu32(INIT_VECTORS, 36), buffer.readu32(INIT_VECTORS, 40), buffer.readu32(INIT_VECTORS, 44), buffer.readu32(INIT_VECTORS, 48), buffer.readu32(INIT_VECTORS, 52), buffer.readu32(INIT_VECTORS, 56), buffer.readu32(INIT_VECTORS, 60)

local function ExtractWordsFromBlock(InputBuffer: buffer, StartOffset: number, HighWords: {number}, LowWords: {number})
	for WordIdx = 1, 16 do
		local BytePos = StartOffset + (WordIdx - 1) * 8
		LowWords[WordIdx] = buffer.readu32(InputBuffer, BytePos)
		HighWords[WordIdx] = buffer.readu32(InputBuffer, BytePos + 4)
	end
end

local function ProcessCompressionRound(HighWords: {number}, LowWords: {number}, ByteCounter: number, FinalBlock: boolean, StateHigh: {number}, StateLow: {number})
	local WH1, WH2, WH3, WH4, WH5, WH6, WH7, WH8 = StateHigh[1], StateHigh[2], StateHigh[3], StateHigh[4], StateHigh[5], StateHigh[6], StateHigh[7], StateHigh[8]
	local WL1, WL2, WL3, WL4, WL5, WL6, WL7, WL8 = StateLow[1], StateLow[2], StateLow[3], StateLow[4], StateLow[5], StateLow[6], StateLow[7], StateLow[8]
	local WorkH9, WorkH10, WorkH11, WorkH12, WorkH13, WorkH14, WorkH15, WorkH16 = WH9, WH10, WH11, WH12, WH13, WH14, WH15, WH16
	local WorkL9, WorkL10, WorkL11, WorkL12, WorkL13, WorkL14, WorkL15, WorkL16 = WL9, WL10, WL11, WL12, WL13, WL14, WL15, WL16

	WorkH13 = bit32.bxor(WorkH13, ByteCounter // 0x100000000)
	WorkL13 = bit32.bxor(WorkL13, bit32.bor(ByteCounter, 0))
	if FinalBlock then
		WorkH15 = bit32.bnot(WorkH15)
		WorkL15 = bit32.bnot(WorkL15)
	end

	local CarryBits, MsgHighX, MsgLowX, MsgHighY, MsgLowY = 0, 0, 0, 0, 0

	for RoundNum = 1, 12 do
		local ScheduleBase = (RoundNum - 1) * 16

		do
			local S1, S2 = buffer.readu8(PERMUTATION_TABLE, ScheduleBase + 0), buffer.readu8(PERMUTATION_TABLE, ScheduleBase + 1)
			MsgHighX, MsgLowX = HighWords[S1], LowWords[S1]
			MsgHighY, MsgLowY = HighWords[S2], LowWords[S2]

			CarryBits = WL1 + WL5 + MsgLowX
			WH1 += WH5 + MsgHighX + CarryBits // 0x100000000
			WL1 = bit32.bor(CarryBits, 0)

			CarryBits = WorkH13
			WorkH13 = bit32.bxor(WorkL13, WL1)
			WorkL13 = bit32.bxor(CarryBits, WH1)

			CarryBits = WorkL9 + WorkL13
			WorkH9 += WorkH13 + CarryBits // 0x100000000
			WorkL9 = bit32.bor(CarryBits, 0)

			CarryBits = WH5
			WH5 = bit32.bxor(bit32.rshift(WH5, 24), bit32.lshift(WL5, 8), bit32.rshift(WorkH9, 24), bit32.lshift(WorkL9, 8))
			WL5 = bit32.bxor(bit32.rshift(WL5, 24), bit32.lshift(CarryBits, 8), bit32.rshift(WorkL9, 24), bit32.lshift(WorkH9, 8))

			CarryBits = WL1 + WL5 + MsgLowY
			WH1 += WH5 + MsgHighY + CarryBits // 0x100000000
			WL1 = bit32.bor(CarryBits, 0)

			CarryBits = WorkH13
			WorkH13 = bit32.bxor(bit32.rshift(WorkH13, 16), bit32.lshift(WorkL13, 16), bit32.rshift(WH1, 16), bit32.lshift(WL1, 16))
			WorkL13 = bit32.bxor(bit32.rshift(WorkL13, 16), bit32.lshift(CarryBits, 16), bit32.rshift(WL1, 16), bit32.lshift(WH1, 16))

			CarryBits = WorkL9 + WorkL13
			WorkH9 += WorkH13 + CarryBits // 0x100000000
			WorkL9 = bit32.bor(CarryBits, 0)

			CarryBits = WH5
			WH5 = bit32.bxor(bit32.lshift(WH5, 1), bit32.rshift(WL5, 31), bit32.lshift(WorkH9, 1), bit32.rshift(WorkL9, 31))
			WL5 = bit32.bxor(bit32.lshift(WL5, 1), bit32.rshift(CarryBits, 31), bit32.lshift(WorkL9, 1), bit32.rshift(WorkH9, 31))
		end

		do
			local S3, S4 = buffer.readu8(PERMUTATION_TABLE, ScheduleBase + 2), buffer.readu8(PERMUTATION_TABLE, ScheduleBase + 3)
			MsgHighX, MsgLowX = HighWords[S3], LowWords[S3]
			MsgHighY, MsgLowY = HighWords[S4], LowWords[S4]

			CarryBits = WL2 + WL6 + MsgLowX
			WH2 += WH6 + MsgHighX + CarryBits // 0x100000000
			WL2 = bit32.bor(CarryBits, 0)

			CarryBits = WorkH14
			WorkH14 = bit32.bxor(WorkL14, WL2)
			WorkL14 = bit32.bxor(CarryBits, WH2)

			CarryBits = WorkL10 + WorkL14
			WorkH10 += WorkH14 + CarryBits // 0x100000000
			WorkL10 = bit32.bor(CarryBits, 0)

			CarryBits = WH6
			WH6 = bit32.bxor(bit32.rshift(WH6, 24), bit32.lshift(WL6, 8), bit32.rshift(WorkH10, 24), bit32.lshift(WorkL10, 8))
			WL6 = bit32.bxor(bit32.rshift(WL6, 24), bit32.lshift(CarryBits, 8), bit32.rshift(WorkL10, 24), bit32.lshift(WorkH10, 8))

			CarryBits = WL2 + WL6 + MsgLowY
			WH2 += WH6 + MsgHighY + CarryBits // 0x100000000
			WL2 = bit32.bor(CarryBits, 0)

			CarryBits = WorkH14
			WorkH14 = bit32.bxor(bit32.rshift(WorkH14, 16), bit32.lshift(WorkL14, 16), bit32.rshift(WH2, 16), bit32.lshift(WL2, 16))
			WorkL14 = bit32.bxor(bit32.rshift(WorkL14, 16), bit32.lshift(CarryBits, 16), bit32.rshift(WL2, 16), bit32.lshift(WH2, 16))

			CarryBits = WorkL10 + WorkL14
			WorkH10 += WorkH14 + CarryBits // 0x100000000
			WorkL10 = bit32.bor(CarryBits, 0)

			CarryBits = WH6
			WH6 = bit32.bxor(bit32.lshift(WH6, 1), bit32.rshift(WL6, 31), bit32.lshift(WorkH10, 1), bit32.rshift(WorkL10, 31))
			WL6 = bit32.bxor(bit32.lshift(WL6, 1), bit32.rshift(CarryBits, 31), bit32.lshift(WorkL10, 1), bit32.rshift(WorkH10, 31))
		end

		do
			local S5, S6 = buffer.readu8(PERMUTATION_TABLE, ScheduleBase + 4), buffer.readu8(PERMUTATION_TABLE, ScheduleBase + 5)
			MsgHighX, MsgLowX = HighWords[S5], LowWords[S5]
			MsgHighY, MsgLowY = HighWords[S6], LowWords[S6]

			CarryBits = WL3 + WL7 + MsgLowX
			WH3 += WH7 + MsgHighX + CarryBits // 0x100000000
			WL3 = bit32.bor(CarryBits, 0)

			CarryBits = WorkH15
			WorkH15 = bit32.bxor(WorkL15, WL3)
			WorkL15 = bit32.bxor(CarryBits, WH3)

			CarryBits = WorkL11 + WorkL15
			WorkH11 += WorkH15 + CarryBits // 0x100000000
			WorkL11 = bit32.bor(CarryBits, 0)

			CarryBits = WH7
			WH7 = bit32.bxor(bit32.rshift(WH7, 24), bit32.lshift(WL7, 8), bit32.rshift(WorkH11, 24), bit32.lshift(WorkL11, 8))
			WL7 = bit32.bxor(bit32.rshift(WL7, 24), bit32.lshift(CarryBits, 8), bit32.rshift(WorkL11, 24), bit32.lshift(WorkH11, 8))

			CarryBits = WL3 + WL7 + MsgLowY
			WH3 += WH7 + MsgHighY + CarryBits // 0x100000000
			WL3 = bit32.bor(CarryBits, 0)

			CarryBits = WorkH15
			WorkH15 = bit32.bxor(bit32.rshift(WorkH15, 16), bit32.lshift(WorkL15, 16), bit32.rshift(WH3, 16), bit32.lshift(WL3, 16))
			WorkL15 = bit32.bxor(bit32.rshift(WorkL15, 16), bit32.lshift(CarryBits, 16), bit32.rshift(WL3, 16), bit32.lshift(WH3, 16))

			CarryBits = WorkL11 + WorkL15
			WorkH11 += WorkH15 + CarryBits // 0x100000000
			WorkL11 = bit32.bor(CarryBits, 0)

			CarryBits = WH7
			WH7 = bit32.bxor(bit32.lshift(WH7, 1), bit32.rshift(WL7, 31), bit32.lshift(WorkH11, 1), bit32.rshift(WorkL11, 31))
			WL7 = bit32.bxor(bit32.lshift(WL7, 1), bit32.rshift(CarryBits, 31), bit32.lshift(WorkL11, 1), bit32.rshift(WorkH11, 31))
		end

		do
			local S7, S8 = buffer.readu8(PERMUTATION_TABLE, ScheduleBase + 6), buffer.readu8(PERMUTATION_TABLE, ScheduleBase + 7)
			MsgHighX, MsgLowX = HighWords[S7], LowWords[S7]
			MsgHighY, MsgLowY = HighWords[S8], LowWords[S8]

			CarryBits = WL4 + WL8 + MsgLowX
			WH4 += WH8 + MsgHighX + CarryBits // 0x100000000
			WL4 = bit32.bor(CarryBits, 0)

			CarryBits = WorkH16
			WorkH16 = bit32.bxor(WorkL16, WL4)
			WorkL16 = bit32.bxor(CarryBits, WH4)

			CarryBits = WorkL12 + WorkL16
			WorkH12 += WorkH16 + CarryBits // 0x100000000
			WorkL12 = bit32.bor(CarryBits, 0)

			CarryBits = WH8
			WH8 = bit32.bxor(bit32.rshift(WH8, 24), bit32.lshift(WL8, 8), bit32.rshift(WorkH12, 24), bit32.lshift(WorkL12, 8))
			WL8 = bit32.bxor(bit32.rshift(WL8, 24), bit32.lshift(CarryBits, 8), bit32.rshift(WorkL12, 24), bit32.lshift(WorkH12, 8))

			CarryBits = WL4 + WL8 + MsgLowY
			WH4 += WH8 + MsgHighY + CarryBits // 0x100000000
			WL4 = bit32.bor(CarryBits, 0)

			CarryBits = WorkH16
			WorkH16 = bit32.bxor(bit32.rshift(WorkH16, 16), bit32.lshift(WorkL16, 16), bit32.rshift(WH4, 16), bit32.lshift(WL4, 16))
			WorkL16 = bit32.bxor(bit32.rshift(WorkL16, 16), bit32.lshift(CarryBits, 16), bit32.rshift(WL4, 16), bit32.lshift(WH4, 16))

			CarryBits = WorkL12 + WorkL16
			WorkH12 += WorkH16 + CarryBits // 0x100000000
			WorkL12 = bit32.bor(CarryBits, 0)

			CarryBits = WH8
			WH8 = bit32.bxor(bit32.lshift(WH8, 1), bit32.rshift(WL8, 31), bit32.lshift(WorkH12, 1), bit32.rshift(WorkL12, 31))
			WL8 = bit32.bxor(bit32.lshift(WL8, 1), bit32.rshift(CarryBits, 31), bit32.lshift(WorkL12, 1), bit32.rshift(WorkH12, 31))
		end

		do
			local S9, S10 = buffer.readu8(PERMUTATION_TABLE, ScheduleBase + 8), buffer.readu8(PERMUTATION_TABLE, ScheduleBase + 9)
			MsgHighX, MsgLowX = HighWords[S9], LowWords[S9]
			MsgHighY, MsgLowY = HighWords[S10], LowWords[S10]

			CarryBits = WL1 + WL6 + MsgLowX
			WH1 += WH6 + MsgHighX + CarryBits // 0x100000000
			WL1 = bit32.bor(CarryBits, 0)

			CarryBits = WorkH16
			WorkH16 = bit32.bxor(WorkL16, WL1)
			WorkL16 = bit32.bxor(CarryBits, WH1)

			CarryBits = WorkL11 + WorkL16
			WorkH11 += WorkH16 + CarryBits // 0x100000000
			WorkL11 = bit32.bor(CarryBits, 0)

			CarryBits = WH6
			WH6 = bit32.bxor(bit32.rshift(WH6, 24), bit32.lshift(WL6, 8), bit32.rshift(WorkH11, 24), bit32.lshift(WorkL11, 8))
			WL6 = bit32.bxor(bit32.rshift(WL6, 24), bit32.lshift(CarryBits, 8), bit32.rshift(WorkL11, 24), bit32.lshift(WorkH11, 8))

			CarryBits = WL1 + WL6 + MsgLowY
			WH1 += WH6 + MsgHighY + CarryBits // 0x100000000
			WL1 = bit32.bor(CarryBits, 0)

			CarryBits = WorkH16
			WorkH16 = bit32.bxor(bit32.rshift(WorkH16, 16), bit32.lshift(WorkL16, 16), bit32.rshift(WH1, 16), bit32.lshift(WL1, 16))
			WorkL16 = bit32.bxor(bit32.rshift(WorkL16, 16), bit32.lshift(CarryBits, 16), bit32.rshift(WL1, 16), bit32.lshift(WH1, 16))

			CarryBits = WorkL11 + WorkL16
			WorkH11 += WorkH16 + CarryBits // 0x100000000
			WorkL11 = bit32.bor(CarryBits, 0)

			CarryBits = WH6
			WH6 = bit32.bxor(bit32.lshift(WH6, 1), bit32.rshift(WL6, 31), bit32.lshift(WorkH11, 1), bit32.rshift(WorkL11, 31))
			WL6 = bit32.bxor(bit32.lshift(WL6, 1), bit32.rshift(CarryBits, 31), bit32.lshift(WorkL11, 1), bit32.rshift(WorkH11, 31))
		end

		do
			local S11, S12 = buffer.readu8(PERMUTATION_TABLE, ScheduleBase + 10), buffer.readu8(PERMUTATION_TABLE, ScheduleBase + 11)
			MsgHighX, MsgLowX = HighWords[S11], LowWords[S11]
			MsgHighY, MsgLowY = HighWords[S12], LowWords[S12]

			CarryBits = WL2 + WL7 + MsgLowX
			WH2 += WH7 + MsgHighX + CarryBits // 0x100000000
			WL2 = bit32.bor(CarryBits, 0)

			CarryBits = WorkH13
			WorkH13 = bit32.bxor(WorkL13, WL2)
			WorkL13 = bit32.bxor(CarryBits, WH2)

			CarryBits = WorkL12 + WorkL13
			WorkH12 += WorkH13 + CarryBits // 0x100000000
			WorkL12 = bit32.bor(CarryBits, 0)

			CarryBits = WH7
			WH7 = bit32.bxor(bit32.rshift(WH7, 24), bit32.lshift(WL7, 8), bit32.rshift(WorkH12, 24), bit32.lshift(WorkL12, 8))
			WL7 = bit32.bxor(bit32.rshift(WL7, 24), bit32.lshift(CarryBits, 8), bit32.rshift(WorkL12, 24), bit32.lshift(WorkH12, 8))

			CarryBits = WL2 + WL7 + MsgLowY
			WH2 += WH7 + MsgHighY + CarryBits // 0x100000000
			WL2 = bit32.bor(CarryBits, 0)

			CarryBits = WorkH13
			WorkH13 = bit32.bxor(bit32.rshift(WorkH13, 16), bit32.lshift(WorkL13, 16), bit32.rshift(WH2, 16), bit32.lshift(WL2, 16))
			WorkL13 = bit32.bxor(bit32.rshift(WorkL13, 16), bit32.lshift(CarryBits, 16), bit32.rshift(WL2, 16), bit32.lshift(WH2, 16))

			CarryBits = WorkL12 + WorkL13
			WorkH12 += WorkH13 + CarryBits // 0x100000000
			WorkL12 = bit32.bor(CarryBits, 0)

			CarryBits = WH7
			WH7 = bit32.bxor(bit32.lshift(WH7, 1), bit32.rshift(WL7, 31), bit32.lshift(WorkH12, 1), bit32.rshift(WorkL12, 31))
			WL7 = bit32.bxor(bit32.lshift(WL7, 1), bit32.rshift(CarryBits, 31), bit32.lshift(WorkL12, 1), bit32.rshift(WorkH12, 31))
		end

		do
			local S13, S14 = buffer.readu8(PERMUTATION_TABLE, ScheduleBase + 12), buffer.readu8(PERMUTATION_TABLE, ScheduleBase + 13)
			MsgHighX, MsgLowX = HighWords[S13], LowWords[S13]
			MsgHighY, MsgLowY = HighWords[S14], LowWords[S14]

			CarryBits = WL3 + WL8 + MsgLowX
			WH3 += WH8 + MsgHighX + CarryBits // 0x100000000
			WL3 = bit32.bor(CarryBits, 0)

			CarryBits = WorkH14
			WorkH14 = bit32.bxor(WorkL14, WL3)
			WorkL14 = bit32.bxor(CarryBits, WH3)

			CarryBits = WorkL9 + WorkL14
			WorkH9 += WorkH14 + CarryBits // 0x100000000
			WorkL9 = bit32.bor(CarryBits, 0)

			CarryBits = WH8
			WH8 = bit32.bxor(bit32.rshift(WH8, 24), bit32.lshift(WL8, 8), bit32.rshift(WorkH9, 24), bit32.lshift(WorkL9, 8))
			WL8 = bit32.bxor(bit32.rshift(WL8, 24), bit32.lshift(CarryBits, 8), bit32.rshift(WorkL9, 24), bit32.lshift(WorkH9, 8))

			CarryBits = WL3 + WL8 + MsgLowY
			WH3 += WH8 + MsgHighY + CarryBits // 0x100000000
			WL3 = bit32.bor(CarryBits, 0)

			CarryBits = WorkH14
			WorkH14 = bit32.bxor(bit32.rshift(WorkH14, 16), bit32.lshift(WorkL14, 16), bit32.rshift(WH3, 16), bit32.lshift(WL3, 16))
			WorkL14 = bit32.bxor(bit32.rshift(WorkL14, 16), bit32.lshift(CarryBits, 16), bit32.rshift(WL3, 16), bit32.lshift(WH3, 16))

			CarryBits = WorkL9 + WorkL14
			WorkH9 += WorkH14 + CarryBits // 0x100000000
			WorkL9 = bit32.bor(CarryBits, 0)

			CarryBits = WH8
			WH8 = bit32.bxor(bit32.lshift(WH8, 1), bit32.rshift(WL8, 31), bit32.lshift(WorkH9, 1), bit32.rshift(WorkL9, 31))
			WL8 = bit32.bxor(bit32.lshift(WL8, 1), bit32.rshift(CarryBits, 31), bit32.lshift(WorkL9, 1), bit32.rshift(WorkH9, 31))
		end

		do
			local S15, S16 = buffer.readu8(PERMUTATION_TABLE, ScheduleBase + 14), buffer.readu8(PERMUTATION_TABLE, ScheduleBase + 15)
			MsgHighX, MsgLowX = HighWords[S15], LowWords[S15]
			MsgHighY, MsgLowY = HighWords[S16], LowWords[S16]

			CarryBits = WL4 + WL5 + MsgLowX
			WH4 += WH5 + MsgHighX + CarryBits // 0x100000000
			WL4 = bit32.bor(CarryBits, 0)

			CarryBits = WorkH15
			WorkH15 = bit32.bxor(WorkL15, WL4)
			WorkL15 = bit32.bxor(CarryBits, WH4)

			CarryBits = WorkL10 + WorkL15
			WorkH10 += WorkH15 + CarryBits // 0x100000000
			WorkL10 = bit32.bor(CarryBits, 0)

			CarryBits = WH5
			WH5 = bit32.bxor(bit32.rshift(WH5, 24), bit32.lshift(WL5, 8), bit32.rshift(WorkH10, 24), bit32.lshift(WorkL10, 8))
			WL5 = bit32.bxor(bit32.rshift(WL5, 24), bit32.lshift(CarryBits, 8), bit32.rshift(WorkL10, 24), bit32.lshift(WorkH10, 8))

			CarryBits = WL4 + WL5 + MsgLowY
			WH4 += WH5 + MsgHighY + CarryBits // 0x100000000
			WL4 = bit32.bor(CarryBits, 0)

			CarryBits = WorkH15
			WorkH15 = bit32.bxor(bit32.rshift(WorkH15, 16), bit32.lshift(WorkL15, 16), bit32.rshift(WH4, 16), bit32.lshift(WL4, 16))
			WorkL15 = bit32.bxor(bit32.rshift(WorkL15, 16), bit32.lshift(CarryBits, 16), bit32.rshift(WL4, 16), bit32.lshift(WH4, 16))

			CarryBits = WorkL10 + WorkL15
			WorkH10 += WorkH15 + CarryBits // 0x100000000
			WorkL10 = bit32.bor(CarryBits, 0)

			CarryBits = WH5
			WH5 = bit32.bxor(bit32.lshift(WH5, 1), bit32.rshift(WL5, 31), bit32.lshift(WorkH10, 1), bit32.rshift(WorkL10, 31))
			WL5 = bit32.bxor(bit32.lshift(WL5, 1), bit32.rshift(CarryBits, 31), bit32.lshift(WorkL10, 1), bit32.rshift(WorkH10, 31))
		end
	end

	StateHigh[1] = bit32.bxor(StateHigh[1], WH1, WorkH9)
	StateLow[1] = bit32.bxor(StateLow[1], WL1, WorkL9)
	StateHigh[2] = bit32.bxor(StateHigh[2], WH2, WorkH10)
	StateLow[2] = bit32.bxor(StateLow[2], WL2, WorkL10)
	StateHigh[3] = bit32.bxor(StateHigh[3], WH3, WorkH11)
	StateLow[3] = bit32.bxor(StateLow[3], WL3, WorkL11)
	StateHigh[4] = bit32.bxor(StateHigh[4], WH4, WorkH12)
	StateLow[4] = bit32.bxor(StateLow[4], WL4, WorkL12)
	StateHigh[5] = bit32.bxor(StateHigh[5], WH5, WorkH13)
	StateLow[5] = bit32.bxor(StateLow[5], WL5, WorkL13)
	StateHigh[6] = bit32.bxor(StateHigh[6], WH6, WorkH14)
	StateLow[6] = bit32.bxor(StateLow[6], WL6, WorkL14)
	StateHigh[7] = bit32.bxor(StateHigh[7], WH7, WorkH15)
	StateLow[7] = bit32.bxor(StateLow[7], WL7, WorkL15)
	StateHigh[8] = bit32.bxor(StateHigh[8], WH8, WorkH16)
	StateLow[8] = bit32.bxor(StateLow[8], WL8, WorkL16)
end

local OutputFormat = string.rep("%08x", 16)
local function HashDigest(InputData: buffer, OutputLength: number, KeyData: buffer?): string
	local KeyLength = KeyData and buffer.len(KeyData) or 0
	local DataLength = buffer.len(InputData)

	local StateHigh = { WH9, WH10, WH11, WH12, WH13, WH14, WH15, WH16 }
	local StateLow = { WL9, WL10, WL11, WL12, WL13, WL14, WL15, WL16 }

	StateLow[1] = bit32.bxor(StateLow[1], 0x01010000, bit32.lshift(KeyLength, 8), OutputLength)

	local BlockHigh = table.create(16)
	local BlockLow = table.create(16)
	local ProcessedBytes = KeyLength > 0 and 128 or 0

	if KeyLength > 0 and KeyData then
		local KeyPadding = buffer.create(BLOCK_SIZE_BYTES)
		buffer.copy(KeyPadding, 0, KeyData)
		ExtractWordsFromBlock(KeyPadding, 0, BlockHigh, BlockLow)
		ProcessCompressionRound(BlockHigh, BlockLow, ProcessedBytes, DataLength == 0, StateHigh, StateLow)
	end

	local RemainingBytes = DataLength % BLOCK_SIZE_BYTES
	local FinalBlockSize = RemainingBytes == 0 and BLOCK_SIZE_BYTES or RemainingBytes

	for BlockStart = 0, DataLength - FinalBlockSize - 1, BLOCK_SIZE_BYTES do
		ExtractWordsFromBlock(InputData, BlockStart, BlockHigh, BlockLow)
		ProcessedBytes += BLOCK_SIZE_BYTES
		ProcessCompressionRound(BlockHigh, BlockLow, ProcessedBytes, false, StateHigh, StateLow)
	end

	if KeyLength == 0 or DataLength > 0 then
		local PaddedBlock = buffer.create(BLOCK_SIZE_BYTES)
		local CopyBytes = math.min(FinalBlockSize, DataLength)
		local CopyStart = math.max(0, DataLength - FinalBlockSize)
		if CopyBytes > 0 then
			buffer.copy(PaddedBlock, 0, InputData, CopyStart, CopyBytes)
		end
		
		ExtractWordsFromBlock(PaddedBlock, 0, BlockHigh, BlockLow)
		ProcessCompressionRound(BlockHigh, BlockLow, ProcessedBytes + CopyBytes, true, StateHigh, StateLow)
	end

	local FinalDigest = string.format(
		OutputFormat,
		bit32.byteswap(StateLow[1]), bit32.byteswap(StateHigh[1]),
		bit32.byteswap(StateLow[2]), bit32.byteswap(StateHigh[2]),
		bit32.byteswap(StateLow[3]), bit32.byteswap(StateHigh[3]),
		bit32.byteswap(StateLow[4]), bit32.byteswap(StateHigh[4]),
		bit32.byteswap(StateLow[5]), bit32.byteswap(StateHigh[5]),
		bit32.byteswap(StateLow[6]), bit32.byteswap(StateHigh[6]),
		bit32.byteswap(StateLow[7]), bit32.byteswap(StateHigh[7]),
		bit32.byteswap(StateLow[8]), bit32.byteswap(StateHigh[8])
	)

	return string.sub(FinalDigest, 1, OutputLength * 2)
end

local function BLAKE2b(InputData: buffer, OutputLength: number?, KeyData: buffer?): string
	if InputData == nil then
		error("InputData cannot be nil", 2)
	end
	
	if typeof(InputData) ~= "buffer" then
		error(`InputData must be a buffer, got {typeof(InputData)}`, 2)
	end

	if OutputLength then
		if typeof(OutputLength) ~= "number" then
			error(`OutputLength must be a number, got {typeof(OutputLength)}`, 2)
		end
		
		if OutputLength ~= math.floor(OutputLength) then
			error(`OutputLength must be an integer, got {OutputLength}`, 2)
		end
		
		if OutputLength < BLAKE2B_MIN_OUTPUT_BYTES or OutputLength > BLAKE2B_MAX_OUTPUT_BYTES then
			error(`OutputLength must be between {BLAKE2B_MIN_OUTPUT_BYTES} and {BLAKE2B_MAX_OUTPUT_BYTES} bytes, got {OutputLength} bytes`, 2)
		end
	end

	if KeyData then
		if typeof(KeyData) ~= "buffer" then
			error(`KeyData must be a buffer, got {typeof(KeyData)}`, 2)
		end
		
		local KeyLength = buffer.len(KeyData)
		if KeyLength == 0 then
			error("KeyData cannot be empty", 2)
		end
		
		if KeyLength > BLAKE2B_MAX_KEY_BYTES then
			error(`KeyData must be at most {BLAKE2B_MAX_KEY_BYTES} bytes long, got {KeyLength} bytes`, 2)
		end
	end

	return HashDigest(InputData, OutputLength or DEFAULT_OUTPUT_BYTES, KeyData)
end

return BLAKE2b