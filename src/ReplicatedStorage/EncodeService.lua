--[[

written by @forveined | https://condogame.fun

]]


local RunService = game:GetService("RunService")
local Cryptography = require(script.Parent.cryptography)

local Xor = Cryptography.Encryption.XOR
local RandomString = Cryptography.Utilities.RandomString
local Conversions = Cryptography.Utilities.Conversions

export type EncodeService = {
	Encode: (self: EncodeService, data: string) -> string,
	Decode: (self: EncodeService, encodedData: string) -> string,
}

local EncodeService: EncodeService = {} :: any
EncodeService.__index = EncodeService

local SECRET = "inputyoursecrethere"
local EncryptionKey: buffer = buffer.fromstring(SECRET)

function EncodeService.New(): EncodeService
	local self = setmetatable({}, EncodeService)
	return self
end

function EncodeService:Encode(data: string): string
	assert(type(data) == "string", "Data must be a string")
	local dataBuffer = buffer.fromstring(data)
	local encryptedBuffer = Xor(dataBuffer, EncryptionKey)
	return Conversions.ToHex(encryptedBuffer)
end

function EncodeService:Decode(encodedData: string): string
	assert(type(encodedData) == "string", "Encoded data must be a string")
	local encryptedBuffer = Conversions.FromHex(encodedData)
	local decryptedBuffer = Xor(encryptedBuffer, EncryptionKey)
	return buffer.tostring(decryptedBuffer)
end

return EncodeService
