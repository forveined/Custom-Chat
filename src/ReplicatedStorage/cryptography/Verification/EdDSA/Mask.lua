--[=[
	Cryptography library: Masked X25519 (Double Key Exchange)

	Provides plausible deniability through dual-key ECDH exchange.
	Each exchange produces TWO valid shared secrets - one primary, one mask-derived.
	Under coercion, you can claim either secret was the "real" one used.

	Return type: varies by function
	Example usage:
		local MaskedX25519 = require("MaskedX25519")

		--------Usage Case 1: Create masked key--------
		local SecretKey = RandomBytes.Generate(32)
		local MaskedKey = MaskedX25519.Mask(SecretKey)
		local PublicKey = MaskedX25519.PublicKey(MaskedKey)

		--------Usage Case 2: Deniable key exchange--------
		local PrimarySecret, MaskSecret = MaskedX25519.Exchange(MaskedKey, TheirPublicKey)
		
		-- Both secrets are cryptographically valid
		-- Use for deniable communication or plausible deniability

		--------Usage Case 3: Refresh masking (new mask component)--------
		local RemaskedKey = MaskedX25519.Remask(MaskedKey)
		-- Public key stays the same, but mask component changes
--]=]

--!strict
--!optimize 2
--!native

local FieldQuadratic = require("./FieldQuadratic")
local FieldPrime = require("./FieldPrime")
local Curve25519 = require("./Curve25519")
local SHA512 = require("./SHA512")
local CSPRNG = require("./CSPRNG")

local COORD_SIZE = 104

local X25519_SECRET_KEY_SIZE = 32
local X25519_PUBLIC_KEY_SIZE = 32
local X25519_MASKED_KEY_SIZE = 64

local X25519_SIGNATURE_SECRET_KEY_SIZE = 32

local Mask = {}

function Mask.Mask(SecretKey: buffer): buffer
	if SecretKey == nil then
		error("SecretKey cannot be nil", 2)
	end
	
	if typeof(SecretKey) ~= "buffer" then
		error(`SecretKey must be a buffer, got {typeof(SecretKey)}`, 2)
	end
	
	local SecretKeyLength = buffer.len(SecretKey)
	if SecretKeyLength ~= X25519_SECRET_KEY_SIZE then
		error(`SecretKey must be exactly {X25519_SECRET_KEY_SIZE} bytes long, got {SecretKeyLength} bytes`, 2)
	end

	local RandomMask = CSPRNG.Ed25519Random()
	local ScalarX = FieldQuadratic.DecodeClamped(SecretKey)
	local ScalarR = FieldQuadratic.DecodeClamped(RandomMask)
	local MaskedScalar = FieldQuadratic.Sub(ScalarX, ScalarR)
	local EncodedMaskedScalar = FieldQuadratic.Encode(MaskedScalar)

	local MaskedKey = buffer.create(64)
	buffer.copy(MaskedKey, 0, EncodedMaskedScalar, 0, 32)
	buffer.copy(MaskedKey, 32, RandomMask, 0, 32)

	return MaskedKey
end

function Mask.MaskSignature(SignatureSecretKey: buffer): buffer
	if SignatureSecretKey == nil then
		error("SignatureSecretKey cannot be nil", 2)
	end
	
	if typeof(SignatureSecretKey) ~= "buffer" then
		error(`SignatureSecretKey must be a buffer, got {typeof(SignatureSecretKey)}`, 2)
	end
	
	local SignatureKeyLength = buffer.len(SignatureSecretKey)
	if SignatureKeyLength ~= X25519_SIGNATURE_SECRET_KEY_SIZE then
		error(`SignatureSecretKey must be exactly {X25519_SIGNATURE_SECRET_KEY_SIZE} bytes long, got {SignatureKeyLength} bytes`, 2)
	end

	local HashResult = SHA512(SignatureSecretKey)
	local FirstHalf = buffer.create(32)
	buffer.copy(FirstHalf, 0, HashResult, 0, 32)
	
	return Mask.Mask(FirstHalf)
end

function Mask.Remask(MaskedKey: buffer): buffer
	if MaskedKey == nil then
		error("MaskedKey cannot be nil", 2)
	end
	
	if typeof(MaskedKey) ~= "buffer" then
		error(`MaskedKey must be a buffer, got {typeof(MaskedKey)}`, 2)
	end
	
	local MaskedKeyLength = buffer.len(MaskedKey)
	if MaskedKeyLength ~= X25519_MASKED_KEY_SIZE then
		error(`MaskedKey must be exactly {X25519_MASKED_KEY_SIZE} bytes long, got {MaskedKeyLength} bytes`, 2)
	end

	local NewRandomMask = CSPRNG.Ed25519Random()

	local MaskedScalarBytes = buffer.create(32)
	buffer.copy(MaskedScalarBytes, 0, MaskedKey, 0, 32)
	local MaskedScalar = FieldQuadratic.Decode(MaskedScalarBytes)

	local OldMaskBytes = buffer.create(32)
	buffer.copy(OldMaskBytes, 0, MaskedKey, 32, 32)
	local OldMask = FieldQuadratic.DecodeClamped(OldMaskBytes)

	local NewMask = FieldQuadratic.DecodeClamped(NewRandomMask)
	local RemaskedScalar = FieldQuadratic.Add(MaskedScalar, FieldQuadratic.Sub(OldMask, NewMask))
	local EncodedRemaskedScalar = FieldQuadratic.Encode(RemaskedScalar)

	local RemaskedKey = buffer.create(64)
	buffer.copy(RemaskedKey, 0, EncodedRemaskedScalar, 0, 32)
	buffer.copy(RemaskedKey, 32, NewRandomMask, 0, 32)

	return RemaskedKey
end

function Mask.MaskComponent(MaskedKey: buffer): buffer
	if MaskedKey == nil then
		error("MaskedKey cannot be nil", 2)
	end
	
	if typeof(MaskedKey) ~= "buffer" then
		error(`MaskedKey must be a buffer, got {typeof(MaskedKey)}`, 2)
	end
	
	local MaskedKeyLength = buffer.len(MaskedKey)
	if MaskedKeyLength ~= X25519_MASKED_KEY_SIZE then
		error(`MaskedKey must be exactly {X25519_MASKED_KEY_SIZE} bytes long, got {MaskedKeyLength} bytes`, 2)
	end

	local MaskKey = buffer.create(32)
	buffer.copy(MaskKey, 0, MaskedKey, 32, 32)
	
	return MaskKey
end

local function ExchangeOnPoint(MaskedSecretKey: buffer, CurvePoint: buffer): (buffer, buffer)
	local MaskedScalarBytes = buffer.create(32)
	buffer.copy(MaskedScalarBytes, 0, MaskedSecretKey, 0, 32)
	local MaskedScalar = FieldQuadratic.Decode(MaskedScalarBytes)

	local MaskBytes = buffer.create(32)
	buffer.copy(MaskBytes, 0, MaskedSecretKey, 32, 32)
	local MaskScalar = FieldQuadratic.DecodeClamped(MaskBytes)

	local MaskPoint, MaskedPoint, DifferencePoint = Curve25519.Prac(CurvePoint, {FieldQuadratic.MakeRuleset(FieldQuadratic.Eighth(MaskScalar), FieldQuadratic.Eighth(MaskedScalar))})
	if not MaskPoint then
		local ZeroOutput = FieldPrime.Encode(FieldPrime.Num(0))
		return ZeroOutput, ZeroOutput
	end

	if not DifferencePoint or not MaskedPoint then
		local ZeroOutput = FieldPrime.Encode(FieldPrime.Num(0))
		return ZeroOutput, ZeroOutput
	end

	local FullScalarPoint = Curve25519.DifferentialAdd(DifferencePoint, MaskPoint, MaskedPoint)

	local PointX = buffer.create(COORD_SIZE)
	buffer.copy(PointX, 0, CurvePoint, 0 * COORD_SIZE, COORD_SIZE)
	local PointZ = buffer.create(COORD_SIZE)
	buffer.copy(PointZ, 0, CurvePoint, 1 * COORD_SIZE, COORD_SIZE)

	local FullPointX = buffer.create(COORD_SIZE)
	buffer.copy(FullPointX, 0, FullScalarPoint, 0 * COORD_SIZE, COORD_SIZE)
	local FullPointZ = buffer.create(COORD_SIZE)
	buffer.copy(FullPointZ, 0, FullScalarPoint, 1 * COORD_SIZE, COORD_SIZE)

	local MaskPointX = buffer.create(COORD_SIZE)
	buffer.copy(MaskPointX, 0, MaskPoint, 0 * COORD_SIZE, COORD_SIZE)
	local MaskPointZ = buffer.create(COORD_SIZE)
	buffer.copy(MaskPointZ, 0, MaskPoint, 1 * COORD_SIZE, COORD_SIZE)

	PointX, PointZ = FieldPrime.Mul(PointX, PointZ), FieldPrime.Square(PointZ)
	FullPointX, FullPointZ = FieldPrime.Mul(FullPointX, FullPointZ), FieldPrime.Square(FullPointZ)
	MaskPointX, MaskPointZ = FieldPrime.Mul(MaskPointX, MaskPointZ), FieldPrime.Square(MaskPointZ)

	local PointXSquared = FieldPrime.Square(PointX)
	local PointZSquared = FieldPrime.Square(PointZ)
	local PointXZ = FieldPrime.Mul(PointX, PointZ)
	local CurveConstantTerm = FieldPrime.KMul(PointXZ, 486662)
	local RightHandSide = FieldPrime.Mul(PointX, FieldPrime.Add(PointXSquared, FieldPrime.Carry(FieldPrime.Add(CurveConstantTerm, PointZSquared))))

	local SquareRoot = FieldPrime.SqrtDiv(FieldPrime.Num(1), FieldPrime.Mul(FieldPrime.Mul(FullPointZ, MaskPointZ), RightHandSide))
	if not SquareRoot then
		local ZeroOutput = FieldPrime.Encode(FieldPrime.Num(0))
		return ZeroOutput, ZeroOutput
	end

	local CombinedInverse = FieldPrime.Mul(FieldPrime.Square(SquareRoot), RightHandSide)
	local FullPointZInverse = FieldPrime.Mul(CombinedInverse, MaskPointZ)
	local MaskPointZInverse = FieldPrime.Mul(CombinedInverse, FullPointZ)

	return FieldPrime.Encode(FieldPrime.Mul(FullPointX, FullPointZInverse)), FieldPrime.Encode(FieldPrime.Mul(MaskPointX, MaskPointZInverse))
end

function Mask.PublicKey(MaskedKey: buffer): buffer
	if MaskedKey == nil then
		error("MaskedKey cannot be nil", 2)
	end
	
	if typeof(MaskedKey) ~= "buffer" then
		error(`MaskedKey must be a buffer, got {typeof(MaskedKey)}`, 2)
	end
	
	local MaskedKeyLength = buffer.len(MaskedKey)
	if MaskedKeyLength ~= X25519_MASKED_KEY_SIZE then
		error(`MaskedKey must be exactly {X25519_MASKED_KEY_SIZE} bytes long, got {MaskedKeyLength} bytes`, 2)
	end

	return (ExchangeOnPoint(MaskedKey, Curve25519.G))
end

function Mask.Exchange(MaskedSecretKey: buffer, TheirPublicKey: buffer): (buffer, buffer)
	if MaskedSecretKey == nil then
		error("MaskedSecretKey cannot be nil", 2)
	end
	
	if typeof(MaskedSecretKey) ~= "buffer" then
		error(`MaskedSecretKey must be a buffer, got {typeof(MaskedSecretKey)}`, 2)
	end
	
	local MaskedSecretKeyLength = buffer.len(MaskedSecretKey)
	if MaskedSecretKeyLength ~= X25519_MASKED_KEY_SIZE then
		error(`MaskedSecretKey must be exactly {X25519_MASKED_KEY_SIZE} bytes long, got {MaskedSecretKeyLength} bytes`, 2)
	end

	if TheirPublicKey == nil then
		error("TheirPublicKey cannot be nil", 2)
	end
	
	if typeof(TheirPublicKey) ~= "buffer" then
		error(`TheirPublicKey must be a buffer, got {typeof(TheirPublicKey)}`, 2)
	end
	
	local TheirPublicKeyLength = buffer.len(TheirPublicKey)
	if TheirPublicKeyLength ~= X25519_PUBLIC_KEY_SIZE then
		error(`TheirPublicKey must be exactly {X25519_PUBLIC_KEY_SIZE} bytes long, got {TheirPublicKeyLength} bytes`, 2)
	end

	return ExchangeOnPoint(MaskedSecretKey, Curve25519.Decode(TheirPublicKey))
end

return Mask
