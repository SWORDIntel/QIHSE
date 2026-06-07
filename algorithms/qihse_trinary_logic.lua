-- QIHSE - Balanced Ternary Logic (K3) and Buffer Implementation
-- Extracted from legacy framework (TRITON VCPU)

local M = {}

-- ═══════════════════════════════════════════════════════════════
-- TRITON CONSTANTS
-- ═══════════════════════════════════════════════════════════════

local TRIT_NEG = -1
local TRIT_ZERO = 0
local TRIT_POS = 1

-- Constant-Time K3 Logic LUTs
-- Indexed by (trit + 2) to get 1, 2, 3
local LUT_KAND = {
    {-1, -1, -1}, -- -1 AND {-1, 0, 1}
    {-1,  0,  0}, --  0 AND {-1, 0, 1}
    {-1,  0,  1}, --  1 AND {-1, 0, 1}
}
local LUT_KOR = {
    {-1,  0,  1}, -- -1 OR {-1, 0, 1}
    { 0,  0,  1}, --  0 OR {-1, 0, 1}
    { 1,  1,  1}, --  1 OR {-1, 0, 1}
}
local LUT_KNOT = {1, 0, -1} -- NOT {-1, 0, 1}
local LUT_SBOX_27 = {13, 24, 7, 2, 19, 11, 20, 5, 15, 22, 1, 9, 17, 0, 26, 4, 14, 21, 6, 10, 3, 25, 8, 12, 16, 18, 23}
M.active_sbox = LUT_SBOX_27

-- ═══════════════════════════════════════════════════════════════
-- KLEENE K3 LOGIC GATES (Constant-Time)
-- ═══════════════════════════════════════════════════════════════

local function clamp_trit(t)
    if type(t) ~= "number" then return 0 end
    if t >= 1 then return 1 end
    if t <= -1 then return -1 end
    return 0
end
M.clamp_trit = clamp_trit

function M.knot(a) return LUT_KNOT[clamp_trit(a) + 2] end
function M.kand(a, b) return LUT_KAND[clamp_trit(a) + 2][clamp_trit(b) + 2] end
function M.kor(a, b) return LUT_KOR[clamp_trit(a) + 2][clamp_trit(b) + 2] end

function M.bnt(a)
    if a == 0 then return 0 end
    return -a
end

local function trit_add(a, b, cin)
    local sum = a + b + (cin or 0)
    local carry = 0
    if sum > 1 then carry = 1; sum = sum - 3 end
    if sum < -1 then carry = -1; sum = sum + 3 end
    return sum, carry
end
M.trit_add = trit_add

local function trit_mul(a, b) return a * b end
M.trit_mul = trit_mul

local function trit_cmp(a, b)
    if a < b then return TRIT_NEG end
    if a > b then return TRIT_POS end
    return TRIT_ZERO
end
M.trit_cmp = trit_cmp

-- ═══════════════════════════════════════════════════════════════
-- TRIT BUFFER: Multi-trit integer representation
-- ═══════════════════════════════════════════════════════════════

local TritBuf = {}
TritBuf.__index = TritBuf

function M.tritbuf(n_trits)
    local buf = { trits = {}, n = n_trits or 8 }
    for i = 1, buf.n do buf.trits[i] = TRIT_ZERO end
    return setmetatable(buf, TritBuf)
end

function TritBuf:set(idx, val)
    if type(idx) ~= "number" then return end
    idx = math.floor(idx)
    if idx < 1 or idx > self.n then return end
    if val ~= -1 and val ~= 0 and val ~= 1 then return end
    self.trits[idx] = val
end

function TritBuf:get(idx)
    return self.trits[idx] or TRIT_ZERO
end

function TritBuf:to_decimal()
    local val, pow = 0, 1
    for i = 1, self.n do
        val = val + (self.trits[i] * pow)
        pow = pow * 3
    end
    return val
end

function TritBuf:from_decimal(dec)
    if type(dec) ~= "number" then return self end
    local n = math.floor(math.abs(dec))
    local sign = (dec < 0) and -1 or 1
    for i = 1, self.n do
        local rem = n % 3
        n = math.floor(n / 3)
        if rem == 2 then
            self.trits[i] = -1
            n = n + 1
        elseif rem == 1 then
            self.trits[i] = 1
        else
            self.trits[i] = 0
        end
        if sign == -1 then self.trits[i] = -self.trits[i] end
    end
    return self
end

function TritBuf:copy()
    local c = M.tritbuf(self.n)
    self:copy_into(c)
    return c
end

function TritBuf:copy_into(dest)
    local n = self.n
    local s_trits = self.trits
    local d_trits = dest.trits
    for i = 1, n do d_trits[i] = s_trits[i] end
end

function TritBuf:add(other)
    local res = M.tritbuf(self.n)
    self:add_into(res, other)
    return res
end

function TritBuf:add_into(dest, other)
    local n = self.n
    local s_trits = self.trits
    local o_trits = other.trits
    local d_trits = dest.trits
    local carry = 0
    for i = 1, n do
        local sum = s_trits[i] + o_trits[i] + carry
        if sum > 1 then carry = 1; sum = sum - 3
        elseif sum < -1 then carry = -1; sum = sum + 3
        else carry = 0 end
        d_trits[i] = sum
    end
end

function TritBuf:mul(other)
    local res = M.tritbuf(self.n)
    self:mul_into(res, other)
    return res
end

function TritBuf:mul_into(dest, other, workspace)
    local n = self.n
    local s_trits = self.trits
    local o_trits = other.trits
    local d_trits = dest.trits

    -- Clear destination
    for i = 1, n do d_trits[i] = 0 end

    for i = 1, n do
        local s_i = s_trits[i]
        if s_i ~= 0 then
            for j = 1, n - i + 1 do
                local prod = s_i * o_trits[j]
                if prod ~= 0 then
                    local idx, carry = i + j - 1, prod
                    while carry ~= 0 and idx <= n do
                        local s = d_trits[idx] + carry
                        if s > 1 then carry = 1; s = s - 3
                        elseif s < -1 then carry = -1; s = s + 3
                        else carry = 0 end
                        d_trits[idx] = s
                        idx = idx + 1
                    end
                end
            end
        end
    end
end

M.TritBuf = TritBuf

return M
