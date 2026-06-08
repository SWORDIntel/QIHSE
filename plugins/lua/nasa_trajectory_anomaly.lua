local ffi = require("ffi")
local math = require("math")

-- TRITON INJECTOR ARGUMENTS
local vec_ptr, dims = ...
local vec = ffi.cast("const float*", vec_ptr)

-- NASA ORBITAL TRAJECTORY ANOMALY DETECTION
-- Analyzes telemetry vectors from Low Earth Orbit (LEO) assets to detect micro-meteoroid impacts or orbital decay

-- Dims 0-2: Expected X, Y, Z velocity vectors
-- Dims 3-5: Actual X, Y, Z velocity vectors
-- Dims 6-8: Gyroscopic pitch, yaw, roll deviation
-- Dim 9: Thermal shielding variance

local delta_vx = vec[3] - vec[0]
local delta_vy = vec[4] - vec[1]
local delta_vz = vec[5] - vec[2]

-- Calculate total velocity deviation vector magnitude
local velocity_deviation = math.sqrt((delta_vx * delta_vx) + (delta_vy * delta_vy) + (delta_vz * delta_vz))

local pitch_dev = math.abs(vec[6])
local yaw_dev = math.abs(vec[7])
local roll_dev = math.abs(vec[8])

local thermal_variance = vec[9]

-- Detection Condition A: Sudden Micro-Meteoroid Impact
-- Causes an instantaneous velocity deviation paired with immediate gyroscopic tumble
if velocity_deviation > 5.0 and (pitch_dev > 2.5 or yaw_dev > 2.5 or roll_dev > 2.5) then
    return true -- Flag for emergency collision avoidance / damage control
end

-- Detection Condition B: Atmospheric Drag / Orbital Decay
-- Gradual but consistent velocity loss paired with a rising thermal variance due to atmospheric friction
if delta_vx < -1.0 and delta_vy < -1.0 and thermal_variance > 1.5 then
    return true -- Flag for immediate thruster re-boost
end

return false -- Nominal trajectory
