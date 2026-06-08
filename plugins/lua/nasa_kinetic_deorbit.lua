local ffi = require("ffi")
local math = require("math")

-- TRITON INJECTOR ARGUMENTS
local vec_ptr, dims = ...
local vec = ffi.cast("const float*", vec_ptr)

-- NASA KINETIC DEORBIT CALCULATION
-- Calculates the necessary gyroscopic pitch/yaw/roll thruster burns to intentionally 
-- deorbit an asset into an intersecting trajectory with a hostile orbital asset.

-- Target Asset Orbital Mechanics
local target_altitude = vec[0]       -- Target altitude in km
local target_velocity_x = vec[1]     -- Target X-axis velocity
local target_velocity_y = vec[2]
local target_velocity_z = vec[3]

-- Our Asset Orbital Mechanics
local current_altitude = vec[4]      -- Current altitude in km
local current_mass = vec[5]          -- Mass of our asset (impact force scaling)

-- Gyro Thruster Capabilities
local max_pitch_burn = vec[6]        -- Max delta-V available for pitch axis
local max_yaw_burn = vec[7]          -- Max delta-V available for yaw axis
local max_roll_burn = vec[8]         -- Max delta-V available for roll axis

-- 1. Calculate required Delta-V to intersect target altitude
local altitude_delta = current_altitude - target_altitude
local required_retrograde_burn = altitude_delta * 0.05 -- Simplified orbital mechanics coefficient

-- 2. Distribute the required retrograde burn purely across gyroscopic thrusters
-- We assume the main engine is dead, requiring an aggressive tumbling maneuver to alter trajectory
local total_gyro_capability = max_pitch_burn + max_yaw_burn + max_roll_burn

if total_gyro_capability < required_retrograde_burn then
    return false -- Insufficient thruster fuel to alter orbital plane
end

-- 3. Calculate intercept vector magnitude (Hostile collision course)
-- If we successfully drop altitude, we must match the hostile X/Y/Z vector window
local intercept_window = math.sqrt(
    (target_velocity_x * target_velocity_x) + 
    (target_velocity_y * target_velocity_y) + 
    (target_velocity_z * target_velocity_z)
)

-- 4. Calculate kinetic yield on impact (Mass * Intercept Velocity)
local kinetic_yield_megajoules = 0.5 * current_mass * (intercept_window * intercept_window)

-- If the kinetic yield is sufficient to destroy the target asset (e.g. > 500 MJ),
-- and we have the thruster fuel to initiate the deorbit tumble, flag as a viable kinetic strike.
if kinetic_yield_megajoules > 500.0 then
    -- Log internal telemetry flag for auto-sequencer
    return true
end

return false
