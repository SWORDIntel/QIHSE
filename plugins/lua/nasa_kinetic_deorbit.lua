local ffi = require("ffi")
local math = require("math")

-- TRITON INJECTOR ARGUMENTS
local vec_ptr, dims = ...
local vec = ffi.cast("const float*", vec_ptr)

-- NASA KINETIC INTERCEPT: NON-DESTRUCTIVE MISSION KILL (SPIN-OUT)
-- Calculates a multi-day orbital phasing intercept designed NOT to vaporize the target,
-- but to impart an unrecoverable angular momentum transfer (tumble), permanently exceeding 
-- the target's Control Moment Gyroscope (CMG) saturation limits without creating a massive debris field.

-- Constants
local MU = 398600.4418            -- Earth's standard gravitational parameter (km^3/s^2)
local RE = 6371.0                 -- Earth's equatorial radius (km)
local J2 = 0.00108263             -- Earth's J2 perturbation constant

-- Intercept Temporal Target
local target_time_of_flight = vec[0]   -- Days until desired impact window
local target_time_seconds = target_time_of_flight * 86400.0

-- Target Asset Orbital Elements & Hardware Limits
local target_a = vec[1] + RE           
local target_e = vec[2]                
local target_i = math.rad(vec[3])      
local target_raan = math.rad(vec[4])   
local target_cmg_saturation_limit = vec[5] -- Max N·m·s the target's reaction wheels can absorb

-- Our Asset Orbital Elements & Thruster Limits
local current_a = vec[6] + RE
local current_e = vec[7]
local current_i = math.rad(vec[8])
local current_raan = math.rad(vec[9])
local current_mass = vec[10]            -- Mass in kg
local available_thrust = vec[11]

-- 1. Calculate Nodal Precession (J2 Perturbation)
local function calc_nodal_precession_rate(a, e, i)
    local n = math.sqrt(MU / math.pow(a, 3))
    local p = a * (1 - e*e)
    return -1.5 * n * J2 * math.pow(RE / p, 2) * math.cos(i)
end

local target_future_raan = target_raan + (calc_nodal_precession_rate(target_a, target_e, target_i) * target_time_seconds)
local current_future_raan = current_raan + (calc_nodal_precession_rate(current_a, current_e, current_i) * target_time_seconds)

-- 2. Plane Change & Transfer Orbit Calculation
local delta_i = target_i - current_i
local delta_raan = target_future_raan - current_future_raan
local plane_change_angle = math.acos(math.cos(current_i)*math.cos(target_i) + math.sin(current_i)*math.sin(target_i)*math.cos(delta_raan))

local current_v = math.sqrt(MU / current_a)
local transfer_a = (current_a + target_a) / 2.0
local v_transfer_periapsis = math.sqrt(MU * ((2.0 / current_a) - (1.0 / transfer_a)))

local required_delta_v = math.sqrt(current_v^2 + v_transfer_periapsis^2 - 2 * current_v * v_transfer_periapsis * math.cos(plane_change_angle))

-- 3. Thruster Capability Check
local acceleration = available_thrust / current_mass
local max_delta_v_possible = acceleration * (target_time_seconds * 0.5)

if max_delta_v_possible < required_delta_v then
    return false -- Insufficient thrust to match the temporal phase window
end

-- 4. Grazing Impact / Angular Momentum Transfer Calculation
-- We do not want a head-on megajoule impact. We want a grazing vector (e.g. 5-10 m/s relative velocity).
local grazing_velocity_ms = 8.5 

-- Angular momentum L = r x (m * v)
-- Assuming impact at the extreme edge of the target's solar array (approx 5 meters from center of mass)
local impact_radius_meters = 5.0
local angular_momentum_imparted = impact_radius_meters * current_mass * grazing_velocity_ms

if angular_momentum_imparted > target_cmg_saturation_limit then
    -- The kinetic tap will instantly saturate the target's reaction wheels.
    -- The target will enter an unrecoverable tumble, lose solar pointing, and experience a permanent mission kill 
    -- without generating a hazardous high-velocity debris cloud.
    return true
end

return false
