local ffi = require("ffi")
local math = require("math")

-- TRITON INJECTOR ARGUMENTS
local vec_ptr, dims = ...
local vec = ffi.cast("const float*", vec_ptr)

-- NASA KINETIC INTERCEPT: TEMPORAL PHASING MANEUVER
-- Calculates a multi-day orbital phasing intercept using non-impulsive gyroscopic thrust.
-- Accounts for J2 gravitational perturbations (Earth's oblateness) and temporal time-of-flight.

-- Constants
local MU = 398600.4418            -- Earth's standard gravitational parameter (km^3/s^2)
local RE = 6371.0                 -- Earth's equatorial radius (km)
local J2 = 0.00108263             -- Earth's J2 perturbation constant

-- Intercept Temporal Target
local target_time_of_flight = vec[0]   -- Days until desired impact window
local target_time_seconds = target_time_of_flight * 86400.0

-- Target Asset Orbital Elements
local target_a = vec[1] + RE           -- Target semi-major axis (km)
local target_e = vec[2]                -- Target eccentricity
local target_i = math.rad(vec[3])      -- Target inclination (radians)
local target_raan = math.rad(vec[4])   -- Target Right Ascension of Ascending Node

-- Our Asset Orbital Elements
local current_a = vec[5] + RE
local current_e = vec[6]
local current_i = math.rad(vec[7])
local current_raan = math.rad(vec[8])

local current_mass = vec[9]            -- Mass in kg

-- Gyro Thruster Capabilities (Continuous non-impulsive thrust in N)
local available_thrust = vec[10]

-- 1. Calculate Nodal Precession (J2 Perturbation) for both orbits over the Time of Flight
-- Real satellites drift over days; we must calculate exactly where their orbital planes will be.
local function calc_nodal_precession_rate(a, e, i)
    local n = math.sqrt(MU / math.pow(a, 3)) -- Mean motion
    local p = a * (1 - e*e)                  -- Semi-latus rectum
    -- d(Omega)/dt
    return -1.5 * n * J2 * math.pow(RE / p, 2) * math.cos(i)
end

local target_precession_rate = calc_nodal_precession_rate(target_a, target_e, target_i)
local current_precession_rate = calc_nodal_precession_rate(current_a, current_e, current_i)

local target_future_raan = target_raan + (target_precession_rate * target_time_seconds)
local current_future_raan = current_raan + (current_precession_rate * target_time_seconds)

-- 2. Plane Change Calculation (To align the RAAN and Inclination at time of impact)
-- If the future planes don't intersect, we need a plane change maneuver.
local delta_i = target_i - current_i
local delta_raan = target_future_raan - current_future_raan
local plane_change_angle = math.acos(math.cos(current_i)*math.cos(target_i) + math.sin(current_i)*math.sin(target_i)*math.cos(delta_raan))

-- 3. Required Delta-V for combined Hohmann Transfer + Plane Change
local current_v = math.sqrt(MU / current_a)
local transfer_a = (current_a + target_a) / 2.0
local v_transfer_periapsis = math.sqrt(MU * ((2.0 / current_a) - (1.0 / transfer_a)))

-- Approximate Delta-V required to enter transfer orbit and change plane simultaneously
local required_delta_v = math.sqrt(current_v^2 + v_transfer_periapsis^2 - 2 * current_v * v_transfer_periapsis * math.cos(plane_change_angle))

-- 4. Thruster Capability Check
-- Can our continuous gyro thrusters generate this Delta-V over the timeframe?
-- F = ma -> a = F/m -> Delta-V = a * t
local acceleration = available_thrust / current_mass
local max_delta_v_possible = acceleration * (target_time_seconds * 0.5) -- Assuming we can only thrust half the time due to solar power limits

if max_delta_v_possible < required_delta_v then
    return false -- Insufficient thrust to match the target's temporal phase window
end

-- 5. Impact Yield Calculation
-- Assuming a head-on or high-angle intercept, kinetic velocity is roughly the sum of their orbital velocities
local target_v = math.sqrt(MU / target_a)
local intercept_velocity = current_v + target_v -- Max theoretical closing speed in km/s
local intercept_velocity_ms = intercept_velocity * 1000.0

local kinetic_yield_megajoules = 0.5 * current_mass * (intercept_velocity_ms * intercept_velocity_ms) / 1000000.0

if kinetic_yield_megajoules > 500.0 then
    -- Telemetry indicates we can successfully drift into the target's exact spatial coordinates
    -- after J2 orbital decay, with sufficient yield to destroy it.
    return true
end

return false
