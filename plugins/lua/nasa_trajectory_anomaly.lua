local ffi = require("ffi")
local math = require("math")

-- TRITON INJECTOR ARGUMENTS
local vec_ptr, dims = ...
local vec = ffi.cast("const float*", vec_ptr)

-- NASA ORBITAL TRAJECTORY ANOMALY DETECTION: ADVERSARIAL MANEUVERS
-- Analyzes highly precise orbital telemetry to detect if a satellite has been covertly hijacked 
-- (e.g. an adversary burning Station Keeping fuel to reposition the asset for intelligence gathering).

-- Vector Dimensions 0-23 represent hourly Semi-Major Axis (SMA) telemetry readings over the last 24 hours (in km)
-- Vector Dimension 24 is the expected atmospheric drag coefficient (Ballistic Coefficient)
-- Vector Dimension 25 is the Solar Flux Index (F10.7) proxy for atmospheric density expansion

local expected_drag_coeff = vec[24]
local solar_flux_index = vec[25]

-- 1. Calculate Expected Keplerian Orbital Decay (SMA loss per hour due to drag)
-- High solar flux expands the atmosphere, increasing drag on LEO satellites
local atmospheric_density_factor = 1.0 + (solar_flux_index * 0.005)
local expected_hourly_sma_decay = expected_drag_coeff * atmospheric_density_factor

-- 2. Analyze the 24-hour telemetry window
local abnormal_burn_detected = false
local total_unaccounted_delta_v = 0.0

for i = 1, 23 do
    local previous_sma = vec[i-1]
    local current_sma = vec[i]
    
    -- The actual change in altitude
    local actual_sma_change = current_sma - previous_sma
    
    -- Subtract the expected decay. If the result is highly positive, the satellite increased altitude.
    -- If it's highly negative, it dropped faster than orbital mechanics dictate.
    local unaccounted_variance = actual_sma_change - (-expected_hourly_sma_decay)
    
    -- A threshold of 5 meters/hour variance is noise. 
    -- Anything beyond that requires physical thruster activation.
    if math.abs(unaccounted_variance) > 0.005 then 
        total_unaccounted_delta_v = total_unaccounted_delta_v + math.abs(unaccounted_variance)
        abnormal_burn_detected = true
    end
end

-- 3. Flag Covert Hijack or Spoofing
-- If the satellite is executing micro-burns not scheduled in the Station Keeping manifest,
-- it is likely being repositioned by an adversary for a new surveillance tasking, or intentionally dumped.
if abnormal_burn_detected and total_unaccounted_delta_v > 0.05 then
    -- Analyst logic: Unaccounted orbital energy exceeds 50 meters of uncommanded altitude shift.
    return true -- Flag for immediate Command & Control (C2) cryptographic lockdown
end

return false
