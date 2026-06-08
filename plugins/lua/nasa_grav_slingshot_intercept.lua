local ffi = require("ffi")
local math = require("math")

-- TRITON INJECTOR ARGUMENTS
local vec_ptr, dims = ...
local vec = ffi.cast("const float*", vec_ptr)

-- NASA CISLUNAR GRAVITATIONAL SLINGSHOT (PATROL INTERCEPT)
-- Calculates an instantaneous high-Delta-V intercept trajectory using a gravitational 
-- assist (slingshot) around a celestial body (e.g., the Moon) rather than relying on multi-day phasing.

-- Dimensions 0-3: Planetary/Celestial Gravity Field DB (Passed directly from QIHSE)
local BODY_MU = vec[0]                 -- Gravitational parameter of assist body (e.g., Moon: 4904.8695 km^3/s^2)
local BODY_RADIUS = vec[1]             -- Radius of assist body (km)
local BODY_VELOCITY_X = vec[2]         -- Assist body orbital velocity X
local BODY_VELOCITY_Y = vec[3]         -- Assist body orbital velocity Y

-- Dimensions 4-7: Our Asset State
local asset_v_inf_in_x = vec[4]        -- Hyperbolic arrival velocity vector (V-infinity in) X
local asset_v_inf_in_y = vec[5]        -- Hyperbolic arrival velocity vector (V-infinity in) Y
local asset_periapsis = vec[6]         -- Planned flyby periapsis radius (km from body center)
local asset_max_thrust = vec[7]        -- Available Delta-V for trajectory correction maneuvers (TCM)

-- Dimensions 8-9: Hostile Target Projected Intercept Window
local target_v_out_req_x = vec[8]      -- Required exit velocity vector X to intercept hostile
local target_v_out_req_y = vec[9]      -- Required exit velocity vector Y to intercept hostile

-- 1. Calculate Hyperbolic Arrival Magnitude (V-infinity)
local v_inf_in_mag = math.sqrt(asset_v_inf_in_x^2 + asset_v_inf_in_y^2)

-- 2. Calculate the Turning Angle (Delta) of the Gravitational Slingshot
-- Equation: sin(delta / 2) = 1 / (1 + (r_p * v_inf^2 / MU))
local e = 1.0 + (asset_periapsis * v_inf_in_mag^2 / BODY_MU) -- Eccentricity of the flyby hyperbola
local turn_angle = 2.0 * math.asin(1.0 / e)

-- 3. Calculate the Post-Slingshot Exit Velocity Vector (V-infinity out)
-- Rotating the incoming V-infinity vector by the turn angle
local cos_delta = math.cos(turn_angle)
local sin_delta = math.sin(turn_angle)

local v_inf_out_x = asset_v_inf_in_x * cos_delta - asset_v_inf_in_y * sin_delta
local v_inf_out_y = asset_v_inf_in_x * sin_delta + asset_v_inf_in_y * cos_delta

-- Absolute heliocentric/geocentric exit velocity = Body Velocity + V-infinity out
local absolute_exit_v_x = BODY_VELOCITY_X + v_inf_out_x
local absolute_exit_v_y = BODY_VELOCITY_Y + v_inf_out_y

-- 4. Calculate required Trajectory Correction Maneuver (TCM)
local tcm_x = target_v_out_req_x - absolute_exit_v_x
local tcm_y = target_v_out_req_y - absolute_exit_v_y
local required_tcm_delta_v = math.sqrt(tcm_x^2 + tcm_y^2)

-- 5. Intercept Viability Check
-- If our available thruster fuel can bridge the gap between the slingshot exit trajectory 
-- and the required intercept trajectory, we execute the gravity assist.
if required_tcm_delta_v < asset_max_thrust then
    -- The gravitational assist provides the necessary kinetic energy. 
    -- The onboard fuel is sufficient for the final course correction.
    -- Proceed with the mission kill intercept.
    return true
end

return false
