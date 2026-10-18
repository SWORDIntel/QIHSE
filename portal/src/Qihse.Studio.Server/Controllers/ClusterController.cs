using Microsoft.AspNetCore.Mvc;
using Qihse.Studio.Server.Models;

namespace Qihse.Studio.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ClusterController : ControllerBase
{
    [HttpGet("slots")]
    public IActionResult GetSlots() =>
        StatusCode(StatusCodes.Status501NotImplemented,
            new { error = "Live cluster slot discovery has not been implemented." });

    [HttpPost("moveslots")]
    public IActionResult MoveSlots([FromBody] SlotRange request) =>
        StatusCode(StatusCodes.Status501NotImplemented,
            new { error = "Authenticated cluster slot migration has not been implemented." });
}
