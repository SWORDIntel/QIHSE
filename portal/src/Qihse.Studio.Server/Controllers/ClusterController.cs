using Microsoft.AspNetCore.Mvc;
using Qihse.Studio.Server.Models;
using Qihse.Studio.Server.Services;

namespace Qihse.Studio.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ClusterController : ControllerBase
{
    private readonly ClusterMeshService _meshService;

    public ClusterController(ClusterMeshService meshService)
    {
        _meshService = meshService;
    }

    [HttpGet("slots")]
    public ActionResult<List<SlotRange>> GetSlots()
    {
        var slots = new List<SlotRange>
        {
            new(0, 4549, "node-0"),
            new(4550, 10922, "node-5"),
            new(10923, 16383, "node-1")
        };
        return Ok(slots);
    }

    [HttpPost("moveslots")]
    public IActionResult MoveSlots([FromBody] SlotRange request)
    {
        // Rebalance action triggered
        return Ok(new { success = true, message = $"Slots {request.Start}-{request.End} migration scheduled to {request.MasterNodeId}" });
    }
}
