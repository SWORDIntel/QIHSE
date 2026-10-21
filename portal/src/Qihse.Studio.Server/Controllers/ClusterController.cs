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
    public IActionResult GetSlots()
    {
        var frame = _meshService.LatestFrame;
        if (frame == null || frame.Nodes.Count == 0)
            return Ok(Array.Empty<SlotRange>());

        var slotList = new List<SlotRange>();
        foreach (var node in frame.Nodes.Where(n => n.ClusterType == "lan"))
        {
            if (string.IsNullOrEmpty(node.ShardSlots) || node.ShardSlots.Contains("unassigned") || node.ShardSlots.Contains("Offline")) continue;
            var ranges = node.ShardSlots.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            foreach (var r in ranges)
            {
                var parts = r.Split('-');
                if (parts.Length == 2 && int.TryParse(parts[0], out int start) && int.TryParse(parts[1], out int end))
                {
                    slotList.Add(new SlotRange(start, end, $"{node.Name} ({node.Id})"));
                }
            }
        }
        return Ok(slotList.OrderBy(s => s.Start));
    }

    [HttpPost("moveslots")]
    public IActionResult MoveSlots([FromBody] SlotRange request) =>
        StatusCode(StatusCodes.Status501NotImplemented,
            new { error = "Authenticated cluster slot migration has not been implemented." });
}
