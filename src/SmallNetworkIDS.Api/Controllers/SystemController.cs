using Microsoft.AspNetCore.Mvc;
using SmallNetworkIDS.Api.Services;

namespace SmallNetworkIDS.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class SystemController : ControllerBase
{
    private readonly IDSService _idsService;

    public SystemController(IDSService idsService)
    {
        _idsService = idsService;
    }

    /// <summary>
    /// Get system health and uptime
    /// </summary>
    [HttpGet("health")]
    public ActionResult<object> GetHealth()
    {
        return Ok(new
        {
            status = "healthy",
            uptime = _idsService.GetUptime().ToString(),
            timestamp = DateTime.UtcNow
        });
    }
}
