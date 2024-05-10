using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace UserRegistration.Controllers
{
    public abstract class BaseController : Controller
    {
        public string UserId
        {
            get
            {
                if (User != null && User.Identity.IsAuthenticated)
                {
                    return User.FindFirst(ClaimTypes.Email).Value;
                }
                else
                {
                    return string.Empty;
                }
            }
        }
    }
}
