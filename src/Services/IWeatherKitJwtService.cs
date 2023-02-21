using System.Security.Cryptography;
using System.Text;
using System;
using Skynet.CustomerPortal.Service.Helpers;

namespace Skynet.CustomerPortal.Service.Services.Interfaces;

public interface IWeatherKitJwtService
{
    public string GetToken(DateTimeOffset requestDateTime);
}