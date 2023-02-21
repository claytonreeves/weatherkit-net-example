using Skynet.CustomerPortal.Service.Helpers;
using Skynet.CustomerPortal.Service.Services.Interfaces;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text;
using System;

namespace Skynet.CustomerPortal.Service.Services;

public class WeatherKitJwtService : IWeatherKitJwtService
{
    private Helpers.WeatherKitConfig _weatherKitConfig;
    private DateTimeOffset _tokenExpiration;
    private readonly int _tokenExpirationMinutes = 28;
    private string _token;

    public WeatherKitJwtService(WeatherKitConfig weatherKitConfig)
    {
        _weatherKitConfig = weatherKitConfig;
        _tokenExpirationMinutes = (_weatherKitConfig.TokenExpirationMinutes ?? 30) - 2;
        if (_tokenExpirationMinutes < 0)
        {
            _tokenExpirationMinutes=0;
        }
    }

    public string GetToken(DateTimeOffset requestDateTime)
    {
        if (!string.IsNullOrWhiteSpace(_token) && requestDateTime >= _tokenExpiration) return _token;
        
        _token = GetNewToken(requestDateTime);
        _tokenExpiration = requestDateTime.AddMinutes(_tokenExpirationMinutes);

        return _token;
    }

    private string GetNewToken(DateTimeOffset requestDateTime)
    {
        //Reference -> https://developer.apple.com/documentation/weatherkitrestapi/request_authentication_for_weatherkit_rest_api
        var header = new
        {
            alg = "ES256",
            kid = _weatherKitConfig.KeyIdentifier,
            id = _weatherKitConfig.TeamID + "." + _weatherKitConfig.ServiceID
        };

        var payload = new
        {
            iss = _weatherKitConfig.TeamID,
            iat = requestDateTime.ToUnixTimeSeconds(),
            exp = requestDateTime.AddMinutes(_weatherKitConfig.TokenExpirationMinutes ?? 30).ToUnixTimeSeconds(),
            sub = _weatherKitConfig.ServiceID
        };

        var headerBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header));
        var payloadBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload));

        var jwt = EncodingHelper.JwtBase64Encode(headerBytes)
            + "." + EncodingHelper.JwtBase64Encode(payloadBytes);

        var messageBytes = Encoding.UTF8.GetBytes(jwt);

        var crypto = ECDsa.Create();
        crypto.ImportPkcs8PrivateKey(Convert.FromBase64String(_weatherKitConfig.PrivateKey ?? string.Empty), out _);

        var signature = crypto.SignData(messageBytes, HashAlgorithmName.SHA256);

        return jwt + "." + EncodingHelper.JwtBase64Encode(signature);
    }
}