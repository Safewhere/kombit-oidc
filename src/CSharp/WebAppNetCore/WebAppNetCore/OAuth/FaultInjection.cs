using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;

namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// A deliberate protocol violation, for negative tests of the Identify building blocks. A fault works only when the setting
    /// Testing:EnableFaultInjection is true. The expected results come from section 5 of the Identify design; "verify" marks a
    /// result that the design does not state.
    /// </summary>
    public enum Fault
    {
        None,

        // Sign-in faults.
        SkipPar,
        ExtraBrowserParameter,
        AssertionAudienceArray,
        AssertionFutureIat,
        ParProofKeyMismatch,
        NoDPoPProof,
        WrongDPoPKey,
        WrongHtu,
        SmallDPoPKey,
        RedeemCodeTwice,

        // UserInfo faults.
        BearerAtUserInfo,
        MissingAth,
        ReplayDPoPProof,

        // Refresh faults.
        NewDPoPKeyOnRefresh
    }

    public static class FaultInjection
    {
        public const string FieldName = "fault";
        private const string PropertiesKey = ".fault";

        public static readonly Fault[] SignInFaults =
        {
            Fault.SkipPar, Fault.ExtraBrowserParameter, Fault.AssertionAudienceArray, Fault.AssertionFutureIat, Fault.ParProofKeyMismatch,
            Fault.NoDPoPProof, Fault.WrongDPoPKey, Fault.WrongHtu, Fault.SmallDPoPKey, Fault.RedeemCodeTwice
        };

        public static readonly Fault[] UserInfoFaults = { Fault.BearerAtUserInfo, Fault.MissingAth, Fault.ReplayDPoPProof };

        public static readonly Fault[] RefreshFaults = { Fault.NewDPoPKeyOnRefresh };

        private static readonly Dictionary<Fault, string> ExpectedResults = new Dictionary<Fault, string>
        {
            [Fault.SkipPar] = "A direct authorization request. Expected: invalid_request when the connection requires PAR.",
            [Fault.ExtraBrowserParameter] = "scope next to request_uri in the browser request (GET only). Expected: an error response (verify).",
            [Fault.AssertionAudienceArray] = "Client assertion aud as a JSON array. Expected: invalid_client with clientAssertion.audience=issuer.",
            [Fault.AssertionFutureIat] = "Client assertion iat 120 seconds in the future. Expected: invalid_client when clientJwt.clockSkewInSeconds is below 120.",
            [Fault.ParProofKeyMismatch] = "A PAR proof of another key than dpop_jkt. Expected: invalid_request.",
            [Fault.NoDPoPProof] = "No proof at the token endpoint. Expected: invalid_dpop_proof when DPoP is required; an error for a bound code (verify).",
            [Fault.WrongDPoPKey] = "A token proof of a new key. Expected: invalid_grant for a bound code.",
            [Fault.WrongHtu] = "A token proof with the authorization endpoint as htu. Expected: invalid_dpop_proof.",
            [Fault.SmallDPoPKey] = "A token proof of an RSA 1024 key. Expected: invalid_dpop_proof.",
            [Fault.RedeemCodeTwice] = "A second redemption of the code after a successful one. Expected: invalid_grant for the second; Identify then revokes the tokens of the code, so the sign-in fails at UserInfo with invalid_token.",
            [Fault.BearerAtUserInfo] = "The Bearer scheme with a DPoP-bound token. Expected: invalid_token.",
            [Fault.MissingAth] = "A UserInfo proof without ath. Expected: invalid_token.",
            [Fault.ReplayDPoPProof] = "The same UserInfo proof in two calls. Expected: invalid_token for the second call.",
            [Fault.NewDPoPKeyOnRefresh] = "A new DPoP key for the refresh request. Expected: success, and the new access token has a new cnf.jkt."
        };

        public static string Describe(Fault fault) => ExpectedResults.TryGetValue(fault, out var description) ? description : string.Empty;

        /// <summary>
        /// Reads a fault from a form field. Returns None when fault injection is off, the field is empty, or the fault does not
        /// belong to the action.
        /// </summary>
        public static Fault Parse(string value, IConfiguration configuration, IEnumerable<Fault> allowedFaults)
        {
            if (!configuration.EnableFaultInjection() || string.IsNullOrEmpty(value))
            {
                return Fault.None;
            }

            return Enum.TryParse<Fault>(value, ignoreCase: false, out var fault) && allowedFaults.Contains(fault) ? fault : Fault.None;
        }

        /// <summary>
        /// Puts a sign-in fault into the properties, so that OnRedirectToIdentityProvider can give it to the state of the sign-in.
        /// </summary>
        public static void Write(AuthenticationProperties properties, Fault fault)
        {
            if (fault != Fault.None)
            {
                properties.Items[PropertiesKey] = fault.ToString();
            }
        }

        public static Fault Read(AuthenticationProperties properties)
        {
            return properties.Items.TryGetValue(PropertiesKey, out var value) && Enum.TryParse<Fault>(value, out var fault) ? fault : Fault.None;
        }
    }
}
