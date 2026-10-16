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

        // Sign-in faults: the pushed request.
        ParWithoutClientAuthentication,
        ParRedirectUriExtraPath,
        ParRedirectUriExtraQuery,

        // Sign-in faults: forged DPoP proofs at the token endpoint.
        ProofAlgNone,
        ProofHmac,
        ProofSignatureOtherKey,
        ProofWithoutJti,

        // Sign-in faults: forged client assertions, at PAR and at the token endpoint.
        AssertionAlgNone,
        AssertionHmacWithClientSecret,
        AssertionSignedByOtherKey,
        AssertionExpired,
        AssertionWithoutExp,
        AssertionIssuerNotClient,

        // Sign-in faults: the token request of the code.
        RedeemAsOtherClient,
        MissingCodeVerifier,
        TokenRedirectUriMismatch,

        // UserInfo faults.
        BearerAtUserInfo,
        MissingAth,
        ReplayDPoPProof,
        UserInfoProofOtherKey,
        UserInfoProofWrongHtm,
        UserInfoProofWrongHtu,
        UserInfoProofWrongAth,

        // Refresh faults.
        NewDPoPKeyOnRefresh,
        ReplayDPoPProofOnRefresh,
        RefreshAsOtherClient,
        ReuseRotatedRefreshToken
    }

    public static class FaultInjection
    {
        public const string FieldName = "fault";
        private const string PropertiesKey = ".fault";

        public static readonly Fault[] SignInFaults =
        {
            Fault.SkipPar, Fault.ExtraBrowserParameter, Fault.AssertionAudienceArray, Fault.AssertionFutureIat, Fault.ParProofKeyMismatch,
            Fault.NoDPoPProof, Fault.WrongDPoPKey, Fault.WrongHtu, Fault.SmallDPoPKey, Fault.RedeemCodeTwice,
            Fault.ParWithoutClientAuthentication, Fault.ParRedirectUriExtraPath, Fault.ParRedirectUriExtraQuery,
            Fault.ProofAlgNone, Fault.ProofHmac, Fault.ProofSignatureOtherKey, Fault.ProofWithoutJti,
            Fault.AssertionAlgNone, Fault.AssertionHmacWithClientSecret, Fault.AssertionSignedByOtherKey,
            Fault.AssertionExpired, Fault.AssertionWithoutExp, Fault.AssertionIssuerNotClient,
            Fault.RedeemAsOtherClient, Fault.MissingCodeVerifier, Fault.TokenRedirectUriMismatch
        };

        public static readonly Fault[] UserInfoFaults =
        {
            Fault.BearerAtUserInfo, Fault.MissingAth, Fault.ReplayDPoPProof,
            Fault.UserInfoProofOtherKey, Fault.UserInfoProofWrongHtm, Fault.UserInfoProofWrongHtu, Fault.UserInfoProofWrongAth
        };

        public static readonly Fault[] RefreshFaults =
        {
            Fault.NewDPoPKeyOnRefresh, Fault.ReplayDPoPProofOnRefresh, Fault.RefreshAsOtherClient, Fault.ReuseRotatedRefreshToken
        };

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
            [Fault.NewDPoPKeyOnRefresh] = "A new DPoP key for the refresh request. Expected: success, and the new access token has a new cnf.jkt.",
            [Fault.ParWithoutClientAuthentication] = "A pushed request with client_id and no client authentication. Expected: invalid_client.",
            [Fault.ParRedirectUriExtraPath] = "The registered redirect URI with an extra path segment /x in the pushed request. Expected: invalid_request.",
            [Fault.ParRedirectUriExtraQuery] = "The registered redirect URI with an extra query ?x=1 in the pushed request. Expected: invalid_request.",
            [Fault.ProofAlgNone] = "A token proof with alg none and no signature. Expected: invalid_dpop_proof.",
            [Fault.ProofHmac] = "A token proof with alg HS256, signed with a random key. Expected: invalid_dpop_proof.",
            [Fault.ProofSignatureOtherKey] = "A token proof with the jwk of the DPoP key, signed with another key. Expected: invalid_dpop_proof.",
            [Fault.ProofWithoutJti] = "A token proof without jti. Expected: invalid_dpop_proof.",
            [Fault.AssertionAlgNone] = "Client assertions with alg none and no signature. Expected: invalid_client.",
            [Fault.AssertionHmacWithClientSecret] = "Client assertions with alg HS256, signed with the client secret (client_secret_jwt). Expected: invalid_client.",
            [Fault.AssertionSignedByOtherKey] = "Client assertions with the kid of the client key, signed with a key outside the JWKS. Expected: invalid_client.",
            [Fault.AssertionExpired] = "Client assertions with exp 60 seconds and iat 120 seconds in the past. Expected: invalid_client.",
            [Fault.AssertionWithoutExp] = "Client assertions without exp. Expected: invalid_client.",
            [Fault.AssertionIssuerNotClient] = "Client assertions with iss Testing:OtherClientId and the client ID as sub. Expected: invalid_client.",
            [Fault.RedeemAsOtherClient] = "The token request of the code as Testing:OtherClientId, with an assertion signed by the client key (private_key_jwt). Expected: invalid_grant.",
            [Fault.MissingCodeVerifier] = "A token request without code_verifier. Expected: invalid_grant (verify).",
            [Fault.TokenRedirectUriMismatch] = "A token request with redirect_uri /other-callback instead of the redirect URI of the authorization request. Expected: invalid_grant.",
            [Fault.UserInfoProofOtherKey] = "A valid UserInfo proof of a new key, not the key of the access token. Expected: invalid_token (verify).",
            [Fault.UserInfoProofWrongHtm] = "A UserInfo proof with htm POST for a GET request. Expected: invalid_token (verify).",
            [Fault.UserInfoProofWrongHtu] = "A UserInfo proof with the token endpoint as htu. Expected: invalid_token (verify).",
            [Fault.UserInfoProofWrongAth] = "A UserInfo proof with the ath of another access token value. Expected: invalid_token (verify).",
            [Fault.ReplayDPoPProofOnRefresh] = "Two refresh requests with the same proof; the result is the second. Expected: invalid_dpop_proof for the second (verify).",
            [Fault.RefreshAsOtherClient] = "The refresh request as Testing:OtherClientId, with an assertion signed by the client key (private_key_jwt). Expected: invalid_grant.",
            [Fault.ReuseRotatedRefreshToken] = "A refresh that rotates the refresh token, then a refresh with the old one. Needs a connection that rotates. Expected: invalid_grant for the old one."
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
