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

        // Sign-in faults: more of the pushed request.
        ParMissingCodeChallenge,
        ParMissingCodeChallengeMethod,
        ParPlainPkce,
        ParMissingRedirectUri,
        ParRepeatedParameter,
        ParRequestParameter,
        ParNestedRequestUri,
        UnknownResponseTypeComponent,
        ResponseTypeWithToken,
        ParProofTokenEndpointHtu,

        // Sign-in faults: more DPoP proofs at the token endpoint.
        ProofWrongHtm,
        ProofHtuPathCase,
        ProofIatFuture,
        ProofIatOld,
        ProofTypJwt,
        ProofPrivateJwkMembers,
        TwoProofs,
        ProofHtuWithQuery,
        ProofHtuHostUpperCase,
        ProofIatRecent,
        ProofNbfFuture,
        WrongDPoPKeyThenRetry,

        // Sign-in faults: more client assertions and the token request of the code.
        AssertionWithoutJti,
        AssertionAndClientSecret,
        ClientIdNotSubject,
        WrongCodeVerifier,
        RedeemCodeAfter10Seconds,
        RedeemCodeAfter5Seconds,

        // Introspection faults.
        IntrospectWithClientSecret,

        // Refresh faults that also exist as sign-in faults: NoDPoPProof.
        ReplayClientAssertion,

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
        ReuseRotatedRefreshToken,

        // UserInfo faults: the scheme and the place of the access token.
        DPoPSchemeForBearerToken,
        AccessTokenInForm,
        DPoPSchemeWithoutProof,

        // Revocation faults.
        RevokeWithClientSecret,

        // Client credentials faults.
        PasswordGrant,

        // Sign-in faults: token proofs without a required claim, the client assertion of the pushed request at the token
        // endpoint, and a client assertion with nbf in the future.
        ProofWithoutHtm,
        ProofWithoutHtu,
        ProofWithoutIat,
        ReplayParAssertionAtToken,
        AssertionNbfFuture,

        // UserInfo faults: forged, incomplete, or old proofs, and the access token in the query.
        UserInfoProofAlgNone,
        UserInfoProofSignatureOtherKey,
        UserInfoProofWithoutJti,
        UserInfoProofIatOld,
        AccessTokenInQuery,

        // Requests without client authentication at the introspection, revocation, and token endpoints.
        IntrospectWithoutClientAuthentication,
        RevokeWithoutClientAuthentication,
        RefreshWithoutClientAuthentication,

        // Substituted and injected values: the ID token at UserInfo, a scope that was not granted, another client at
        // introspection and revocation, browser parameters next to request_uri, and keys in the client assertion header.
        IdTokenAtUserInfo,
        RefreshWiderScope,
        IntrospectAsOtherClient,
        RevokeAsOtherClient,
        ExtraBrowserRedirectUri,
        BrowserWithoutClientId,
        AssertionHeaderJwk,
        AssertionHeaderX5c,
        AssertionHeaderJku
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
            Fault.RedeemAsOtherClient, Fault.MissingCodeVerifier, Fault.TokenRedirectUriMismatch,
            Fault.ParMissingCodeChallenge, Fault.ParMissingCodeChallengeMethod, Fault.ParPlainPkce, Fault.ParMissingRedirectUri,
            Fault.ParRepeatedParameter, Fault.ParRequestParameter, Fault.ParNestedRequestUri, Fault.UnknownResponseTypeComponent,
            Fault.ResponseTypeWithToken, Fault.ParProofTokenEndpointHtu,
            Fault.ProofWrongHtm, Fault.ProofHtuPathCase, Fault.ProofIatFuture, Fault.ProofIatOld, Fault.ProofTypJwt, Fault.ProofPrivateJwkMembers,
            Fault.TwoProofs, Fault.ProofHtuWithQuery, Fault.ProofHtuHostUpperCase, Fault.ProofIatRecent, Fault.ProofNbfFuture, Fault.WrongDPoPKeyThenRetry,
            Fault.AssertionWithoutJti, Fault.AssertionAndClientSecret, Fault.ClientIdNotSubject, Fault.WrongCodeVerifier,
            Fault.RedeemCodeAfter10Seconds, Fault.RedeemCodeAfter5Seconds,
            Fault.ProofWithoutHtm, Fault.ProofWithoutHtu, Fault.ProofWithoutIat, Fault.ReplayParAssertionAtToken, Fault.AssertionNbfFuture,
            Fault.ExtraBrowserRedirectUri, Fault.BrowserWithoutClientId, Fault.AssertionHeaderJwk, Fault.AssertionHeaderX5c, Fault.AssertionHeaderJku
        };

        public static readonly Fault[] IntrospectionFaults =
        {
            Fault.IntrospectWithClientSecret, Fault.IntrospectWithoutClientAuthentication, Fault.IntrospectAsOtherClient
        };

        public static readonly Fault[] RevocationFaults = { Fault.RevokeWithClientSecret, Fault.RevokeWithoutClientAuthentication, Fault.RevokeAsOtherClient };

        /// <summary>The sign-in faults that change the browser request after the push.</summary>
        public static readonly Fault[] BrowserRequestFaults = { Fault.ExtraBrowserParameter, Fault.ExtraBrowserRedirectUri, Fault.BrowserWithoutClientId };

        public static readonly Fault[] ClientCredentialsFaults = { Fault.PasswordGrant };

        public static readonly Fault[] UserInfoFaults =
        {
            Fault.BearerAtUserInfo, Fault.MissingAth, Fault.ReplayDPoPProof,
            Fault.UserInfoProofOtherKey, Fault.UserInfoProofWrongHtm, Fault.UserInfoProofWrongHtu, Fault.UserInfoProofWrongAth,
            Fault.DPoPSchemeForBearerToken, Fault.AccessTokenInForm, Fault.DPoPSchemeWithoutProof,
            Fault.UserInfoProofAlgNone, Fault.UserInfoProofSignatureOtherKey, Fault.UserInfoProofWithoutJti, Fault.UserInfoProofIatOld,
            Fault.AccessTokenInQuery, Fault.IdTokenAtUserInfo
        };

        public static readonly Fault[] RefreshFaults =
        {
            Fault.NewDPoPKeyOnRefresh, Fault.ReplayDPoPProofOnRefresh, Fault.RefreshAsOtherClient, Fault.ReuseRotatedRefreshToken,
            Fault.NoDPoPProof, Fault.ReplayClientAssertion, Fault.RefreshWithoutClientAuthentication, Fault.RefreshWiderScope
        };

        private static readonly Dictionary<Fault, string> ExpectedResults = new Dictionary<Fault, string>
        {
            [Fault.SkipPar] = "A direct authorization request. Expected: invalid_request when the connection requires PAR.",
            [Fault.ExtraBrowserParameter] = "scope next to request_uri in the browser request (GET with PAR only; otherwise the sign-in does not start). Expected: an error response (verify).",
            [Fault.AssertionAudienceArray] = "Client assertion aud as a JSON array. Expected: invalid_client with clientAssertion.audience=issuer.",
            [Fault.AssertionFutureIat] = "Client assertion iat 120 seconds in the future. Expected: invalid_client when clientJwt.clockSkewInSeconds is below 120.",
            [Fault.ParProofKeyMismatch] = "A PAR proof of another key than dpop_jkt. Expected: invalid_request.",
            [Fault.NoDPoPProof] = "No proof at the token endpoint. Expected: invalid_dpop_proof when DPoP is required; an error for a bound code (verify).",
            [Fault.WrongDPoPKey] = "A token proof of a new key. Expected: invalid_grant for a bound code.",
            [Fault.WrongHtu] = "A token proof with the authorization endpoint as htu. Expected: invalid_dpop_proof.",
            [Fault.SmallDPoPKey] = "A token proof of an RSA 1024 key. Expected: invalid_dpop_proof.",
            [Fault.RedeemCodeTwice] = "A second redemption of the code after a successful one. Expected: invalid_grant for the second; Identify then revokes the tokens of the code, so the sign-in fails at UserInfo with invalid_token.",
            [Fault.BearerAtUserInfo] = "The Bearer scheme with a DPoP-bound token. Expected: HTTP 401 invalid_token.",
            [Fault.MissingAth] = "A UserInfo proof without ath. Expected: HTTP 401 invalid_dpop_proof.",
            [Fault.ReplayDPoPProof] = "The same UserInfo proof in two calls. Expected: HTTP 401 invalid_dpop_proof for the second call.",
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
            [Fault.UserInfoProofOtherKey] = "A valid UserInfo proof of a new key, not the key of the access token. Expected: HTTP 401 invalid_dpop_proof.",
            [Fault.UserInfoProofWrongHtm] = "A UserInfo proof with htm POST for a GET request. Expected: HTTP 401 invalid_dpop_proof.",
            [Fault.UserInfoProofWrongHtu] = "A UserInfo proof with the token endpoint as htu. Expected: HTTP 401 invalid_dpop_proof.",
            [Fault.UserInfoProofWrongAth] = "A UserInfo proof with the ath of another access token value. Expected: HTTP 401 invalid_dpop_proof.",
            [Fault.ReplayDPoPProofOnRefresh] = "Two refresh requests with the same proof; the result is the second. Expected: invalid_dpop_proof for the second (verify).",
            [Fault.RefreshAsOtherClient] = "The refresh request as Testing:OtherClientId, with an assertion signed by the client key (private_key_jwt). Expected: invalid_grant.",
            [Fault.ParMissingCodeChallenge] = "A pushed request without code_challenge. Expected: invalid_request.",
            [Fault.ParMissingCodeChallengeMethod] = "A pushed request without code_challenge_method. Expected: invalid_request.",
            [Fault.ParPlainPkce] = "A pushed request with code_challenge_method plain. Expected: invalid_request.",
            [Fault.ParMissingRedirectUri] = "A pushed request without redirect_uri. Expected: invalid_request.",
            [Fault.ParRepeatedParameter] = "A pushed request with the scope parameter twice. Expected: invalid_request.",
            [Fault.ParRequestParameter] = "A pushed request with a request parameter (an unsigned request object). Expected: invalid_request.",
            [Fault.ParNestedRequestUri] = "A pushed request with a request_uri parameter. Expected: invalid_request.",
            [Fault.UnknownResponseTypeComponent] = "A pushed request with response_type \"code unknown\". Expected: unsupported_response_type.",
            [Fault.ResponseTypeWithToken] = "A pushed request with response_type \"code token\". Expected: an error (verify: unauthorized_client or unsupported_response_type).",
            [Fault.ParProofTokenEndpointHtu] = "A PAR proof with the token endpoint as htu. Expected: invalid_dpop_proof.",
            [Fault.ProofWrongHtm] = "A token proof with htm GET for the POST request. Expected: invalid_dpop_proof.",
            [Fault.ProofHtuPathCase] = "A token proof with the htu path in upper case. Expected: invalid_dpop_proof.",
            [Fault.ProofIatFuture] = "A token proof with iat 120 seconds in the future. Expected: invalid_dpop_proof.",
            [Fault.ProofIatOld] = "A token proof with iat 90 seconds in the past. Expected: invalid_dpop_proof.",
            [Fault.ProofTypJwt] = "A token proof with typ JWT instead of dpop+jwt. Expected: invalid_dpop_proof.",
            [Fault.ProofPrivateJwkMembers] = "A token proof whose jwk header has the private key members. Expected: invalid_dpop_proof.",
            [Fault.TwoProofs] = "A token request with two DPoP headers. Expected: invalid_dpop_proof.",
            [Fault.ProofHtuWithQuery] = "A token proof with a query in htu. Expected: success after normalization.",
            [Fault.ProofHtuHostUpperCase] = "A token proof with the htu host in upper case. Expected: success after normalization.",
            [Fault.ProofIatRecent] = "A token proof with iat 30 seconds in the past. Expected: success.",
            [Fault.ProofNbfFuture] = "A token proof with nbf 120 seconds in the future. Expected: invalid_dpop_proof (requires a build with the nbf check).",
            [Fault.WrongDPoPKeyThenRetry] = "A token request with a new key, then one with the key of the sign-in. Expected: invalid_grant, then success.",
            [Fault.AssertionWithoutJti] = "Client assertions without jti. Expected: invalid_client.",
            [Fault.AssertionAndClientSecret] = "Client assertions together with client_secret in the same request. Expected: invalid_client.",
            [Fault.ClientIdNotSubject] = "The form client_id Testing:OtherClientId with an assertion of this client. Expected: invalid_client.",
            [Fault.WrongCodeVerifier] = "A token request with another code_verifier. Expected: invalid_grant.",
            [Fault.RedeemCodeAfter10Seconds] = "The sample waits 10 seconds before it redeems the code. Expected: invalid_grant when the code lifetime is shorter.",
            [Fault.RedeemCodeAfter5Seconds] = "The sample waits 5 seconds before it redeems the code. Expected: success when the code lifetime is longer.",
            [Fault.IntrospectWithClientSecret] = "The introspection request with client_secret_post instead of the configured method. Expected: invalid_client.",
            [Fault.ReplayClientAssertion] = "Two refresh requests with the same client assertion; the result is the second. Expected: invalid_client for the second.",
            [Fault.ReuseRotatedRefreshToken] = "A refresh that rotates the refresh token, then a refresh with the old one. Needs a connection that rotates. Expected: invalid_grant for the old one.",
            [Fault.DPoPSchemeForBearerToken] = "An access token without cnf.jkt with the DPoP scheme and a valid proof of a new key. Needs DPoP:BindAccessTokens=false. Expected: HTTP 401 invalid_token.",
            [Fault.AccessTokenInForm] = "A POST with the DPoP-bound access token in the access_token form parameter and a valid proof, without an Authorization header. Expected: HTTP 401 invalid_token.",
            [Fault.DPoPSchemeWithoutProof] = "The DPoP scheme with the DPoP-bound access token and no DPoP header. Expected: HTTP 401 invalid_dpop_proof.",
            [Fault.RevokeWithClientSecret] = "The revocation request with client_secret_post instead of the configured method. Expected: invalid_client.",
            [Fault.PasswordGrant] = "A token request with grant_type password, a user name that does not exist, and a random password, instead of client credentials. Expected: unauthorized_client when the connection does not allow the password flow.",
            [Fault.ProofWithoutHtm] = "A token proof without htm. Expected: invalid_dpop_proof.",
            [Fault.ProofWithoutHtu] = "A token proof without htu. Expected: invalid_dpop_proof.",
            [Fault.ProofWithoutIat] = "A token proof without iat. Expected: invalid_dpop_proof.",
            [Fault.ReplayParAssertionAtToken] = "The token request of the code with the client assertion of the pushed request. Needs private_key_jwt and PAR. Expected: invalid_client, because the PAR endpoint used its jti.",
            [Fault.AssertionNbfFuture] = "Client assertions with nbf 120 seconds in the future and iat now. Expected: invalid_client (verify).",
            [Fault.UserInfoProofAlgNone] = "A UserInfo proof with the jwk of the DPoP key, alg none, and no signature. Expected: HTTP 401 invalid_dpop_proof.",
            [Fault.UserInfoProofSignatureOtherKey] = "A UserInfo proof with the jwk of the DPoP key, signed with another key. Expected: HTTP 401 invalid_dpop_proof.",
            [Fault.UserInfoProofWithoutJti] = "A UserInfo proof without jti. Expected: HTTP 401 invalid_dpop_proof.",
            [Fault.UserInfoProofIatOld] = "A UserInfo proof with iat 90 seconds in the past. Expected: HTTP 401 invalid_dpop_proof.",
            [Fault.AccessTokenInQuery] = "A GET with the DPoP-bound access token in the access_token query parameter and a valid proof, without an Authorization header. Expected: HTTP 401 invalid_token, or HTTP 400 invalid_request when UserInfo does not read the query (verify).",
            [Fault.IntrospectWithoutClientAuthentication] = "The introspection request with client_id and no client authentication. Expected: invalid_client.",
            [Fault.RevokeWithoutClientAuthentication] = "The revocation request with client_id and no client authentication. Expected: invalid_client.",
            [Fault.RefreshWithoutClientAuthentication] = "The refresh request of a confidential client with client_id and no client authentication. Expected: invalid_client.",
            [Fault.IdTokenAtUserInfo] = "The ID token of the sign-in with the Bearer scheme instead of the access token. Expected: HTTP 401 invalid_token (verify).",
            [Fault.RefreshWiderScope] = "A refresh request with the scope of the sign-in and the scope fapi-fault-not-granted. Expected: invalid_scope, or a token without the extra scope (verify).",
            [Fault.IntrospectAsOtherClient] = "The introspection request as Testing:OtherClientId, with an assertion signed by the client key (private_key_jwt). Expected: an error or active false (verify).",
            [Fault.RevokeAsOtherClient] = "The revocation request as Testing:OtherClientId, with an assertion signed by the client key (private_key_jwt). Expected: the access token stays valid; an error (verify).",
            [Fault.ExtraBrowserRedirectUri] = "redirect_uri /fault-redirect next to request_uri in the browser request (GET with PAR only). Expected: the code goes to the pushed redirect URI, or an error.",
            [Fault.BrowserWithoutClientId] = "Only request_uri in the browser request, without client_id (GET with PAR only). Expected: invalid_request (verify).",
            [Fault.AssertionHeaderJwk] = "Client assertions signed with a new key, without kid, and with the new key as jwk in the header. Expected: invalid_client.",
            [Fault.AssertionHeaderX5c] = "Client assertions signed with a new key, without kid, and with a self-signed certificate of the new key as x5c in the header. Expected: invalid_client.",
            [Fault.AssertionHeaderJku] = "Client assertions signed with a new key, without kid, and with a jku URL of a host that does not exist in the header. Expected: invalid_client."
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
