package uk.gov.hmrc.oauth;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.source.*;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.*;
import com.nimbusds.jwt.proc.*;

import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;

class ValidateToken {

    public static void main(String[] args) throws Exception {
        String accessToken =
                "eyJ0eXAiOiJKV1QiLCJub25jZSI6ImlCek55RVRHcXI2amFMVi1OTHJqVzdBOUVZRVFSMy1Bc3F5bVFDeG4wazQiLCJhbGciOiJSUzI1NiIsIng1dCI6Ii1LSTNROW5OUjdiUm9meG1lWm9YcWJIWkdldyIsImtpZCI6Ii1LSTNROW5OUjdiUm9meG1lWm9YcWJIWkdldyJ9.eyJhdWQiOiIwMDAwMDAwMy0wMDAwLTAwMDAtYzAwMC0wMDAwMDAwMDAwMDAiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8xMTUxMjUyNi03YTcyLTRkNDEtOGJjYS0zNWJkMDI3Njg1YTMvIiwiaWF0IjoxNjgxNzQ0NTE4LCJuYmYiOjE2ODE3NDQ1MTgsImV4cCI6MTY4MTc0OTU5OCwiYWNjdCI6MCwiYWNyIjoiMSIsImFpbyI6IkFWUUFxLzhUQUFBQTFFd3JCYTZJRElHY1FpQTBwdis5cGRqT3JvU1lYNEc3TGZQdHQzSXMzOGFaRG1aZFh2RHh6clJ4eHU1QTI5TGFNTVMxcnJ3NlMwMmtGdTJtTVQ5RlBjWGc3dlBWL3FQdUlZemI4VWM2V0xjPSIsImFtciI6WyJwd2QiLCJtZmEiXSwiYXBwX2Rpc3BsYXluYW1lIjoiYXp1ciBTUUwgZGIxIiwiYXBwaWQiOiIyZTFkMGI2Yy1kZTg4LTQ5ZDMtOGQ4ZS0wYzI3NzJhM2QwMTQiLCJhcHBpZGFjciI6IjAiLCJmYW1pbHlfbmFtZSI6IkFiaXRvbCIsImdpdmVuX25hbWUiOiJCcnVubyIsImlkdHlwIjoidXNlciIsImlwYWRkciI6IjE4LjE3MC4xLjE4IiwibmFtZSI6IkJydW5vIEFiaXRvbCIsIm9pZCI6ImQ3MWQ5OTQ5LWMzMDYtNDdhOC04MDhmLWE1NjZmZGVhMWQzMyIsInBsYXRmIjoiOCIsInB1aWQiOiIxMDAzMjAwMjhDNzk2MThBIiwicmgiOiIwLkFVNEFKaVZSRVhKNlFVMkx5alc5QW5hRm93TUFBQUFBQUFBQXdBQUFBQUFBQUFDREFPOC4iLCJzY3AiOiJvcGVuaWQgcHJvZmlsZSBVc2VyLlJlYWRCYXNpYy5BbGwgZW1haWwiLCJzaWduaW5fc3RhdGUiOlsia21zaSJdLCJzdWIiOiJrQXlsM1UzRTJtRjVsbVJhYkU0SUhpWkZRRVNsNzhxMDdWYjNLLXRQT1pRIiwidGVuYW50X3JlZ2lvbl9zY29wZSI6IkVVIiwidGlkIjoiMTE1MTI1MjYtN2E3Mi00ZDQxLThiY2EtMzViZDAyNzY4NWEzIiwidW5pcXVlX25hbWUiOiJCcnVub0FAcG9zaXRkZXYuY28udWsiLCJ1cG4iOiJCcnVub0FAcG9zaXRkZXYuY28udWsiLCJ1dGkiOiJBR0xmd3VucEwwS3NOWFdtSlpvNUFBIiwidmVyIjoiMS4wIiwid2lkcyI6WyJiNzlmYmY0ZC0zZWY5LTQ2ODktODE0My03NmIxOTRlODU1MDkiXSwieG1zX3N0Ijp7InN1YiI6IjIydVpfeWR6cW5iOTNPNHhYRlRvS1l0UlE2TFlvdXY3MzZDVmUzc1FzNUEifSwieG1zX3RjZHQiOjE2Nzc3NDMwMDN9.ZoJD0ors78grNzlslKNaNR81cFX2Pqcjp28ceCdL2sjTDxQhz7OREqKNvW8PQHtcAYDLwRRWAYylcJtuVxVzxsRobXafLjsXHIFrQcmZUK-D8M1TjGtlzOlnPgxm0-zcB-uulXPSdFs5NdYbnnWEfetZTiGIHrenpRMcQxHRAakFAVualKtBbmsH9lFNNd7NoYFgOQTXgtH75SdUqDv6_Z_Q9rZ3_NggCkeRx6gP_zv6BPdk3tpGAFYAJMtsbPcvavpjSRh26_P425En-aHoA4vhPfMPGYXHMSxmamH2Y7jx3GXQ-HJgPadUQqLR6qZBFC1pcCIJRM0PR13leBBNMQ";

// Create a JWT processor for the access tokens
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor =
                new DefaultJWTProcessor<>();

// Set the required "typ" header "at+jwt" for access tokens issued by the
// Connect2id server, may not be set by other servers
        jwtProcessor.setJWSTypeVerifier(
                new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("jwt")));

// The public RSA keys to validate the signatures will be sourced from the
// OAuth 2.0 server's JWK set, published at a well-known URL. The RemoteJWKSet
// object caches the retrieved keys to speed up subsequent look-ups and can
// also handle key-rollover
        JWKSource<SecurityContext> keySource =
                new RemoteJWKSet<>(new URL("https://login.microsoftonline.com/11512526-7a72-4d41-8bca-35bd027685a3/discovery/keys?appid=6731de76-14a6-49ae-97bc-6eba6914391e"));

// The expected JWS algorithm of the access tokens (agreed out-of-band)
        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

// Configure the JWT processor with a key selector to feed matching public
// RSA keys sourced from the JWK set URL
        JWSKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);

        jwtProcessor.setJWSKeySelector(keySelector);

        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(
                new JWTClaimsSet.Builder()
                        .issuer("https://sts.windows.net/11512526-7a72-4d41-8bca-35bd027685a3/")
                        .audience("api://2e1d0b6c-de88-49d3-8d8e-0c2772a3d014")
                        .claim("appid","2e1d0b6c-de88-49d3-8d8e-0c2772a3d014")
                        .claim("scp", "Denodo.Read")
                        .build(),
                new HashSet<>(Arrays.asList("sub"))));

// Process the token
        SecurityContext ctx = null; // optional context parameter, not required here
        JWTClaimsSet claimsSet = jwtProcessor.process(accessToken, ctx);

// Print out the token claims set
        System.out.println(claimsSet.toJSONObject());
    }

}
