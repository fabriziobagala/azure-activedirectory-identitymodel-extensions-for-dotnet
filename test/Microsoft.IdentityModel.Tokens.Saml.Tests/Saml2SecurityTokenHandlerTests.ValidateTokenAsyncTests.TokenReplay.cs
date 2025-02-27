﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Saml2;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
#nullable enable
    public partial class Saml2SecurityTokenHandlerTests
    {
        [Theory, MemberData(nameof(ValidateTokenAsync_TokenReplay_TestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_TokenReplayComparison(ValidateTokenAsyncTokenReplayTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateTokenAsync_TokenReplayComparison", theoryData);

            Saml2SecurityTokenHandler saml2TokenHandler = new Saml2SecurityTokenHandler();

            Saml2SecurityToken saml2Token = CreateTokenForTokenReplayValidation(theoryData.TokenHasExpiration);

            // Validate the token using TokenValidationParameters
            TokenValidationResult tokenValidationResult =
                await saml2TokenHandler.ValidateTokenAsync(saml2Token.Assertion.CanonicalString, theoryData.TokenValidationParameters);

            // Validate the token using ValidationParameters.
            ValidationResult<ValidatedToken> validationResult =
                await saml2TokenHandler.ValidateTokenAsync(
                    saml2Token,
                    theoryData.ValidationParameters!,
                    theoryData.CallContext,
                    CancellationToken.None);

            // Ensure the validity of the results match the expected result.
            if (tokenValidationResult.IsValid != theoryData.ExpectedIsValid)
                context.AddDiff($"tokenValidationResult.IsValid != theoryData.ExpectedIsValid");

            if (validationResult.IsValid != theoryData.ExpectedIsValid)
                context.AddDiff($"validationResult.IsValid != theoryData.ExpectedIsValid");

            if (!theoryData.ExpectedIsValid)
            {
                // Verify the exception provided by both paths match.
                var tokenValidationResultException = tokenValidationResult.Exception;
                var validationResultException = validationResult.UnwrapError().GetException();

                theoryData.ExpectedException.ProcessException(tokenValidationResultException, context);
                theoryData.ExpectedExceptionValidationParameters!.ProcessException(validationResultException, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenAsyncTokenReplayTheoryData> ValidateTokenAsync_TokenReplay_TestCases
        {
            get
            {
                var successfulTokenReplayCache = new TokenReplayCache
                {
                    OnAddReturnValue = true,
                    OnFindReturnValue = false,
                };

                var failToAddTokenReplayCache = new TokenReplayCache
                {
                    OnAddReturnValue = false,
                    OnFindReturnValue = false,
                };

                var tokenAlreadySavedTokenReplayCache = new TokenReplayCache
                {
                    OnAddReturnValue = true,
                    OnFindReturnValue = true,
                };

                var theoryData = new TheoryData<ValidateTokenAsyncTokenReplayTheoryData>();

                theoryData.Add(new ValidateTokenAsyncTokenReplayTheoryData("Valid_TokenHasNotBeenReplayed")
                {
                    TokenValidationParameters = CreateTokenValidationParameters(successfulTokenReplayCache),
                    ValidationParameters = CreateValidationParameters(successfulTokenReplayCache),
                });

                theoryData.Add(new ValidateTokenAsyncTokenReplayTheoryData("Valid_TokenHasNoExpiration_TokenReplayCacheIsNull")
                {
                    TokenHasExpiration = false,
                    TokenValidationParameters = CreateTokenValidationParameters(null),
                    ValidationParameters = CreateValidationParameters(null),
                });

                theoryData.Add(new ValidateTokenAsyncTokenReplayTheoryData("Invalid_TokenHasNoExpiration_TokenReplayCacheIsNotNull")
                {
                    TokenHasExpiration = false,
                    TokenValidationParameters = CreateTokenValidationParameters(successfulTokenReplayCache),
                    ValidationParameters = CreateValidationParameters(successfulTokenReplayCache),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenNoExpirationException("IDX10227:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenNoExpirationException("IDX10227:"),
                });

                theoryData.Add(new ValidateTokenAsyncTokenReplayTheoryData("Invalid_TokenCouldNotBeAdded")
                {
                    TokenValidationParameters = CreateTokenValidationParameters(failToAddTokenReplayCache),
                    ValidationParameters = CreateValidationParameters(failToAddTokenReplayCache),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenReplayAddFailedException("IDX10229:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenReplayAddFailedException("IDX10229:"),
                });

                theoryData.Add(new ValidateTokenAsyncTokenReplayTheoryData("Invalid_TokenHasBeenReplayed")
                {
                    TokenValidationParameters = CreateTokenValidationParameters(tokenAlreadySavedTokenReplayCache),
                    ValidationParameters = CreateValidationParameters(tokenAlreadySavedTokenReplayCache),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenReplayDetectedException("IDX10228:"),
                    ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenReplayDetectedException("IDX10228:"),
                });

                return theoryData;

                static TokenValidationParameters CreateTokenValidationParameters(ITokenReplayCache? tokenReplayCache)
                {
                    var tokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = false,
                        ValidateIssuer = false,
                        ValidateLifetime = false,
                        ValidateTokenReplay = true,
                        ValidateIssuerSigningKey = false,
                        RequireSignedTokens = false,
                        TokenReplayCache = tokenReplayCache
                    };

                    return tokenValidationParameters;
                }

                static ValidationParameters CreateValidationParameters(ITokenReplayCache? tokenReplayCache)
                {
                    ValidationParameters validationParameters = new ValidationParameters();
                    validationParameters.TokenReplayCache = tokenReplayCache;

                    validationParameters.AlgorithmValidator = SkipValidationDelegates.SkipAlgorithmValidation;
                    validationParameters.AudienceValidator = SkipValidationDelegates.SkipAudienceValidation;
                    validationParameters.IssuerSigningKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation;
                    validationParameters.IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation;
                    validationParameters.LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation;
                    validationParameters.SignatureValidator = SkipValidationDelegates.SkipSignatureValidation;
                    validationParameters.TokenTypeValidator = SkipValidationDelegates.SkipTokenTypeValidation;

                    return validationParameters;
                }
            }
        }

        public class ValidateTokenAsyncTokenReplayTheoryData : TheoryDataBase
        {
            public ValidateTokenAsyncTokenReplayTheoryData(string testId) : base(testId) { }

            internal ExpectedException? ExpectedExceptionValidationParameters { get; set; } = ExpectedException.NoExceptionExpected;

            internal bool TokenHasExpiration { get; set; } = true;

            internal bool ExpectedIsValid { get; set; } = true;

            internal ValidationParameters? ValidationParameters { get; set; }

            internal TokenValidationParameters? TokenValidationParameters { get; set; }
        }

        private static Saml2SecurityToken CreateTokenForTokenReplayValidation(bool hasExpiration = true)
        {
            Saml2SecurityTokenHandler saml2SecurityTokenHandler = new Saml2SecurityTokenHandler();
            // If the token has expiration, we use the default times.
            saml2SecurityTokenHandler.SetDefaultTimesOnTokenCreation = hasExpiration;

            SecurityTokenDescriptor securityTokenDescriptor;

            if (!hasExpiration)
            {
                securityTokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = Default.ClaimsIdentity,
                    Issuer = Default.Issuer,
                    Audience = Default.Audience,
                    Expires = null,
                    NotBefore = null,
                    IssuedAt = null,
                };
            }
            else
            {
                securityTokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = Default.ClaimsIdentity,
                    Issuer = Default.Issuer,
                    Audience = Default.Audience,
                };
            }

            return (Saml2SecurityToken)saml2SecurityTokenHandler.CreateToken(securityTokenDescriptor);
        }
    }
}
#nullable restore
