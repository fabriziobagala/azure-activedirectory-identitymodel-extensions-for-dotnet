﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Contains information about a message that is used to generate a message for logging or exceptions.
    /// </summary>
    internal class MessageDetail
    {
        private string _message;

        // TODO - remove the need to create NonPII objects, we could use tuples <bool, object> where bool == true => object is PII.
        // TODO - does this need to be ReadOnlyMemory<char>?
        /// <summary>
        /// Creates an instance of <see cref="MessageDetail"/>
        /// </summary>
        /// <param name="formatString">The message to be formated.</param>
        /// <param name="parameters">The parameters for formatting.</param>
        public MessageDetail(string formatString, params object[] parameters)
        {
            // TODO - paramter validation.
            FormatString = formatString;
            Parameters = parameters;
        }

        /// <summary>
        /// Creates a message detail for a null parameter.
        /// </summary>
        /// <param name="parameterName">The name of the parameter.</param>
        /// <returns>A new <see cref="MessageDetail"/>.</returns>
        public static MessageDetail NullParameter(string parameterName)
            => new MessageDetail(LogMessages.IDX10000, LogHelper.MarkAsNonPII(parameterName));

        /// <summary>
        /// Gets the formatted message.
        /// </summary>
        public string Message
        {
            get
            {
                _message ??= LogHelper.FormatInvariant(FormatString, Parameters);
                return _message;
            }
        }

        private string FormatString { get; }

        private object[] Parameters { get; }
    }
}
