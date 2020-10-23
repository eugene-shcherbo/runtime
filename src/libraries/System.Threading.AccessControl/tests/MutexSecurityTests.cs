// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Principal;
using System;
using Xunit;
using System.Collections;
using System.Collections.Generic;

namespace System.Security.AccessControl
{
    public class MutexSecurityTests
    {
        [Theory]
        [InlineData(typeof(NTAccount))]
        [InlineData(typeof(SecurityIdentifier))]
        public void DefaultCtor_CreateObjectWithEmptyDACL(Type identityType)
        {
            // Act
            var ms = new MutexSecurity();

            // Assert
            string securityDescriptorSsdl = ms.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
            Assert.Contains("D:", securityDescriptorSsdl);
            Assert.Empty(ms.GetAccessRules(true, includeInherited: false, identityType));
        }

        [Theory]
        [MemberData(nameof(AccessRuleInvalidArguments))]
        public void AccessRuleFactory_ThrowsException_WhenInvalidArguments(IdentityReference identity, MutexRights rights, AccessControlType accessType, Type exceptionType)
        {
            // Arrange
            var ms = new MutexSecurity();

            // Act & Assert
            Assert.Throws(exceptionType,
                () => ms.AccessRuleFactory(identity, (int)rights, isInherited: false, InheritanceFlags.None, PropagationFlags.None, accessType));
        }

        [Theory]
        [MemberData(nameof(AccessRuleValidArguments))]
        public void AccessRuleFactory_CreatesMutexAccessRuleWithSpecifiedParameters(IdentityReference identity, MutexRights rights, AccessControlType accessType)
        {
            // Arrange
            var ms = new MutexSecurity();

            // Act
            AccessRule rule = ms.AccessRuleFactory(identity, (int)rights, isInherited: false, InheritanceFlags.None, PropagationFlags.None, accessType);

            // Assert
            var mutexRule = rule as MutexAccessRule;
            Assert.NotNull(mutexRule);
            Assert.Equal(mutexRule.IdentityReference, identity);
            Assert.Equal(mutexRule.AccessControlType, accessType);
            Assert.Equal(mutexRule.MutexRights, rights);
        }

        [Fact]
        public void AddAccessRule_ThrowsException_WhenRuleIsNull()
        {
            // Arrange
            var ms = new MutexSecurity();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => ms.AddAccessRule(null));
        }

        [Theory]
        [InlineData(MutexRights.FullControl, AccessControlType.Allow)]
        [InlineData(MutexRights.FullControl, AccessControlType.Deny)]
        [InlineData(MutexRights.Synchronize, AccessControlType.Allow)]
        [InlineData(MutexRights.Synchronize, AccessControlType.Deny)]
        [InlineData(MutexRights.Modify, AccessControlType.Allow)]
        [InlineData(MutexRights.Modify, AccessControlType.Deny)]
        [InlineData(MutexRights.ChangePermissions | MutexRights.Delete, AccessControlType.Allow)]
        [InlineData(MutexRights.ChangePermissions | MutexRights.Delete, AccessControlType.Deny)]
        public void AddAccessRule_AddSpecificRule(MutexRights rights, AccessControlType accessType)
        {
            // Arrange
            var ms = new MutexSecurity();
            var identity = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            var expcetedAccessRule = new MutexAccessRule(identity, rights, accessType);

            // Act
            ms.AddAccessRule(expcetedAccessRule);

            // Assert
            AuthorizationRuleCollection accessRules = ms.GetAccessRules(includeExplicit: true, includeInherited: false, identity.GetType());
            Assert.Equal(1, accessRules.Count);
            MutexAccessRule actualAccessRule = accessRules[0] as MutexAccessRule;
            Assert.NotNull(actualAccessRule);
            Assert.Equal(expcetedAccessRule.MutexRights, actualAccessRule.MutexRights);
            Assert.Equal(expcetedAccessRule.IdentityReference, actualAccessRule.IdentityReference);
            Assert.Equal(expcetedAccessRule.AccessControlType, actualAccessRule.AccessControlType);
        }

        // TODO: Test that merge works when rule is for the same user and with the same Access Control Type

        public static IEnumerable<object[]> AccessRuleValidArguments()
        {
            var identity = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);

            return new []
            {
                new object[] { identity, MutexRights.ChangePermissions, AccessControlType.Allow },
                new object[] { identity, MutexRights.ChangePermissions | MutexRights.Delete, AccessControlType.Deny },
                new object[] { identity, MutexRights.FullControl, AccessControlType.Allow }
            };
        }

        public static IEnumerable<object[]> AccessRuleInvalidArguments()
        {
            var identity = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);

            return new[]
            {
                // Identity Reference is null
                new object[] { null, MutexRights.ChangePermissions, AccessControlType.Allow, typeof(ArgumentNullException) },

                // MutexRights = 0 which is not valid
                new object[] { identity, 0, AccessControlType.Deny, typeof(ArgumentException) },

                // AccessControl is not valid enum value
                new object[] { identity, MutexRights.FullControl, -1, typeof(ArgumentOutOfRangeException) }
            };
        }
    }
}
