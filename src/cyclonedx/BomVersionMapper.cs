// This file is part of CycloneDX CLI Tool
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an “AS IS” BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) OWASP Foundation. All Rights Reserved.
using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using CycloneDX.Models;
using CycloneDX.Models.Vulnerabilities;

namespace CycloneDX.Cli
{
    /// <summary>
    /// Maps a BOM between CycloneDX specification versions.
    ///
    /// Upgrades are lossless, only the spec version marker changes. Downgrades
    /// drop elements that do not exist in the target version and map enum
    /// values that are not valid in the target version to the closest valid
    /// value. Every action taken is recorded in a human readable mapping
    /// report.
    /// </summary>
    internal static class BomVersionMapper
    {
        // external reference types valid in CycloneDX v1.4
        private static readonly HashSet<ExternalReference.ExternalReferenceType> ExternalReferenceTypesV1_4 = new HashSet<ExternalReference.ExternalReferenceType>
        {
            ExternalReference.ExternalReferenceType.Other,
            ExternalReference.ExternalReferenceType.Vcs,
            ExternalReference.ExternalReferenceType.Issue_Tracker,
            ExternalReference.ExternalReferenceType.Website,
            ExternalReference.ExternalReferenceType.Advisories,
            ExternalReference.ExternalReferenceType.Bom,
            ExternalReference.ExternalReferenceType.Mailing_List,
            ExternalReference.ExternalReferenceType.Social,
            ExternalReference.ExternalReferenceType.Chat,
            ExternalReference.ExternalReferenceType.Documentation,
            ExternalReference.ExternalReferenceType.Support,
            ExternalReference.ExternalReferenceType.Distribution,
            ExternalReference.ExternalReferenceType.License,
            ExternalReference.ExternalReferenceType.Build_Meta,
            ExternalReference.ExternalReferenceType.Build_System,
            ExternalReference.ExternalReferenceType.Release_Notes,
        };

        // hash algorithms valid in CycloneDX v1.4 - v1.6
        private static readonly HashSet<Hash.HashAlgorithm> HashAlgorithmsV1_6 = new HashSet<Hash.HashAlgorithm>
        {
            Hash.HashAlgorithm.MD5,
            Hash.HashAlgorithm.SHA_1,
            Hash.HashAlgorithm.SHA_256,
            Hash.HashAlgorithm.SHA_384,
            Hash.HashAlgorithm.SHA_512,
            Hash.HashAlgorithm.SHA3_256,
            Hash.HashAlgorithm.SHA3_384,
            Hash.HashAlgorithm.SHA3_512,
            Hash.HashAlgorithm.BLAKE2b_256,
            Hash.HashAlgorithm.BLAKE2b_384,
            Hash.HashAlgorithm.BLAKE2b_512,
            Hash.HashAlgorithm.BLAKE3,
        };

        public static Bom MapToVersion(Bom bom, SpecificationVersion targetVersion, IList<string> mappingReport)
        {
            Contract.Requires(bom != null);
            var report = mappingReport ?? new List<string>();
            var sourceVersion = bom.SpecVersion;

            if (sourceVersion == targetVersion)
            {
                report.Add($"BOM is already at spec version {SpecificationVersionHelpers.VersionString(targetVersion)}, no conversion required.");
                return bom;
            }

            if ((int)targetVersion > (int)sourceVersion)
            {
                bom.SpecVersion = targetVersion;
                report.Add($"Upgraded BOM from spec version {SpecificationVersionHelpers.VersionString(sourceVersion)} to {SpecificationVersionHelpers.VersionString(targetVersion)} (lossless).");
                return bom;
            }

            report.Add($"Downgrading BOM from spec version {SpecificationVersionHelpers.VersionString(sourceVersion)} to {SpecificationVersionHelpers.VersionString(targetVersion)}.");

            ReportDroppedElements(bom, targetVersion, report);

            // setting the spec version and round tripping through the version
            // aware serializer drops all elements that don't exist in the
            // target version
            bom.SpecVersion = targetVersion;
            var mappedBom = Json.Serializer.Deserialize(Json.Serializer.Serialize(bom));

            // map enum values that are not valid in the target version to the
            // closest valid value
            MapEnumValues(mappedBom, targetVersion, report);

            return mappedBom;
        }

        private static void ReportDroppedElements(Bom bom, SpecificationVersion targetVersion, IList<string> report)
        {
            var targetVersionString = SpecificationVersionHelpers.VersionString(targetVersion);

            if ((int)targetVersion < (int)SpecificationVersion.v1_5)
            {
                if (bom.Formulation != null && bom.Formulation.Count > 0)
                    report.Add($"Dropped 'formulation' (not supported in spec version {targetVersionString}).");
                if (bom.Metadata?.Lifecycles != null && bom.Metadata.Lifecycles.Count > 0)
                    report.Add($"Dropped 'metadata.lifecycles' (not supported in spec version {targetVersionString}).");
            }

            if ((int)targetVersion < (int)SpecificationVersion.v1_6)
            {
                if (bom.Annotations != null && bom.Annotations.Count > 0)
                    report.Add($"Dropped 'annotations' (not supported in spec version {targetVersionString}).");
                if (bom.Declarations != null)
                    report.Add($"Dropped 'declarations' (not supported in spec version {targetVersionString}).");
                if (bom.Definitions != null)
                    report.Add($"Dropped 'definitions' (not supported in spec version {targetVersionString}).");
            }

            if ((int)targetVersion < (int)SpecificationVersion.v1_7)
            {
                if (bom.Citations != null && bom.Citations.Count > 0)
                    report.Add($"Dropped 'citations' (not supported in spec version {targetVersionString}).");
            }

            foreach (var component in EnumerateAllComponents(bom))
            {
                var componentName = ComponentName(component);

                if (!ComponentTypeValidIn(component.Type, targetVersion))
                {
                    report.Add($"Component '{componentName}' type '{ToKebabCase(component.Type.ToString())}' is not supported in spec version {targetVersionString}, mapped to 'library'.");
                }

                if ((int)targetVersion < (int)SpecificationVersion.v1_5)
                {
                    if (component.ModelCard != null)
                        report.Add($"Dropped 'modelCard' from component '{componentName}' (not supported in spec version {targetVersionString}).");
                }

                if ((int)targetVersion < (int)SpecificationVersion.v1_6)
                {
                    if (component.OmniborId != null && component.OmniborId.Count > 0)
                        report.Add($"Dropped 'omniborId' from component '{componentName}' (not supported in spec version {targetVersionString}).");
                    if (component.Swhid != null && component.Swhid.Count > 0)
                        report.Add($"Dropped 'swhid' from component '{componentName}' (not supported in spec version {targetVersionString}).");
                    if (component.CryptoProperties != null)
                        report.Add($"Dropped 'cryptoProperties' from component '{componentName}' (not supported in spec version {targetVersionString}).");
                    if (component.Tags != null && component.Tags.Count > 0)
                        report.Add($"Dropped 'tags' from component '{componentName}' (not supported in spec version {targetVersionString}).");
                    if (component.Evidence?.Identity != null)
                        report.Add($"Dropped 'evidence.identity' from component '{componentName}' (not supported in spec version {targetVersionString}).");
                }

                if ((int)targetVersion < (int)SpecificationVersion.v1_5 && component.Licenses != null)
                {
                    foreach (var licenseChoice in component.Licenses)
                    {
                        if (licenseChoice?.License?.Acknowledgement != null)
                        {
                            report.Add($"Dropped license 'acknowledgement' from component '{componentName}' (not supported in spec version {targetVersionString}).");
                            break;
                        }
                    }
                }
            }

            if (bom.Vulnerabilities != null && (int)targetVersion < (int)SpecificationVersion.v1_5)
            {
                foreach (var vulnerability in bom.Vulnerabilities)
                {
                    if (vulnerability.Ratings == null) continue;
                    foreach (var rating in vulnerability.Ratings)
                    {
                        if (rating.Method == ScoreMethod.CVSSV4 || rating.Method == ScoreMethod.SSVC)
                        {
                            var methodName = rating.Method.ToString().Replace("CVSSV", "CVSSv", StringComparison.Ordinal);
                            report.Add($"Dropped '{methodName}' rating from vulnerability '{vulnerability.Id}' (not supported in spec version {targetVersionString}).");
                        }
                    }
                }
            }
        }

        private static void MapEnumValues(Bom bom, SpecificationVersion targetVersion, IList<string> report)
        {
            foreach (var component in EnumerateAllComponents(bom))
            {
                MapHashes(component, report);
            }

            if ((int)targetVersion >= (int)SpecificationVersion.v1_5) return;

            MapExternalReferences(bom.ExternalReferences, report);

            foreach (var component in EnumerateAllComponents(bom))
            {
                MapExternalReferences(component.ExternalReferences, report);
            }

            if (bom.Services != null)
            {
                foreach (var service in EnumerateAllServices(bom.Services))
                {
                    MapExternalReferences(service.ExternalReferences, report);
                }
            }

            if (bom.Compositions != null)
            {
                foreach (var composition in bom.Compositions)
                {
                    switch (composition.Aggregate)
                    {
                        case Composition.AggregateType.Incomplete_First_Party_Opensource_Only:
                        case Composition.AggregateType.Incomplete_First_Party_Proprietary_Only:
                            report.Add($"Mapped composition aggregate '{composition.Aggregate.ToString().ToLowerInvariant()}' to 'incomplete_first_party_only'.");
                            composition.Aggregate = Composition.AggregateType.Incomplete_First_Party_Only;
                            break;
                        case Composition.AggregateType.Incomplete_Third_Party_Opensource_Only:
                        case Composition.AggregateType.Incomplete_Third_Party_Proprietary_Only:
                            report.Add($"Mapped composition aggregate '{composition.Aggregate.ToString().ToLowerInvariant()}' to 'incomplete_third_party_only'.");
                            composition.Aggregate = Composition.AggregateType.Incomplete_Third_Party_Only;
                            break;
                    }
                }
            }
        }

        private static void MapExternalReferences(List<ExternalReference> externalReferences, IList<string> report)
        {
            if (externalReferences == null) return;
            foreach (var externalReference in externalReferences)
            {
                if (!ExternalReferenceTypesV1_4.Contains(externalReference.Type))
                {
                    report.Add($"Mapped external reference type '{ToKebabCase(externalReference.Type.ToString())}' to 'other' ({externalReference.Url}).");
                    externalReference.Type = ExternalReference.ExternalReferenceType.Other;
                }
            }
        }

        private static void MapHashes(Component component, IList<string> report)
        {
            if (component.Hashes == null) return;
            for (var i = component.Hashes.Count - 1; i >= 0; i--)
            {
                if (!HashAlgorithmsV1_6.Contains(component.Hashes[i].Alg))
                {
                    report.Add($"Dropped hash algorithm '{component.Hashes[i].Alg.ToString().Replace('_', '-')}' from component '{ComponentName(component)}' (not supported in target spec version).");
                    component.Hashes.RemoveAt(i);
                }
            }
            if (component.Hashes.Count == 0) component.Hashes = null;
        }

        private static IEnumerable<Component> EnumerateAllComponents(Bom bom)
        {
            if (bom.Metadata?.Component != null)
            {
                foreach (var component in EnumerateComponentTree(bom.Metadata.Component)) yield return component;
            }
            if (bom.Components != null)
            {
                foreach (var component in bom.Components)
                {
                    foreach (var nested in EnumerateComponentTree(component)) yield return nested;
                }
            }
        }

        private static IEnumerable<Component> EnumerateComponentTree(Component component)
        {
            yield return component;
            if (component.Components != null)
            {
                foreach (var child in component.Components)
                {
                    foreach (var nested in EnumerateComponentTree(child)) yield return nested;
                }
            }
        }

        private static IEnumerable<Service> EnumerateAllServices(IEnumerable<Service> services)
        {
            foreach (var service in services)
            {
                yield return service;
                if (service.Services != null)
                {
                    foreach (var nested in EnumerateAllServices(service.Services)) yield return nested;
                }
            }
        }

        private static string ComponentName(Component component)
        {
            return component.BomRef ?? component.Purl ?? component.Name;
        }

        private static string ToKebabCase(string enumName)
        {
            return enumName.Replace('_', '-').ToLowerInvariant();
        }

        private static bool ComponentTypeValidIn(Component.Classification type, SpecificationVersion version)
        {
            switch (type)
            {
                case Component.Classification.Data:
                case Component.Classification.Machine_Learning_Model:
                    return (int)version >= (int)SpecificationVersion.v1_5;
                case Component.Classification.Platform:
                case Component.Classification.Device_Driver:
                case Component.Classification.Cryptographic_Asset:
                    return (int)version >= (int)SpecificationVersion.v1_6;
                default:
                    return true;
            }
        }
    }
}
