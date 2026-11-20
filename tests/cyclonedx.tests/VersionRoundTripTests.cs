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
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Xunit;
using CycloneDX.Models;
using CycloneDX.Cli.Commands;

namespace CycloneDX.Cli.Tests
{
    public class VersionRoundTripTests
    {
        private static readonly string ResourceDirectory = Path.Combine("Resources", "RoundTrip");

        public static IEnumerable<object[]> V14Boms => new[]
        {
            new object[] { "bom-rt-1.4-01.xml" },
            new object[] { "bom-rt-1.4-02.json" },
            new object[] { "bom-rt-1.4-03.xml" },
            new object[] { "bom-rt-1.4-04.json" },
            new object[] { "bom-rt-1.4-05.xml" },
        };

        public static IEnumerable<object[]> V16Boms => new[]
        {
            new object[] { "bom-rt-1.6-01.json" },
            new object[] { "bom-rt-1.6-02.xml" },
            new object[] { "bom-rt-1.6-03.json" },
            new object[] { "bom-rt-1.6-04.xml" },
            new object[] { "bom-rt-1.6-05.json" },
        };

        private static Bom DeserializeBom(string filename)
        {
            var contents = File.ReadAllText(filename);
            return filename.EndsWith(".json", System.StringComparison.Ordinal)
                ? Json.Serializer.Deserialize(contents)
                : Xml.Serializer.Deserialize(contents);
        }

        private static ValidationResult ValidateBom(string filename, SpecificationVersion version)
        {
            var contents = File.ReadAllText(filename);
            return filename.EndsWith(".json", System.StringComparison.Ordinal)
                ? Json.Validator.Validate(contents, version)
                : Xml.Validator.Validate(contents, version);
        }

        private static string CanonicalJson(Bom bom, SpecificationVersion version)
        {
            bom.SpecVersion = version;
            return Json.Serializer.Serialize(bom);
        }

        private static async Task<string> ConvertToVersion(string inputFile, string outputFilename, SpecificationVersion version)
        {
            var exitCode = await ConvertCommand.Convert(new ConvertCommandOptions
            {
                InputFile = inputFile,
                OutputFile = outputFilename,
                InputFormat = ConvertFormat.autodetect,
                OutputFormat = ConvertFormat.autodetect,
                OutputVersion = version,
            }).ConfigureAwait(false);
            Assert.Equal(0, exitCode);
            return outputFilename;
        }

        [Theory]
        [MemberData(nameof(V14Boms))]
        public async Task RoundTrip_1_4_To_1_6_And_Back(string inputFilename)
        {
            using (var tempDirectory = new TempDirectory())
            {
                var inputFile = Path.Combine(ResourceDirectory, inputFilename);
                var upgradedFile = Path.Combine(tempDirectory.DirectoryPath, "upgraded.json");
                var roundTrippedFile = Path.Combine(tempDirectory.DirectoryPath, "roundtripped.json");

                // upgrade 1.4 -> 1.6 and validate against the 1.6 schema
                await ConvertToVersion(inputFile, upgradedFile, SpecificationVersion.v1_6).ConfigureAwait(false);
                Assert.True(ValidateBom(upgradedFile, SpecificationVersion.v1_6).Valid);

                // downgrade 1.6 -> 1.4 and validate against the 1.4 schema
                await ConvertToVersion(upgradedFile, roundTrippedFile, SpecificationVersion.v1_4).ConfigureAwait(false);
                Assert.True(ValidateBom(roundTrippedFile, SpecificationVersion.v1_4).Valid);

                // upgrading is lossless, the round tripped BOM must be
                // identical to the original
                var original = DeserializeBom(inputFile);
                var roundTripped = DeserializeBom(roundTrippedFile);
                Assert.Equal(
                    CanonicalJson(original, SpecificationVersion.v1_4),
                    CanonicalJson(roundTripped, SpecificationVersion.v1_4));
            }
        }

        [Theory]
        [MemberData(nameof(V16Boms))]
        public async Task RoundTrip_1_6_To_1_4_And_Back(string inputFilename)
        {
            using (var tempDirectory = new TempDirectory())
            {
                var inputFile = Path.Combine(ResourceDirectory, inputFilename);
                var downgradedFile = Path.Combine(tempDirectory.DirectoryPath, "downgraded.json");
                var roundTrippedFile = Path.Combine(tempDirectory.DirectoryPath, "roundtripped.json");

                // downgrade 1.6 -> 1.4 and validate against the 1.4 schema
                await ConvertToVersion(inputFile, downgradedFile, SpecificationVersion.v1_4).ConfigureAwait(false);
                Assert.True(ValidateBom(downgradedFile, SpecificationVersion.v1_4).Valid);

                // upgrade 1.4 -> 1.6 and validate against the 1.6 schema
                await ConvertToVersion(downgradedFile, roundTrippedFile, SpecificationVersion.v1_6).ConfigureAwait(false);
                Assert.True(ValidateBom(roundTrippedFile, SpecificationVersion.v1_6).Valid);

                // the round tripped BOM must be identical to mapping the
                // original BOM down to 1.4 and back up to 1.6
                var report = new List<string>();
                var expected = BomVersionMapper.MapToVersion(DeserializeBom(inputFile), SpecificationVersion.v1_4, report);
                expected = BomVersionMapper.MapToVersion(expected, SpecificationVersion.v1_6, report);
                var roundTripped = DeserializeBom(roundTrippedFile);
                Assert.Equal(
                    CanonicalJson(expected, SpecificationVersion.v1_6),
                    CanonicalJson(roundTripped, SpecificationVersion.v1_6));
            }
        }

        [Theory]
        [MemberData(nameof(V16Boms))]
        public void Downgrade_1_6_To_1_4_Produces_Mapping_Report(string inputFilename)
        {
            var report = new List<string>();
            var bom = DeserializeBom(Path.Combine(ResourceDirectory, inputFilename));

            var mapped = BomVersionMapper.MapToVersion(bom, SpecificationVersion.v1_4, report);

            Assert.Equal(SpecificationVersion.v1_4, mapped.SpecVersion);
            Assert.Contains(report, entry => entry.Contains("Downgrading", System.StringComparison.Ordinal));
            Assert.True(report.Count > 1);
        }
    }
}
