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
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using CycloneDX.Cli.Commands;
using CycloneDX.Json;
using CycloneDX.Models;
using Xunit;

namespace CycloneDX.Cli.Tests
{
    public class DiffTests
    {
        [Fact]
        public async Task NoiseOnly_IsNotReportedAsARealChange()
        {
            var fromBom = await LoadBom("noise-only-from.json").ConfigureAwait(false);
            var toBom = await LoadBom("noise-only-to.json").ConfigureAwait(false);

            var result = SemanticDiff.Compare(fromBom, toBom);

            Assert.False(result.HasChanges);
            Assert.Equal(0, result.RealChangeCount);
            Assert.Empty(result.Components.Added);
            Assert.Empty(result.Components.Removed);
            Assert.Empty(result.Versions);
            Assert.Empty(result.Dependencies.Added);
            Assert.Empty(result.Dependencies.Removed);
            Assert.Equal(2, result.Noise.Count);
            Assert.Contains(result.Noise, noise => noise.Category == "metadata.timestamp");
            Assert.Contains(result.Noise, noise => noise.Category == "metadata.tools");
        }

        [Fact]
        public async Task SingleVersionChange_DoesNotCauseComponentOrDependencyChurn()
        {
            var fromBom = await LoadBom("version-change-from.json").ConfigureAwait(false);
            var toBom = await LoadBom("version-change-to.json").ConfigureAwait(false);

            var result = SemanticDiff.Compare(fromBom, toBom);

            Assert.True(result.HasChanges);
            Assert.Equal(1, result.RealChangeCount);
            Assert.Empty(result.Components.Added);
            Assert.Empty(result.Components.Removed);
            Assert.Empty(result.Dependencies.Added);
            Assert.Empty(result.Dependencies.Removed);
            var versionChange = Assert.Single(result.Versions);
            Assert.Equal("lib-b", versionChange.Name);
            Assert.Equal("2.0.0", versionChange.FromVersion);
            Assert.Equal("2.1.0", versionChange.ToVersion);
            Assert.Equal(2, result.Noise.Count);
        }

        [Fact]
        public async Task DependencyChange_ReportsOnlyTheAffectedComponentAndEdge()
        {
            var fromBom = await LoadBom("dependency-change-from.json").ConfigureAwait(false);
            var toBom = await LoadBom("dependency-change-to.json").ConfigureAwait(false);

            var result = SemanticDiff.Compare(fromBom, toBom);

            Assert.True(result.HasChanges);
            Assert.Equal(4, result.RealChangeCount);
            Assert.Empty(result.Versions);

            var removedComponent = Assert.Single(result.Components.Removed);
            Assert.Equal("lib-b", removedComponent.Name);
            Assert.Equal("2.0.0", removedComponent.Version);

            var addedComponent = Assert.Single(result.Components.Added);
            Assert.Equal("lib-c", addedComponent.Name);
            Assert.Equal("3.0.0", addedComponent.Version);

            var removedDependency = Assert.Single(result.Dependencies.Removed);
            Assert.Equal("lib-a", removedDependency.From.Name);
            Assert.Equal("lib-b", removedDependency.To.Name);

            var addedDependency = Assert.Single(result.Dependencies.Added);
            Assert.Equal("lib-a", addedDependency.From.Name);
            Assert.Equal("lib-c", addedDependency.To.Name);

            Assert.Equal(2, result.Noise.Count);
        }

        [Fact]
        public async Task SemanticJsonReport_ListsRealChangesAndClassifiesMetadataNoise()
        {
            var output = await RunDiff(new DiffCommandOptions
            {
                FromFile = Path.Combine("Resources", "Diff", "version-change-from.json"),
                ToFile = Path.Combine("Resources", "Diff", "version-change-to.json"),
                FromFormat = CycloneDXBomFormat.autodetect,
                ToFormat = CycloneDXBomFormat.autodetect,
                OutputFormat = CommandOutputFormat.json,
                Semantic = true,
            }).ConfigureAwait(false);

            using var document = JsonDocument.Parse(output);
            var semanticDiff = document.RootElement.GetProperty("semanticDiff");

            Assert.True(semanticDiff.GetProperty("hasChanges").GetBoolean());
            Assert.True(semanticDiff.GetProperty("hasNoise").GetBoolean());
            Assert.Equal(1, semanticDiff.GetProperty("realChangeCount").GetInt32());
            Assert.Single(semanticDiff.GetProperty("versions").EnumerateArray());
            Assert.Empty(semanticDiff.GetProperty("components").GetProperty("added").EnumerateArray());
            Assert.Empty(semanticDiff.GetProperty("components").GetProperty("removed").EnumerateArray());
            Assert.Empty(semanticDiff.GetProperty("dependencies").GetProperty("added").EnumerateArray());
            Assert.Empty(semanticDiff.GetProperty("dependencies").GetProperty("removed").EnumerateArray());

            var noiseCategories = semanticDiff.GetProperty("noise")
                .EnumerateArray()
                .Select(noise => noise.GetProperty("category").GetString())
                .ToList();
            Assert.Contains("metadata.timestamp", noiseCategories);
            Assert.Contains("metadata.tools", noiseCategories);
            Assert.All(
                semanticDiff.GetProperty("noise").EnumerateArray(),
                noise => Assert.True(noise.GetProperty("isNoise").GetBoolean()));
        }

        [Fact]
        public async Task ComponentVersionsOption_RetainsLegacyJsonShape()
        {
            var output = await RunDiff(new DiffCommandOptions
            {
                FromFile = Path.Combine("Resources", "Diff", "version-change-from.json"),
                ToFile = Path.Combine("Resources", "Diff", "version-change-to.json"),
                FromFormat = CycloneDXBomFormat.autodetect,
                ToFormat = CycloneDXBomFormat.autodetect,
                OutputFormat = CommandOutputFormat.json,
                ComponentVersions = true,
            }).ConfigureAwait(false);

            using var document = JsonDocument.Parse(output);
            Assert.True(document.RootElement.TryGetProperty("componentVersions", out var componentVersions));
            Assert.False(document.RootElement.TryGetProperty("semanticDiff", out _));

            var libB = componentVersions.GetProperty("lib-b");
            Assert.Single(libB.GetProperty("added").EnumerateArray());
            Assert.Single(libB.GetProperty("removed").EnumerateArray());
        }

        [Fact]
        public async Task SemanticDiff_WorksAcrossInputFormats()
        {
            using var tempDirectory = new TempDirectory();
            var xmlPath = Path.Combine(tempDirectory.DirectoryPath, "from.xml");
            var convertExitCode = await ConvertCommand.Convert(new ConvertCommandOptions
            {
                InputFile = Path.Combine("Resources", "Diff", "version-change-from.json"),
                OutputFile = xmlPath,
                InputFormat = ConvertFormat.json,
                OutputFormat = ConvertFormat.xml,
            }).ConfigureAwait(false);
            Assert.Equal(0, convertExitCode);

            var fromBom = await CliUtils.InputBomHelper(xmlPath, CycloneDXBomFormat.xml).ConfigureAwait(false);
            var toBom = await LoadBom("version-change-to.json").ConfigureAwait(false);
            var result = SemanticDiff.Compare(fromBom, toBom);

            Assert.Equal(1, result.RealChangeCount);
            var versionChange = Assert.Single(result.Versions);
            Assert.Equal("lib-b", versionChange.Name);
            Assert.Equal("2.0.0", versionChange.FromVersion);
            Assert.Equal("2.1.0", versionChange.ToVersion);
        }

        private static async Task<Bom> LoadBom(string filename)
        {
            using var stream = File.OpenRead(Path.Combine("Resources", "Diff", filename));
            return await Serializer.DeserializeAsync(stream).ConfigureAwait(false);
        }

        private static async Task<string> RunDiff(DiffCommandOptions options)
        {
            var originalOutput = Console.Out;
            using var writer = new StringWriter();
            Console.SetOut(writer);

            try
            {
                var exitCode = await DiffCommand.Diff(options).ConfigureAwait(false);
                Assert.Equal(0, exitCode);
            }
            finally
            {
                Console.SetOut(originalOutput);
            }

            return writer.ToString();
        }
    }
}
