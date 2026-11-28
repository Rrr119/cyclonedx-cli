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
using System.Globalization;
using System.Linq;
using CycloneDX.Cli.Models;
using CycloneDX.Models;

namespace CycloneDX.Cli
{
    internal static class SemanticDiff
    {
        internal static SemanticDiffResult Compare(Bom fromBom, Bom toBom)
        {
            ArgumentNullException.ThrowIfNull(fromBom);
            ArgumentNullException.ThrowIfNull(toBom);

            var fromComponents = CollectComponents(fromBom);
            var toComponents = CollectComponents(toBom);

            var result = new SemanticDiffResult
            {
                Components = CompareComponents(fromComponents, toComponents),
                Dependencies = CompareDependencies(fromBom, toBom),
                Noise = CompareNoise(fromBom, toBom),
            };

            result.Versions = CompareVersions(fromComponents, toComponents);

            return result;
        }

        private static List<ComponentSnapshot> CollectComponents(Bom bom)
        {
            var components = new List<ComponentSnapshot>();
            AddComponent(bom.Metadata?.Component, components);

            if (bom.Components != null)
            {
                foreach (var component in bom.Components)
                {
                    AddComponent(component, components);
                }
            }

            return components;
        }

        private static void AddComponent(Component component, List<ComponentSnapshot> components)
        {
            if (component == null) return;

            components.Add(new ComponentSnapshot
            {
                Type = component.Type.ToString(),
                Group = component.Group,
                Name = component.Name,
                Version = component.Version,
                Purl = component.Purl,
                BomRef = component.BomRef,
            });

            if (component.Components != null)
            {
                foreach (var nestedComponent in component.Components)
                {
                    AddComponent(nestedComponent, components);
                }
            }
        }

        private static ComponentChanges CompareComponents(
            List<ComponentSnapshot> fromComponents,
            List<ComponentSnapshot> toComponents)
        {
            var changes = new ComponentChanges();
            var fromByIdentity = GroupByIdentity(fromComponents);
            var toByIdentity = GroupByIdentity(toComponents);

            foreach (var identity in fromByIdentity.Keys.Union(toByIdentity.Keys))
            {
                fromByIdentity.TryGetValue(identity, out var fromMatches);
                toByIdentity.TryGetValue(identity, out var toMatches);

                var fromVersions = GetVersionSet(fromMatches);
                var toVersions = GetVersionSet(toMatches);

                if (fromVersions.Count == 0)
                {
                    changes.Added.AddRange(DistinctComponents(toMatches));
                    continue;
                }

                if (toVersions.Count == 0)
                {
                    changes.Removed.AddRange(DistinctComponents(fromMatches));
                    continue;
                }

                var removedVersions = fromVersions.Except(toVersions, StringComparer.Ordinal).ToList();
                var addedVersions = toVersions.Except(fromVersions, StringComparer.Ordinal).ToList();

                if (removedVersions.Count == 1 && addedVersions.Count == 1)
                {
                    continue;
                }

                changes.Removed.AddRange(DistinctComponents(fromMatches.Where(c => removedVersions.Contains(c.Version ?? string.Empty))));
                changes.Added.AddRange(DistinctComponents(toMatches.Where(c => addedVersions.Contains(c.Version ?? string.Empty))));
            }

            SortComponents(changes.Added);
            SortComponents(changes.Removed);
            return changes;
        }

        private static List<ComponentVersionChange> CompareVersions(
            List<ComponentSnapshot> fromComponents,
            List<ComponentSnapshot> toComponents)
        {
            var changes = new List<ComponentVersionChange>();
            var fromByIdentity = GroupByIdentity(fromComponents);
            var toByIdentity = GroupByIdentity(toComponents);

            foreach (var identity in fromByIdentity.Keys.Intersect(toByIdentity.Keys))
            {
                var fromVersions = GetVersionSet(fromByIdentity[identity]);
                var toVersions = GetVersionSet(toByIdentity[identity]);
                var removedVersions = fromVersions.Except(toVersions, StringComparer.Ordinal).ToList();
                var addedVersions = toVersions.Except(fromVersions, StringComparer.Ordinal).ToList();

                if (removedVersions.Count == 1 && addedVersions.Count == 1)
                {
                    var fromComponent = fromByIdentity[identity][0];
                    var toComponent = toByIdentity[identity][0];
                    changes.Add(new ComponentVersionChange
                    {
                        Type = toComponent.Type,
                        Group = toComponent.Group,
                        Name = toComponent.Name,
                        Purl = toComponent.Purl,
                        FromVersion = removedVersions[0],
                        ToVersion = addedVersions[0],
                    });
                }
            }

            changes.Sort((left, right) =>
                string.Compare(left.DisplayName, right.DisplayName, StringComparison.Ordinal));
            return changes;
        }

        private static DependencyChanges CompareDependencies(Bom fromBom, Bom toBom)
        {
            var fromEdges = GetDependencyEdges(fromBom);
            var toEdges = GetDependencyEdges(toBom);
            var changes = new DependencyChanges();

            foreach (var edge in fromEdges)
            {
                if (!toEdges.ContainsKey(edge.Key))
                {
                    changes.Removed.Add(edge.Value);
                }
            }

            foreach (var edge in toEdges)
            {
                if (!fromEdges.ContainsKey(edge.Key))
                {
                    changes.Added.Add(edge.Value);
                }
            }

            changes.Added.Sort((left, right) =>
                string.Compare(left.DisplayValue, right.DisplayValue, StringComparison.Ordinal));
            changes.Removed.Sort((left, right) =>
                string.Compare(left.DisplayValue, right.DisplayValue, StringComparison.Ordinal));
            return changes;
        }

        private static Dictionary<string, DependencyEdgeChange> GetDependencyEdges(Bom bom)
        {
            var edges = new Dictionary<string, DependencyEdgeChange>(StringComparer.Ordinal);
            if (bom.Dependencies == null) return edges;

            var componentsByRef = GetComponentsByRef(bom);

            foreach (var dependency in bom.Dependencies)
            {
                AddDependencyEdges(dependency, componentsByRef, edges);
            }

            return edges;
        }

        private static void AddDependencyEdges(
            Dependency dependency,
            Dictionary<string, ComponentSnapshot> componentsByRef,
            Dictionary<string, DependencyEdgeChange> edges)
        {
            if (dependency?.Dependencies == null) return;

            foreach (var child in dependency.Dependencies)
            {
                if (child == null) continue;

                var from = ResolveEndpoint(dependency.Ref, componentsByRef);
                var to = ResolveEndpoint(child.Ref, componentsByRef);
                var edgeKey = GetReferenceIdentity(dependency.Ref) + "\u0000" + GetReferenceIdentity(child.Ref);

                if (!edges.ContainsKey(edgeKey))
                {
                    edges[edgeKey] = new DependencyEdgeChange
                    {
                        From = from,
                        To = to,
                    };
                }

                AddDependencyEdges(child, componentsByRef, edges);
            }
        }

        private static Dictionary<string, ComponentSnapshot> GetComponentsByRef(Bom bom)
        {
            var components = new Dictionary<string, ComponentSnapshot>(StringComparer.Ordinal);
            var allComponents = CollectComponents(bom);

            foreach (var component in allComponents)
            {
                if (!string.IsNullOrEmpty(component.BomRef))
                {
                    components[component.BomRef] = component;
                }
                if (!string.IsNullOrEmpty(component.Purl))
                {
                    components[component.Purl] = component;
                }
            }

            return components;
        }

        private static DependencyEndpoint ResolveEndpoint(
            string reference,
            Dictionary<string, ComponentSnapshot> componentsByRef)
        {
            if (!string.IsNullOrEmpty(reference)
                && componentsByRef.TryGetValue(reference, out var component))
            {
                return new DependencyEndpoint
                {
                    Group = component.Group,
                    Name = component.Name,
                    Version = component.Version,
                    Purl = component.Purl,
                    Ref = reference,
                };
            }

            return new DependencyEndpoint
            {
                Ref = reference,
            };
        }

        private static List<NoiseChange> CompareNoise(Bom fromBom, Bom toBom)
        {
            var noise = new List<NoiseChange>();

            var fromTimestamp = fromBom.Metadata?.Timestamp;
            var toTimestamp = toBom.Metadata?.Timestamp;
            if (fromTimestamp != toTimestamp)
            {
                noise.Add(new NoiseChange
                {
                    Category = "metadata.timestamp",
                    ChangeType = "modified",
                    From = FormatTimestamp(fromTimestamp),
                    To = FormatTimestamp(toTimestamp),
                });
            }

            var fromTools = GetTools(fromBom);
            var toTools = GetTools(toBom);

            foreach (var toolIdentity in fromTools.Keys.Union(toTools.Keys))
            {
                fromTools.TryGetValue(toolIdentity, out var fromTool);
                toTools.TryGetValue(toolIdentity, out var toTool);

                if (fromTool == null)
                {
                    noise.Add(new NoiseChange
                    {
                        Category = "metadata.tools",
                        ChangeType = "added",
                        Name = toTool.Name,
                        To = toTool.Version,
                    });
                }
                else if (toTool == null)
                {
                    noise.Add(new NoiseChange
                    {
                        Category = "metadata.tools",
                        ChangeType = "removed",
                        Name = fromTool.Name,
                        From = fromTool.Version,
                    });
                }
                else if (!string.Equals(fromTool.Version, toTool.Version, StringComparison.Ordinal))
                {
                    noise.Add(new NoiseChange
                    {
                        Category = "metadata.tools",
                        ChangeType = "versionChanged",
                        Name = fromTool.Name,
                        From = fromTool.Version,
                        To = toTool.Version,
                    });
                }
            }

            noise.Sort((left, right) =>
                string.Compare(left.DisplayValue, right.DisplayValue, StringComparison.Ordinal));
            return noise;
        }

        private static Dictionary<string, ToolSnapshot> GetTools(Bom bom)
        {
            var tools = new Dictionary<string, ToolSnapshot>(StringComparer.Ordinal);
            var metadata = bom.Metadata;
            var toolChoices = metadata?.Tools;

            if (toolChoices?.Tools != null)
            {
                foreach (var tool in toolChoices.Tools)
                {
                    if (tool == null) continue;

                    AddTool(tools, tool.Vendor, tool.Name, tool.Version);
                }
            }

            if (toolChoices?.Components != null)
            {
                foreach (var component in toolChoices.Components)
                {
                    if (component == null) continue;

                    AddToolComponent(tools, component);
                }
            }

            if (metadata?.ProtobufTools != null)
            {
                foreach (var tool in metadata.ProtobufTools)
                {
                    if (tool == null) continue;

                    AddTool(tools, tool.Vendor, tool.Name, tool.Version);
                    if (tool.Components != null)
                    {
                        foreach (var component in tool.Components)
                        {
                            if (component == null) continue;

                            AddToolComponent(tools, component);
                        }
                    }
                }
            }

            return tools;
        }

        private static void AddTool(
            Dictionary<string, ToolSnapshot> tools,
            string vendor,
            string name,
            string version)
        {
            var identity = "tool:" + (vendor ?? string.Empty) + "/" + (name ?? string.Empty);
            tools[identity] = new ToolSnapshot
            {
                Name = string.IsNullOrEmpty(vendor) ? name : vendor + "/" + name,
                Version = version,
            };
        }

        private static void AddToolComponent(
            Dictionary<string, ToolSnapshot> tools,
            Component component)
        {
            var identity = GetComponentIdentity(component);
            tools[identity] = new ToolSnapshot
            {
                Name = component.Name,
                Version = component.Version,
            };
        }

        private static Dictionary<string, List<ComponentSnapshot>> GroupByIdentity(
            List<ComponentSnapshot> components)
        {
            var grouped = new Dictionary<string, List<ComponentSnapshot>>(StringComparer.Ordinal);

            foreach (var component in components)
            {
                var identity = GetComponentIdentity(component);
                if (!grouped.TryGetValue(identity, out var matches))
                {
                    matches = new List<ComponentSnapshot>();
                    grouped[identity] = matches;
                }
                matches.Add(component);
            }

            return grouped;
        }

        private static HashSet<string> GetVersionSet(List<ComponentSnapshot> components)
        {
            if (components == null) return new HashSet<string>(StringComparer.Ordinal);
            return new HashSet<string>(
                components.Select(component => component.Version ?? string.Empty),
                StringComparer.Ordinal);
        }

        private static List<ComponentSnapshot> DistinctComponents(IEnumerable<ComponentSnapshot> components)
        {
            return components
                .GroupBy(component => GetComponentIdentity(component) + "\u0000" + (component.Version ?? string.Empty))
                .Select(group => group.First())
                .ToList();
        }

        private static void SortComponents(List<ComponentSnapshot> components)
        {
            components.Sort((left, right) =>
                string.Compare(left.DisplayName, right.DisplayName, StringComparison.Ordinal));
        }

        private static string GetComponentIdentity(ComponentSnapshot component)
        {
            return GetComponentIdentity(component.Purl, component.Group, component.Name, component.BomRef);
        }

        private static string GetComponentIdentity(Component component)
        {
            return GetComponentIdentity(component.Purl, component.Group, component.Name, component.BomRef);
        }

        private static string GetComponentIdentity(
            string purl,
            string group,
            string name,
            string bomRef)
        {
            if (!string.IsNullOrWhiteSpace(purl))
            {
                return "purl:" + StripPurlVersion(purl.Trim());
            }

            if (!string.IsNullOrWhiteSpace(name))
            {
                return "component:" + (group?.Trim() ?? string.Empty) + "/" + name.Trim();
            }

            if (!string.IsNullOrWhiteSpace(bomRef))
            {
                return "bom-ref:" + bomRef.Trim();
            }

            return "component:unknown";
        }

        private static string GetReferenceIdentity(string reference)
        {
            if (string.IsNullOrWhiteSpace(reference)) return string.Empty;
            if (reference.StartsWith("pkg:", StringComparison.OrdinalIgnoreCase))
            {
                return "purl:" + StripPurlVersion(reference.Trim());
            }

            return reference.Trim();
        }

        private static string StripPurlVersion(string purl)
        {
            var suffixIndex = purl.IndexOf('?', StringComparison.Ordinal);
            if (suffixIndex < 0)
            {
                suffixIndex = purl.IndexOf('#', StringComparison.Ordinal);
            }
            var coreEnd = suffixIndex < 0 ? purl.Length : suffixIndex;
            var schemeSeparator = purl.IndexOf('/', StringComparison.Ordinal);

            if (schemeSeparator < 0 || schemeSeparator >= coreEnd) return purl;

            var atIndex = purl.LastIndexOf('@', coreEnd - 1, coreEnd - schemeSeparator);
            if (atIndex <= schemeSeparator) return purl;

            return purl.Remove(atIndex, coreEnd - atIndex);
        }

        private static string FormatTimestamp(DateTime? timestamp)
        {
            return timestamp?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
        }

        private sealed class ToolSnapshot
        {
            public string Name { get; set; }
            public string Version { get; set; }
        }
    }
}
