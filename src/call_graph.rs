//! Call graphs from disassembly and symbols.
//!
//! Entry points for callers:
//! - [`call_graph_for_path`]: path in, bounded [`CallGraphReport`] out (does the
//!   symbol, disassembly and graph steps itself).
//! - [`summarize_call_graph`]: bound an existing [`CallGraph`] (for example one
//!   built with [`generate_call_graph`] from an already cached disassembly).
#![allow(dead_code)]
use crate::disassembly::{DisassemblyResult, FlowControl};
use crate::function_analysis::SymbolTable;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

/// Represents a complete call graph for analyzed binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraph {
    pub nodes: Vec<CallGraphNode>,
    pub edges: Vec<CallGraphEdge>,
    pub entry_points: Vec<u64>,
    pub unreachable_functions: Vec<u64>,
    pub statistics: CallGraphStatistics,
}

/// Individual node in the call graph representing a function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphNode {
    pub function_address: u64,
    pub function_name: String,
    pub node_type: NodeType,
    pub complexity: u32,
    pub in_degree: u32,  // Number of callers
    pub out_degree: u32, // Number of callees
    pub is_recursive: bool,
    pub call_depth: Option<u32>, // Distance from entry point
}

/// Type of node in the call graph
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeType {
    EntryPoint,
    Library,
    Internal,
    External,
    Indirect,
    Virtual,
    Unknown,
}

/// Edge representing a function call relationship
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphEdge {
    pub caller: u64,
    pub callee: u64,
    pub call_type: CallType,
    pub call_sites: Vec<u64>, // Addresses where calls occur
    pub weight: u32,          // Number of call sites
}

/// Type of function call
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CallType {
    Direct,
    Indirect,
    Virtual,
    Conditional,
    TailCall,
}

/// Statistics about the call graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphStatistics {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub max_depth: u32,
    pub unreachable_count: usize,
    pub recursive_functions: usize,
    pub leaf_functions: usize,
    pub root_functions: usize,
    pub avg_in_degree: f64,
    pub avg_out_degree: f64,
    pub strongly_connected_components: usize,
}

/// Generates a complete call graph from disassembly and symbol information
#[allow(dead_code)]
pub fn generate_call_graph(
    path: &Path,
    disassembly: &DisassemblyResult,
    symbols: &SymbolTable,
) -> Result<CallGraph> {
    generate_call_graph_with_arch(path, None, disassembly, symbols)
}

/// Like [`generate_call_graph`] for a universal (fat) Mach-O: imports are
/// resolved in the slice named by `arch`.
#[allow(dead_code)]
pub fn generate_call_graph_with_arch(
    path: &Path,
    arch: Option<&str>,
    disassembly: &DisassemblyResult,
    symbols: &SymbolTable,
) -> Result<CallGraph> {
    let mut graph_builder = CallGraphBuilder::new();

    // Stubs and table slots of imported functions, by address.
    let import_targets: HashMap<u64, String> = std::fs::read(path)
        .map(|buffer| crate::control_flow::resolve_import_targets_with_arch(&buffer, arch))
        .unwrap_or_default();

    // Build initial nodes from symbol table
    for function in &symbols.functions {
        graph_builder.add_node(
            function.address,
            function.name.clone(),
            if function.is_entry_point {
                NodeType::EntryPoint
            } else if function.is_imported {
                NodeType::Library
            } else {
                NodeType::Internal
            },
        );
    }
    for (address, name) in &import_targets {
        let name = name.split('@').next().unwrap_or(name);
        graph_builder.add_node(*address, format!("{name}@plt"), NodeType::External);
    }

    // Sized functions sorted by start, for locating the function of an
    // instruction by binary search (the old linear scan per instruction was
    // quadratic on large binaries).
    // PE and Mach-O symbols carry no size: such a function runs to the next
    // function symbol (as disassembly's function grouping does).
    let code_end = disassembly
        .instructions
        .last()
        .map_or(0, |i| i.address.saturating_add(i.size as u64));
    let mut starts: Vec<(u64, u64)> = symbols
        .functions
        .iter()
        .filter(|f| !f.is_imported)
        .map(|f| (f.address, f.size))
        .collect();
    starts.sort_unstable_by_key(|(address, size)| (*address, std::cmp::Reverse(*size)));
    starts.dedup_by_key(|(address, _)| *address);
    let mut ranges: Vec<(u64, u64, u64)> = Vec::with_capacity(starts.len());
    for (i, (address, size)) in starts.iter().enumerate() {
        let end = if *size > 0 {
            address.saturating_add(*size)
        } else {
            starts.get(i + 1).map_or(code_end, |(next, _)| *next)
        };
        if end > *address {
            ranges.push((*address, end, *address));
        }
    }
    ranges.sort_unstable();
    let function_at = |address: u64| -> Option<u64> {
        let idx = ranges.partition_point(|(start, _, _)| *start <= address);
        ranges[..idx]
            .iter()
            .rev()
            .take(8)
            .find(|(start, end, _)| address >= *start && address < *end)
            .map(|(_, _, func)| *func)
    };
    let function_starts: HashSet<u64> = symbols.functions.iter().map(|f| f.address).collect();

    // Analyze instructions to find call relationships
    let mut current_function = None;

    for instruction in &disassembly.instructions {
        // Track current function based on address
        if let Some(func) = function_at(instruction.address) {
            current_function = Some(func);
        }

        // Look for call instructions
        match &instruction.flow_control {
            Some(FlowControl::Call {
                target,
                is_indirect,
            }) => {
                if let Some(caller) = current_function {
                    if *is_indirect {
                        // A call through a known import slot is a call to that import.
                        let slot = crate::control_flow::indirect_slot_address(
                            &instruction.operands,
                            instruction.address,
                            instruction.size,
                        )
                        .filter(|slot| import_targets.contains_key(slot));
                        if let Some(slot) = slot {
                            graph_builder.add_edge(
                                caller,
                                slot,
                                CallType::Direct,
                                instruction.address,
                            );
                            continue;
                        }
                        // Create placeholder for indirect call
                        let indirect_addr = 0xFFFF_FFFF_0000_0000 | instruction.address;
                        graph_builder.add_node(
                            indirect_addr,
                            format!("indirect_call_{:x}", instruction.address),
                            NodeType::Indirect,
                        );
                        graph_builder.add_edge(
                            caller,
                            indirect_addr,
                            CallType::Indirect,
                            instruction.address,
                        );
                    } else if let Some(target_addr) = target {
                        graph_builder.add_edge(
                            caller,
                            *target_addr,
                            CallType::Direct,
                            instruction.address,
                        );
                    }
                }
            }
            Some(FlowControl::Jump {
                target,
                conditional,
            }) => {
                // Check if this might be a tail call optimization
                if let (Some(caller), Some(target_addr), false) =
                    (current_function, target, conditional)
                {
                    if *target_addr != caller
                        && (function_starts.contains(target_addr)
                            || import_targets.contains_key(target_addr))
                    {
                        // This could be a tail call
                        graph_builder.add_edge(
                            caller,
                            *target_addr,
                            CallType::TailCall,
                            instruction.address,
                        );
                    }
                }
            }
            _ => {}
        }
    }

    // Check for dynamic/PLT calls in imports
    for import in &symbols.imports {
        if let Some(addr) = import.address {
            graph_builder.add_node(addr, format!("{}@plt", import.name), NodeType::External);
        }
    }

    // Build the final graph
    let mut graph = graph_builder.build();

    // Detect entry points
    graph.detect_entry_points(symbols);

    // Find unreachable functions
    graph.find_unreachable_functions();

    // Detect recursive functions
    graph.detect_recursive_functions();

    // Calculate call depths from entry points
    graph.calculate_call_depths();

    // Calculate statistics
    graph.calculate_statistics();

    Ok(graph)
}

struct CallGraphBuilder {
    nodes: HashMap<u64, CallGraphNode>,
    edges: Vec<CallGraphEdge>,
    edge_map: HashMap<(u64, u64), usize>, // (caller, callee) -> edge index
}

impl CallGraphBuilder {
    fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            edge_map: HashMap::new(),
        }
    }

    fn add_node(&mut self, address: u64, name: String, node_type: NodeType) {
        self.nodes.entry(address).or_insert(CallGraphNode {
            function_address: address,
            function_name: name,
            node_type,
            complexity: 0,
            in_degree: 0,
            out_degree: 0,
            is_recursive: false,
            call_depth: None,
        });
    }

    fn add_edge(
        &mut self,
        caller_addr: u64,
        callee_addr: u64,
        call_type: CallType,
        call_site: u64,
    ) {
        let key = (caller_addr, callee_addr);

        if let Some(&edge_idx) = self.edge_map.get(&key) {
            // Edge exists, add call site
            self.edges[edge_idx].call_sites.push(call_site);
            self.edges[edge_idx].weight = self.edges[edge_idx].weight.saturating_add(1);
        } else {
            // New edge
            let edge_idx = self.edges.len();
            self.edges.push(CallGraphEdge {
                caller: caller_addr,
                callee: callee_addr,
                call_type,
                call_sites: vec![call_site],
                weight: 1,
            });
            self.edge_map.insert(key, edge_idx);
        }

        // Update degrees
        if let Some(caller_node) = self.nodes.get_mut(&caller_addr) {
            caller_node.out_degree = caller_node.out_degree.saturating_add(1);
        }
        if let Some(callee_node) = self.nodes.get_mut(&callee_addr) {
            callee_node.in_degree = callee_node.in_degree.saturating_add(1);
        }
    }

    fn build(self) -> CallGraph {
        CallGraph {
            nodes: self.nodes.into_values().collect(),
            edges: self.edges,
            entry_points: Vec::new(),
            unreachable_functions: Vec::new(),
            statistics: CallGraphStatistics {
                total_nodes: 0,
                total_edges: 0,
                max_depth: 0,
                unreachable_count: 0,
                recursive_functions: 0,
                leaf_functions: 0,
                root_functions: 0,
                avg_in_degree: 0.0,
                avg_out_degree: 0.0,
                strongly_connected_components: 0,
            },
        }
    }
}

impl CallGraph {
    fn detect_entry_points(&mut self, symbols: &SymbolTable) {
        // Entry points from symbol table
        for function in &symbols.functions {
            if function.is_entry_point {
                self.entry_points.push(function.address);
            }
        }

        // Also consider functions with no callers as potential entry points
        let mut seen: HashSet<u64> = self.entry_points.iter().copied().collect();
        for node in &self.nodes {
            if node.in_degree == 0
                && node.node_type == NodeType::Internal
                && seen.insert(node.function_address)
            {
                self.entry_points.push(node.function_address);
            }
        }
    }

    fn find_unreachable_functions(&mut self) {
        let mut reachable = HashSet::new();
        let mut queue = VecDeque::new();

        // Start from all entry points
        for &entry in &self.entry_points {
            queue.push_back(entry);
            reachable.insert(entry);
        }

        let adjacency = self.adjacency();

        // BFS to find all reachable functions
        while let Some(current) = queue.pop_front() {
            for &callee in adjacency.get(&current).into_iter().flatten() {
                if reachable.insert(callee) {
                    queue.push_back(callee);
                }
            }
        }

        // Find unreachable functions
        self.unreachable_functions = self
            .nodes
            .iter()
            .filter(|node| !reachable.contains(&node.function_address))
            .map(|node| node.function_address)
            .collect();
    }

    fn adjacency(&self) -> HashMap<u64, Vec<u64>> {
        let mut adjacency: HashMap<u64, Vec<u64>> = HashMap::new();
        for edge in &self.edges {
            adjacency.entry(edge.caller).or_default().push(edge.callee);
        }
        adjacency
    }

    fn detect_recursive_functions(&mut self) {
        let adjacency = self.adjacency();

        // Iterative DFS (an explicit stack: call chains in large binaries are
        // deep enough to overflow the thread stack with recursion).
        let mut visited: HashSet<u64> = HashSet::new();
        let mut on_stack: HashSet<u64> = HashSet::new();
        let mut recursive_funcs: HashSet<u64> = HashSet::new();

        for node in &self.nodes {
            if visited.contains(&node.function_address) {
                continue;
            }
            visited.insert(node.function_address);
            on_stack.insert(node.function_address);
            let mut stack: Vec<(u64, usize)> = vec![(node.function_address, 0)];
            while let Some((current, next_index)) = stack.last().copied() {
                let neighbors = adjacency.get(&current).map_or(&[][..], Vec::as_slice);
                if let Some(&neighbor) = neighbors.get(next_index) {
                    if let Some(top) = stack.last_mut() {
                        top.1 += 1;
                    }
                    if !visited.contains(&neighbor) {
                        visited.insert(neighbor);
                        on_stack.insert(neighbor);
                        stack.push((neighbor, 0));
                    } else if on_stack.contains(&neighbor) {
                        // Found a cycle
                        recursive_funcs.insert(neighbor);
                        recursive_funcs.insert(current);
                    }
                } else {
                    on_stack.remove(&current);
                    stack.pop();
                }
            }
        }

        // Mark recursive functions
        for node in &mut self.nodes {
            if recursive_funcs.contains(&node.function_address) {
                node.is_recursive = true;
            }
        }
    }

    fn calculate_call_depths(&mut self) {
        let mut depths: HashMap<u64, u32> = HashMap::new();
        let mut queue = VecDeque::new();

        let adjacency = self.adjacency();

        // Initialize entry points with depth 0
        for &entry in &self.entry_points {
            depths.insert(entry, 0);
            queue.push_back((entry, 0u32));
        }

        // BFS to calculate depths
        while let Some((current, depth)) = queue.pop_front() {
            for &callee in adjacency.get(&current).into_iter().flatten() {
                let new_depth = depth.saturating_add(1);

                // Update if we found a shorter path or first path
                let should_update = depths.get(&callee).is_none_or(|&d| new_depth < d);

                if should_update {
                    depths.insert(callee, new_depth);
                    queue.push_back((callee, new_depth));
                }
            }
        }

        // Update nodes with calculated depths
        for node in &mut self.nodes {
            node.call_depth = depths.get(&node.function_address).copied();
        }
    }

    fn calculate_statistics(&mut self) {
        let total_nodes = self.nodes.len();
        let total_edges = self.edges.len();

        let max_depth = self
            .nodes
            .iter()
            .filter_map(|n| n.call_depth)
            .max()
            .unwrap_or(0);

        let recursive_functions = self.nodes.iter().filter(|n| n.is_recursive).count();

        let leaf_functions = self.nodes.iter().filter(|n| n.out_degree == 0).count();

        let root_functions = self.nodes.iter().filter(|n| n.in_degree == 0).count();

        let total_in_degree: u64 = self.nodes.iter().map(|n| u64::from(n.in_degree)).sum();

        let total_out_degree: u64 = self.nodes.iter().map(|n| u64::from(n.out_degree)).sum();

        let avg_in_degree = if total_nodes > 0 {
            total_in_degree as f64 / total_nodes as f64
        } else {
            0.0
        };

        let avg_out_degree = if total_nodes > 0 {
            total_out_degree as f64 / total_nodes as f64
        } else {
            0.0
        };

        // Simple SCC count (could be improved with Tarjan's algorithm)
        let strongly_connected_components = self.count_sccs();

        self.statistics = CallGraphStatistics {
            total_nodes,
            total_edges,
            max_depth,
            unreachable_count: self.unreachable_functions.len(),
            recursive_functions,
            leaf_functions,
            root_functions,
            avg_in_degree,
            avg_out_degree,
            strongly_connected_components,
        };
    }

    fn count_sccs(&self) -> usize {
        // Simplified SCC counting - just count recursive functions
        // as each forms at least one SCC
        // A full implementation would use Tarjan's or Kosaraju's algorithm
        self.nodes.iter().filter(|n| n.is_recursive).count().max(1)
    }

    /// Generate visualization data for the call graph (e.g., for Graphviz)
    pub fn to_dot(&self) -> String {
        let mut dot = String::from("digraph CallGraph {\n");
        dot.push_str("  rankdir=LR;\n");
        dot.push_str("  node [shape=box];\n");

        // Define nodes with styling
        for node in &self.nodes {
            let color = match node.node_type {
                NodeType::EntryPoint => "green",
                NodeType::Library => "lightblue",
                NodeType::Internal => "white",
                NodeType::External => "gray",
                NodeType::Indirect => "yellow",
                NodeType::Virtual => "orange",
                NodeType::Unknown => "red",
            };

            let style = if node.is_recursive {
                "filled,bold"
            } else if self.unreachable_functions.contains(&node.function_address) {
                "filled,dashed"
            } else {
                "filled"
            };

            dot.push_str(&format!(
                "  \"{}\" [label=\"{}\\n{:x}\", style=\"{}\", fillcolor=\"{}\"];\n",
                node.function_address, node.function_name, node.function_address, style, color
            ));
        }

        // Define edges
        for edge in &self.edges {
            let style = match edge.call_type {
                CallType::Direct => "solid",
                CallType::Indirect => "dashed",
                CallType::Virtual => "dotted",
                CallType::Conditional => "dashed",
                CallType::TailCall => "tapered",
            };

            dot.push_str(&format!(
                "  \"{}\" -> \"{}\" [style=\"{}\", label=\"{}\"];\n",
                edge.caller, edge.callee, style, edge.weight
            ));
        }

        dot.push_str("}\n");
        dot
    }
}

/// Most nodes and edges a [`CallGraphReport`] carries.
pub const MAX_REPORT_NODES: usize = 5_000;
pub const MAX_REPORT_EDGES: usize = 20_000;
/// Most call sites kept per edge in a report.
pub const MAX_CALL_SITES_PER_EDGE: usize = 8;

/// A call graph cut to a bounded size, plus what was cut.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphReport {
    /// The graph. Nodes are the `MAX_REPORT_NODES` with the most calls in or out
    /// (all of them when fewer), edges only between kept nodes (at most
    /// `MAX_REPORT_EDGES`, heaviest first), call sites per edge limited.
    /// `statistics` always describe the full graph.
    pub graph: CallGraph,
    pub nodes_total: usize,
    pub edges_total: usize,
    pub truncated: bool,
    /// What was cut, if anything.
    pub notes: Vec<String>,
}

/// Build the call graph of the binary at `path` and bound it.
///
/// Reads the file, analyzes its symbols, disassembles its code section and
/// builds the graph. Calls to imported functions appear as `External` nodes named
/// `<name>@plt`. Works for ELF, PE and Mach-O files the disassembler supports
/// (x86, x86-64, ARM, ARM64) that carry function symbols for their code; a
/// binary without them (stripped, or most PE files, whose symbols are imports
/// only) yields no edges and a note saying so. Mach-O import names keep their
/// leading underscore. Other files return an error that names the problem.
pub fn call_graph_for_path(path: &Path) -> Result<CallGraphReport> {
    call_graph_for_path_with_arch(path, None)
}

/// Like [`call_graph_for_path`] for a universal (fat) Mach-O: the slice named
/// by `arch` (for example `"arm64"`) is analyzed; `None` picks the host
/// architecture if present, else the first slice.
pub fn call_graph_for_path_with_arch(path: &Path, arch: Option<&str>) -> Result<CallGraphReport> {
    let symbols = crate::function_analysis::analyze_symbols_with_arch(path, arch)?;
    let (disassembly, _) = crate::disassembly::disassemble_binary_with_arch(path, arch, &symbols)?;
    let calls = disassembly
        .instructions
        .iter()
        .filter(|i| matches!(i.flow_control, Some(FlowControl::Call { .. })))
        .count();
    let graph = generate_call_graph_with_arch(path, arch, &disassembly, &symbols)?;
    let no_edges = graph.edges.is_empty();
    let mut report = summarize_call_graph(graph);
    if no_edges && calls > 0 {
        report.notes.push(format!(
            "the code has {calls} call instructions but none could be attributed to a function: the file has no function symbols for its code (stripped), so the graph has no edges"
        ));
    }
    Ok(report)
}

/// Bound `graph` to `MAX_REPORT_NODES` nodes and `MAX_REPORT_EDGES` edges.
pub fn summarize_call_graph(mut graph: CallGraph) -> CallGraphReport {
    let nodes_total = graph.nodes.len();
    let edges_total = graph.edges.len();
    let mut notes = Vec::new();

    if nodes_total > MAX_REPORT_NODES {
        graph.nodes.sort_by(|a, b| {
            let degree = |n: &CallGraphNode| u64::from(n.in_degree) + u64::from(n.out_degree);
            degree(b)
                .cmp(&degree(a))
                .then(a.function_address.cmp(&b.function_address))
        });
        graph.nodes.truncate(MAX_REPORT_NODES);
        let kept: HashSet<u64> = graph.nodes.iter().map(|n| n.function_address).collect();
        graph
            .edges
            .retain(|e| kept.contains(&e.caller) && kept.contains(&e.callee));
        graph.unreachable_functions.retain(|a| kept.contains(a));
        graph.entry_points.retain(|a| kept.contains(a));
        notes.push(format!(
            "kept the {MAX_REPORT_NODES} of {nodes_total} nodes with the most calls in or out"
        ));
    } else {
        graph.nodes.sort_by_key(|n| n.function_address);
    }
    if graph.edges.len() > MAX_REPORT_EDGES {
        graph
            .edges
            .sort_by(|a, b| b.weight.cmp(&a.weight).then(a.caller.cmp(&b.caller)));
        graph.edges.truncate(MAX_REPORT_EDGES);
        notes.push(format!(
            "kept the {MAX_REPORT_EDGES} heaviest of {edges_total} edges"
        ));
    }
    let mut sites_cut = false;
    for edge in &mut graph.edges {
        if edge.call_sites.len() > MAX_CALL_SITES_PER_EDGE {
            edge.call_sites.truncate(MAX_CALL_SITES_PER_EDGE);
            sites_cut = true;
        }
    }
    if sites_cut {
        notes.push(format!(
            "call_sites lists the first {MAX_CALL_SITES_PER_EDGE} sites of an edge; weight is the real count"
        ));
    }

    CallGraphReport {
        truncated: !notes.is_empty(),
        graph,
        nodes_total,
        edges_total,
        notes,
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_call_graph_generation() {
        // Placeholder test - basic smoke test
        let graph = CallGraph {
            nodes: Vec::new(),
            edges: Vec::new(),
            entry_points: Vec::new(),
            unreachable_functions: Vec::new(),
            statistics: CallGraphStatistics {
                total_nodes: 0,
                total_edges: 0,
                max_depth: 0,
                unreachable_count: 0,
                recursive_functions: 0,
                leaf_functions: 0,
                root_functions: 0,
                avg_in_degree: 0.0,
                avg_out_degree: 0.0,
                strongly_connected_components: 0,
            },
        };
        assert_eq!(graph.nodes.len(), 0);
    }
}
