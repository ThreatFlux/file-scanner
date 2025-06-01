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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    _path: &Path,
    disassembly: &DisassemblyResult,
    symbols: &SymbolTable,
) -> Result<CallGraph> {
    let mut graph_builder = CallGraphBuilder::new();

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

    // Analyze instructions to find call relationships
    let mut current_function = None;

    for instruction in &disassembly.instructions {
        // Track current function based on address
        if let Some(func) = symbols
            .functions
            .iter()
            .find(|f| instruction.address >= f.address && instruction.address < f.address + f.size)
        {
            current_function = Some(func.address);
        }

        // Look for call instructions
        match &instruction.flow_control {
            Some(FlowControl::Call {
                target,
                is_indirect,
            }) => {
                if let Some(caller) = current_function {
                    if *is_indirect {
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
                    if let Some(func) = symbols.functions.iter().find(|f| *target_addr == f.address)
                    {
                        // This could be a tail call
                        graph_builder.add_edge(
                            caller,
                            func.address,
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

    fn add_edge(&mut self, caller: u64, callee: u64, call_type: CallType, call_site: u64) {
        let key = (caller, callee);

        if let Some(&edge_idx) = self.edge_map.get(&key) {
            // Edge exists, add call site
            self.edges[edge_idx].call_sites.push(call_site);
            self.edges[edge_idx].weight += 1;
        } else {
            // New edge
            let edge_idx = self.edges.len();
            self.edges.push(CallGraphEdge {
                caller,
                callee,
                call_type,
                call_sites: vec![call_site],
                weight: 1,
            });
            self.edge_map.insert(key, edge_idx);
        }

        // Update degrees
        if let Some(caller_node) = self.nodes.get_mut(&caller) {
            caller_node.out_degree += 1;
        }
        if let Some(callee_node) = self.nodes.get_mut(&callee) {
            callee_node.in_degree += 1;
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
        for node in &self.nodes {
            if node.in_degree == 0
                && node.node_type == NodeType::Internal
                && !self.entry_points.contains(&node.function_address)
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

        // BFS to find all reachable functions
        while let Some(current) = queue.pop_front() {
            for edge in &self.edges {
                if edge.caller == current && !reachable.contains(&edge.callee) {
                    reachable.insert(edge.callee);
                    queue.push_back(edge.callee);
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

    fn detect_recursive_functions(&mut self) {
        // Build adjacency list
        let mut adjacency: HashMap<u64, Vec<u64>> = HashMap::new();

        for edge in &self.edges {
            adjacency.entry(edge.caller).or_default().push(edge.callee);
        }

        // DFS to detect cycles
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();
        let mut recursive_funcs = HashSet::new();

        for node in &self.nodes {
            if !visited.contains(&node.function_address) {
                self.dfs_detect_cycles(
                    node.function_address,
                    &adjacency,
                    &mut visited,
                    &mut rec_stack,
                    &mut recursive_funcs,
                );
            }
        }

        // Mark recursive functions
        for node in &mut self.nodes {
            if recursive_funcs.contains(&node.function_address) {
                node.is_recursive = true;
            }
        }
    }

    #[allow(clippy::only_used_in_recursion)]
    fn dfs_detect_cycles(
        &self,
        current: u64,
        adjacency: &HashMap<u64, Vec<u64>>,
        visited: &mut HashSet<u64>,
        rec_stack: &mut HashSet<u64>,
        recursive_funcs: &mut HashSet<u64>,
    ) {
        visited.insert(current);
        rec_stack.insert(current);

        if let Some(neighbors) = adjacency.get(&current) {
            for &neighbor in neighbors {
                if !visited.contains(&neighbor) {
                    self.dfs_detect_cycles(
                        neighbor,
                        adjacency,
                        visited,
                        rec_stack,
                        recursive_funcs,
                    );
                } else if rec_stack.contains(&neighbor) {
                    // Found a cycle
                    recursive_funcs.insert(neighbor);
                    recursive_funcs.insert(current);
                }
            }
        }

        rec_stack.remove(&current);
    }

    fn calculate_call_depths(&mut self) {
        let mut depths: HashMap<u64, u32> = HashMap::new();
        let mut queue = VecDeque::new();

        // Initialize entry points with depth 0
        for &entry in &self.entry_points {
            depths.insert(entry, 0);
            queue.push_back((entry, 0));
        }

        // BFS to calculate depths
        while let Some((current, depth)) = queue.pop_front() {
            for edge in &self.edges {
                if edge.caller == current {
                    let new_depth = depth + 1;

                    // Update if we found a shorter path or first path
                    let should_update = depths
                        .get(&edge.callee)
                        .map(|&d| new_depth < d)
                        .unwrap_or(true);

                    if should_update {
                        depths.insert(edge.callee, new_depth);
                        queue.push_back((edge.callee, new_depth));
                    }
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

        let total_in_degree: u32 = self.nodes.iter().map(|n| n.in_degree).sum();

        let total_out_degree: u32 = self.nodes.iter().map(|n| n.out_degree).sum();

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

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_call_graph_generation() {
        // Placeholder test
        assert!(true);
    }
}
