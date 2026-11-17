#![allow(missing_docs)]
//! Control Flow Graph (CFG) construction and analysis.
//!
//! Builds a Control Flow Graph (CFG) from Solidity AST to enable:
//! - Execution path analysis
//! - Vulnerability detection across execution flows
//! - Data flow tracking through branches
//! - Loop detection and analysis

use crate::ast::AstFunction;
use crate::errors::{AnalysisError, AnalysisResult};
use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

/// A basic block in the control flow graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    /// Unique identifier for this block.
    pub id: usize,
    /// Statements in this block.
    pub statements: Vec<Statement>,
    /// Block dominates other blocks.
    pub dominates: Vec<usize>,
    /// Block is dominated by these blocks.
    pub dominated_by: Vec<usize>,
    /// Is this a loop header.
    pub is_loop_header: bool,
    /// Is this an exit block.
    pub is_exit: bool,
}

impl BasicBlock {
    /// Create a new basic block.
    pub fn new(id: usize) -> Self {
        Self {
            id,
            statements: Vec::new(),
            dominates: Vec::new(),
            dominated_by: Vec::new(),
            is_loop_header: false,
            is_exit: false,
        }
    }

    /// Add a statement to this block.
    pub fn add_statement(&mut self, stmt: Statement) {
        self.statements.push(stmt);
    }
}

/// Statement in a basic block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Statement {
    /// Variable assignment.
    Assignment { target: String, value: String },
    /// Conditional branch.
    Branch { condition: String },
    /// State mutation.
    StateMutation { variable: String, value: String },
    /// Function call.
    FunctionCall { function: String, args: Vec<String> },
    /// Return statement.
    Return { value: Option<String> },
    /// Generic statement.
    Generic { code: String },
}

/// Control Flow Graph for a function.
#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    /// Directed graph of basic blocks.
    graph: DiGraph<BasicBlock, String>,
    /// Map from block ID to node index.
    block_map: HashMap<usize, NodeIndex>,
    /// Entry block ID.
    entry_block: usize,
    /// Exit blocks.
    exit_blocks: Vec<usize>,
    /// Next block ID to assign.
    next_id: usize,
}

impl ControlFlowGraph {
    /// Create a new CFG for a function.
    pub fn new() -> Self {
        let mut cfg = Self {
            graph: DiGraph::new(),
            block_map: HashMap::new(),
            entry_block: 0,
            exit_blocks: Vec::new(),
            next_id: 0,
        };

        // Create entry block
        let entry = cfg.new_block();
        cfg.entry_block = entry;

        cfg
    }

    /// Create a new basic block in the CFG.
    pub fn new_block(&mut self) -> usize {
        let id = self.next_id;
        self.next_id += 1;

        let block = BasicBlock::new(id);
        let node_idx = self.graph.add_node(block);
        self.block_map.insert(id, node_idx);

        id
    }

    /// Add an edge from one block to another.
    pub fn add_edge(
        &mut self,
        from: usize,
        to: usize,
        label: impl Into<String>,
    ) -> AnalysisResult<()> {
        let from_idx = self
            .block_map
            .get(&from)
            .copied()
            .ok_or_else(|| AnalysisError::cfg("Block not found"))?;

        let to_idx = self
            .block_map
            .get(&to)
            .copied()
            .ok_or_else(|| AnalysisError::cfg("Target block not found"))?;

        self.graph.add_edge(from_idx, to_idx, label.into());
        Ok(())
    }

    /// Add a statement to a block.
    pub fn add_statement(&mut self, block_id: usize, stmt: Statement) -> AnalysisResult<()> {
        let node_idx = self
            .block_map
            .get(&block_id)
            .copied()
            .ok_or_else(|| AnalysisError::cfg("Block not found"))?;

        if let Some(block) = self.graph.node_weight_mut(node_idx) {
            block.add_statement(stmt);
            Ok(())
        } else {
            Err(AnalysisError::cfg("Failed to get block"))
        }
    }

    /// Mark a block as an exit block.
    pub fn mark_exit(&mut self, block_id: usize) -> AnalysisResult<()> {
        let node_idx = self
            .block_map
            .get(&block_id)
            .copied()
            .ok_or_else(|| AnalysisError::cfg("Block not found"))?;

        if let Some(block) = self.graph.node_weight_mut(node_idx) {
            block.is_exit = true;
            self.exit_blocks.push(block_id);
            Ok(())
        } else {
            Err(AnalysisError::cfg("Failed to get block"))
        }
    }

    /// Compute dominance relationships.
    pub fn compute_dominance(&mut self) -> AnalysisResult<()> {
        info!("Computing dominance relationships for CFG");

        // Entry block dominates all reachable blocks
        self.compute_dominators()?;

        // Compute dominated_by relationships
        let dominators: HashMap<usize, Vec<usize>> = self
            .block_map
            .iter()
            .map(|(&id, &idx)| {
                let dominates = self
                    .graph
                    .node_weight(idx)
                    .map(|b| b.dominates.clone())
                    .unwrap_or_default();
                (id, dominates)
            })
            .collect();

        for (dominator_id, dominated_blocks) in dominators {
            for dominated_id in dominated_blocks {
                let node_idx = self
                    .block_map
                    .get(&dominated_id)
                    .copied()
                    .ok_or_else(|| AnalysisError::cfg("Block not found"))?;

                if let Some(block) = self.graph.node_weight_mut(node_idx) {
                    block.dominated_by.push(dominator_id);
                }
            }
        }

        Ok(())
    }

    /// Compute immediate dominators using iterative algorithm.
    fn compute_dominators(&mut self) -> AnalysisResult<()> {
        let blocks: Vec<usize> = self.block_map.keys().copied().collect();

        if blocks.is_empty() {
            return Ok(());
        }

        // Initialize: everyone is dominated by all blocks
        let mut dominators: HashMap<usize, Vec<usize>> =
            blocks.iter().map(|&id| (id, blocks.clone())).collect();

        // Entry block only dominates itself
        if let Some(entry_doms) = dominators.get_mut(&self.entry_block) {
            entry_doms.clear();
            entry_doms.push(self.entry_block);
        }

        // Iterate until fixpoint
        let mut changed = true;
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 100;

        while changed && iterations < MAX_ITERATIONS {
            changed = false;
            iterations += 1;

            for &block_id in &blocks {
                if block_id == self.entry_block {
                    continue;
                }

                // Find predecessors
                let node_idx = self
                    .block_map
                    .get(&block_id)
                    .copied()
                    .ok_or_else(|| AnalysisError::cfg("Block not found"))?;

                let mut pred_dominators: Option<Vec<usize>> = None;

                for pred_idx in self
                    .graph
                    .neighbors_directed(node_idx, petgraph::Direction::Incoming)
                {
                    let pred_id = self
                        .graph
                        .node_weight(pred_idx)
                        .map(|b| b.id)
                        .ok_or_else(|| AnalysisError::cfg("Predecessor not found"))?;

                    let pred_doms = dominators
                        .get(&pred_id)
                        .cloned()
                        .ok_or_else(|| AnalysisError::cfg("Predecessor dominators not found"))?;

                    pred_dominators = match pred_dominators {
                        None => Some(pred_doms),
                        Some(current) => {
                            let intersection: Vec<_> = current
                                .iter()
                                .filter(|d| pred_doms.contains(d))
                                .copied()
                                .collect();
                            Some(intersection)
                        }
                    };
                }

                // dom(block) = {block} ∪ intersection(dom(predecessors))
                if let Some(mut pred_doms) = pred_dominators {
                    pred_doms.push(block_id);
                    pred_doms.sort();
                    pred_doms.dedup();

                    if let Some(old_doms) = dominators.get_mut(&block_id) {
                        if *old_doms != pred_doms {
                            *old_doms = pred_doms;
                            changed = true;
                        }
                    }
                }
            }
        }

        debug!(
            "Dominance computation converged after {} iterations",
            iterations
        );

        // Update graph with dominance info
        for (block_id, doms) in dominators {
            if let Some(node_idx) = self.block_map.get(&block_id).copied() {
                if let Some(block) = self.graph.node_weight_mut(node_idx) {
                    block.dominates = doms.into_iter().filter(|&id| id != block_id).collect();
                }
            }
        }

        Ok(())
    }

    /// Check if block `a` dominates block `b`.
    pub fn dominates(&self, a: usize, b: usize) -> bool {
        self.block_map
            .get(&a)
            .and_then(|&idx| self.graph.node_weight(idx))
            .map(|block| block.dominates.contains(&b))
            .unwrap_or(false)
    }

    /// Detect loops in the CFG.
    pub fn detect_loops(&mut self) -> AnalysisResult<Vec<Loop>> {
        info!("Detecting loops in CFG");

        let mut loops = Vec::new();

        // Back edge detection: edge to dominator = loop
        let blocks: Vec<usize> = self.block_map.keys().copied().collect();

        for &block_id in &blocks {
            let node_idx = self
                .block_map
                .get(&block_id)
                .copied()
                .ok_or_else(|| AnalysisError::cfg("Block not found"))?;

            // Collect successors first to avoid borrowing issues
            let successors: Vec<_> = self.graph.neighbors(node_idx).collect();

            for succ_idx in successors {
                let succ_id = self
                    .graph
                    .node_weight(succ_idx)
                    .map(|b| b.id)
                    .ok_or_else(|| AnalysisError::cfg("Successor not found"))?;

                // Back edge if successor dominates this block
                if self.dominates(succ_id, block_id) {
                    loops.push(Loop {
                        header: succ_id,
                        back_edges: vec![(block_id, succ_id)],
                        body_blocks: vec![succ_id],
                    });

                    // Mark as loop header
                    if let Some(block) = self.graph.node_weight_mut(succ_idx) {
                        block.is_loop_header = true;
                    }
                }
            }
        }

        info!("Found {} loops", loops.len());
        Ok(loops)
    }

    /// Get all reachable blocks from a starting block.
    pub fn reachable(&self, from: usize) -> AnalysisResult<Vec<usize>> {
        let start_idx = self
            .block_map
            .get(&from)
            .copied()
            .ok_or_else(|| AnalysisError::cfg("Block not found"))?;

        let mut reachable = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut queue = vec![start_idx];

        while let Some(node_idx) = queue.pop() {
            if !visited.insert(node_idx) {
                continue;
            }

            if let Some(block) = self.graph.node_weight(node_idx) {
                reachable.push(block.id);
            }

            for succ_idx in self.graph.neighbors(node_idx) {
                queue.push(succ_idx);
            }
        }

        Ok(reachable)
    }

    /// Get entry block ID.
    pub fn entry(&self) -> usize {
        self.entry_block
    }

    /// Get exit block IDs.
    pub fn exits(&self) -> Vec<usize> {
        self.exit_blocks.clone()
    }

    /// Get block count.
    pub fn block_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Block IDs in deterministic order.
    pub fn block_ids(&self) -> Vec<usize> {
        let mut ids: Vec<_> = self.block_map.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// Read a block by its stable ID.
    pub fn block(&self, block_id: usize) -> Option<&BasicBlock> {
        self.block_map
            .get(&block_id)
            .and_then(|index| self.graph.node_weight(*index))
    }

    /// Predecessor block IDs in deterministic order.
    pub fn predecessors(&self, block_id: usize) -> AnalysisResult<Vec<usize>> {
        self.neighbors(block_id, petgraph::Direction::Incoming)
    }

    /// Successor block IDs in deterministic order.
    pub fn successors(&self, block_id: usize) -> AnalysisResult<Vec<usize>> {
        self.neighbors(block_id, petgraph::Direction::Outgoing)
    }

    fn neighbors(
        &self,
        block_id: usize,
        direction: petgraph::Direction,
    ) -> AnalysisResult<Vec<usize>> {
        let index = self
            .block_map
            .get(&block_id)
            .copied()
            .ok_or_else(|| AnalysisError::cfg("Block not found"))?;
        let mut ids: Vec<_> = self
            .graph
            .neighbors_directed(index, direction)
            .filter_map(|neighbor| self.graph.node_weight(neighbor).map(|block| block.id))
            .collect();
        ids.sort_unstable();
        Ok(ids)
    }
}

impl Default for ControlFlowGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents a loop in the CFG.
#[derive(Debug, Clone)]
pub struct Loop {
    /// Loop header block.
    pub header: usize,
    /// Back edges (from, to).
    pub back_edges: Vec<(usize, usize)>,
    /// Blocks in loop body.
    pub body_blocks: Vec<usize>,
}

/// CFG Builder for function analysis.
pub struct CfgBuilder;

impl CfgBuilder {
    /// Build CFG from a function's AST.
    pub fn build(function: &AstFunction) -> AnalysisResult<ControlFlowGraph> {
        debug!("Building CFG for function '{}'", function.name);

        let mut cfg = ControlFlowGraph::new();

        let entry = cfg.entry();
        for source in &function.body {
            cfg.add_statement(entry, parse_statement(source))?;
        }
        cfg.mark_exit(entry)?;

        // Compute dominance
        cfg.compute_dominance()?;

        // Detect loops
        cfg.detect_loops()?;

        Ok(cfg)
    }
}

fn parse_statement(source: &str) -> Statement {
    let code = source.trim().trim_end_matches(';').trim();
    if let Some(value) = code.strip_prefix("return") {
        let value = value.trim();
        return Statement::Return {
            value: (!value.is_empty()).then(|| value.to_string()),
        };
    }
    if code.starts_with("if ") || code.starts_with("if(") || code.starts_with("require(") {
        return Statement::Branch {
            condition: code.to_string(),
        };
    }
    if let Some((left, right)) = code.split_once('=') {
        let target = left
            .split_whitespace()
            .last()
            .unwrap_or(left)
            .trim()
            .to_string();
        return Statement::Assignment {
            target,
            value: right.trim().to_string(),
        };
    }
    Statement::Generic {
        code: code.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cfg_creation() {
        let mut cfg = ControlFlowGraph::new();
        let block1 = cfg.entry();
        let block2 = cfg.new_block();
        let block3 = cfg.new_block();

        assert_eq!(cfg.block_count(), 3);
        assert_eq!(block1, 0);
        assert_eq!(block2, 1);
        assert_eq!(block3, 2);
    }

    #[test]
    fn test_cfg_edges() {
        let mut cfg = ControlFlowGraph::new();
        let b1 = cfg.entry();
        let b2 = cfg.new_block();
        let b3 = cfg.new_block();

        cfg.add_edge(b1, b2, "true").ok();
        cfg.add_edge(b1, b3, "false").ok();

        assert_eq!(cfg.block_count(), 3);
    }

    #[test]
    fn test_cfg_exit_marking() {
        let mut cfg = ControlFlowGraph::new();
        let entry = cfg.entry();

        cfg.mark_exit(entry).ok();
        assert!(cfg.exits().contains(&entry));
    }

    #[test]
    fn builder_preserves_linear_function_statements() {
        let function = AstFunction {
            name: "withdraw".to_string(),
            parameters: Vec::new(),
            returns: Vec::new(),
            visibility: crate::ast::Visibility::Public,
            is_mutable: true,
            is_pure: false,
            is_view: false,
            modifiers: Vec::new(),
            body: vec![
                "uint256 amount = msg.value;".to_string(),
                "uint256 fee = amount / 100;".to_string(),
                "return fee;".to_string(),
            ],
            id: 1,
        };

        let cfg = CfgBuilder::build(&function).expect("CFG builds");
        let block = cfg.block(cfg.entry()).expect("entry block");
        assert_eq!(block.statements.len(), 3);
        assert!(matches!(
            &block.statements[0],
            Statement::Assignment { target, value }
                if target == "amount" && value == "msg.value"
        ));
        assert!(matches!(
            &block.statements[2],
            Statement::Return { value: Some(value) } if value == "fee"
        ));
    }

    #[test]
    fn predecessor_and_successor_views_are_stable() {
        let mut cfg = ControlFlowGraph::new();
        let entry = cfg.entry();
        let second = cfg.new_block();
        cfg.add_edge(entry, second, "next").expect("edge");
        assert_eq!(cfg.successors(entry).expect("successors"), vec![second]);
        assert_eq!(cfg.predecessors(second).expect("predecessors"), vec![entry]);
    }
}
