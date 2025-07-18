const std = @import("std");
const testing = std.testing;
const tree_math = @import("tree_math.zig");
const binary_tree = @import("binary_tree.zig");

const LeafNodeIndex = tree_math.LeafNodeIndex;
const ParentNodeIndex = tree_math.ParentNodeIndex;
const TreeNodeIndex = tree_math.TreeNodeIndex;
const TreeSize = tree_math.TreeSize;
const BinaryTree = binary_tree.BinaryTree;
const TreeNode = binary_tree.TreeNode;

pub const BinaryTreeDiffError = error{
    /// Tree would become too large
    TreeTooLarge,
    /// Tree would become too small
    TreeTooSmall,
    /// Memory allocation failed
    OutOfMemory,
};

/// Represents a staged diff that can be merged into a tree
pub fn StagedDiff(comptime L: type, comptime P: type) type {
    return struct {
        const Self = @This();
        
        leaf_diff: std.AutoHashMap(LeafNodeIndex, L),
        parent_diff: std.AutoHashMap(ParentNodeIndex, P),
        size: TreeSize,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, size: TreeSize) !Self {
            return Self{
                .leaf_diff = std.AutoHashMap(LeafNodeIndex, L).init(allocator),
                .parent_diff = std.AutoHashMap(ParentNodeIndex, P).init(allocator),
                .size = size,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            self.leaf_diff.deinit();
            self.parent_diff.deinit();
        }

        /// Get the projected tree size after merge
        pub fn treeSize(self: *const Self) TreeSize {
            return self.size;
        }
    };
}

/// Represents a diff that tracks changes to a binary tree
pub fn Diff(comptime L: type, comptime P: type) type {
    return struct {
        const Self = @This();
        const Tree = BinaryTree(L, P);
        const StagedDiffType = StagedDiff(L, P);
        
        original_tree: *const Tree,
        leaf_diff: std.AutoHashMap(LeafNodeIndex, L),
        parent_diff: std.AutoHashMap(ParentNodeIndex, P),
        size: TreeSize,
        allocator: std.mem.Allocator,

        /// Create a new diff from a tree
        pub fn init(allocator: std.mem.Allocator, tree: *const Tree) !Self {
            return Self{
                .original_tree = tree,
                .leaf_diff = std.AutoHashMap(LeafNodeIndex, L).init(allocator),
                .parent_diff = std.AutoHashMap(ParentNodeIndex, P).init(allocator),
                .size = tree.treeSize(),
                .allocator = allocator,
            };
        }

        /// Clean up allocated memory
        pub fn deinit(self: *Self) void {
            self.leaf_diff.deinit();
            self.parent_diff.deinit();
        }

        /// Grow the tree by adding a new subtree to the right
        pub fn growTree(self: *Self) !void {
            // Prevent the tree from becoming too large
            if (self.size.asU32() > tree_math.MAX_TREE_SIZE / 2) {
                return BinaryTreeDiffError.TreeTooLarge;
            }
            // When growing, we double the number of leaves
            const current_leaves = self.size.leafCount();
            const new_leaves = current_leaves * 2;
            self.size = TreeSize.new(new_leaves);
        }

        /// Shrink the tree by removing the rightmost subtree
        pub fn shrinkTree(self: *Self) !void {
            // First make sure that the tree isn't getting too small
            if (self.size.asU32() <= tree_math.MIN_TREE_SIZE) {
                return BinaryTreeDiffError.TreeTooSmall;
            }
            
            // When shrinking, we halve the number of leaves
            const current_leaves = self.size.leafCount();
            const new_leaves = current_leaves / 2;
            const new_size = TreeSize.new(new_leaves);
            const new_leaf_count = new_size.leafCount();
            const new_parent_count = new_size.asU32() / 2;  // parent count for a full binary tree
            
            // Remove nodes from the diff that are now outside the tree
            var leaf_keys_to_remove = std.ArrayList(LeafNodeIndex).init(self.allocator);
            defer leaf_keys_to_remove.deinit();
            
            var leaf_iter = self.leaf_diff.iterator();
            while (leaf_iter.next()) |entry| {
                if (entry.key_ptr.asU32() >= new_leaf_count) {
                    try leaf_keys_to_remove.append(entry.key_ptr.*);
                }
            }
            
            for (leaf_keys_to_remove.items) |key| {
                _ = self.leaf_diff.remove(key);
            }
            
            var parent_keys_to_remove = std.ArrayList(ParentNodeIndex).init(self.allocator);
            defer parent_keys_to_remove.deinit();
            
            var parent_iter = self.parent_diff.iterator();
            while (parent_iter.next()) |entry| {
                if (entry.key_ptr.asU32() >= new_parent_count) {
                    try parent_keys_to_remove.append(entry.key_ptr.*);
                }
            }
            
            for (parent_keys_to_remove.items) |key| {
                _ = self.parent_diff.remove(key);
            }
            
            self.size = new_size;
        }

        /// Replace the content of a leaf node
        pub fn replaceLeaf(self: *Self, leaf_index: LeafNodeIndex, new_leaf: L) !void {
            std.debug.assert(leaf_index.asU32() < self.leafCount());
            try self.leaf_diff.put(leaf_index, new_leaf);
        }

        /// Replace the content of a parent node
        pub fn replaceParent(self: *Self, parent_index: ParentNodeIndex, new_parent: P) !void {
            std.debug.assert(parent_index.asU32() < self.parentCount());
            try self.parent_diff.put(parent_index, new_parent);
        }

        /// Get a leaf from the diff or original tree
        pub fn leaf(self: *const Self, leaf_index: LeafNodeIndex) ?*const L {
            // Check if it's in the diff
            if (self.leaf_diff.get(leaf_index)) |node| {
                return &node;
            }
            // If it's not in the diff and outside the current size, return null
            if (leaf_index.asU32() >= self.leafCount()) {
                return null;
            }
            // Otherwise get from original tree
            return self.original_tree.leafByIndex(leaf_index);
        }

        /// Get a parent from the diff or original tree
        pub fn parent(self: *const Self, parent_index: ParentNodeIndex) ?*const P {
            // Check if it's in the diff
            if (self.parent_diff.get(parent_index)) |node| {
                return &node;
            }
            // If it's not in the diff and outside the current size, return null
            if (parent_index.asU32() >= self.parentCount()) {
                return null;
            }
            // Otherwise get from original tree
            return self.original_tree.parentByIndex(parent_index);
        }

        /// Get the direct path from a leaf to the root
        pub fn directPath(self: *const Self, leaf_index: LeafNodeIndex) ![]ParentNodeIndex {
            return tree_math.directPath(leaf_index, self.size, self.allocator);
        }

        /// Set all nodes in the direct path to a copy of the given node
        pub fn setDirectPathToNode(self: *Self, leaf_index: LeafNodeIndex, node: *const P) !void {
            const direct_path = try self.directPath(leaf_index);
            defer self.allocator.free(direct_path);
            
            for (direct_path) |parent_index| {
                try self.replaceParent(parent_index, node.*);
            }
        }

        /// Get the leaf count of the diff
        pub fn leafCount(self: *const Self) u32 {
            return self.size.leafCount();
        }

        /// Get the parent count of the diff
        pub fn parentCount(self: *const Self) u32 {
            // For a full binary tree: parent_count = total_nodes / 2
            return self.size.asU32() / 2;
        }

        /// Get the size of the diff tree
        pub fn treeSize(self: *const Self) TreeSize {
            return self.size;
        }

        /// Get the root node of the diff
        pub fn root(self: *const Self) u32 {
            return tree_math.root(self.size);
        }

        /// Convert to a staged diff for merging
        pub fn toStaged(self: *const Self) !StagedDiffType {
            var staged = try StagedDiffType.init(self.allocator, self.size);
            errdefer staged.deinit();

            // Copy leaf diffs
            var leaf_iter = self.leaf_diff.iterator();
            while (leaf_iter.next()) |entry| {
                try staged.leaf_diff.put(entry.key_ptr.*, entry.value_ptr.*);
            }

            // Copy parent diffs
            var parent_iter = self.parent_diff.iterator();
            while (parent_iter.next()) |entry| {
                try staged.parent_diff.put(entry.key_ptr.*, entry.value_ptr.*);
            }

            return staged;
        }
    };
}

// Extension method for BinaryTree to create diffs
pub fn emptyDiff(comptime L: type, comptime P: type) fn(*const BinaryTree(L, P), std.mem.Allocator) anyerror!Diff(L, P) {
    return struct {
        fn f(tree: *const BinaryTree(L, P), allocator: std.mem.Allocator) !Diff(L, P) {
            return Diff(L, P).init(allocator, tree);
        }
    }.f;
}

// Extension method for BinaryTree to merge diffs
pub fn merge(comptime L: type, comptime P: type) fn(*BinaryTree(L, P), *StagedDiff(L, P)) anyerror!void {
    return struct {
        fn f(tree: *BinaryTree(L, P), staged: *StagedDiff(L, P)) !void {
            // Resize tree arrays if needed
            const new_leaf_count = staged.size.leafCount();
            const new_parent_count = staged.size.asU32() / 2;
            
            // Ensure capacity
            try tree.leaf_nodes.ensureTotalCapacity(new_leaf_count);
            try tree.parent_nodes.ensureTotalCapacity(new_parent_count);
            
            // Resize to new size (may grow or shrink)
            tree.leaf_nodes.items.len = new_leaf_count;
            tree.parent_nodes.items.len = new_parent_count;
            
            // Apply leaf diffs
            var leaf_iter = staged.leaf_diff.iterator();
            while (leaf_iter.next()) |entry| {
                const idx = entry.key_ptr.asUsize();
                if (idx < tree.leaf_nodes.items.len) {
                    tree.leaf_nodes.items[idx] = entry.value_ptr.*;
                }
            }
            
            // Apply parent diffs
            var parent_iter = staged.parent_diff.iterator();
            while (parent_iter.next()) |entry| {
                const idx = entry.key_ptr.asUsize();
                if (idx < tree.parent_nodes.items.len) {
                    tree.parent_nodes.items[idx] = entry.value_ptr.*;
                }
            }
        }
    }.f;
}

// Tests

test "diff creation and basic operations" {
    const Tree = BinaryTree(u32, u32);
    const DiffType = Diff(u32, u32);
    const Node = TreeNode(u32, u32);
    
    const allocator = testing.allocator;
    
    // Create a tree
    const nodes = [_]Node{
        Node{ .leaf = 2 },
        Node{ .parent = 0 },
        Node{ .leaf = 4 },
    };
    
    var tree = try Tree.init(allocator, &nodes);
    defer tree.deinit();
    
    // Create a diff
    var diff = try DiffType.init(allocator, &tree);
    defer diff.deinit();
    
    // Test size reporting
    try testing.expectEqual(tree.treeSize(), diff.treeSize());
    try testing.expectEqual(tree.leafCount(), diff.leafCount());
    
    // Test leaf replacement
    try diff.replaceLeaf(LeafNodeIndex.new(0), 10);
    try testing.expectEqual(@as(u32, 10), diff.leaf(LeafNodeIndex.new(0)).?.*);
    try testing.expectEqual(@as(u32, 4), diff.leaf(LeafNodeIndex.new(1)).?.*); // Unchanged
}

test "diff grow and shrink" {
    const Tree = BinaryTree(u32, u32);
    const DiffType = Diff(u32, u32);
    const Node = TreeNode(u32, u32);
    
    const allocator = testing.allocator;
    
    // Start with a small tree
    const nodes = [_]Node{
        Node{ .leaf = 1 },
    };
    
    var tree = try Tree.init(allocator, &nodes);
    defer tree.deinit();
    
    var diff = try DiffType.init(allocator, &tree);
    defer diff.deinit();
    
    // Test growing
    try testing.expectEqual(@as(u32, 1), diff.treeSize().asU32());
    try diff.growTree();
    try testing.expectEqual(@as(u32, 3), diff.treeSize().asU32());
    try diff.growTree();
    try testing.expectEqual(@as(u32, 7), diff.treeSize().asU32());
    
    // Test shrinking
    try diff.shrinkTree();
    try testing.expectEqual(@as(u32, 3), diff.treeSize().asU32());
    
    // Test can't shrink below minimum
    try diff.shrinkTree();
    try testing.expectEqual(@as(u32, 1), diff.treeSize().asU32());
    const result = diff.shrinkTree();
    try testing.expectError(BinaryTreeDiffError.TreeTooSmall, result);
}

test "diff merge" {
    const Tree = BinaryTree(u32, u32);
    const DiffType = Diff(u32, u32);
    const Node = TreeNode(u32, u32);
    
    const allocator = testing.allocator;
    
    // Create initial tree
    const nodes = [_]Node{
        Node{ .leaf = 1 },
        Node{ .parent = 0 },
        Node{ .leaf = 2 },
    };
    
    var tree = try Tree.init(allocator, &nodes);
    defer tree.deinit();
    
    // Create and modify diff
    var diff = try DiffType.init(allocator, &tree);
    defer diff.deinit();
    
    try diff.replaceLeaf(LeafNodeIndex.new(0), 10);
    try diff.replaceLeaf(LeafNodeIndex.new(1), 20);
    try diff.replaceParent(ParentNodeIndex.new(0), 5);
    
    // Convert to staged diff
    var staged = try diff.toStaged();
    defer staged.deinit();
    
    // Merge back into tree
    try merge(u32, u32)(&tree, &staged);
    
    // Verify changes were applied
    try testing.expectEqual(@as(u32, 10), tree.leafByIndex(LeafNodeIndex.new(0)).?.*);
    try testing.expectEqual(@as(u32, 20), tree.leafByIndex(LeafNodeIndex.new(1)).?.*);
    try testing.expectEqual(@as(u32, 5), tree.parentByIndex(ParentNodeIndex.new(0)).?.*);
}

test "diff direct path operations" {
    const Tree = BinaryTree(u32, u32);
    const DiffType = Diff(u32, u32);
    const Node = TreeNode(u32, u32);
    
    const allocator = testing.allocator;
    
    // Create a tree with 7 nodes (4 leaves)
    const nodes = [_]Node{
        Node{ .leaf = 1 },    // 0
        Node{ .parent = 10 }, // 1
        Node{ .leaf = 2 },    // 2
        Node{ .parent = 20 }, // 3
        Node{ .leaf = 3 },    // 4
        Node{ .parent = 30 }, // 5
        Node{ .leaf = 4 },    // 6
    };
    
    var tree = try Tree.init(allocator, &nodes);
    defer tree.deinit();
    
    var diff = try DiffType.init(allocator, &tree);
    defer diff.deinit();
    
    // Test direct path
    const path = try diff.directPath(LeafNodeIndex.new(0));
    defer allocator.free(path);
    
    try testing.expectEqual(@as(usize, 2), path.len);
    try testing.expectEqual(@as(u32, 1), path[0].toTreeIndex());
    try testing.expectEqual(@as(u32, 3), path[1].toTreeIndex());
    
    // Test setting direct path to a value
    const new_value: u32 = 99;
    try diff.setDirectPathToNode(LeafNodeIndex.new(0), &new_value);
    
    // Verify the direct path nodes were updated
    try testing.expectEqual(@as(u32, 99), diff.parent(ParentNodeIndex.new(0)).?.*);
    try testing.expectEqual(@as(u32, 99), diff.parent(ParentNodeIndex.new(1)).?.*);
    
    // Verify other nodes were not changed
    try testing.expectEqual(@as(u32, 30), diff.parent(ParentNodeIndex.new(2)).?.*);
}