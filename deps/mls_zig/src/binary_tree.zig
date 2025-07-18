const std = @import("std");
const testing = std.testing;
const tree_math = @import("tree_math.zig");
const LeafNodeIndex = tree_math.LeafNodeIndex;
const ParentNodeIndex = tree_math.ParentNodeIndex;
const TreeNodeIndex = tree_math.TreeNodeIndex;
const TreeSize = tree_math.TreeSize;

/// Represents a node in the binary tree
pub fn TreeNode(comptime L: type, comptime P: type) type {
    return union(enum) {
        leaf: L,
        parent: P,
    };
}

/// Binary tree error types
pub const BinaryTreeError = error{
    /// Number of nodes doesn't create a full, left-balanced binary tree
    InvalidNumberOfNodes,
    /// Number of nodes exceeds maximum tree size
    OutOfRange,
    /// Wrong node type at given position (leaf where parent expected or vice versa)
    WrongNodeType,
};

/// A representation of a full, left-balanced binary tree that uses simple
/// arrays to store nodes. Each tree has to consist of at least one node.
pub fn BinaryTree(comptime L: type, comptime P: type) type {
    return struct {
        const Self = @This();
        const Node = TreeNode(L, P);

        leaf_nodes: std.ArrayList(L),
        parent_nodes: std.ArrayList(P),
        allocator: std.mem.Allocator,

        /// Create a tree from the given slice of nodes. The slice of nodes can't
        /// be empty and has to yield a full, left-balanced binary tree.
        pub fn init(allocator: std.mem.Allocator, nodes: []const Node) !Self {
            // No more than 2^30 nodes
            if (nodes.len > tree_math.MAX_TREE_SIZE) {
                return BinaryTreeError.OutOfRange;
            }
            
            // Must have odd number of nodes for a full binary tree
            if (nodes.len % 2 != 1) {
                return BinaryTreeError.InvalidNumberOfNodes;
            }

            var leaf_nodes = std.ArrayList(L).init(allocator);
            var parent_nodes = std.ArrayList(P).init(allocator);
            errdefer {
                leaf_nodes.deinit();
                parent_nodes.deinit();
            }

            // Split the nodes into two arrays, one for leaves and one for parents
            for (nodes, 0..) |node, i| {
                switch (node) {
                    .leaf => |l| {
                        if (i % 2 == 0) {
                            try leaf_nodes.append(l);
                        } else {
                            return BinaryTreeError.WrongNodeType;
                        }
                    },
                    .parent => |p| {
                        if (i % 2 == 1) {
                            try parent_nodes.append(p);
                        } else {
                            return BinaryTreeError.WrongNodeType;
                        }
                    },
                }
            }

            return Self{
                .leaf_nodes = leaf_nodes,
                .parent_nodes = parent_nodes,
                .allocator = allocator,
            };
        }

        /// Clean up allocated memory
        pub fn deinit(self: *Self) void {
            self.leaf_nodes.deinit();
            self.parent_nodes.deinit();
        }

        /// Obtain a reference to the data contained in the leaf node at index
        pub fn leafByIndex(self: *const Self, leaf_index: LeafNodeIndex) ?*const L {
            if (leaf_index.asUsize() < self.leaf_nodes.items.len) {
                return &self.leaf_nodes.items[leaf_index.asUsize()];
            }
            return null;
        }

        /// Obtain a reference to the data contained in the parent node at index
        pub fn parentByIndex(self: *const Self, parent_index: ParentNodeIndex) ?*const P {
            if (parent_index.asUsize() < self.parent_nodes.items.len) {
                return &self.parent_nodes.items[parent_index.asUsize()];
            }
            return null;
        }

        /// Return the size of the tree (total number of nodes)
        pub fn treeSize(self: *const Self) TreeSize {
            const total_nodes = self.leaf_nodes.items.len + self.parent_nodes.items.len;
            return TreeSize.new(@intCast(total_nodes));
        }

        /// Return the number of leaf nodes in the tree
        pub fn leafCount(self: *const Self) u32 {
            return @intCast(self.leaf_nodes.items.len);
        }

        /// Return the number of parent nodes in the tree
        pub fn parentCount(self: *const Self) u32 {
            return @intCast(self.parent_nodes.items.len);
        }

        /// Leaf iterator item type
        pub const LeafItem = struct {
            index: LeafNodeIndex,
            value: *const L,
        };

        /// Iterator for leaves
        pub const LeafIterator = struct {
            tree: *const Self,
            index: u32,

            pub fn next(self: *LeafIterator) ?LeafItem {
                if (self.index >= self.tree.leaf_nodes.items.len) {
                    return null;
                }
                
                const result = LeafItem{
                    .index = LeafNodeIndex.new(self.index),
                    .value = &self.tree.leaf_nodes.items[self.index],
                };
                self.index += 1;
                return result;
            }
        };

        /// Returns an iterator over the leaves
        pub fn leaves(self: *const Self) LeafIterator {
            return LeafIterator{
                .tree = self,
                .index = 0,
            };
        }

        /// Parent iterator item type
        pub const ParentItem = struct {
            index: ParentNodeIndex,
            value: *const P,
        };

        /// Iterator for parents
        pub const ParentIterator = struct {
            tree: *const Self,
            index: u32,

            pub fn next(self: *ParentIterator) ?ParentItem {
                if (self.index >= self.tree.parent_nodes.items.len) {
                    return null;
                }
                
                const result = ParentItem{
                    .index = ParentNodeIndex.new(self.index),
                    .value = &self.tree.parent_nodes.items[self.index],
                };
                self.index += 1;
                return result;
            }
        };

        /// Returns an iterator over the parents
        pub fn parents(self: *const Self) ParentIterator {
            return ParentIterator{
                .tree = self,
                .index = 0,
            };
        }
    };
}

// Tests

test "tree creation - wrong number of nodes" {
    const Tree = BinaryTree(u32, u32);
    const Node = TreeNode(u32, u32);
    
    const allocator = testing.allocator;
    
    // Test with even number of nodes (should fail)
    const nodes = [_]Node{
        Node{ .leaf = 1 },
        Node{ .parent = 0 },
    };
    
    const result = Tree.init(allocator, &nodes);
    try testing.expectError(BinaryTreeError.InvalidNumberOfNodes, result);
}

test "tree creation and basic operations" {
    const Tree = BinaryTree(u32, u32);
    const Node = TreeNode(u32, u32);
    
    const allocator = testing.allocator;
    
    // Create a valid tree with 3 nodes
    const nodes = [_]Node{
        Node{ .leaf = 1 },
        Node{ .parent = 0 },
        Node{ .leaf = 2 },
    };
    
    var tree = try Tree.init(allocator, &nodes);
    defer tree.deinit();
    
    // Test size reporting
    try testing.expectEqual(@as(u32, 3), tree.treeSize().asU32());
    try testing.expectEqual(@as(u32, 2), tree.leafCount());
    try testing.expectEqual(@as(u32, 1), tree.parentCount());
    
    // Test node access
    try testing.expectEqual(@as(u32, 1), tree.leafByIndex(LeafNodeIndex.new(0)).?.*);
    try testing.expectEqual(@as(u32, 0), tree.parentByIndex(ParentNodeIndex.new(0)).?.*);
    try testing.expectEqual(@as(u32, 2), tree.leafByIndex(LeafNodeIndex.new(1)).?.*);
}

test "tree with single node" {
    const Tree = BinaryTree(u32, u32);
    const Node = TreeNode(u32, u32);
    
    const allocator = testing.allocator;
    
    const nodes = [_]Node{
        Node{ .leaf = 1 },
    };
    
    var tree = try Tree.init(allocator, &nodes);
    defer tree.deinit();
    
    try testing.expectEqual(@as(u32, 1), tree.treeSize().asU32());
    try testing.expectEqual(@as(u32, 1), tree.leafCount());
    try testing.expectEqual(@as(u32, 0), tree.parentCount());
}

test "leaf iterator" {
    const Tree = BinaryTree(u32, u32);
    const Node = TreeNode(u32, u32);
    
    const allocator = testing.allocator;
    
    const nodes = [_]Node{
        Node{ .leaf = 2 },
        Node{ .parent = 0 },
        Node{ .leaf = 4 },
    };
    
    var tree = try Tree.init(allocator, &nodes);
    defer tree.deinit();
    
    // Test leaf iteration
    var iter = tree.leaves();
    
    if (iter.next()) |item| {
        try testing.expectEqual(@as(u32, 0), item.index.asU32());
        try testing.expectEqual(@as(u32, 2), item.value.*);
    } else {
        try testing.expect(false);
    }
    
    if (iter.next()) |item| {
        try testing.expectEqual(@as(u32, 1), item.index.asU32());
        try testing.expectEqual(@as(u32, 4), item.value.*);
    } else {
        try testing.expect(false);
    }
    
    try testing.expectEqual(@as(?Tree.LeafItem, null), iter.next());
}

test "wrong node type" {
    const Tree = BinaryTree(u32, u32);
    const Node = TreeNode(u32, u32);
    
    const allocator = testing.allocator;
    
    // Parent node at even index (should be leaf)
    const nodes1 = [_]Node{
        Node{ .parent = 0 },
        Node{ .leaf = 1 },
        Node{ .leaf = 2 },
    };
    
    const result1 = Tree.init(allocator, &nodes1);
    try testing.expectError(BinaryTreeError.WrongNodeType, result1);
    
    // Leaf node at odd index (should be parent)
    const nodes2 = [_]Node{
        Node{ .leaf = 1 },
        Node{ .leaf = 2 },
        Node{ .leaf = 3 },
    };
    
    const result2 = Tree.init(allocator, &nodes2);
    try testing.expectError(BinaryTreeError.WrongNodeType, result2);
}