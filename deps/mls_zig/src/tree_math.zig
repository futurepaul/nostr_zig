const std = @import("std");
const testing = std.testing;

pub const MAX_TREE_SIZE: u32 = 1 << 30;
pub const MIN_TREE_SIZE: u32 = 1;

/// LeafNodeIndex references a leaf node in a tree.
pub const LeafNodeIndex = struct {
    value: u32,

    /// Create a new LeafNodeIndex from a u32.
    pub fn new(index: u32) LeafNodeIndex {
        return LeafNodeIndex{ .value = index };
    }

    /// Return the inner value as u32.
    pub fn asU32(self: LeafNodeIndex) u32 {
        return self.value;
    }

    /// Return the inner value as usize.
    pub fn asUsize(self: LeafNodeIndex) usize {
        return @as(usize, self.value);
    }

    /// Return the index as a TreeNodeIndex value.
    pub fn toTreeIndex(self: LeafNodeIndex) u32 {
        return self.value * 2;
    }

    /// Create from a tree node index (must be even/leaf node)
    pub fn fromTreeIndex(node_index: u32) LeafNodeIndex {
        std.debug.assert(node_index % 2 == 0);
        return LeafNodeIndex{ .value = node_index / 2 };
    }
};

/// ParentNodeIndex references a parent node in a tree.
pub const ParentNodeIndex = struct {
    value: u32,

    /// Create a new ParentNodeIndex from a u32.
    pub fn new(index: u32) ParentNodeIndex {
        return ParentNodeIndex{ .value = index };
    }

    /// Return the inner value as u32.
    pub fn asU32(self: ParentNodeIndex) u32 {
        return self.value;
    }

    /// Return the inner value as usize.
    pub fn asUsize(self: ParentNodeIndex) usize {
        return @as(usize, self.value);
    }

    /// Return the index as a TreeNodeIndex value.
    pub fn toTreeIndex(self: ParentNodeIndex) u32 {
        return self.value * 2 + 1;
    }

    /// Create from a tree node index (must be odd/parent node)
    pub fn fromTreeIndex(node_index: u32) ParentNodeIndex {
        std.debug.assert(node_index > 0);
        std.debug.assert(node_index % 2 == 1);
        return ParentNodeIndex{ .value = (node_index - 1) / 2 };
    }
};

/// TreeNodeIndex references a node in a tree.
pub const TreeNodeIndex = union(enum) {
    leaf: LeafNodeIndex,
    parent: ParentNodeIndex,

    /// Create a new TreeNodeIndex from a u32.
    pub fn new(index: u32) TreeNodeIndex {
        if (index % 2 == 0) {
            return TreeNodeIndex{ .leaf = LeafNodeIndex.fromTreeIndex(index) };
        } else {
            return TreeNodeIndex{ .parent = ParentNodeIndex.fromTreeIndex(index) };
        }
    }

    /// Return the inner value as u32.
    pub fn asU32(self: TreeNodeIndex) u32 {
        return switch (self) {
            .leaf => |index| index.toTreeIndex(),
            .parent => |index| index.toTreeIndex(),
        };
    }

    /// Return the inner value as usize.
    pub fn asUsize(self: TreeNodeIndex) usize {
        return @as(usize, self.asU32());
    }

    /// Check if this is a leaf node
    pub fn isLeaf(self: TreeNodeIndex) bool {
        return self == .leaf;
    }

    /// Check if this is a parent node
    pub fn isParent(self: TreeNodeIndex) bool {
        return self == .parent;
    }
};

/// TreeSize represents the size of a tree in nodes
pub const TreeSize = struct {
    value: u32,

    /// Create a new TreeSize from nodes, which will be rounded up to the
    /// next power of 2. The tree size then reflects the smallest tree that can
    /// contain the number of nodes.
    pub fn new(nodes: u32) TreeSize {
        const k = log2(nodes);
        const shift_amount = @as(u5, @intCast(k + 1));
        return TreeSize{ .value = (@as(u32, 1) << shift_amount) - 1 };
    }

    /// Return the inner value as u32.
    pub fn asU32(self: TreeSize) u32 {
        return self.value;
    }

    /// Return the number of leaf nodes in the tree.
    pub fn leafCount(self: TreeSize) u32 {
        return (self.value + 1) / 2;
    }
};

test "LeafNodeIndex creation and access" {
    const index = LeafNodeIndex.new(5);
    try testing.expectEqual(@as(u32, 5), index.asU32());
    try testing.expectEqual(@as(usize, 5), index.asUsize());
}

test "ParentNodeIndex creation and access" {
    const index = ParentNodeIndex.new(3);
    try testing.expectEqual(@as(u32, 3), index.asU32());
    try testing.expectEqual(@as(usize, 3), index.asUsize());
    try testing.expectEqual(@as(u32, 7), index.toTreeIndex());
}

/// Calculate log2 of a u32
fn log2(x: u32) usize {
    if (x == 0) {
        return 0;
    }
    return @as(usize, 31 - @clz(x));
}

/// Calculate the level of a node in the tree
pub fn level(index: u32) usize {
    const x = index;
    if ((x & 0x01) == 0) {
        return 0;
    }
    var k: u5 = 0;
    while (((x >> k) & 0x01) == 1) {
        k += 1;
    }
    return @as(usize, k);
}

test "TreeNodeIndex conversions" {
    // Test leaf node (even indices)
    const leaf_tree = TreeNodeIndex.new(4);
    try testing.expect(leaf_tree == .leaf);
    try testing.expectEqual(@as(u32, 4), leaf_tree.asU32());
    
    // Test parent node (odd indices)  
    const parent_tree = TreeNodeIndex.new(5);
    try testing.expect(parent_tree == .parent);
    try testing.expectEqual(@as(u32, 5), parent_tree.asU32());
}

test "log2 function" {
    try testing.expectEqual(@as(usize, 0), log2(0));
    try testing.expectEqual(@as(usize, 0), log2(1));
    try testing.expectEqual(@as(usize, 1), log2(2));
    try testing.expectEqual(@as(usize, 1), log2(3));
    try testing.expectEqual(@as(usize, 2), log2(4));
    try testing.expectEqual(@as(usize, 2), log2(5));
    try testing.expectEqual(@as(usize, 2), log2(7));
    try testing.expectEqual(@as(usize, 3), log2(8));
    try testing.expectEqual(@as(usize, 4), log2(16));
}

test "level function" {
    // Leaf nodes (even) have level 0
    try testing.expectEqual(@as(usize, 0), level(0));
    try testing.expectEqual(@as(usize, 0), level(2));
    try testing.expectEqual(@as(usize, 0), level(4));
    
    // Parent nodes (odd) have level based on trailing ones
    try testing.expectEqual(@as(usize, 1), level(1));
    try testing.expectEqual(@as(usize, 2), level(3));
    try testing.expectEqual(@as(usize, 1), level(5));
    try testing.expectEqual(@as(usize, 3), level(7));
}

test "TreeSize calculations" {
    try testing.expectEqual(@as(u32, 1), TreeSize.new(1).asU32());
    try testing.expectEqual(@as(u32, 3), TreeSize.new(3).asU32());
    try testing.expectEqual(@as(u32, 7), TreeSize.new(5).asU32());
    try testing.expectEqual(@as(u32, 7), TreeSize.new(7).asU32());
    try testing.expectEqual(@as(u32, 15), TreeSize.new(9).asU32());
    try testing.expectEqual(@as(u32, 15), TreeSize.new(11).asU32());
    try testing.expectEqual(@as(u32, 15), TreeSize.new(13).asU32());
    try testing.expectEqual(@as(u32, 15), TreeSize.new(15).asU32());
    try testing.expectEqual(@as(u32, 31), TreeSize.new(17).asU32());
}

test "TreeNodeIndex is_leaf and is_parent" {
    const leaf = TreeNodeIndex.new(4);
    try testing.expect(leaf.isLeaf());
    try testing.expect(!leaf.isParent());
    
    const parent_node = TreeNodeIndex.new(5);
    try testing.expect(!parent_node.isLeaf());
    try testing.expect(parent_node.isParent());
}

/// Calculate the root node of a tree of the given size
pub fn root(size: TreeSize) u32 {
    const size_val = size.asU32();
    std.debug.assert(size_val > 0);
    return (@as(u32, 1) << @as(u5, @intCast(log2(size_val)))) - 1;
}

/// Calculate the parent of a node in the tree
/// Warning: There is no check about the tree size and whether the parent is
/// beyond the root
pub fn parent(x: TreeNodeIndex) ParentNodeIndex {
    const x_val = x.asU32();
    const k = level(x_val);
    const b = (x_val >> @as(u5, @intCast(k + 1))) & 0x01;
    const index = (x_val | (@as(u32, 1) << @as(u5, @intCast(k)))) ^ (b << @as(u5, @intCast(k + 1)));
    return ParentNodeIndex.fromTreeIndex(index);
}

/// Calculate the left child of a parent node
pub fn left(index: ParentNodeIndex) TreeNodeIndex {
    const x = index.toTreeIndex();
    const k = level(x);
    std.debug.assert(k > 0);
    const child_index = x ^ (@as(u32, 0x01) << @as(u5, @intCast(k - 1)));
    return TreeNodeIndex.new(child_index);
}

/// Calculate the right child of a parent node
pub fn right(index: ParentNodeIndex) TreeNodeIndex {
    const x = index.toTreeIndex();
    const k = level(x);
    std.debug.assert(k > 0);
    const child_index = x ^ (@as(u32, 0x03) << @as(u5, @intCast(k - 1)));
    return TreeNodeIndex.new(child_index);
}

/// Calculate the sibling of a node
pub fn sibling(index: TreeNodeIndex) TreeNodeIndex {
    const p = parent(index);
    const parent_idx = p.toTreeIndex();
    const node_idx = index.asU32();
    
    if (node_idx < parent_idx) {
        return right(p);
    } else {
        return left(p);
    }
}

/// Direct path from a leaf node to the root.
/// Does not include the node itself.
pub fn directPath(node_index: LeafNodeIndex, size: TreeSize, allocator: std.mem.Allocator) ![]ParentNodeIndex {
    const r = root(size);
    
    var path = std.ArrayList(ParentNodeIndex).init(allocator);
    var x = node_index.toTreeIndex();
    
    while (x != r) {
        const parent_node = parent(TreeNodeIndex.new(x));
        try path.append(parent_node);
        x = parent_node.toTreeIndex();
    }
    
    return path.toOwnedSlice();
}

test "root function" {
    try testing.expectEqual(@as(u32, 0), root(TreeSize.new(1)));
    try testing.expectEqual(@as(u32, 1), root(TreeSize.new(2)));
    try testing.expectEqual(@as(u32, 1), root(TreeSize.new(3)));
    try testing.expectEqual(@as(u32, 3), root(TreeSize.new(4)));
    try testing.expectEqual(@as(u32, 3), root(TreeSize.new(5)));
    try testing.expectEqual(@as(u32, 3), root(TreeSize.new(7)));
    try testing.expectEqual(@as(u32, 7), root(TreeSize.new(8)));
    try testing.expectEqual(@as(u32, 7), root(TreeSize.new(15)));
    try testing.expectEqual(@as(u32, 15), root(TreeSize.new(16)));
}

test "parent calculations" {
    // Tree with 2 leaves (3 nodes total)
    // Node 0 (leaf) -> parent 1
    try testing.expectEqual(@as(u32, 1), parent(TreeNodeIndex.new(0)).toTreeIndex());
    // Node 2 (leaf) -> parent 1  
    try testing.expectEqual(@as(u32, 1), parent(TreeNodeIndex.new(2)).toTreeIndex());
    
    // Tree with 4 leaves (7 nodes total)
    // Node 0 (leaf) -> parent 1
    try testing.expectEqual(@as(u32, 1), parent(TreeNodeIndex.new(0)).toTreeIndex());
    // Node 1 (parent) -> parent 3
    try testing.expectEqual(@as(u32, 3), parent(TreeNodeIndex.new(1)).toTreeIndex());
    // Node 2 (leaf) -> parent 1
    try testing.expectEqual(@as(u32, 1), parent(TreeNodeIndex.new(2)).toTreeIndex());
    // Node 4 (leaf) -> parent 5
    try testing.expectEqual(@as(u32, 5), parent(TreeNodeIndex.new(4)).toTreeIndex());
    // Node 5 (parent) -> parent 3
    try testing.expectEqual(@as(u32, 3), parent(TreeNodeIndex.new(5)).toTreeIndex());
    // Node 6 (leaf) -> parent 5
    try testing.expectEqual(@as(u32, 5), parent(TreeNodeIndex.new(6)).toTreeIndex());
}

test "left and right children" {
    // Parent node 1 has left child 0 and right child 2
    const p1 = ParentNodeIndex.new(0); // This is parent at tree index 1
    try testing.expectEqual(@as(u32, 0), left(p1).asU32());
    try testing.expectEqual(@as(u32, 2), right(p1).asU32());
    
    // In a tree with 4 leaves:
    // Parent node 3 has left child 1 and right child 5
    const p3 = ParentNodeIndex.new(1); // This is parent at tree index 3
    try testing.expectEqual(@as(u32, 1), left(p3).asU32());
    try testing.expectEqual(@as(u32, 5), right(p3).asU32());
    
    // Parent node 5 has left child 4 and right child 6
    const p5 = ParentNodeIndex.new(2); // This is parent at tree index 5
    try testing.expectEqual(@as(u32, 4), left(p5).asU32());
    try testing.expectEqual(@as(u32, 6), right(p5).asU32());
}

test "sibling calculations" {
    // Tree with 2 leaves
    try testing.expectEqual(@as(u32, 2), sibling(TreeNodeIndex.new(0)).asU32());
    try testing.expectEqual(@as(u32, 0), sibling(TreeNodeIndex.new(2)).asU32());
    
    // Tree with 4 leaves
    try testing.expectEqual(@as(u32, 2), sibling(TreeNodeIndex.new(0)).asU32());
    try testing.expectEqual(@as(u32, 5), sibling(TreeNodeIndex.new(1)).asU32());
    try testing.expectEqual(@as(u32, 0), sibling(TreeNodeIndex.new(2)).asU32());
    try testing.expectEqual(@as(u32, 6), sibling(TreeNodeIndex.new(4)).asU32());
    try testing.expectEqual(@as(u32, 1), sibling(TreeNodeIndex.new(5)).asU32());
    try testing.expectEqual(@as(u32, 4), sibling(TreeNodeIndex.new(6)).asU32());
}

test "direct path" {
    const allocator = testing.allocator;
    
    // Test direct path from leaf 0 in a tree with 4 leaves
    {
        const path = try directPath(LeafNodeIndex.new(0), TreeSize.new(4), allocator);
        defer allocator.free(path);
        
        try testing.expectEqual(@as(usize, 2), path.len);
        try testing.expectEqual(@as(u32, 1), path[0].toTreeIndex());
        try testing.expectEqual(@as(u32, 3), path[1].toTreeIndex());
    }
    
    // Test direct path from leaf 2 in a tree with 8 leaves  
    {
        const path = try directPath(LeafNodeIndex.new(2), TreeSize.new(8), allocator);
        defer allocator.free(path);
        
        try testing.expectEqual(@as(usize, 3), path.len);
        try testing.expectEqual(@as(u32, 5), path[0].toTreeIndex());
        try testing.expectEqual(@as(u32, 3), path[1].toTreeIndex());
        try testing.expectEqual(@as(u32, 7), path[2].toTreeIndex());
    }
    
    // Test direct path from leaf 0 in a tree with 1 leaf (should be empty)
    {
        const path = try directPath(LeafNodeIndex.new(0), TreeSize.new(1), allocator);
        defer allocator.free(path);
        
        try testing.expectEqual(@as(usize, 0), path.len);
    }
}