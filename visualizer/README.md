# NIP-EE MLS Visual Explainer

An interactive visualization tool for understanding the NIP-EE (Nostr Implementation Possibilities - End-to-End Encryption) MLS (Message Layer Security) protocol. This visualizer demonstrates how MLS group messaging works in the context of Nostr, using WebAssembly-compiled Zig code for cryptographic operations.

## Overview

This project provides a step-by-step visual demonstration of:
- Identity creation and key generation
- MLS Key Package publication (Nostr Kind 443)
- Group creation and management
- Welcome message distribution (Nostr Kind 444)
- Encrypted group messaging (Nostr Kind 445)

## Architecture

### Components

- **Frontend**: React + TypeScript application built with Bun
- **Cryptography**: Zig library compiled to WebAssembly
- **Visualization**: Mermaid diagrams and Framer Motion animations
- **UI**: Tailwind CSS with shadcn/ui components

### Key Features

1. **Split-screen Interface**: Shows Alice and Bob as separate participants
2. **Protocol State Diagram**: Visual representation of MLS state transitions
3. **Event Timeline**: Real-time display of Nostr events being created
4. **Message Flow Visualization**: Animated arrows showing data exchange
5. **Raw Event Inspector**: Click any event to see its Nostr structure

## Prerequisites

- [Bun](https://bun.sh/) (v1.0 or later)
- [Zig](https://ziglang.org/) (v0.11 or later) - for building WASM
- A modern web browser with WebAssembly support

## Installation

1. Clone the repository and navigate to the visualizer directory:
```bash
cd nostr_zig/visualizer
```

2. Install dependencies:
```bash
bun install
```

3. Build the WASM module (from the parent directory):
```bash
cd ..
zig build wasm
```

4. Copy the WASM file to the visualizer (if not already present):
```bash
cp .zig-cache/o/*/nostr_mls.wasm visualizer/src/nostr_mls.wasm
```

## Running the Visualizer

Start the development server:
```bash
bun dev
```

The visualizer will be available at `http://localhost:3001`

## Usage Guide

### Step-by-Step Flow

1. **Create Identities**: Click "Create Identity" for both Alice and Bob
2. **Publish Key Packages**: Both participants publish their MLS key packages
3. **Create Group**: Alice creates a new MLS group
4. **Send Welcome**: Alice sends a welcome message to Bob
5. **Join Group**: Bob processes the welcome to join the group
6. **Exchange Messages**: Both can now send encrypted messages

### Understanding the Visualization

- **State Diagram**: Shows current protocol state with highlighted transitions
- **Event Timeline**: Displays Nostr events as they're created
  - 📦 Key Package (Kind 443)
  - ✉️ Welcome (Kind 444)
  - 💬 Group Message (Kind 445)
- **Message Flow**: Animated arrows show communication between participants and the relay

## Project Structure

```
visualizer/
├── src/
│   ├── components/
│   │   ├── MLSVisualizer.tsx      # Main container
│   │   ├── ParticipantPanel.tsx   # Alice/Bob UI panels
│   │   ├── ProtocolFlow.tsx       # Center visualization
│   │   ├── StateTransitionDiagram.tsx # Mermaid state diagram
│   │   ├── EventTimeline.tsx      # Nostr event display
│   │   ├── MessageFlow.tsx        # Message exchange visualization
│   │   └── WasmProvider.tsx       # WASM context provider
│   ├── lib/
│   │   └── wasm.ts               # WASM bindings
│   ├── nostr_mls.wasm           # Compiled Zig cryptography
│   └── index.tsx                # Entry point
├── build.ts                     # Bun build configuration
└── package.json
```

## Technical Details

### WASM Integration

The Zig Nostr library is compiled to WebAssembly and provides:
- Identity generation (private/public key pairs)
- Key package creation and serialization
- Group state management
- Message encryption/decryption

### Nostr Event Types

- **Kind 443**: MLS Key Package - Published by users to enable others to add them to groups
- **Kind 444**: MLS Welcome - Sent to new group members with group state
- **Kind 445**: MLS Group Message - Encrypted messages within a group

### Current Limitations

This is a demonstration/educational tool. The current implementation:
- Uses placeholder cryptography (not production MLS)
- Simulates Nostr relay behavior locally
- Focuses on protocol flow rather than security

## Building for Production

```bash
bun run build
```

This creates an optimized build in the `dist/` directory.

## Development

### Adding New Features

1. WASM functions are defined in `../src/wasm_exports.zig`
2. TypeScript bindings are in `src/lib/wasm.ts`
3. React components follow a modular structure
4. State management uses React hooks and context

### Debugging

- Browser console shows WASM initialization logs
- Each component logs key actions
- Event inspector shows raw Nostr event structure

## Contributing

Contributions are welcome! Please:
1. Follow the existing code style
2. Add tests for new features
3. Update documentation as needed
4. Test WASM compilation before submitting

## License

[Same as parent project]

## Acknowledgments

- Built with [Bun](https://bun.sh/) and [Zig](https://ziglang.org/)
- UI components from [shadcn/ui](https://ui.shadcn.com/)
- Diagrams powered by [Mermaid](https://mermaid.js.org/)
- Animations by [Framer Motion](https://www.framer.com/motion/)
