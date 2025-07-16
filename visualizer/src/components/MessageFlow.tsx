import React from 'react';
import { motion } from 'framer-motion';
import { MLSState, ProtocolStep } from './MLSVisualizer';

interface MessageFlowProps {
  aliceState: MLSState;
  bobState: MLSState;
  currentStep: ProtocolStep;
}

export function MessageFlow({ aliceState, bobState, currentStep }: MessageFlowProps) {
  const flows = [];

  // Key Package Flow
  if (aliceState.keyPackage && currentStep >= 'keyPackages') {
    flows.push({
      id: 'alice-kp',
      from: 'Alice',
      to: 'Relay',
      label: 'Key Package (Kind 443)',
      icon: '📦',
    });
  }

  if (bobState.keyPackage && currentStep >= 'keyPackages') {
    flows.push({
      id: 'bob-kp',
      from: 'Bob',
      to: 'Relay',
      label: 'Key Package (Kind 443)',
      icon: '📦',
    });
  }

  // Welcome Flow
  if (currentStep >= 'welcome' && aliceState.groups.size > 0) {
    flows.push({
      id: 'welcome',
      from: 'Alice',
      to: 'Bob',
      label: 'Welcome (Kind 444)',
      icon: '✉️',
    });
  }

  // Message Flow
  const aliceMessages = aliceState.messages.filter(m => m.sender === 'Alice');
  const bobMessages = bobState.messages.filter(m => m.sender === 'Bob');

  aliceMessages.forEach((msg, idx) => {
    flows.push({
      id: `alice-msg-${idx}`,
      from: 'Alice',
      to: 'Bob',
      label: 'Encrypted Message (Kind 445)',
      icon: '🔐',
    });
  });

  bobMessages.forEach((msg, idx) => {
    flows.push({
      id: `bob-msg-${idx}`,
      from: 'Bob',
      to: 'Alice',
      label: 'Encrypted Message (Kind 445)',
      icon: '🔐',
    });
  });

  return (
    <div className="relative h-64">
      {/* Participants */}
      <div className="absolute left-0 top-1/2 -translate-y-1/2">
        <div className="bg-blue-500 text-white px-4 py-2 rounded-lg font-semibold">
          Alice
        </div>
      </div>
      
      <div className="absolute left-1/2 top-1/4 -translate-x-1/2">
        <div className="bg-gray-500 text-white px-4 py-2 rounded-lg font-semibold">
          Relay
        </div>
      </div>

      <div className="absolute right-0 top-1/2 -translate-y-1/2">
        <div className="bg-green-500 text-white px-4 py-2 rounded-lg font-semibold">
          Bob
        </div>
      </div>

      {/* Message Flows */}
      {flows.map((flow, index) => (
        <motion.div
          key={flow.id}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: index * 0.2 }}
          className="absolute inset-0 pointer-events-none"
        >
          <MessageArrow
            from={flow.from}
            to={flow.to}
            label={flow.label}
            icon={flow.icon}
          />
        </motion.div>
      ))}

      {currentStep === 'setup' && (
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="text-gray-500 text-center">
            <div className="text-2xl mb-2">🔑</div>
            <div>Creating identities...</div>
          </div>
        </div>
      )}
    </div>
  );
}

interface MessageArrowProps {
  from: string;
  to: string;
  label: string;
  icon: string;
}

function MessageArrow({ from, to, label, icon }: MessageArrowProps) {
  // Simplified arrow positioning
  const getPosition = (participant: string) => {
    switch (participant) {
      case 'Alice': return { x: '10%', y: '50%' };
      case 'Relay': return { x: '50%', y: '25%' };
      case 'Bob': return { x: '90%', y: '50%' };
      default: return { x: '50%', y: '50%' };
    }
  };

  const fromPos = getPosition(from);
  const toPos = getPosition(to);

  return (
    <svg className="absolute inset-0 w-full h-full">
      <defs>
        <marker
          id="arrowhead"
          markerWidth="10"
          markerHeight="7"
          refX="9"
          refY="3.5"
          orient="auto"
        >
          <polygon
            points="0 0, 10 3.5, 0 7"
            fill="#6B7280"
          />
        </marker>
      </defs>
      
      <line
        x1={fromPos.x}
        y1={fromPos.y}
        x2={toPos.x}
        y2={toPos.y}
        stroke="#6B7280"
        strokeWidth="2"
        markerEnd="url(#arrowhead)"
      />
      
      <text
        x={`${(parseInt(fromPos.x) + parseInt(toPos.x)) / 2}%`}
        y={`${(parseInt(fromPos.y) + parseInt(toPos.y)) / 2}%`}
        textAnchor="middle"
        className="fill-gray-600 text-xs"
      >
        <tspan x={`${(parseInt(fromPos.x) + parseInt(toPos.x)) / 2}%`} dy="-0.5em">
          {icon} {label}
        </tspan>
      </text>
    </svg>
  );
}