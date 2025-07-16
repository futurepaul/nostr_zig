import React, { useMemo, useEffect, useRef } from 'react';
import mermaid from 'mermaid';
import { ProtocolStep } from './MLSVisualizer';

// Initialize mermaid
mermaid.initialize({ 
  startOnLoad: false,
  theme: 'neutral',
  themeVariables: {
    primaryColor: '#3B82F6',
    primaryTextColor: '#fff',
    primaryBorderColor: '#1E40AF',
    lineColor: '#6B7280',
    secondaryColor: '#E5E7EB',
    tertiaryColor: '#F3F4F6'
  }
});

interface StateTransitionDiagramProps {
  currentStep: ProtocolStep;
}

export function StateTransitionDiagram({ currentStep }: StateTransitionDiagramProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const diagramId = useMemo(() => `mermaid-${Math.random().toString(36).substr(2, 9)}`, []);

  const diagram = useMemo(() => {
    const highlightClass = (step: ProtocolStep) => 
      step === currentStep ? ':::current' : '';

    return `
      stateDiagram-v2
        [*] --> Setup${highlightClass('setup')}: Initialize Identities
        Setup --> KeyPackages${highlightClass('keyPackages')}: Publish Key Packages
        KeyPackages --> GroupCreation${highlightClass('groupCreation')}: Alice Creates Group
        GroupCreation --> Welcome${highlightClass('welcome')}: Send Welcome to Bob
        Welcome --> GroupJoined${highlightClass('groupJoined')}: Bob Processes Welcome
        GroupJoined --> Messaging${highlightClass('messaging')}: Exchange Messages
        Messaging --> Messaging: Send/Receive
        
        classDef current fill:#3B82F6,stroke:#1E40AF,color:#fff
    `;
  }, [currentStep]);

  useEffect(() => {
    const renderDiagram = async () => {
      if (containerRef.current) {
        try {
          const { svg } = await mermaid.render(diagramId, diagram);
          containerRef.current.innerHTML = svg;
        } catch (error) {
          console.error('Failed to render mermaid diagram:', error);
          containerRef.current.innerHTML = '<div class="text-red-500">Failed to render diagram</div>';
        }
      }
    };
    
    renderDiagram();
  }, [diagram, diagramId]);

  return (
    <div className="flex justify-center" ref={containerRef}>
      {/* Mermaid diagram will be rendered here */}
    </div>
  );
}