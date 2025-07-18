import React, { createContext, useContext, useState, useCallback } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';

interface InfoMessage {
  id: string;
  title: string;
  content: string;
  type?: 'info' | 'warning' | 'error';
}

interface InfoPanelContextType {
  showInfo: (title: string, content: string, type?: 'info' | 'warning' | 'error') => void;
  clearInfo: () => void;
  currentInfo: InfoMessage | null;
}

const InfoPanelContext = createContext<InfoPanelContextType | null>(null);

export function useInfoPanel() {
  const context = useContext(InfoPanelContext);
  if (!context) {
    throw new Error('useInfoPanel must be used within InfoPanelProvider');
  }
  return context;
}

export function InfoPanelProvider({ children }: { children: React.ReactNode }) {
  const [currentInfo, setCurrentInfo] = useState<InfoMessage | null>(null);

  const showInfo = useCallback((title: string, content: string, type: 'info' | 'warning' | 'error' = 'info') => {
    setCurrentInfo({
      id: Date.now().toString(),
      title,
      content,
      type,
    });
  }, []);

  const clearInfo = useCallback(() => {
    setCurrentInfo(null);
  }, []);

  return (
    <InfoPanelContext.Provider value={{ showInfo, clearInfo, currentInfo }}>
      {children}
      {currentInfo && <InfoPanelDisplay />}
    </InfoPanelContext.Provider>
  );
}

function InfoPanelDisplay() {
  const { currentInfo, clearInfo } = useInfoPanel();

  if (!currentInfo) return null;

  const typeStyles = {
    info: 'bg-blue-50 border-blue-200',
    warning: 'bg-yellow-50 border-yellow-200',
    error: 'bg-red-50 border-red-200',
  };

  const iconMap = {
    info: '💡',
    warning: '⚠️',
    error: '❌',
  };

  return (
    <div className="fixed bottom-4 right-4 z-50 max-w-md">
      <Card className={`border-2 shadow-lg ${typeStyles[currentInfo.type || 'info']}`}>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-semibold flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span>{iconMap[currentInfo.type || 'info']}</span>
              {currentInfo.title}
            </div>
            <button
              onClick={clearInfo}
              className="text-gray-500 hover:text-gray-700 text-lg leading-none"
              aria-label="Close"
            >
              ✕
            </button>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm whitespace-pre-wrap">{currentInfo.content}</p>
        </CardContent>
      </Card>
    </div>
  );
}

// Helper component to replace InfoTooltip
interface InfoButtonProps {
  title: string;
  content: string;
  children?: React.ReactNode;
}

export function InfoButton({ title, content, children }: InfoButtonProps) {
  const { showInfo } = useInfoPanel();

  return (
    <button
      onClick={() => showInfo(title, content)}
      className="text-blue-500 hover:text-blue-700 cursor-help text-xs ml-1"
      type="button"
    >
      {children || 'ℹ️'}
    </button>
  );
}

// Wrapper component to replace InfoTooltip usage
interface InfoWrapperProps {
  tooltip: string;
  children: React.ReactNode;
}

export function InfoWrapper({ tooltip, children }: InfoWrapperProps) {
  const { showInfo } = useInfoPanel();
  
  // Extract title from children if it's a string or has text content
  const title = typeof children === 'string' 
    ? children 
    : React.Children.toArray(children).find(child => typeof child === 'string') || 'Information';

  return (
    <div className="inline-flex items-center gap-1">
      {children}
      <button
        onClick={() => showInfo(title as string, tooltip)}
        className="text-blue-500 hover:text-blue-700 cursor-help text-xs"
        type="button"
      >
        ℹ️
      </button>
    </div>
  );
}