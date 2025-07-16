import React from 'react';
import { KeyPackage } from './MLSVisualizer';
import { Card, CardContent } from './ui/card';

interface KeyPackageManagerProps {
  keyPackage: KeyPackage;
}

export function KeyPackageManager({ keyPackage }: KeyPackageManagerProps) {
  const dataPreview = Array.from(keyPackage.data.slice(0, 8))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  return (
    <Card>
      <CardContent className="pt-4">
        <div className="space-y-2">
          <div className="flex items-center space-x-2">
            <div className="text-2xl">📦</div>
            <div>
              <div className="font-semibold">Key Package</div>
              <div className="text-xs font-mono text-gray-500">
                {dataPreview}...
              </div>
            </div>
          </div>
          <div className="text-xs text-gray-500">
            Published at {new Date(keyPackage.timestamp).toLocaleTimeString()}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}