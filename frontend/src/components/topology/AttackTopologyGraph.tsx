import React, { useMemo, useState } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  type Node,
  type Edge,
  Position,
  MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Network } from 'lucide-react';
import type { CanonicalEvent } from '../../types';

interface AttackTopologyGraphProps {
  events: CanonicalEvent[];
  height?: string | number;
}

export const AttackTopologyGraph: React.FC<AttackTopologyGraphProps> = ({
  events = [],
  height = '500px',
}) => {
  const [selectedEntity, setSelectedEntity] = useState<{ type: string; id: string } | null>(null);

  // Transform real canonical events into entity relationship nodes & edges
  const { nodes, edges } = useMemo(() => {
    const sourceIps = new Set<string>();
    const accounts = new Set<string>();
    const devices = new Set<string>();
    const destIps = new Set<string>();
    const ports = new Set<string>();

    const edgesList: Edge[] = [];
    const edgeSet = new Set<string>();

    // Process up to 100 recent events to avoid rendering thousands of duplicates
    const subset = events.slice(0, 100);

    subset.forEach((ev) => {
      const srcIp = ev.source_ip;
      const account = ev.user_id;
      const dev = ev.device_id;
      const destIp = ev.destination_ip;
      const port = ev.port ? String(ev.port) : null;

      if (srcIp) sourceIps.add(srcIp);
      if (account) accounts.add(account);
      if (dev) devices.add(dev);
      if (destIp) destIps.add(destIp);
      if (port) ports.add(port);

      // Connect IP -> Account
      if (srcIp && account) {
        const key = `e-src-${srcIp}-acc-${account}`;
        if (!edgeSet.has(key)) {
          edgeSet.add(key);
          edgesList.push({
            id: key,
            source: `ip-${srcIp}`,
            target: `acc-${account}`,
            animated: true,
            style: { stroke: '#00d2ff', strokeWidth: 1.5 },
            markerEnd: { type: MarkerType.ArrowClosed, color: '#00d2ff' },
          });
        }
      }

      // Connect Account -> Device
      if (account && dev) {
        const key = `e-acc-${account}-dev-${dev}`;
        if (!edgeSet.has(key)) {
          edgeSet.add(key);
          edgesList.push({
            id: key,
            source: `acc-${account}`,
            target: `dev-${dev}`,
            style: { stroke: '#3a86ff', strokeWidth: 1.5 },
            markerEnd: { type: MarkerType.ArrowClosed, color: '#3a86ff' },
          });
        }
      }

      // Connect IP -> Dest IP directly if no account (e.g. port scan)
      if (srcIp && destIp && !account) {
        const key = `e-src-${srcIp}-dest-${destIp}`;
        if (!edgeSet.has(key)) {
          edgeSet.add(key);
          edgesList.push({
            id: key,
            source: `ip-${srcIp}`,
            target: `dest-${destIp}`,
            animated: true,
            style: { stroke: '#f97316', strokeWidth: 1.5 },
            markerEnd: { type: MarkerType.ArrowClosed, color: '#f97316' },
          });
        }
      }

      // Connect Dest IP -> Port
      if (destIp && port) {
        const key = `e-dest-${destIp}-port-${port}`;
        if (!edgeSet.has(key)) {
          edgeSet.add(key);
          edgesList.push({
            id: key,
            source: `dest-${destIp}`,
            target: `port-${port}`,
            style: { stroke: '#8b9bb4', strokeWidth: 1.2 },
            markerEnd: { type: MarkerType.ArrowClosed, color: '#8b9bb4' },
          });
        }
      }
    });

    const nodesList: Node[] = [];

    // Column 1: Source IPs (x = 50)
    Array.from(sourceIps).slice(0, 10).forEach((ip, idx) => {
      nodesList.push({
        id: `ip-${ip}`,
        position: { x: 40, y: 40 + idx * 75 },
        data: { label: ip, type: 'SOURCE IP' },
        sourcePosition: Position.Right,
        style: {
          background: '#0d131d',
          color: '#00d2ff',
          border: '1px solid #00d2ff80',
          borderRadius: '8px',
          padding: '8px 12px',
          fontSize: '11px',
          fontFamily: 'monospace',
          fontWeight: 600,
          boxShadow: '0 0 10px rgba(0, 210, 255, 0.15)',
        },
      });
    });

    // Column 2: Target Accounts (x = 280)
    Array.from(accounts).slice(0, 8).forEach((acc, idx) => {
      nodesList.push({
        id: `acc-${acc}`,
        position: { x: 280, y: 50 + idx * 80 },
        data: { label: acc, type: 'ACCOUNT' },
        targetPosition: Position.Left,
        sourcePosition: Position.Right,
        style: {
          background: '#0d131d',
          color: '#f0f4fc',
          border: '1px solid #3a86ff80',
          borderRadius: '8px',
          padding: '8px 12px',
          fontSize: '11px',
          fontFamily: 'monospace',
          fontWeight: 600,
        },
      });
    });

    // Column 3: Devices (x = 520)
    Array.from(devices).slice(0, 8).forEach((dev, idx) => {
      nodesList.push({
        id: `dev-${dev}`,
        position: { x: 520, y: 60 + idx * 80 },
        data: { label: dev, type: 'DEVICE' },
        targetPosition: Position.Left,
        sourcePosition: Position.Right,
        style: {
          background: '#0d131d',
          color: '#c084fc',
          border: '1px solid #9333ea80',
          borderRadius: '8px',
          padding: '8px 12px',
          fontSize: '11px',
          fontFamily: 'monospace',
        },
      });
    });

    // Column 4: Destination IPs (x = 760)
    Array.from(destIps).slice(0, 8).forEach((dest, idx) => {
      nodesList.push({
        id: `dest-${dest}`,
        position: { x: 760, y: 50 + idx * 80 },
        data: { label: dest, type: 'DESTINATION' },
        targetPosition: Position.Left,
        sourcePosition: Position.Right,
        style: {
          background: '#0d131d',
          color: '#f97316',
          border: '1px solid #f9731680',
          borderRadius: '8px',
          padding: '8px 12px',
          fontSize: '11px',
          fontFamily: 'monospace',
        },
      });
    });

    // Column 5: Destination Ports (x = 1000)
    Array.from(ports).slice(0, 10).forEach((port, idx) => {
      nodesList.push({
        id: `port-${port}`,
        position: { x: 1000, y: 40 + idx * 60 },
        data: { label: `Port ${port}`, type: 'PORT' },
        targetPosition: Position.Left,
        style: {
          background: '#0d131d',
          color: '#34d399',
          border: '1px solid #10b98180',
          borderRadius: '6px',
          padding: '6px 10px',
          fontSize: '10px',
          fontFamily: 'monospace',
        },
      });
    });

    return { nodes: nodesList, edges: edgesList };
  }, [events]);

  return (
    <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl overflow-hidden shadow-xl relative flex flex-col">
      <div className="p-4 border-b border-[#1c2638] flex items-center justify-between bg-[#090e17]">
        <div className="flex items-center space-x-2.5">
          <Network className="w-5 h-5 text-cyan-400" />
          <div>
            <h2 className="text-sm font-semibold text-white tracking-wide">Attack Topology</h2>
            <p className="text-xs text-slate-400">
              Entity relationship view: Source IP → Account → Device → Destination → Port
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-3 text-xs font-mono">
          <span className="flex items-center space-x-1 text-cyan-400">
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
            <span>IP</span>
          </span>
          <span className="flex items-center space-x-1 text-blue-400">
            <span className="w-2 h-2 rounded-full bg-blue-400" />
            <span>Account</span>
          </span>
          <span className="flex items-center space-x-1 text-purple-400">
            <span className="w-2 h-2 rounded-full bg-purple-400" />
            <span>Device</span>
          </span>
          <span className="flex items-center space-x-1 text-orange-400">
            <span className="w-2 h-2 rounded-full bg-orange-400" />
            <span>Dest IP</span>
          </span>
          <span className="flex items-center space-x-1 text-emerald-400">
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            <span>Port</span>
          </span>
        </div>
      </div>

      <div style={{ height }} className="w-full relative">
        {nodes.length === 0 ? (
          <div className="h-full flex items-center justify-center text-xs font-mono text-slate-500">
            No active entity relationships found in recent telemetry.
          </div>
        ) : (
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodeClick={(_, node) =>
              setSelectedEntity({ type: node.data?.type as string, id: node.data?.label as string })
            }
            fitView
            minZoom={0.2}
            maxZoom={1.5}
            proOptions={{ hideAttribution: true }}
          >
            <Background color="#162030" gap={16} />
            <Controls className="bg-[#0d131d] border border-[#1c2638] fill-slate-300" />
          </ReactFlow>
        )}

        {/* Selected Entity Inspector Panel */}
        {selectedEntity && (
          <div className="absolute top-4 right-4 bg-[#090e17]/95 border border-cyan-800/80 rounded-xl p-4 w-72 shadow-2xl backdrop-blur text-xs z-10">
            <div className="flex items-center justify-between border-b border-[#1c2638] pb-2 mb-2">
              <span className="text-[10px] font-mono text-cyan-400 uppercase font-bold tracking-wider">
                {selectedEntity.type}
              </span>
              <button
                onClick={() => setSelectedEntity(null)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>
            <div className="font-mono text-sm font-bold text-slate-100 break-all mb-2">
              {selectedEntity.id}
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Active telemetry node correlated from real canonical events stored in SQLite.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
