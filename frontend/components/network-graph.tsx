'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import { CytoscapeGraphData, FraudRing, ShellChainPath } from '@/lib/types';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Slider } from '@/components/ui/slider';
import { X, ZoomIn, ZoomOut } from 'lucide-react';
import { Button } from '@/components/ui/button';

type PatternFilter =
  | 'all'
  | 'cycle'
  | 'fan_in'
  | 'fan_out'
  | 'shell_chain'
  | 'suspicious';

interface NetworkGraphProps {
  graphData: CytoscapeGraphData;
  fraudRings: FraudRing[];
  highlightedNodes?: string[];
  onNodeClick?: (accountId: string) => void;
}

// TASK 5: Consistent pattern-based color scheme
const PATTERN_COLORS: Record<string, string> = {
  cycle: '#ef4444',
  fan_in: '#3b82f6',
  fan_out: '#f97316',
  shell_chain: '#a855f7',
  community: '#10b981',
};

const PATTERN_LABELS: Record<string, string> = {
  cycle: 'Cycle',
  fan_in: 'Fan-In',
  fan_out: 'Fan-Out',
  shell_chain: 'Shell Chain',
  community: 'Community',
};

function getNodeColor(patterns: string[] | undefined | null): string {
  if (!patterns || patterns.length === 0) return '#6366f1';
  // Priority: cycle > shell > fan_in > fan_out
  const priority = ['cycle', 'shell_chain', 'fan_in', 'fan_out'];
  for (const p of priority) {
    if (patterns.includes(p)) return PATTERN_COLORS[p];
  }
  return '#ef4444';
}

function getEdgeColor(patternTypes: string[] | undefined | null): string {
  if (!patternTypes || patternTypes.length === 0) return '#6366f1';
  const priority = ['cycle', 'shell_chain', 'fan_in', 'fan_out'];
  for (const p of priority) {
    if (patternTypes.includes(p)) return PATTERN_COLORS[p];
  }
  return '#ef4444';
}

export function NetworkGraph({
  graphData,
  fraudRings,
  highlightedNodes = [],
  onNodeClick,
}: NetworkGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<any>(null);
  const hoverTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [tooltipNode, setTooltipNode] = useState<any>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const [tooltipVisible, setTooltipVisible] = useState(false);
  const [pinnedNode, setPinnedNode] = useState<any>(null);
  const [shellPanel, setShellPanel] = useState<{
    nodeId: string;
    paths: ShellChainPath[];
  } | null>(null);
  const [patternFilter, setPatternFilter] = useState<PatternFilter>('all');
  const [zoomLevel, setZoomLevel] = useState([1]);

  // Use refs for values needed inside Cytoscape event handlers
  // to avoid recreating the entire graph on every state change
  const pinnedNodeRef = useRef<any>(null);
  const onNodeClickRef = useRef(onNodeClick);
  pinnedNodeRef.current = pinnedNode;
  onNodeClickRef.current = onNodeClick;

  // TASK 8: Performance safeguard
  const isLargeGraph = graphData.nodes.length > 300;

  const getFilteredElements = useCallback(
    (filter: PatternFilter) => {
      if (filter === 'all') {
        return {
          nodes: graphData.nodes,
          edges: graphData.edges,
        };
      }

      if (filter === 'suspicious') {
        const suspNodes = graphData.nodes.filter(
          (n) => n.data.is_suspicious
        );
        const suspIds = new Set(suspNodes.map((n) => n.data.id));
        const suspEdges = graphData.edges.filter(
          (e) => suspIds.has(e.data.source) && suspIds.has(e.data.target)
        );
        return { nodes: suspNodes, edges: suspEdges };
      }

      // Filter by pattern type - find nodes involved in this pattern via edges
      const relevantEdges = graphData.edges.filter((e) =>
        (e.data.pattern_types || []).includes(filter)
      );
      const nodeIds = new Set<string>();
      relevantEdges.forEach((e) => {
        nodeIds.add(e.data.source);
        nodeIds.add(e.data.target);
      });
      const patternNodes = graphData.nodes.filter((n) =>
        nodeIds.has(n.data.id)
      );
      return { nodes: patternNodes, edges: relevantEdges };
    },
    [graphData]
  );

  // TASK 1: Layout config based on filter and size
  const getLayoutConfig = useCallback(
    (filter: PatternFilter, nodeCount: number) => {
      const animate = !isLargeGraph && nodeCount < 300;

      if (filter === 'cycle') {
        return {
          name: 'breadthfirst',
          animate,
          fit: true,
          padding: 50,
          spacingFactor: 1.5,
          directed: true,
          circle: true,
        };
      }

      if (filter === 'fan_in' || filter === 'fan_out') {
        return {
          name: 'concentric',
          animate,
          fit: true,
          padding: 50,
          minNodeSpacing: 50,
          concentric: (node: any) => {
            return node.data('suspicion_score') || 0;
          },
          levelWidth: () => 2,
        };
      }

      // Default: cose (force-directed)
      return {
        name: 'cose',
        animate,
        fit: true,
        padding: 50,
        nodeRepulsion: () => (nodeCount > 100 ? 12000 : 8000),
        idealEdgeLength: () => (nodeCount > 100 ? 150 : 120),
        gravity: 0.25,
        numIter: nodeCount > 200 ? 200 : 400,
        nodeDimensionsIncludeLabels: true,
      };
    },
    [isLargeGraph]
  );

  // Main Cytoscape initialization effect
  // Only depends on graphData and patternFilter – NOT on pinnedNode/onNodeClick
  useEffect(() => {
    let cancelled = false;
    let layoutRef: any = null;

    const destroyCy = (instance: any) => {
      if (!instance) return;
      try {
        if (!instance.destroyed()) {
          // Stop any running layout first to prevent notify errors
          try { instance.stop(); } catch (_) {}
          instance.destroy();
        }
      } catch (_) {}
    };

    const init = async () => {
      if (!containerRef.current) return;

      const cytoscape = (await import('cytoscape')).default;

      // If this effect was cleaned up while we were importing, bail out
      if (cancelled) return;

      // Destroy previous instance safely
      destroyCy(cyRef.current);
      cyRef.current = null;

      const { nodes: filteredNodes, edges: filteredEdges } =
        getFilteredElements(patternFilter);

      if (filteredNodes.length === 0) {
        cyRef.current = null;
        return;
      }

      // Store complex data (tooltips, fan-in txns, shell paths) outside of
      // Cytoscape elements to avoid style-hint crashes from non-primitive data
      const nodeDataMap = new Map<string, any>();

      const elements: any[] = [];

      filteredNodes.forEach((node) => {
        const patterns = node.data.detected_patterns || [];
        const isSuspicious = !!node.data.is_suspicious;
        const hasMultiplePatterns = patterns.length > 1;
        const score = node.data.suspicion_score ?? 0;

        // Store full data for tooltip lookups (NOT inside Cytoscape)
        nodeDataMap.set(node.data.id, node.data);

        // Determine classes for pattern-based coloring (avoids data() mappers for colors)
        const classes: string[] = [];

        // Primary pattern class for background-color
        const priority = ['cycle', 'shell_chain', 'fan_in', 'fan_out', 'community'];
        for (const p of priority) {
          if (patterns.includes(p)) {
            classes.push(`pat-${p}`);
            break;
          }
        }

        // Secondary pattern class for border-color (multi-pattern nodes)
        if (hasMultiplePatterns) {
          classes.push('multi-pattern');
          const secondary = patterns.filter((p: string) => p !== patterns[0]);
          for (const p of priority) {
            if (secondary.includes(p)) {
              classes.push(`bdr-${p}`);
              break;
            }
          }
        }

        if (isSuspicious) classes.push('suspicious');
        if (score > 70) classes.push('critical');

        elements.push({
          group: 'nodes',
          data: {
            // Only primitive values for data() mappers — numeric only
            id: node.data.id,
            label: node.data.label || node.data.id || '',
            suspicion_score: score,
            is_suspicious: isSuspicious,
            in_degree: node.data.in_degree ?? 0,
            out_degree: node.data.out_degree ?? 0,
            total_amount_sent: node.data.total_amount_sent ?? 0,
            total_amount_received: node.data.total_amount_received ?? 0,
            total_transactions: node.data.total_transactions ?? 0,
            // Numeric-only data mappers (safe — they go through updateGrKey, not updateGrKeyWStr)
            nodeSize: isSuspicious
              ? 28 + Math.min(score / 3, 22)
              : 18,
            borderWidth: hasMultiplePatterns ? 5 : isSuspicious ? 3 : 1.5,
          },
          classes: classes.join(' '),
        });
      });

      filteredEdges.forEach((edge, idx) => {
        const patternTypes = edge.data.pattern_types || [];
        const classes: string[] = [];

        // Edge pattern class for color
        const priority = ['cycle', 'shell_chain', 'fan_in', 'fan_out', 'community'];
        for (const p of priority) {
          if (patternTypes.includes(p)) {
            classes.push(`ept-${p}`);
            break;
          }
        }
        if (patternTypes.length > 0) classes.push('patterned');

        elements.push({
          group: 'edges',
          data: {
            id: `e${idx}`,
            source: edge.data.source,
            target: edge.data.target,
            amount: edge.data.amount ?? 0,
            transaction_count: edge.data.transaction_count ?? 0,
            label: edge.data.label || '',
            // Numeric-only data mapper (safe)
            edgeWidth: isLargeGraph
              ? 1
              : patternTypes.length > 0
              ? 2
              : 1.2,
          },
          classes: classes.join(' '),
        });
      });

      const layoutConfig = getLayoutConfig(
        patternFilter,
        filteredNodes.length
      );

      // Double-check container and cancellation before creating instance
      if (cancelled || !containerRef.current) return;

      let cy: any;
      try {
        cy = cytoscape({
          container: containerRef.current,
          elements,
          // Use a preset layout initially, run layout manually afterwards
          // to keep a reference for stopping it on cleanup
          layout: { name: 'preset' },
          style: [
            // ── NODE BASE ─────────────────────────────────
            // Colors are set via classes, NOT data() mappers, to avoid
            // Cytoscape updateGrKeyWStr crash (color props have type.multiple=true
            // which bypasses the numeric hash path and calls strVal.length)
            {
              selector: 'node',
              style: {
                'background-color': '#6366f1',
                width: 'data(nodeSize)',
                height: 'data(nodeSize)',
                'border-width': 'data(borderWidth)',
                'border-color': 'rgba(255,255,255,0.15)',
                label: isLargeGraph ? '' : 'data(label)',
                'font-size': '8px',
                color: '#cbd5e1',
                'text-valign': 'bottom',
                'text-margin-y': 6,
                'text-outline-width': 2,
                'text-outline-color': '#0a0e1a',
                'min-zoomed-font-size': 10,
              } as any,
            },
            // ── NODE PATTERN COLORS (background) ──────────
            { selector: 'node.pat-cycle', style: { 'background-color': '#ef4444' } as any },
            { selector: 'node.pat-fan_in', style: { 'background-color': '#3b82f6' } as any },
            { selector: 'node.pat-fan_out', style: { 'background-color': '#f97316' } as any },
            { selector: 'node.pat-shell_chain', style: { 'background-color': '#a855f7' } as any },
            { selector: 'node.pat-community', style: { 'background-color': '#10b981' } as any },
            // ── NODE BORDER COLORS (secondary pattern) ────
            { selector: 'node.suspicious', style: { 'border-color': '#ffffff', 'font-weight': 'bold', 'font-size': '9px' } as any },
            { selector: 'node.bdr-cycle', style: { 'border-color': '#ef4444' } as any },
            { selector: 'node.bdr-fan_in', style: { 'border-color': '#3b82f6' } as any },
            { selector: 'node.bdr-fan_out', style: { 'border-color': '#f97316' } as any },
            { selector: 'node.bdr-shell_chain', style: { 'border-color': '#a855f7' } as any },
            { selector: 'node.bdr-community', style: { 'border-color': '#10b981' } as any },
            // ── NODE STATES ───────────────────────────────
            { selector: 'node.critical', style: { 'border-color': '#fbbf24', 'border-width': 4 } as any },
            { selector: 'node.hovered', style: { 'border-width': 6, 'z-index': 50 } as any },
            // ── EDGE BASE ─────────────────────────────────
            {
              selector: 'edge',
              style: {
                width: 'data(edgeWidth)',
                'line-color': '#6366f1',
                'target-arrow-color': '#6366f1',
                'target-arrow-shape': 'triangle',
                'curve-style': 'bezier',
                'arrow-scale': 0.7,
                opacity: 0.6,
                label: '',
                'font-size': '7px',
                color: '#94a3b8',
                'text-outline-width': 1.5,
                'text-outline-color': '#0a0e1a',
              } as any,
            },
            // ── EDGE PATTERN COLORS ───────────────────────
            { selector: 'edge.ept-cycle', style: { 'line-color': '#ef4444', 'target-arrow-color': '#ef4444' } as any },
            { selector: 'edge.ept-fan_in', style: { 'line-color': '#3b82f6', 'target-arrow-color': '#3b82f6' } as any },
            { selector: 'edge.ept-fan_out', style: { 'line-color': '#f97316', 'target-arrow-color': '#f97316' } as any },
            { selector: 'edge.ept-shell_chain', style: { 'line-color': '#a855f7', 'target-arrow-color': '#a855f7' } as any },
            { selector: 'edge.ept-community', style: { 'line-color': '#10b981', 'target-arrow-color': '#10b981' } as any },
            // ── HIGHLIGHTS ────────────────────────────────
            {
              selector: '.highlighted',
              style: {
                'border-color': '#fbbf24',
                'border-width': 6,
                'z-index': 100,
              } as any,
            },
            {
              selector: '.highlighted-edge',
              style: {
                'line-color': '#fbbf24',
                'target-arrow-color': '#fbbf24',
                width: 3,
                'z-index': 100,
              } as any,
            },
            // ── EDGE LABEL ON HOVER ───────────────────────
            {
              selector: 'edge.show-label',
              style: {
                label: 'data(label)',
              } as any,
            },
            // ── ZOOM-BASED LABELS ─────────────────────────
            { selector: 'node.show-label', style: { label: 'data(label)', 'font-size': '9px' } as any },
            { selector: 'node.show-label-suspicious', style: { label: 'data(label)' } as any },
          ],
          minZoom: 0.2,
          maxZoom: 4,
        });
      } catch (err) {
        console.error('Cytoscape creation error:', err);
        cyRef.current = null;
        return;
      }

      // If cancelled during cy creation, destroy immediately
      if (cancelled) {
        destroyCy(cy);
        return;
      }

      // Run layout with a stored reference so we can stop it on cleanup
      try {
        layoutRef = cy.layout(layoutConfig as any);
        layoutRef.run();
      } catch (_) {}

      // Critical nodes are already styled via the 'critical' class — no animation needed
      // (Removes all .animate() calls that could corrupt strValue in Cytoscape style hints)

      // Hover tooltip with 300ms delay — use addClass/removeClass only (no .style() calls)
      cy.on('mouseover', 'node', (evt: any) => {
        if (cy.destroyed()) return;
        const node = evt.target;
        if (containerRef.current) containerRef.current.style.cursor = 'pointer';
        try {
          node.addClass('hovered');
        } catch (_) {}

        if (hoverTimeoutRef.current) clearTimeout(hoverTimeoutRef.current);
        hoverTimeoutRef.current = setTimeout(() => {
          try {
            if (cy.destroyed()) return;
            const renderedPos = node.renderedPosition();
            setTooltipPos({ x: renderedPos.x, y: renderedPos.y });
            const nodeId = node.data('id');
            const fullData = nodeDataMap.get(nodeId);
            setTooltipNode({ ...node.data(), ...fullData });
            setTooltipVisible(true);
          } catch (_) {}
        }, 300);
      });

      cy.on('mouseout', 'node', (evt: any) => {
        if (cy.destroyed()) return;
        const node = evt.target;
        if (containerRef.current) containerRef.current.style.cursor = 'default';

        if (hoverTimeoutRef.current) {
          clearTimeout(hoverTimeoutRef.current);
          hoverTimeoutRef.current = null;
        }

        try {
          node.removeClass('hovered');
          const currentPinned = pinnedNodeRef.current;
          if (!currentPinned || currentPinned.id !== node.data('id')) {
            setTooltipVisible(false);
            setTimeout(() => {
              if (!pinnedNodeRef.current) setTooltipNode(null);
            }, 200);
          }
        } catch (_) {}
      });

      // Show edge label on hover
      cy.on('mouseover', 'edge', (evt: any) => {
        if (cy.destroyed()) return;
        try { evt.target.addClass('show-label'); } catch (_) {}
      });
      cy.on('mouseout', 'edge', (evt: any) => {
        if (cy.destroyed()) return;
        try { evt.target.removeClass('show-label'); } catch (_) {}
      });

      // Click node to pin tooltip & open shell panel
      cy.on('tap', 'node', (evt: any) => {
        if (cy.destroyed()) return;
        try {
          const cyData = evt.target.data();
          const fullData = nodeDataMap.get(cyData.id);
          const nodeData = { ...cyData, ...fullData };
          const renderedPos = evt.target.renderedPosition();
          setPinnedNode(nodeData);
          setTooltipNode(nodeData);
          setTooltipPos({ x: renderedPos.x, y: renderedPos.y });
          setTooltipVisible(true);

          if (
            nodeData.shell_chain_paths &&
            nodeData.shell_chain_paths.length > 0
          ) {
            setShellPanel({
              nodeId: nodeData.id,
              paths: nodeData.shell_chain_paths,
            });
          }

          if (onNodeClickRef.current) onNodeClickRef.current(nodeData.id);
        } catch (_) {}
      });

      cy.on('tap', (evt: any) => {
        if (cy.destroyed()) return;
        if (evt.target === cy) {
          setPinnedNode(null);
          setTooltipNode(null);
          setTooltipVisible(false);
        }
      });

      // Show labels when zoomed in — use addClass/removeClass (no .style() calls)
      cy.on('zoom', () => {
        try {
          if (cy.destroyed()) return;
          const zoom = cy.zoom();
          setZoomLevel([zoom]);
          const nodes = cy.nodes();
          if (zoom > 1.5) {
            nodes.addClass('show-label');
            nodes.removeClass('show-label-suspicious');
          } else if (zoom > 0.8) {
            nodes.removeClass('show-label');
            nodes.filter('[?is_suspicious]').addClass('show-label-suspicious');
            nodes.filter('[!is_suspicious]').removeClass('show-label-suspicious');
          } else {
            nodes.removeClass('show-label show-label-suspicious');
          }
        } catch (_) {}
      });

      cyRef.current = cy;
    };

    init();

    return () => {
      cancelled = true;
      if (hoverTimeoutRef.current) clearTimeout(hoverTimeoutRef.current);
      // Stop the layout before destroying to prevent notify errors
      if (layoutRef) {
        try { layoutRef.stop(); } catch (_) {}
        layoutRef = null;
      }
      destroyCy(cyRef.current);
      cyRef.current = null;
    };
  }, [graphData, patternFilter, getFilteredElements, getLayoutConfig, isLargeGraph]);

  // Highlight nodes from external selection
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || cy.destroyed()) return;
    try {
      cy.elements().removeClass('highlighted highlighted-edge');
      if (highlightedNodes.length > 0) {
        highlightedNodes.forEach((nodeId) => {
          cy.getElementById(nodeId).addClass('highlighted');
        });
        cy.edges().forEach((edge: any) => {
          const src = edge.source().id();
          const tgt = edge.target().id();
          if (
            highlightedNodes.includes(src) &&
            highlightedNodes.includes(tgt)
          ) {
            edge.addClass('highlighted-edge');
          }
        });
      }
    } catch (_) { /* ignore if cy was destroyed between check and use */ }
  }, [highlightedNodes]);

  // TASK 7: Filter transitions — no .animate() calls to avoid strValue corruption
  const handleFilterChange = (value: string) => {
    setPatternFilter(value as PatternFilter);
    setPinnedNode(null);
    setTooltipNode(null);
    setTooltipVisible(false);
    setShellPanel(null);
  };

  // Zoom controls
  const handleZoom = (direction: 'in' | 'out') => {
    const cy = cyRef.current;
    if (!cy || cy.destroyed()) return;
    try {
      const current = cy.zoom();
      const newZoom =
        direction === 'in'
          ? Math.min(current * 1.3, 4)
          : Math.max(current / 1.3, 0.2);
      cy.animate({ zoom: newZoom, duration: 200 } as any);
    } catch (e) {
      // Ignore zoom errors on destroyed instances
    }
  };

  const handleZoomSlider = (value: number[]) => {
    const cy = cyRef.current;
    if (!cy || cy.destroyed()) return;
    try {
      cy.zoom(value[0]);
      cy.center();
    } catch (e) {
      // Ignore zoom errors on destroyed instances
    }
  };

  const displayNode = pinnedNode || (tooltipVisible ? tooltipNode : null);

  const { nodes: currentNodes } = getFilteredElements(patternFilter);
  const filterLabel: Record<PatternFilter, string> = {
    all: 'Full Transaction Network',
    cycle: 'Cycles (3-5)',
    fan_in: 'Fan-In Networks',
    fan_out: 'Fan-Out Networks',
    shell_chain: 'Shell Chains Only',
    suspicious: 'Suspicious Accounts Only',
  };

  return (
    <div className="relative">
      {/* TASK 3: Pattern filter selector */}
      <div className="flex items-center gap-3 mb-4">
        <label className="text-xs font-medium text-muted-foreground whitespace-nowrap">
          View Pattern
        </label>
        <Select value={patternFilter} onValueChange={handleFilterChange}>
          <SelectTrigger className="w-[240px] h-8 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Full Transaction Network</SelectItem>
            <SelectItem value="cycle">Cycles (3-5)</SelectItem>
            <SelectItem value="fan_in">Fan-In Networks</SelectItem>
            <SelectItem value="fan_out">Fan-Out Networks</SelectItem>
            <SelectItem value="shell_chain">Shell Chains Only</SelectItem>
            <SelectItem value="suspicious">Suspicious Accounts Only</SelectItem>
          </SelectContent>
        </Select>

        {patternFilter !== 'all' && (
          <Badge
            className="text-xs"
            style={{
              backgroundColor:
                PATTERN_COLORS[patternFilter] || '#6366f1',
              color: '#fff',
            }}
          >
            {filterLabel[patternFilter]} ({currentNodes.length} nodes)
          </Badge>
        )}

        <span className="text-xs text-muted-foreground ml-auto">
          {graphData.nodes.length} accounts / {graphData.edges.length} edges
        </span>
      </div>

      {/* Graph container */}
      <div className="relative overflow-hidden">
        <div
          ref={containerRef}
          className="w-full border border-border rounded-lg bg-[#070b14]"
          style={{ height: '600px' }}
        />

        {/* TASK 6: Zoom controls */}
        <div className="absolute bottom-4 right-4 flex flex-col items-center gap-2 z-40 bg-background/80 backdrop-blur-sm border border-border rounded-lg p-2">
          <Button
            variant="secondary"
            size="icon"
            className="h-7 w-7"
            onClick={() => handleZoom('in')}
          >
            <ZoomIn className="h-3.5 w-3.5" />
          </Button>
          <div className="h-28">
            <Slider
              value={zoomLevel}
              min={0.2}
              max={4}
              step={0.1}
              orientation="vertical"
              className="min-h-0! h-full"
              onValueChange={handleZoomSlider}
            />
          </div>
          <Button
            variant="secondary"
            size="icon"
            className="h-7 w-7"
            onClick={() => handleZoom('out')}
          >
            <ZoomOut className="h-3.5 w-3.5" />
          </Button>
        </div>

        {/* Empty state */}
        {currentNodes.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center">
            <p className="text-muted-foreground text-sm">
              No nodes match the selected filter.
            </p>
          </div>
        )}

        {/* TASK 2: Smooth tooltip (fade-in/out) */}
        {displayNode && (
          <div
            className="absolute z-50 pointer-events-none"
            style={{
              left: Math.min(tooltipPos.x + 16, (containerRef.current?.clientWidth ?? 600) - 320),
              top: Math.max(tooltipPos.y - 20, 8),
              opacity: tooltipVisible || pinnedNode ? 1 : 0,
              transition: 'opacity 200ms ease-in-out, left 100ms ease-out, top 100ms ease-out',
            }}
          >
            <Card
              className={`p-3 bg-card/95 backdrop-blur-sm shadow-2xl min-w-[260px] max-w-[300px] border ${
                displayNode.suspicion_score > 70
                  ? 'border-red-500/60'
                  : 'border-border'
              } pointer-events-auto`}
            >
              <div className="space-y-2.5">
                {/* Header */}
                <div className="flex items-center justify-between gap-2">
                  <span
                    className={`font-mono text-sm font-semibold ${
                      displayNode.suspicion_score > 70
                        ? 'text-red-400'
                        : 'text-foreground'
                    }`}
                  >
                    {displayNode.id}
                  </span>
                  {displayNode.is_suspicious && (
                    <Badge
                      variant="destructive"
                      className="text-[10px] px-1.5 py-0"
                    >
                      SUSPICIOUS
                    </Badge>
                  )}
                </div>

                {/* Score */}
                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-muted-foreground">
                      Suspicion Score
                    </span>
                    <span
                      className="font-bold font-mono"
                      style={{
                        color:
                          displayNode.suspicion_score > 70
                            ? '#ef4444'
                            : displayNode.suspicion_score > 30
                            ? '#f59e0b'
                            : '#22c55e',
                      }}
                    >
                      {displayNode.suspicion_score}/100
                    </span>
                  </div>
                  <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: `${displayNode.suspicion_score}%`,
                        backgroundColor:
                          displayNode.suspicion_score > 70
                            ? '#ef4444'
                            : displayNode.suspicion_score > 30
                            ? '#f59e0b'
                            : '#22c55e',
                      }}
                    />
                  </div>
                </div>

                {/* Patterns & Ring IDs */}
                {displayNode.detected_patterns?.length > 0 && (
                  <div>
                    <span className="text-[10px] text-muted-foreground block mb-1">
                      Detected Patterns
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {displayNode.detected_patterns.map(
                        (p: string) => (
                          <Badge
                            key={p}
                            className="text-[10px] px-1.5 py-0"
                            style={{
                              backgroundColor:
                                PATTERN_COLORS[p] || '#6366f1',
                              color: '#fff',
                            }}
                          >
                            {PATTERN_LABELS[p] || p}
                          </Badge>
                        )
                      )}
                    </div>
                  </div>
                )}

                {displayNode.ring_ids?.length > 0 && (
                  <div>
                    <span className="text-[10px] text-muted-foreground block mb-1">
                      Ring ID
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {displayNode.ring_ids.map((r: string) => (
                        <Badge
                          key={r}
                          variant="outline"
                          className="text-[10px] font-mono px-1.5 py-0"
                        >
                          {r}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Stats */}
                <div className="text-[11px] space-y-1 pt-2 border-t border-border">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">
                      Total Transactions
                    </span>
                    <span className="font-mono text-foreground">
                      {displayNode.total_transactions ?? (displayNode.in_degree + displayNode.out_degree)}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">
                      Total Amount Sent
                    </span>
                    <span className="font-mono text-foreground">
                      $
                      {displayNode.total_amount_sent?.toLocaleString() ||
                        '0'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">
                      Total Amount Received
                    </span>
                    <span className="font-mono text-foreground">
                      $
                      {displayNode.total_amount_received?.toLocaleString() ||
                        '0'}
                    </span>
                  </div>
                </div>

                {/* TASK 4: Fan-in transactions */}
                {displayNode.fan_in_transactions?.length > 0 && (
                  <div className="pt-2 border-t border-border">
                    <span className="text-[10px] text-blue-400 font-semibold block mb-1.5">
                      Fan-in Transactions (Last 72h):
                    </span>
                    <div className="max-h-32 overflow-y-auto space-y-0.5">
                      {displayNode.fan_in_transactions
                        .slice(0, 10)
                        .map((tx: any, i: number) => (
                          <div
                            key={i}
                            className="text-[10px] font-mono text-muted-foreground flex justify-between gap-2"
                          >
                            <span className="truncate">
                              {tx.sender_id} {'->'}  {tx.receiver_id}
                            </span>
                            <span className="whitespace-nowrap text-foreground">
                              ${tx.amount.toLocaleString()} | {tx.timestamp}
                            </span>
                          </div>
                        ))}
                    </div>
                  </div>
                )}

                {pinnedNode && (
                  <p className="text-[10px] text-muted-foreground italic">
                    Click background to dismiss
                  </p>
                )}
              </div>
            </Card>
          </div>
        )}
      </div>

      {/* TASK 4: Shell Chain Side Panel */}
      {shellPanel && (
        <div className="absolute top-0 right-0 w-80 h-[600px] bg-card/95 backdrop-blur-sm border border-border rounded-r-lg z-50 overflow-y-auto">
          <div className="p-4">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-foreground">
                Shell Chain Paths
              </h3>
              <Button
                variant="ghost"
                size="icon"
                className="h-6 w-6"
                onClick={() => setShellPanel(null)}
              >
                <X className="h-3.5 w-3.5" />
              </Button>
            </div>
            <p className="text-xs text-muted-foreground mb-3">
              Node: <span className="font-mono text-foreground">{shellPanel.nodeId}</span>
            </p>

            {shellPanel.paths.map((sp, idx) => (
              <div key={idx} className="mb-4 p-3 bg-muted/30 rounded-lg">
                <div className="text-xs font-semibold text-purple-400 mb-2">
                  Shell Chain Path:
                </div>
                <div className="text-xs font-mono text-foreground mb-2">
                  {sp.path.join(' -> ')}
                </div>
                <div className="space-y-1">
                  {sp.hops.map((hop, hIdx) => (
                    <div
                      key={hIdx}
                      className="text-[10px] font-mono text-muted-foreground"
                    >
                      {hop.from} {'->'}  {hop.to} |{' '}
                      <span className="text-foreground">
                        ${hop.amount.toLocaleString()}
                      </span>{' '}
                      | {hop.timestamp}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TASK 5: Legend */}
      <div className="mt-4 flex flex-wrap items-center gap-4 text-xs">
        <span className="text-muted-foreground font-medium">Legend:</span>
        {Object.entries(PATTERN_COLORS).map(([key, color]) => (
          <div key={key} className="flex items-center gap-1.5">
            <div
              className="w-3 h-3 rounded-full"
              style={{ backgroundColor: color }}
            />
            <span className="text-muted-foreground">
              {PATTERN_LABELS[key]}
            </span>
          </div>
        ))}
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-full bg-[#6366f1]" />
          <span className="text-muted-foreground">Normal</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-full border-2 border-dashed border-yellow-400" />
          <span className="text-muted-foreground">Highlighted</span>
        </div>
      </div>
    </div>
  );
}
