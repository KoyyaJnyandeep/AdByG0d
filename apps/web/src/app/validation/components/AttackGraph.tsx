"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import * as d3 from "d3";
import type { FusionResult, KillChain } from "../lib/types";

interface AttackGraphProps {
  result: FusionResult | null;
}

type GraphNode = {
  id: string;
  label: string;
  type: string;
  risk: number;
  x?: number;
  y?: number;
  fx?: number | null;
  fy?: number | null;
};

type GraphEdge = {
  source: string | GraphNode;
  target: string | GraphNode;
  label: string;
  risk: number;
};

function buildGraph(result: FusionResult | null): { nodes: GraphNode[]; links: GraphEdge[] } {
  if (!result) return { nodes: [], links: [] };

  const nodes = new Map<string, GraphNode>();
  const links: GraphEdge[] = [];

  const ensure = (id: string, type: string, risk = result.risk_score) => {
    if (!nodes.has(id)) {
      nodes.set(id, { id, label: id.replace(/_/g, " "), type, risk });
    }
    return nodes.get(id)!;
  };

  for (const chain of result.kill_chains ?? []) {
    let previous: string | null = null;
    for (const step of chain.steps) {
      const id = `${step.module_id}:${step.technique}`;
      ensure(id, step.module_id, chain.composite_risk);
      if (previous) {
        links.push({ source: previous, target: id, label: step.mitre_id, risk: chain.composite_risk });
      }
      previous = id;
    }
  }

  if (nodes.size === 0) {
    ensure(result.module_id || "module", "module", result.risk_score);
    for (const [tactic, techniques] of Object.entries(result.mitre_coverage ?? {})) {
      for (const technique of techniques) {
        const id = `${tactic}:${technique}`;
        ensure(id, tactic, result.risk_score);
        links.push({ source: result.module_id || "module", target: id, label: technique, risk: result.risk_score });
      }
    }
  }

  return { nodes: [...nodes.values()], links };
}

function nodeColor(node: GraphNode) {
  if (node.risk >= 8) return "#ef4444";
  if (node.risk >= 6) return "#f97316";
  if (node.risk >= 4) return "#eab308";
  if (node.risk >= 2) return "#60a5fa";
  return "#6b7280";
}

export default function AttackGraph({ result }: AttackGraphProps) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const graph = useMemo(() => buildGraph(result), [result]);
  const chains: KillChain[] = result?.kill_chains ?? [];

  useEffect(() => {
    const svgEl = svgRef.current;
    if (!svgEl || graph.nodes.length === 0) return;

    const width = svgEl.clientWidth || 900;
    const height = 460;
    const svg = d3.select(svgEl);
    svg.selectAll("*").remove();

    const root = svg.append("g");
    svg.call(
      d3.zoom<SVGSVGElement, unknown>().scaleExtent([0.4, 3]).on("zoom", (event) => {
        root.attr("transform", event.transform);
      })
    );

    const links = graph.links.map((link) => ({ ...link }));
    const nodes = graph.nodes.map((node) => ({ ...node }));

    const simulation = d3.forceSimulation(nodes)
      .force("link", d3.forceLink<GraphNode, GraphEdge>(links).id((d) => d.id).distance(110))
      .force("charge", d3.forceManyBody().strength(-260))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide(34));

    const link = root.append("g")
      .selectAll("line")
      .data(links)
      .join("line")
      .attr("stroke", (d) => d.risk >= 6 ? "#ef4444aa" : "#ffffff22")
      .attr("stroke-width", (d) => d.risk >= 6 ? 2 : 1);

    const node = root.append("g")
      .selectAll("g")
      .data(nodes)
      .join("g")
      .style("cursor", "pointer")
      .call((selection) => {
        d3.drag<SVGGElement, GraphNode>()
          .on("start", (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on("drag", (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on("end", (event, d) => {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          })(selection as d3.Selection<SVGGElement, GraphNode, SVGGElement, unknown>);
      });

    node.append("circle")
      .attr("r", 18)
      .attr("fill", nodeColor)
      .attr("fill-opacity", 0.22)
      .attr("stroke", nodeColor)
      .attr("stroke-width", 1.5);

    node.append("text")
      .attr("text-anchor", "middle")
      .attr("dy", 34)
      .attr("fill", "#d1d5db")
      .attr("font-size", 10)
      .text((d) => d.label.slice(0, 20));

    node.on("click", (_, d) => setSelected(d));

    simulation.on("tick", () => {
      link
        .attr("x1", (d) => (d.source as GraphNode).x ?? 0)
        .attr("y1", (d) => (d.source as GraphNode).y ?? 0)
        .attr("x2", (d) => (d.target as GraphNode).x ?? 0)
        .attr("y2", (d) => (d.target as GraphNode).y ?? 0);
      node.attr("transform", (d) => `translate(${d.x ?? 0},${d.y ?? 0})`);
    });

    return () => {
      simulation.stop();
    };
  }, [graph]);

  if (!result) {
    return <div className="text-center py-16 text-gray-600 text-sm">Run a module to render the attack graph.</div>;
  }

  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
      <section className="min-h-[460px] rounded-lg border border-white/10 bg-black/30">
        {graph.nodes.length > 0 ? (
          <svg ref={svgRef} className="h-[460px] w-full" role="img" aria-label="Attack graph" />
        ) : (
          <div className="flex h-[460px] items-center justify-center text-sm text-gray-600">No graphable attack paths in this result.</div>
        )}
      </section>

      <aside className="rounded-lg border border-white/10 bg-white/[0.04] p-4">
        <h3 className="mb-3 text-sm font-semibold text-white">Graph Detail</h3>
        {selected ? (
          <div className="space-y-2">
            <div className="text-sm font-bold text-white">{selected.label}</div>
            <div className="text-xs text-gray-500">{selected.type.replace(/_/g, " ")}</div>
            <div className="font-mono text-xs text-orange-300">risk {selected.risk.toFixed(1)}</div>
          </div>
        ) : (
          <div className="text-xs leading-5 text-gray-500">Select a node to inspect its risk contribution.</div>
        )}

        <div className="mt-5">
          <div className="mb-2 text-xs font-semibold text-gray-500">KILL CHAINS</div>
          <div className="space-y-2">
            {chains.slice(0, 6).map((chain) => (
              <div key={chain.chain_id} className="rounded border border-white/10 bg-black/20 p-2">
                <div className="text-xs font-semibold text-white">{chain.name}</div>
                <div className="mt-1 font-mono text-[10px] text-gray-500">{chain.composite_risk.toFixed(1)} risk · {chain.steps.length} steps</div>
              </div>
            ))}
          </div>
        </div>
      </aside>
    </div>
  );
}
