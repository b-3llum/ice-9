import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import ForceGraph2D from 'react-force-graph-2d'
import { intelApi } from '../../api/intel'
import type { GraphEntity, GraphRelationship, EntityType } from '../../types'
import GraphControls from './GraphControls'
import GraphLegend from './GraphLegend'
import NodeTooltip from './NodeTooltip'
import EntityDetail from '../intel/EntityDetail'

const ENTITY_COLORS: Record<EntityType, string> = {
  person: '#3b82f6',
  host: '#22c55e',
  domain: '#a855f7',
  credential: '#ef4444',
  email: '#f59e0b',
  organization: '#06b6d4',
  service: '#6366f1',
  network: '#14b8a6',
  certificate: '#ec4899',
}

interface GraphNode {
  id: string
  name: string
  entity_type: EntityType
  confidence: number
  properties: Record<string, unknown>
  sources: string[]
  val: number // node size
  color: string
}

interface GraphLink {
  source: string
  target: string
  rel_type: string
  confidence: number
}

interface Props {
  campaignId: string
}

export default function IntelGraph({ campaignId }: Props) {
  const queryClient = useQueryClient()
  const graphRef = useRef<any>()
  const [selectedNode, setSelectedNode] = useState<GraphEntity | null>(null)
  const [hoveredNode, setHoveredNode] = useState<GraphNode | null>(null)
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 })
  const [filters, setFilters] = useState<Set<EntityType>>(new Set())
  const [search, setSearch] = useState('')
  const [contextMenu, setContextMenu] = useState<{
    node: GraphNode
    x: number
    y: number
  } | null>(null)

  const { data: graphData, isLoading } = useQuery({
    queryKey: ['graph', campaignId],
    queryFn: () => intelApi.getGraph(campaignId),
    refetchInterval: 15000,
  })

  const enrichMutation = useMutation({
    mutationFn: (entityId: string) => intelApi.enrichEntity(campaignId, entityId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['graph', campaignId] }),
  })

  const profileMutation = useMutation({
    mutationFn: (entityId: string) => intelApi.createProfile(campaignId, entityId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['subjects', campaignId] }),
  })

  // Transform API data to force-graph format
  const { nodes, links } = useMemo(() => {
    if (!graphData) return { nodes: [], links: [] }

    const connectionCounts: Record<string, number> = {}
    for (const edge of graphData.edges) {
      connectionCounts[edge.source_id] = (connectionCounts[edge.source_id] || 0) + 1
      connectionCounts[edge.target_id] = (connectionCounts[edge.target_id] || 0) + 1
    }

    let filteredNodes = graphData.nodes
    if (filters.size > 0) {
      filteredNodes = filteredNodes.filter(n => !filters.has(n.entity_type))
    }
    if (search) {
      const q = search.toLowerCase()
      filteredNodes = filteredNodes.filter(n =>
        n.name.toLowerCase().includes(q) ||
        n.entity_type.includes(q)
      )
    }

    const nodeIds = new Set(filteredNodes.map(n => n.id))

    const nodes: GraphNode[] = filteredNodes.map(n => ({
      id: n.id,
      name: n.name,
      entity_type: n.entity_type,
      confidence: n.confidence,
      properties: n.properties,
      sources: n.sources,
      val: Math.max(2, (connectionCounts[n.id] || 0) + 1),
      color: ENTITY_COLORS[n.entity_type] || '#666',
    }))

    const links: GraphLink[] = graphData.edges
      .filter(e => nodeIds.has(e.source_id) && nodeIds.has(e.target_id))
      .map(e => ({
        source: e.source_id,
        target: e.target_id,
        rel_type: e.rel_type,
        confidence: e.confidence,
      }))

    return { nodes, links }
  }, [graphData, filters, search])

  const handleNodeClick = useCallback((node: GraphNode) => {
    setContextMenu(null)
    const entity = graphData?.nodes.find(n => n.id === node.id) || null
    setSelectedNode(entity)
  }, [graphData])

  const handleNodeRightClick = useCallback((node: GraphNode, event: MouseEvent) => {
    event.preventDefault()
    setContextMenu({ node, x: event.clientX, y: event.clientY })
  }, [])

  const handleNodeHover = useCallback((node: GraphNode | null, prevNode: GraphNode | null) => {
    setHoveredNode(node)
    if (node && graphRef.current) {
      const screen = graphRef.current.graph2ScreenCoords(
        (node as any).x || 0,
        (node as any).y || 0
      )
      setTooltipPos({ x: screen.x, y: screen.y })
    }
  }, [])

  const nodeCanvasObject = useCallback((node: GraphNode, ctx: CanvasRenderingContext2D) => {
    const size = Math.sqrt(node.val) * 3
    const { x, y } = node as any

    // Draw node circle
    ctx.beginPath()
    ctx.arc(x, y, size, 0, Math.PI * 2)
    ctx.fillStyle = node.color
    ctx.globalAlpha = 0.3 + node.confidence * 0.7
    ctx.fill()
    ctx.globalAlpha = 1
    ctx.strokeStyle = node.color
    ctx.lineWidth = 1.5
    ctx.stroke()

    // Draw label
    const label = node.name.length > 20 ? node.name.slice(0, 18) + '...' : node.name
    ctx.font = '3px sans-serif'
    ctx.textAlign = 'center'
    ctx.textBaseline = 'top'
    ctx.fillStyle = '#e5e7eb'
    ctx.fillText(label, x, y + size + 2)
  }, [])

  const linkCanvasObject = useCallback((link: any, ctx: CanvasRenderingContext2D) => {
    const start = link.source
    const end = link.target
    if (!start.x || !end.x) return

    ctx.beginPath()
    ctx.moveTo(start.x, start.y)
    ctx.lineTo(end.x, end.y)
    ctx.strokeStyle = '#4b5563'
    ctx.lineWidth = 0.5 + link.confidence * 1.5
    ctx.globalAlpha = 0.4 + link.confidence * 0.4
    ctx.stroke()
    ctx.globalAlpha = 1
  }, [])

  // Close context menu on click elsewhere
  useEffect(() => {
    const close = () => setContextMenu(null)
    window.addEventListener('click', close)
    return () => window.removeEventListener('click', close)
  }, [])

  if (isLoading) {
    return <div className="text-gray-400 p-8 text-center">Loading intelligence graph...</div>
  }

  if (!graphData || graphData.node_count === 0) {
    return (
      <div className="text-gray-500 p-8 text-center">
        <p className="text-lg mb-2">No entities discovered yet.</p>
        <p className="text-sm">Run reconnaissance phases or extract entities from existing task results.</p>
      </div>
    )
  }

  return (
    <div className="relative">
      <GraphControls
        search={search}
        onSearchChange={setSearch}
        filters={filters}
        onFiltersChange={setFilters}
        nodeCount={nodes.length}
        edgeCount={links.length}
      />

      <div className="bg-ice-900 rounded-lg border border-gray-700 overflow-hidden" style={{ height: '600px' }}>
        <ForceGraph2D
          ref={graphRef}
          graphData={{ nodes, links }}
          nodeId="id"
          nodeCanvasObject={nodeCanvasObject}
          linkCanvasObject={linkCanvasObject}
          onNodeClick={handleNodeClick}
          onNodeRightClick={handleNodeRightClick}
          onNodeHover={handleNodeHover}
          backgroundColor="#0f1117"
          cooldownTicks={100}
          d3AlphaDecay={0.02}
          d3VelocityDecay={0.3}
        />
      </div>

      <GraphLegend />

      {hoveredNode && (
        <NodeTooltip node={hoveredNode} x={tooltipPos.x} y={tooltipPos.y} />
      )}

      {contextMenu && (
        <div
          className="fixed bg-gray-800 border border-gray-600 rounded shadow-lg py-1 z-50"
          style={{ left: contextMenu.x, top: contextMenu.y }}
          onClick={e => e.stopPropagation()}
        >
          <button
            className="block w-full text-left px-4 py-2 text-sm text-gray-200 hover:bg-gray-700"
            onClick={() => {
              enrichMutation.mutate(contextMenu.node.id)
              setContextMenu(null)
            }}
          >
            Enrich
          </button>
          {contextMenu.node.entity_type === 'person' && (
            <>
              <button
                className="block w-full text-left px-4 py-2 text-sm text-gray-200 hover:bg-gray-700"
                onClick={() => {
                  profileMutation.mutate(contextMenu.node.id)
                  setContextMenu(null)
                }}
              >
                Create Profile
              </button>
            </>
          )}
        </div>
      )}

      {selectedNode && (
        <EntityDetail
          campaignId={campaignId}
          entity={selectedNode}
          onClose={() => setSelectedNode(null)}
        />
      )}
    </div>
  )
}
