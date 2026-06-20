from typing import Dict, Any, List
from iris.db import cache

class RelationshipGraph:
    """Builds a relationship graph from correlations."""
    
    def __init__(self):
        self.nodes = set()
        self.edges = []

    def build_from_entity(self, entity: str) -> Dict[str, Any]:
        """Build a graph centered around a specific entity."""
        correlations = cache.get_correlations(entity)
        
        for c in correlations:
            self.nodes.add(c["entity_a"])
            self.nodes.add(c["entity_b"])
            self.edges.append({
                "source": c["entity_a"],
                "target": c["entity_b"],
                "relationship": c["relationship"],
                "confidence": c["confidence"]
            })
            
        return {
            "nodes": list(self.nodes),
            "edges": self.edges
        }
