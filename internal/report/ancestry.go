package report

import "github.com/0x4D31/maratus/internal/artifact"

// artifactAncestry indexes a previously validated parent forest. A saved
// report can have a deep parent chain and many references to the same leaf;
// walking that chain for every proof would multiply independent input bounds.
// DFS intervals make every strict-ancestor check constant-time instead.
type artifactAncestry struct {
	parents   map[string]string
	intervals map[string]artifactInterval
}

type artifactInterval struct {
	start int
	end   int
}

func indexArtifactAncestry(nodes []artifact.Node, parents map[string]string) artifactAncestry {
	index := artifactAncestry{parents: parents, intervals: make(map[string]artifactInterval, len(nodes))}
	children := make(map[string][]string, len(nodes))
	for _, node := range nodes {
		children[node.ParentID] = append(children[node.ParentID], node.ID)
	}

	type visit struct {
		id   string
		exit bool
	}
	stack := make([]visit, 0, len(nodes))
	for _, id := range children[""] {
		stack = append(stack, visit{id: id})
	}
	position := 0
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current.exit {
			interval := index.intervals[current.id]
			interval.end = position
			index.intervals[current.id] = interval
			continue
		}
		index.intervals[current.id] = artifactInterval{start: position}
		position++
		stack = append(stack, visit{id: current.id, exit: true})
		for _, id := range children[current.id] {
			stack = append(stack, visit{id: id})
		}
	}
	return index
}

func (a artifactAncestry) isAncestor(ancestor, node string) bool {
	parent, parentExists := a.intervals[ancestor]
	child, childExists := a.intervals[node]
	return parentExists && childExists && parent.start < child.start && child.start < parent.end
}
